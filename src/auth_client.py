# Shared OAuth 2.0 HTTP client for Entra ID endpoints
# Centralises token/authorise/devicecode calls, structured response capture, and resilient error handling for network timeouts and HTTP 429
# Uses only `requests` + the standard library

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import requests

_DEFAULT_TIMEOUT = 30
_MAX_429_RETRIES = 3
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"

@dataclass
class GraphResponse:
    """Structured record of a single authenticated Microsoft Graph call.

    Exposes ``.status`` (int) and ``.body`` (dict) - the shape the telemetry
    modules' ``_graph()`` helper expects. The bearer token is only ever sent in
    the Authorization header; it is never stored on this object or logged.
    """

    status: int | None
    body: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

@dataclass
class OAuthResponse:
    """Structured record of a single OAuth HTTP exchange."""

    endpoint: str
    http_status: int | None
    entra_error_code: str | None
    error: str | None
    error_description: str | None
    elapsed_ms: int
    body: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.http_status is not None and 200 <= self.http_status < 300

class AuthClient:
    """Thin wrapper over the Entra ID OAuth 2.0 v2.0 endpoints."""

    def __init__(self, authority: str, logger, timeout: int = _DEFAULT_TIMEOUT):
        self.authority = authority.rstrip("/")
        self.log = logger
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "M365-TDVE/1.0 (detection-validation)"}
        )

    # URL helpers
    @property
    def token_url(self) -> str:
        return f"{self.authority}/oauth2/v2.0/token"

    @property
    def devicecode_url(self) -> str:
        return f"{self.authority}/oauth2/v2.0/devicecode"

    @property
    def authorise_url(self) -> str:
        return f"{self.authority}/oauth2/v2.0/authorize"

    # Core POST with 429/timeout handling
    def _post_form(self, url: str, data: dict[str, str]) -> OAuthResponse:
        attempt = 0
        
        while True:
            attempt += 1
            start = time.monotonic()

            try:
                resp = self.session.post(url, data=data, timeout=self.timeout)
            except requests.exceptions.Timeout:
                elapsed = int((time.monotonic() - start) * 1000)
                self.log.warning("Timeout calling %s (attempt %d)", url, attempt)

                return OAuthResponse(url, None, None, "timeout", "Request timed out", elapsed)
            
            except requests.exceptions.RequestException as exc:
                elapsed = int((time.monotonic() - start) * 1000)
                self.log.error("Network error calling %s: %s", url, exc)

                return OAuthResponse(url, None, None, "network_error", str(exc), elapsed)

            elapsed = int((time.monotonic() - start) * 1000)

            # Rate limiting - honor Retry-After and back off.
            if resp.status_code == 429 and attempt <= _MAX_429_RETRIES:
                retry_after = int(resp.headers.get("Retry-After", "5") or "5")
                self.log.warning(
                    "HTTP 429 from %s; backing off %ds (attempt %d/%d)",
                    url, retry_after, attempt, _MAX_429_RETRIES,
                )
                time.sleep(retry_after)
                continue

            return self._to_response(url, resp, elapsed)

    @staticmethod
    def _to_response(url: str, resp: requests.Response,
                     elapsed_ms: int) -> OAuthResponse:
        body: dict[str, Any] = {}
        try:
            body = resp.json()
        except ValueError:
            body = {"raw": resp.text[:2000]}

        error = body.get("error")
        error_desc = body.get("error_description")

        # Entra embeds numeric error codes (e.g. AADSTS50126) in the description; surface the first one for correlation
        entra_code = None
        if error_desc:
            for token in error_desc.replace(":", " ").split():
                if token.startswith("AADSTS") and token[6:].isdigit():
                    entra_code = token[6:]
                    break
        
        return OAuthResponse(
            endpoint=url,
            http_status=resp.status_code,
            entra_error_code=entra_code,
            error=error,
            error_description=error_desc,
            elapsed_ms=elapsed_ms,
            body=body,
        )

    # Public operations
    def ropc_token(self, client_id: str, username: str, password: str,
                   scope: str) -> OAuthResponse:
        """Resource Owner Password Credentials grant.

        Used with a DELIBERATELY INVALID password to generate failed sign-in
        (50126) telemetry, or with a valid test-account password for
        MFA-prompt telemetry.
        """

        return self._post_form(self.token_url, {
            "grant_type": "password",
            "client_id": client_id,
            "username": username,
            "password": password,
            "scope": scope,
        })

    def request_device_code(self, client_id: str, scope: str) -> OAuthResponse:
        """Initiate the device authorisation flow (POST /devicecode)."""

        return self._post_form(self.devicecode_url, {
            "client_id": client_id,
            "scope": scope,
        })

    def poll_device_token(self, client_id: str,
                          device_code: str) -> OAuthResponse:
        """Poll /token for a pending device-code authorisation."""

        return self._post_form(self.token_url, {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": device_code,
        })

    def device_code_login(self, client_id: str, scope: str,
                          timeout_seconds: int = 300) -> OAuthResponse:
        """Run the device-code flow end to end and return the final OAuthResponse.

        Prints the verification URL + user code via the logger, then polls
        ``/token`` until the human completes the interactive sign-in or the flow
        times out. Unlike ROPC, this flow is interactive, so it CAN satisfy an
        MFA requirement (AADSTS50076). On success the returned response's body
        carries ``access_token``. Raises ``RuntimeError`` if the flow cannot be
        initiated or does not complete.
        """
        init = self.request_device_code(client_id, scope)
        if not init.ok:
            raise RuntimeError(
                f"device authorisation request failed "
                f"({init.error or init.http_status})"
            )

        body = init.body or {}
        device_code = body.get("device_code")
        if not device_code:
            raise RuntimeError("device authorisation response contained no device_code")
        user_code = body.get("user_code")
        verification_uri = body.get("verification_uri")
        verification_uri_complete = body.get("verification_uri_complete")
        interval = max(int(body.get("interval", 5) or 5), 1)
        expires_in = int(body.get("expires_in", 900) or 900)

        bar = "=" * 70
        self.log.info(bar)
        self.log.info("ACTION REQUIRED - complete the delegated sign-in to continue")
        self.log.info("  1. Browse to : %s", verification_uri)
        self.log.info("  2. Enter code: %s", user_code)
        if verification_uri_complete:
            self.log.info("  (direct link, code pre-filled): %s", verification_uri_complete)
        self.log.info("  3. Sign in as the TEST account and approve (complete MFA here).")
        self.log.info("Waiting for completion (polling)...")
        self.log.info(bar)

        deadline = time.monotonic() + min(expires_in, timeout_seconds)
        while time.monotonic() < deadline:
            time.sleep(interval)
            poll = self.poll_device_token(client_id, device_code)
            if poll.ok:
                self.log.info("  device-code sign-in complete; delegated token issued")
                return poll

            err = poll.error
            if err == "authorization_pending":
                continue
            if err == "slow_down":
                interval += 5
                continue
            # Any other error is terminal for this flow.
            detail = poll.error_description or err or poll.http_status
            raise RuntimeError(f"device-code sign-in not completed ({err}: {detail})")

        raise RuntimeError("device-code sign-in timed out before a token was issued")

    def graph_get(self, url: str, access_token: str) -> OAuthResponse:
        """Authenticated GET against a resource (e.g. Graph /me).

        Used to prove a device-code session is live by exercising the issued
        token. The token is sent in the Authorization header only; it is never
        logged. Reuses the structured OAuthResponse shape for consistency.
        """

        start = time.monotonic()
        try:
            resp = self.session.get(
                url,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout:
            elapsed = int((time.monotonic() - start) * 1000)
            self.log.warning("Timeout calling %s", url)
            return OAuthResponse(url, None, None, "timeout", "Request timed out", elapsed)
        except requests.exceptions.RequestException as exc:
            elapsed = int((time.monotonic() - start) * 1000)
            self.log.error("Network error calling %s: %s", url, exc)
            return OAuthResponse(url, None, None, "network_error", str(exc), elapsed)

        elapsed = int((time.monotonic() - start) * 1000)
        return self._to_response(url, resp, elapsed)

    def graph_request(self, method: str, path: str, token: str,
                      json: dict[str, Any] | None = None) -> GraphResponse:
        """Authenticated Graph call (GET/POST/PATCH/DELETE).

        ``path`` is relative to the Graph v1.0 root (e.g.
        ``users/{upn}/mailFolders/inbox/messageRules``) or an absolute URL. The
        token is sent only in the Authorization header and is never logged. A
        204/empty response yields an empty body rather than raising.
        """

        url = path if path.startswith("http") else f"{_GRAPH_BASE}/{path.lstrip('/')}"
        try:
            resp = self.session.request(
                method.upper(), url,
                headers={"Authorization": f"Bearer {token}",
                         "Content-Type": "application/json"},
                json=json,
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout:
            self.log.warning("Timeout calling Graph %s %s", method.upper(), path)
            return GraphResponse(None, {}, "timeout")
        except requests.exceptions.RequestException as exc:
            self.log.error("Network error calling Graph %s %s: %s", method.upper(), path, exc)
            return GraphResponse(None, {}, str(exc))

        body: dict[str, Any] = {}
        if resp.content:
            try:
                body = resp.json()
            except ValueError:
                body = {"raw": resp.text[:2000]}

        err = body.get("error")
        error_msg = err.get("message") if isinstance(err, dict) else err
        self.log.info("Graph %s %s -> HTTP %s", method.upper(), path, resp.status_code)
        return GraphResponse(resp.status_code, body, error_msg)
