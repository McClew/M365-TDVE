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
        return f"{self.authority}/oauth2/v2.0/authorise"

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
