# Base class and structured result type for telemetry modules

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

# Default scope for delegated Graph calls. `.default` resolves to whatever
# delegated permissions are configured on the test app registration.
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

@dataclass
class ModuleResult:
    """Structured JSON-serialisable summary of a module execution."""
    module: str
    expected_saas_alerts_event: str
    target_remediation: str
    started_at: str
    duration_seconds: float
    target_user: str | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class TelemetryModule:
    """Base class: each module emits one deterministic class of telemetry.

    Subclasses declare their expected CDR mapping and implement run().
    """

    key: str = "base"
    expected_event: str = ""
    remediation: str = ""

    def __init__(self, config, client, logger):
        self.config = config
        self.client = client
        self.log = logger
        self.settings = (config.modules or {}).get(self.key, {}) or {}

    def _new_result(self, target_user: str | None = None) -> ModuleResult:
        return ModuleResult(
            module=self.key,
            expected_saas_alerts_event=self.expected_event,
            target_remediation=self.remediation,
            started_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            duration_seconds=0.0,
            target_user=target_user,
        )

    def _password_for(self, upn: str) -> str | None:
        """Resolve the configured password for a UPN from the declared targets."""
        for user in self.config.users:
            if user.upn.lower() == upn.lower():
                return user.password or None
        return None

    def _delegated_token(self, upn: str, scope: str = GRAPH_SCOPE) -> str:
        """Acquire a delegated Graph access token for ``upn``.

        Used by the authenticated (post-breach) modules. The flow is chosen by
        ``config.auth.delegated_flow``:

        * ``device_code`` - run ONE interactive sign-in (which can satisfy MFA),
          cache the issued token on the shared client, and reuse it for every
          module in the run. Device code authenticates whoever signs in, so it
          cannot mint a token per-UPN; a mismatch against ``upn`` is warned about
          but the session token is still used.
        * ``ropc`` (default) - the non-interactive password grant, per-user. It
          cannot satisfy MFA (AADSTS50076) and will fail on protected accounts.

        Raises if a token cannot be obtained; the caller records that as a
        per-user error rather than aborting the batch.
        """
        auth = getattr(self.config, "auth", None)
        if auth is not None and auth.delegated_flow == "device_code":
            return self._device_code_token(upn)

        password = self._password_for(upn)
        if not password:
            raise RuntimeError(
                f"no password available for {upn} - add it to targets.users "
                f"or set M365TDVE_TEST_PASSWORD"
            )
        resp = self.client.ropc_token(
            client_id=self.config.client_id,
            username=upn,
            password=password,
            scope=scope,
        )
        return self._extract_token(resp, upn)

    def _device_code_token(self, upn: str) -> str:
        """Return a shared delegated token acquired once via the device-code flow.

        The first call triggers an interactive sign-in (the operator completes
        MFA in a browser); the token and the authenticated UPN are cached on the
        shared ``AuthClient`` so later modules reuse the same live session. A
        failed sign-in is cached too, so a multi-user batch does not re-prompt
        for every target.
        """
        client = self.client
        if getattr(client, "delegated_auth_error", None):
            raise RuntimeError(
                f"device-code session unavailable: {client.delegated_auth_error}"
            )

        token = getattr(client, "delegated_token", None)
        if not token:
            auth = self.config.auth
            try:
                resp = client.device_code_login(
                    self.config.client_id, auth.scope,
                    timeout_seconds=auth.device_code_timeout,
                )
            except Exception as exc:  # cache + re-raise so we prompt only once
                client.delegated_auth_error = str(exc)
                raise
            token = (resp.body or {}).get("access_token")
            if not token:
                client.delegated_auth_error = "device-code flow returned no access_token"
                raise RuntimeError(client.delegated_auth_error)
            client.delegated_token = token
            # Learn who actually signed in, for mismatch warnings. Never log the token.
            who = client.graph_get("https://graph.microsoft.com/v1.0/me", token)
            client.delegated_upn = (
                (who.body or {}).get("userPrincipalName") if who.ok else None
            )

        sess_upn = getattr(client, "delegated_upn", None)
        if sess_upn and sess_upn.lower() != upn.lower():
            self.log.warning(
                "device-code session authenticated as %s but module targets %s; "
                "using the session token (device code cannot mint tokens per-UPN).",
                sess_upn, upn,
            )
        return token

    @staticmethod
    def _extract_token(resp, upn: str) -> str:
        token = (resp.body or {}).get("access_token")
        if not token:
            # Surface the specific Entra cause, not just the OAuth category.
            # `invalid_grant` alone is ambiguous; the AADSTS code and description
            # distinguish bad password / expired / MFA-required / disabled /
            # public-client-misconfigured.
            parts = [p for p in (
                resp.error,
                f"AADSTS{resp.entra_error_code}" if resp.entra_error_code else None,
                resp.error_description,
                f"HTTP {resp.http_status}" if resp.http_status else None,
            ) if p]
            detail = " | ".join(parts) or "no token returned"
            raise RuntimeError(f"ROPC token request for {upn} failed ({detail})")
        return token

    def run(self) -> list[ModuleResult]:  # pragma: no cover - interface
        raise NotImplementedError
