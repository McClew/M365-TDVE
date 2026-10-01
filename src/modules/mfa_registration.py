# MFA-registration telemetry module
# 
# Exercises the authentication-methods API so that both the "security info
# registered" and "security info deleted" detections can be validated. The default
# behaviour is fully reversible: it ADDS a test phone method and then REMOVES it,
# emitting both events without touching any pre-existing method.
# 
# Set ``reset_existing: true`` (only on throwaway test accounts) to additionally
# delete existing phone methods first -- this reproduces the attacker pattern of
# wiping a victim's MFA before registering their own, but will lock out a real user,
# so it is off by default.
# 
# Privilege: managing authentication methods via Graph normally requires an
# Authentication Administrator (or Privileged Authentication Administrator) context,
# not an ordinary user token. Set ``admin_upn`` in the config block to a privileged
# test account; the module authenticates as that account (still via ROPC) and acts
# on each target user. If ``admin_upn`` is unset it falls back to the user's own
# token and will likely 403.
# 
# Integration points: see inbox_rule.py. Keep ``expected_event`` in step with
# ``src/training/reference.py`` (confirm exact strings: e.g. "User registered
# security info" / "User deleted security info" / "Admin registered security info").

from __future__ import annotations

import time
from typing import Any

from .base import ModuleResult, TelemetryModule

def _note(result: ModuleResult, message: str) -> None:
    notes = getattr(result, "notes", None)
    if isinstance(notes, list):
        notes.append(message)
    else:
        result.notes = f"{notes}; {message}" if notes else message

class MfaRegistrationModule(TelemetryModule):
    key = "mfa_registration"
    expected_event = "User registered security info"   # plus "...deleted..."; verify
    remediation = (
        "Verify any change to a user's authentication methods / security info with "
        "the user via a trusted channel. Remove attacker-controlled methods, "
        "require re-registration from a managed device, revoke sessions and reset "
        "credentials. Alert on method changes that closely follow a password "
        "change or risky sign-in."
    )

    def _graph(self, token: str, method: str, path: str, result: ModuleResult,
               json: dict[str, Any] | None = None):
        resp = self.client.graph_request(method, path, token=token, json=json)
        result.calls.append(
            {"method": method, "path": path, "status": getattr(resp, "status", None)}
        )
        return resp

    def run(self) -> list[ModuleResult]:
        results: list[ModuleResult] = []
        admin_upn = self.settings.get("admin_upn")
        test_phone = self.settings.get("test_phone_number", "+1 2065550100")
        reset_existing = self.settings.get("reset_existing", False)
        cleanup = self.settings.get("cleanup", True)

        for user in self.config.users:
            result = self._new_result(target_user=user.upn)
            start = time.monotonic()
            try:
                actor = admin_upn or user.upn
                token = self._delegated_token(actor)
                base = f"users/{user.upn}/authentication/phoneMethods"

                # Optional: remove pre-existing phone methods (destructive).
                if reset_existing:
                    existing = self._graph(token, "GET", base, result)
                    for method in (existing.body or {}).get("value", []):
                        mid = method.get("id")
                        if mid:
                            self._graph(token, "DELETE", f"{base}/{mid}", result)
                            _note(result, f"removed existing phone method {mid}")

                # Add a test method (emits the registration event).
                added = self._graph(
                    token, "POST", base, result,
                    json={"phoneNumber": test_phone, "phoneType": "mobile"},
                )
                method_id = (added.body or {}).get("id")
                result.artifacts.setdefault("created", []).append(
                    {"type": "phoneMethod", "id": method_id, "upn": user.upn}
                )
                _note(result, f"registered test phone method ({method_id})")

                # Remove it again (emits the deletion event; keeps the run benign).
                if cleanup and method_id:
                    self._graph(token, "DELETE", f"{base}/{method_id}", result)
                    _note(result, "removed test phone method")

            except Exception as exc:  # noqa: BLE001
                _note(result, f"error: {exc!r}")

            result.duration_seconds = round(time.monotonic() - start, 3)
            results.append(result)
        return results
