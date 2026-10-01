# Password-change telemetry module
# 
# Performs a self-service password change for each declared test user via
# ``POST /me/changePassword`` (delegated, using the per-user ROPC token). Generates
# the password-change audit event so the detection can be validated.
# 
# IMPORTANT operational notes:
#  * This rotates the test account's password for real. Subsequent ROPC logins use
#    the *new* value, so your credential store / config must be updated to the new
#    password after a run (or set ``new_password`` to the value you keep on file).
#  * ``changePassword`` needs the current and new password. The current password
#    is read from the target's own credential (``targets.users[].password`` /
#    ``M365TDVE_TEST_PASSWORD``) -- the same secret ROPC uses -- so set only
#    ``new_password`` in the modules.password_change block. Only run against
#    disposable test accounts.
#  * Admin-side reset of *another* user is the alternative shape
#    (``PATCH /users/{id}`` with ``passwordProfile`` + a privileged token); it logs
#    as "Reset user password" rather than the self-service event.
# 
# Integration points: see inbox_rule.py. Keep ``expected_event`` in step with
# ``src/training/reference.py`` -- confirm the exact string against your tenant's
# Entra audit log (activityDisplayName varies, e.g. "Change password
# (self-service)").

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


class PasswordChangeModule(TelemetryModule):
    key = "password_change"
    expected_event = "Change user password"   # Entra audit (self-service); verify
    remediation = (
        "Confirm the password change was user-initiated and expected. Correlate "
        "with sign-in risk and recent location/device changes. For unexpected "
        "changes, reset the password again from a trusted context, revoke "
        "sessions, and review registered authentication methods for tampering."
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
        new_password = self.settings.get("new_password")

        for user in self.config.users:
            result = self._new_result(target_user=user.upn)
            start = time.monotonic()
            try:
                # Current password = the target's own credential (the same secret
                # ROPC uses). Fall back to a config value if your loader does not
                # attach the password to the user object.
                current_password = (
                    getattr(user, "password", None)
                    or self.settings.get("current_password")
                )
                if not current_password or not new_password:
                    _note(result, "skipped: no current password for user and/or "
                                  "modules.password_change.new_password not set")
                else:
                    token = self._delegated_token(user.upn)
                    self._graph(
                        token, "POST", "me/changePassword", result,
                        json={"currentPassword": current_password,
                              "newPassword": new_password},
                    )
                    # No secrets recorded in artifacts -- only the fact of the change.
                    result.artifacts.setdefault("created", []).append(
                        {"type": "passwordChange", "upn": user.upn}
                    )
                    _note(result, "self-service password change completed; update "
                                  "the stored credential to the new value")

            except Exception as exc:  # noqa: BLE001
                _note(result, f"error: {exc!r}")

            result.duration_seconds = round(time.monotonic() - start, 3)
            results.append(result)
        return results