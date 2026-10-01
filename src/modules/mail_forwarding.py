# Mail-forwarding telemetry module
# 
# Creates an inbox rule that forwards to a controlled sink address on each declared
# test user. This is the classic BEC exfiltration pattern, so it is a high-value
# detection to validate. It is kept benign by gating the rule behind a synthetic
# subject marker, so real mail is never actually forwarded while the rule's
# *configuration* (external forwardTo) still produces the audit signal.
# 
# Graph note: true mailbox-level forwarding
# (``Set-Mailbox -ForwardingSmtpAddress`` / ``-ForwardingAddress``) is an Exchange
# Online operation and is not exposed in Graph v1.0; it logs as ``Set-Mailbox``.
# This module uses the rule-based path, which is reachable with the per-user ROPC
# token and logs as ``New-InboxRule`` (plus your external-forwarding signals).
# 
# Integration points: see inbox_rule.py (identical client/result contract).
# Keep ``expected_event`` in step with ``src/training/reference.py``.

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

class MailForwardingModule(TelemetryModule):
    key = "mail_forwarding"
    expected_event = "New-InboxRule"          # forwarding rule; see note above
    remediation = (
        "Remove external forwarding. Audit both inbox rules (ForwardTo/RedirectTo) "
        "and mailbox settings (Set-Mailbox ForwardingSmtpAddress / "
        "ForwardingAddress). Alert on auto-forwarding to external domains and "
        "treat it as a likely BEC indicator; revoke sessions and reset "
        "credentials if the change was unauthorised."
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
        rule_name = self.settings.get("rule_name", "ZZ-Telemetry-Forwarding")
        # Point this at a mailbox you control. Keep it off-domain so the rule
        # exercises the "external forwarding" detection path.
        forward_to = self.settings.get("forward_to", "telemetry-sink@example.invalid")
        marker = self.settings.get("match_subject", "TELEMETRY-PROBE")
        cleanup = self.settings.get("cleanup", True)

        for user in self.config.users:
            result = self._new_result(target_user=user.upn)
            start = time.monotonic()
            try:
                token = self._delegated_token(user.upn)

                body = {
                    "displayName": rule_name,
                    "sequence": 1,
                    "isEnabled": True,
                    # Gate on a synthetic marker so no live mail is forwarded.
                    "conditions": {"subjectContains": [marker]},
                    "actions": {
                        "forwardTo": [
                            {"emailAddress": {"address": forward_to, "name": forward_to}}
                        ],
                        "stopProcessingRules": False,
                    },
                }
                resp = self._graph(
                    token, "POST",
                    f"users/{user.upn}/mailFolders/inbox/messageRules",
                    result, json=body,
                )
                rule_id = (resp.body or {}).get("id")
                result.artifacts.setdefault("created", []).append(
                    {"type": "forwardingRule", "id": rule_id,
                     "forwardTo": forward_to, "displayName": rule_name}
                )
                _note(result, f"created forwarding rule to {forward_to} ({rule_id})")

                if cleanup and rule_id:
                    self._graph(
                        token, "DELETE",
                        f"users/{user.upn}/mailFolders/inbox/messageRules/{rule_id}",
                        result,
                    )
                    _note(result, "cleaned up forwarding rule")

            except Exception as exc:  # noqa: BLE001
                _note(result, f"error: {exc!r}")

            result.duration_seconds = round(time.monotonic() - start, 3)
            results.append(result)
        return results
