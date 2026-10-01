# Inbox-rule telemetry module
# 
# Creates a benign, clearly-named inbox rule on each declared test user so the
# matching detection (``New-InboxRule`` in the Exchange / unified audit log) can be
# validated and analysts can practise triaging mailbox-rule abuse.
# 
# Integration points (adjust to match your base.py / client):
# * ``self._delegated_token(upn)`` -> a delegated Graph access token for the UPN
# (resolves the password from the declared targets; raises if none available).
# * ``self.client.graph_request(method, path, token=, json=)`` -> resp with
# ``.status`` (int) and ``.body`` (dict). This is the ONLY place that touches
# the client's write helper -- it is centralised in ``_graph()`` below, so if
# your helper is named differently you only edit that one method.
# * ``ModuleResult`` exposes ``.calls``, ``.artifacts``, ``.notes`` and
# ``.duration_seconds`` and is built via ``self._new_result(target_user=...)``.
# 
# Keep ``expected_event`` in step with ``src/training/reference.py``.

from __future__ import annotations

import time
from typing import Any

from .base import ModuleResult, TelemetryModule

def _note(result: ModuleResult, message: str) -> None:
    """Append a note whether ``ModuleResult.notes`` is a list or a string."""
    notes = getattr(result, "notes", None)
    if isinstance(notes, list):
        notes.append(message)
    else:
        result.notes = f"{notes}; {message}" if notes else message

class InboxRuleModule(TelemetryModule):
    key = "inbox_rule"
    expected_event = "New-InboxRule"          # Exchange / unified audit log
    remediation = (
        "Review the mailbox's inbox rules and remove unexpected entries, "
        "especially rules that forward, delete, mark-as-read or move mail into "
        "an obscure folder to hide it. Confirm the change with the user; if "
        "unauthorised, revoke sessions, reset credentials and re-audit the rules."
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
        rule_name = self.settings.get("rule_name", "ZZ-Telemetry-InboxRule")
        marker = self.settings.get("match_subject", "TELEMETRY-PROBE")
        cleanup = self.settings.get("cleanup", True)

        for user in self.config.users:
            result = self._new_result(target_user=user.upn)
            start = time.monotonic()
            try:
                token = self._delegated_token(user.upn)

                # Benign by construction: the rule only ever matches a synthetic
                # subject marker, so it never acts on real mail. ``markAsRead`` is
                # an inert action. Creating it still emits the New-InboxRule event.
                body = {
                    "displayName": rule_name,
                    "sequence": 1,
                    "isEnabled": True,
                    "conditions": {"subjectContains": [marker]},
                    "actions": {"markAsRead": True, "stopProcessingRules": False},
                }
                resp = self._graph(
                    token, "POST",
                    f"users/{user.upn}/mailFolders/inbox/messageRules",
                    result, json=body,
                )
                rule_id = (resp.body or {}).get("id")
                result.artifacts.setdefault("created", []).append(
                    {"type": "inboxRule", "id": rule_id, "displayName": rule_name}
                )
                _note(result, f"created inbox rule {rule_name!r} ({rule_id})")

                if cleanup and rule_id:
                    self._graph(
                        token, "DELETE",
                        f"users/{user.upn}/mailFolders/inbox/messageRules/{rule_id}",
                        result,
                    )
                    _note(result, "cleaned up inbox rule")

            except Exception as exc:  # noqa: BLE001 - record, don't abort the batch
                _note(result, f"error: {exc!r}")

            result.duration_seconds = round(time.monotonic() - start, 3)
            results.append(result)
        return results
