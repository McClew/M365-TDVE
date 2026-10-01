# Anonymous-sharing telemetry
# 
# Creates an anonymous sharing link to a designated test item via 
# `POST /drives/{driveId}/items/{itemId}/createLink` so the `AnonymousLinkCreated` 
# detection can be validated. Optionally sets an expiration and link password, 
# which is good practice for the real evidence/records use case.
# 
# Privilege: needs Files/Sites write permission and a tenant/site policy that allows
# anonymous links. Set `admin_upn` to the account that owns the sandbox item.

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

class AnonymousSharingModule(TelemetryModule):
    key = "anonymous_sharing"
    expected_event = "AnonymousLinkCreated"    # SharePoint / unified audit log
    remediation = (
        "Review anonymous ('Anyone with the link') shares, especially on sensitive "
        "libraries. Apply expiration and least privilege (view over edit), and "
        "restrict or disable anonymous sharing at the tenant/site level. For "
        "client record access prefer authenticated, time-limited links; revoke any "
        "anonymous link that was not expected."
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
        drive_id = self.settings.get("drive_id")
        item_id = self.settings.get("item_id")
        link_type = self.settings.get("link_type", "view")
        expiration = self.settings.get("expiration_datetime")
        link_password = self.settings.get("link_password")
        cleanup = self.settings.get("cleanup", True)

        for user in self.config.users:
            # target_user here is the actor exercising the share, for traceability
            result = self._new_result(target_user=admin_upn or user.upn)
            start = time.monotonic()
            try:
                if not drive_id or not item_id:
                    _note(result, "skipped: drive_id/item_id not set in "
                                  "modules.anonymous_sharing config")
                    result.duration_seconds = round(time.monotonic() - start, 3)
                    results.append(result)
                    break  # one sandbox item -> one run, not per-user

                token = self._delegated_token(admin_upn or user.upn)

                body: dict[str, Any] = {"type": link_type, "scope": "anonymous"}
                if expiration:
                    body["expirationDateTime"] = expiration
                if link_password:
                    body["password"] = link_password

                created = self._graph(
                    token, "POST",
                    f"drives/{drive_id}/items/{item_id}/createLink",
                    result, json=body,
                )
                perm = created.body or {}
                perm_id = perm.get("id")
                web_url = (perm.get("link") or {}).get("webUrl")
                result.artifacts.setdefault("created", []).append(
                    {"type": "anonymousLink", "permissionId": perm_id,
                     "webUrl": web_url, "scope": "anonymous", "linkType": link_type}
                )
                _note(result, f"created anonymous {link_type} link ({perm_id})")

                if cleanup and perm_id:
                    self._graph(
                        token, "DELETE",
                        f"drives/{drive_id}/items/{item_id}/permissions/{perm_id}",
                        result,
                    )
                    _note(result, "revoked anonymous link")

            except Exception as exc:
                _note(result, f"error: {exc!r}")

            result.duration_seconds = round(time.monotonic() - start, 3)
            results.append(result)
            break  # single sandbox target; remove to share once per declared user
        return results
