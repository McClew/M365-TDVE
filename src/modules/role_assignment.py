# Role-assignment telemetry module
# 
# Assigns a directory role to each declared test user via the unified RBAC endpoint
# (``roleManagement/directory/roleAssignments``) so the "Add member to role"
# detection can be validated. Defaults to a low-impact role ("Directory Readers")
# and cleans the assignment up afterwards.
# 
# The role is resolved by display name (``role_display_name``) rather than a
# hard-coded template GUID, which keeps it correct across tenants. Point it at
# whichever benign role you prefer for drills; for a privilege-escalation drill you
# might temporarily target a more sensitive role on a disposable account.
# 
# Privilege: creating role assignments requires a Privileged Role Administrator (or
# Global Administrator) context. Set ``admin_upn`` to a privileged test account; the
# module authenticates as that account via ROPC. The classic alternative shape is
# ``POST /directoryRoles/{roleObjectId}/members/$ref`` against an instantiated role.
# 
# Integration points: see inbox_rule.py. Keep ``expected_event`` in step with
# ``src/training/reference.py``.

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


class RoleAssignmentModule(TelemetryModule):
    key = "role_assignment"
    expected_event = "Add member to role"      # Entra audit
    remediation = (
        "Validate every privileged role assignment against a change ticket. Remove "
        "unauthorised or standing assignments and prefer time-bound PIM-eligible "
        "assignments. Alert specifically on additions to high-impact roles "
        "(Global Administrator, Privileged Role Administrator, etc.) and "
        "investigate the actor who made the change."
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
        role_name = self.settings.get("role_display_name", "Directory Readers")
        cleanup = self.settings.get("cleanup", True)

        for user in self.config.users:
            result = self._new_result(target_user=user.upn)
            start = time.monotonic()
            try:
                actor = admin_upn or user.upn
                token = self._delegated_token(actor)

                # Resolve the user's directory object id (principalId).
                u = self._graph(
                    token, "GET", f"users/{user.upn}?$select=id", result
                )
                principal_id = (u.body or {}).get("id")

                # Resolve the role definition id by display name.
                rd = self._graph(
                    token, "GET",
                    "roleManagement/directory/roleDefinitions"
                    f"?$filter=displayName eq '{role_name}'&$select=id,displayName",
                    result,
                )
                defs = (rd.body or {}).get("value", [])
                if not defs:
                    _note(result, f"skipped: role {role_name!r} not found")
                    result.duration_seconds = round(time.monotonic() - start, 3)
                    results.append(result)
                    continue
                role_def_id = defs[0].get("id")

                # Create the assignment.
                created = self._graph(
                    token, "POST",
                    "roleManagement/directory/roleAssignments", result,
                    json={
                        "roleDefinitionId": role_def_id,
                        "principalId": principal_id,
                        "directoryScopeId": "/",
                    },
                )
                assignment_id = (created.body or {}).get("id")
                result.artifacts.setdefault("created", []).append(
                    {"type": "roleAssignment", "id": assignment_id,
                     "role": role_name, "principalId": principal_id}
                )
                _note(result, f"assigned role {role_name!r} ({assignment_id})")

                if cleanup and assignment_id:
                    self._graph(
                        token, "DELETE",
                        f"roleManagement/directory/roleAssignments/{assignment_id}",
                        result,
                    )
                    _note(result, "removed role assignment")

            except Exception as exc:  # noqa: BLE001
                _note(result, f"error: {exc!r}")

            result.duration_seconds = round(time.monotonic() - start, 3)
            results.append(result)
        return results
