# Authentication-failure telemetry.
# 
# Sends controlled, rate-limited ROPC requests using a DELIBERATELY INVALID
# password against declared test accounts to produce Entra sign-in failure
# entries (AADSTS50126 invalid credential, 50053 smart-lockout). This does NOT
# attempt to guess valid passwords - it intentionally fails to generate the
# "multiple auth failures" detection signal in CDR.

from __future__ import annotations

import time

from .base import ModuleResult, TelemetryModule

class AuthFailureModule(TelemetryModule):
    key = "auth_failure"
    expected_event = "IAM Event - Multiple Auth Failures"
    remediation = "Smart Lockout / IP Review"

    def run(self) -> list[ModuleResult]:
        attempts = int(self.settings.get("attempts", 5))
        invalid_password = self.settings.get(
            "invalid_password", "TDVE-Invalid-Telemetry-000!"
        )
        delay = float(self.settings.get("delay_seconds", 3))
        scope = self.settings.get("scope", "https://graph.microsoft.com/.default")

        results: list[ModuleResult] = []

        for user in self.config.users:
            result = self._new_result(target_user=user.upn)
            start = time.monotonic()
            self.log.info(
                "auth_failure: generating %d failed sign-in(s) for %s",
                attempts, user.upn,
            )
            observed_codes: set[str] = set()

            for i in range(1, attempts + 1):
                resp = self.client.ropc_token(
                    client_id=self.config.client_id,
                    username=user.upn,
                    password=invalid_password,  # intentionally wrong
                    scope=scope,
                )

                if resp.entra_error_code:
                    observed_codes.add(resp.entra_error_code)

                self.log.info(
                    "  attempt %d/%d -> HTTP %s / AADSTS%s (%s)",
                    i, attempts, resp.http_status,
                    resp.entra_error_code or "?", resp.error or "n/a",
                )

                result.calls.append({
                    "attempt": i,
                    "endpoint": resp.endpoint,
                    "http_status": resp.http_status,
                    "entra_error_code": resp.entra_error_code,
                    "error": resp.error,
                    "elapsed_ms": resp.elapsed_ms,
                })

                if resp.ok:
                    result.notes.append(
                        "WARNING: unexpected success - the configured password "
                        "should be invalid. Aborting further attempts."
                    )
                    self.log.warning(
                        "  unexpected auth SUCCESS for %s; stopping.", user.upn
                    )
                    break
                
                if i < attempts:
                    time.sleep(delay)

            result.artifacts["observed_error_codes"] = sorted(observed_codes)
            result.duration_seconds = round(time.monotonic() - start, 3)
            results.append(result)
        return results
