# Authentication-failure telemetry
#
# Sends controlled, rate-limited ROPC requests using a DELIBERATELY INVALID
# password against declared test accounts to produce Entra sign-in failure
# entries (AADSTS50126 invalid credential, 50053 smart-lockout). This does NOT
# attempt to guess valid passwords - it intentionally fails to generate the
# "multiple auth failures" detection signal in CDR.
#
# Optional success leg (``succeed_after_failures: true``): after the failures,
# perform ONE sign-in with the account's VALID password. This reproduces the
# pattern an on-call engineer is actually paged for - a burst of failures
# followed by a success from the same principal (a spray that worked) - rather
# than failures alone, which are usually just noise. On success the issued
# delegated token is seeded onto the shared client so a chained run pivots
# straight into the post-breach modules as the now-compromised account. The
# success leg needs a valid password AND an account without MFA (ROPC cannot
# satisfy MFA); it is off by default.

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

            if self.settings.get("succeed_after_failures", False):
                self._run_success_leg(user, result, scope, delay)

            result.duration_seconds = round(time.monotonic() - start, 3)
            results.append(result)
        return results

    def _run_success_leg(self, user, result: ModuleResult, scope: str,
                         delay: float) -> None:
        """Append one VALID-password sign-in after the failures.

        Completes the failures-then-success pattern and, on success, seeds the
        shared delegated session so chained post-breach modules run as this
        account. Records the outcome on ``result``; never raises (a failure
        here is recorded as a note, not an abort).
        """
        valid = self._password_for(user.upn)
        if not valid:
            msg = (
                f"success leg skipped: no valid password for {user.upn} "
                "(set targets.users[].password or M365TDVE_TEST_PASSWORD)."
            )
            result.notes.append(msg)
            self.log.warning("auth_failure: %s", msg)
            return

        if delay:
            time.sleep(delay)

        self.log.info(
            "auth_failure: issuing the success leg (valid sign-in) for %s",
            user.upn,
        )
        resp = self.client.ropc_token(
            client_id=self.config.client_id,
            username=user.upn,
            password=valid,
            scope=scope,
        )
        result.calls.append({
            "phase": "success",
            "endpoint": resp.endpoint,
            "http_status": resp.http_status,
            "entra_error_code": resp.entra_error_code,
            "error": resp.error,
            "elapsed_ms": resp.elapsed_ms,
        })

        token = (resp.body or {}).get("access_token")
        if resp.ok and token:
            self._seed_delegated_session(token, user.upn)
            result.artifacts["successful_auth"] = True
            result.notes.append(
                "successful sign-in after failures (failures-then-success "
                "pattern); delegated session seeded for chained post-breach "
                "modules."
            )
            self.log.info(
                "  success leg OK for %s; session seeded for the chain.",
                user.upn,
            )
        else:
            result.artifacts["successful_auth"] = False
            detail = (
                f"AADSTS{resp.entra_error_code}" if resp.entra_error_code
                else resp.error or f"HTTP {resp.http_status}"
            )
            result.notes.append(
                f"success leg did not yield a token ({detail}); the account "
                "likely enforces MFA (ROPC cannot satisfy it) or the password "
                "is wrong. No session seeded."
            )
            self.log.warning(
                "  success leg for %s did not yield a token (%s).",
                user.upn, detail,
            )
