# MFA prompt verification telemetry
#
# Triggers repeated primary-authentication challenges, at configurable intervals,
# against a declared test account that has MFA enabled. This validates that CDR
# recognises repeated MFA-prompt patterns and that MFA notification timeout / denial 
# events are handled. Requires a VALID password for the test account (supply via 
# the M365TDVE_TEST_PASSWORD env var, not the config file).
# 
# Because the account has MFA, the primary credential exchange is expected to be
# followed by an interrupt (e.g. AADSTS50076/50079/50074) rather than a token -
# that interrupt is the telemetry we are validating.
#
# Optional approval leg (``succeed_after_prompts: true``): after the prompt
# burst, reproduce the "fatigue payoff" - one MFA-satisfied sign-in that yields a
# token. ROPC can't satisfy MFA (no token), and a device-code sign-in would emit
# the WRONG signal (a device-code sign-in alert, not a successful MFA event), so
# this uses the INTERACTIVE authorization-code flow: the operator signs in and
# approves the MFA prompt, producing a genuine successful, MFA-satisfied logon.
# On success the delegated session is seeded onto the shared client so a chained
# run pivots straight into the post-breach modules as the now-compromised
# account. It prompts at most once per run (a session already seeded earlier in
# the chain is reused). Off by default.

from __future__ import annotations

import time

from .base import ModuleResult, TelemetryModule


class MfaPromptModule(TelemetryModule):
    key = "mfa_prompt"
    expected_event = "IAM Event - Multiple MFA Prompts"
    remediation = "Force Passkey / FIDO2"

    def run(self) -> list[ModuleResult]:
        prompts = int(self.settings.get("prompts", 3))
        delay = float(self.settings.get("delay_seconds", 20))
        scope = self.settings.get(
            "scope", "https://graph.microsoft.com/.default offline_access"
        )

        results: list[ModuleResult] = []

        for user in self.config.users:
            result = self._new_result(target_user=user.upn)
            start = time.monotonic()

            if not user.password:
                result.notes.append(
                    "skipped: no valid test-account password supplied "
                    "(set M365TDVE_TEST_PASSWORD). MFA prompts require primary "
                    "auth to succeed before the MFA interrupt."
                )

                self.log.warning(
                    "mfa_prompt: skipping %s - no password provided.", user.upn
                )

                result.duration_seconds = round(time.monotonic() - start, 3)
                results.append(result)

                continue

            self.log.info(
                "mfa_prompt: issuing %d primary-auth challenge(s) for %s",
                prompts, user.upn,
            )

            observed_codes: set[str] = set()

            for i in range(1, prompts + 1):
                resp = self.client.ropc_token(
                    client_id=self.config.client_id,
                    username=user.upn,
                    password=user.password,
                    scope=scope,
                )

                if resp.entra_error_code:
                    observed_codes.add(resp.entra_error_code)

                self.log.info(
                    "  prompt %d/%d -> HTTP %s / %s (AADSTS%s)",
                    i, prompts, resp.http_status, resp.error or "token",
                    resp.entra_error_code or "-",
                )
                
                result.calls.append({
                    "prompt": i,
                    "http_status": resp.http_status,
                    "error": resp.error,
                    "entra_error_code": resp.entra_error_code,
                    "elapsed_ms": resp.elapsed_ms,
                })

                if i < prompts:
                    time.sleep(delay)

            result.artifacts["observed_error_codes"] = sorted(observed_codes)

            if self.settings.get("succeed_after_prompts", False):
                self._run_approval_leg(user, result)

            result.duration_seconds = round(time.monotonic() - start, 3)
            results.append(result)

        return results

    def _run_approval_leg(self, user, result: ModuleResult) -> None:
        """Reproduce the fatigue payoff: one interactive MFA-satisfied sign-in.

        Uses the authorization-code flow (not ROPC, which can't satisfy MFA, and
        not device code, which emits the wrong signal): the operator completes
        the sign-in and APPROVES the MFA prompt - a genuine successful,
        MFA-satisfied logon - and the resulting delegated session is seeded for
        chained post-breach modules. Reuses a session already seeded earlier in
        the run. Records the outcome on ``result``; never raises.
        """
        try:
            self._auth_code_token(user.upn)
        except Exception as exc:  # noqa: BLE001 - record, don't abort the batch
            result.artifacts["approved_auth"] = False
            result.notes.append(
                f"approval leg did not complete ({exc}); no session seeded."
            )
            self.log.warning(
                "mfa_prompt: approval leg failed for %s: %s", user.upn, exc
            )
            return

        result.artifacts["approved_auth"] = True
        result.calls.append({"phase": "approval", "flow": "auth_code",
                             "status": "token_issued"})
        result.notes.append(
            "MFA approval completed (fatigue payoff) via interactive sign-in; "
            "delegated session seeded for chained post-breach modules."
        )
        self.log.info(
            "  approval leg OK for %s; session seeded for the chain.", user.upn
        )
