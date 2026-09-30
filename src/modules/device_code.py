# Device-code authorisation telemetry
#
# Initiates the OAuth 2.0 device authorisation flow (POST /devicecode) to
# validate cross-device authentication logging. Three completion modes:
#
#   none   - initiate the flow and (optionally) poll /token to demonstrate the
#            authorization_pending lifecycle. No sign-in occurs. (default)
#   manual - print the user_code + verification URL, then poll until a human
#            completes the sign-in on a second device using a TEST account.
#   auto   - drive a browser (Playwright) to complete the sign-in as a declared
#            TEST account, then poll to collect the issued token.
#
# manual/auto produce a genuine successful cross-device sign-in in YOUR OWN test
# tenant, so that (a) engineers can see what the technique looks like end to end,
# and (b) the resulting live session can be used to exercise the automated
# "Revoke Active Sessions" response. Raw tokens are never logged or written to
# the summary - only non-sensitive proof (scopes, expiry, a hash fingerprint).

from __future__ import annotations

import hashlib
import threading
import time

from .base import ModuleResult, TelemetryModule

# Terminal (non-retryable) device-code poll errors and a short explanation.
_TERMINAL_ERRORS = {
    "authorization_declined": "the user declined the authorisation request",
    "access_denied": "the authorisation request was denied",
    "expired_token": "the device code expired before sign-in completed",
    "bad_verification_code": "the device code was not recognised",
    "invalid_grant": "the authorisation could not be completed (invalid_grant)",
}


class DeviceCodeModule(TelemetryModule):
    key = "device_code"
    expected_event = "IAM Event - Cross-Device Code Auth"
    remediation = "Revoke Active Sessions"

    def run(self) -> list[ModuleResult]:
        scope = self.settings.get(
            "scope", "https://graph.microsoft.com/.default offline_access"
        )
        mode = str(self.settings.get("completion_mode", "none")).lower()
        if mode not in ("none", "manual", "auto"):
            mode = "none"

        result = self._new_result()
        start = time.monotonic()

        self.log.info("device_code: requesting device authorisation (mode=%s)", mode)
        resp = self.client.request_device_code(self.config.client_id, scope)
        result.calls.append({
            "step": "devicecode",
            "http_status": resp.http_status,
            "error": resp.error,
            "elapsed_ms": resp.elapsed_ms,
        })

        if not resp.ok:
            result.notes.append(f"device authorisation request failed: {resp.error}")
            self.log.warning("  device authorisation failed: %s", resp.error)
            result.duration_seconds = round(time.monotonic() - start, 3)
            return [result]

        device_code = resp.body.get("device_code")
        user_code = resp.body.get("user_code")
        verification_uri = resp.body.get("verification_uri")
        verification_uri_complete = resp.body.get("verification_uri_complete")
        interval = int(resp.body.get("interval", 5) or 5)
        expires_in = int(resp.body.get("expires_in", 900) or 900)

        result.artifacts["user_code"] = user_code
        result.artifacts["verification_uri"] = verification_uri
        result.artifacts["expires_in"] = expires_in
        result.artifacts["completion_mode"] = mode

        self.log.info(
            "  device flow started: user_code=%s verification_uri=%s",
            user_code, verification_uri,
        )

        if mode == "none":
            self._demonstrate_pending(result, device_code)
        elif mode == "manual":
            self._complete_manual(
                result, device_code, user_code, verification_uri,
                verification_uri_complete, interval, expires_in,
            )
        elif mode == "auto":
            self._complete_auto_then_poll(
                result, device_code, user_code, verification_uri,
                verification_uri_complete, interval, expires_in,
            )

        result.duration_seconds = round(time.monotonic() - start, 3)
        return [result]

    # ------------------------------------------------------------------ none
    def _demonstrate_pending(self, result: ModuleResult, device_code: str | None) -> None:
        """Original behaviour: poll a fixed number of times to show pending."""
        if not (bool(self.settings.get("poll", False)) and device_code):
            return

        poll_seconds = float(self.settings.get("poll_seconds", 5))
        max_polls = int(self.settings.get("max_polls", 3))

        for i in range(1, max_polls + 1):
            time.sleep(poll_seconds)
            poll = self.client.poll_device_token(self.config.client_id, device_code)
            self.log.info(
                "  poll %d/%d -> %s", i, max_polls,
                poll.error or f"HTTP {poll.http_status}",
            )
            result.calls.append({
                "step": f"poll_{i}",
                "http_status": poll.http_status,
                "error": poll.error,
                "elapsed_ms": poll.elapsed_ms,
            })
            if poll.error != "authorization_pending":
                break

    # ---------------------------------------------------------------- manual
    def _complete_manual(self, result, device_code, user_code, verification_uri,
                         verification_uri_complete, interval, expires_in) -> None:
        if not device_code:
            result.notes.append("no device_code returned; cannot complete flow")
            return

        self._print_manual_banner(user_code, verification_uri, verification_uri_complete)
        self._poll_until_complete(result, device_code, interval, expires_in)

    def _print_manual_banner(self, user_code, verification_uri, verification_uri_complete) -> None:
        bar = "=" * 70
        self.log.info(bar)
        self.log.info("ACTION REQUIRED - complete the sign-in on a SEPARATE device")
        self.log.info("  1. Browse to : %s", verification_uri)
        self.log.info("  2. Enter code: %s", user_code)
        if verification_uri_complete:
            self.log.info("  (direct link, code pre-filled): %s", verification_uri_complete)
        self.log.info("  3. Sign in as the TEST account and approve.")
        self.log.info("Waiting for completion (polling)...")
        self.log.info(bar)

    # ------------------------------------------------------------------ auto
    def _complete_auto_then_poll(self, result, device_code, user_code, verification_uri,
                                 verification_uri_complete, interval, expires_in) -> None:
        if not device_code:
            result.notes.append("no device_code returned; cannot complete flow")
            return

        user = self._resolve_completion_user()
        if user is None:
            result.notes.append(
                "auto completion skipped: no test account with a password available "
                "(set 'complete_as' and supply M365TDVE_TEST_PASSWORD)."
            )
            self.log.error("  auto mode needs a test account + password; see notes.")
            return

        result.target_user = user.upn
        headful = bool(self.settings.get("headful", True))
        nav_timeout = int(self.settings.get("nav_timeout_ms", 30000))

        # Run the browser completion in the background while we poll, mirroring
        # the real attacker/victim split (attacker polls; victim authenticates).
        browser_status: dict[str, object] = {}
        worker = threading.Thread(
            target=self._drive_browser,
            args=(browser_status, user, user_code, verification_uri,
                  verification_uri_complete, headful, nav_timeout),
            daemon=True,
        )
        worker.start()

        self._poll_until_complete(result, device_code, interval, expires_in)

        worker.join(timeout=5)
        if browser_status.get("error"):
            result.notes.append(f"browser automation: {browser_status['error']}")

    def _resolve_completion_user(self):
        want = str(self.settings.get("complete_as", "")).strip().lower()
        candidates = self.config.users or []
        if want:
            for u in candidates:
                if u.upn.lower() == want and u.password:
                    return u
        for u in candidates:
            if u.password:
                return u
        return None

    def _drive_browser(self, status, user, user_code, verification_uri,
                       verification_uri_complete, headful, nav_timeout) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            status["error"] = (
                "playwright not installed - run: pip install playwright "
                "&& python -m playwright install chromium"
            )
            self.log.error("  %s", status["error"])
            return

        self.log.info("  auto: launching browser to complete sign-in as %s", user.upn)
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=not headful)
                page = browser.new_page()
                page.set_default_timeout(nav_timeout)

                page.goto(verification_uri_complete or verification_uri)

                # Code entry screen (skipped when the complete URL pre-fills it).
                if not verification_uri_complete:
                    self._try_fill(page, ["input#otc", "input[name=otc]"], user_code)
                    self._try_click(page, ["input#idSIButton9", "#idSIButton9"])

                # Username / password / stay-signed-in / device confirmation.
                self._try_fill(page, ["input#i0116", "input[type=email]"], user.upn)
                self._try_click(page, ["input#idSIButton9", "#idSIButton9"])

                self._try_fill(page, ["input#i0118", "input[type=password]"], user.password)
                self._try_click(page, ["input#idSIButton9", "#idSIButton9"])

                # "Stay signed in?" and/or the device-code "Continue" confirmation.
                self._try_click(page, ["input#idSIButton9", "#idSIButton9"], required=False)
                self._try_click(page, ["input#idSIButton9", "#idSIButton9"], required=False)

                # Give any MFA / final redirect a moment to settle.
                page.wait_for_timeout(4000)
                status["ok"] = True
                self.log.info("  auto: browser sign-in steps submitted")
                browser.close()
        except Exception as exc:  # broad: selectors/MFA/network all land here
            status["error"] = str(exc)
            self.log.warning("  auto: browser automation did not finish cleanly: %s", exc)

    @staticmethod
    def _try_fill(page, selectors, value) -> bool:
        for sel in selectors:
            try:
                page.wait_for_selector(sel, timeout=8000)
                page.fill(sel, value)
                return True
            except Exception:
                continue
        return False

    def _try_click(self, page, selectors, required: bool = True) -> bool:
        for sel in selectors:
            try:
                page.wait_for_selector(sel, timeout=8000)
                page.click(sel)
                return True
            except Exception:
                continue
        if required:
            self.log.debug("  auto: expected control not found: %s", selectors)
        return False

    # --------------------------------------------------------- shared poller
    def _poll_until_complete(self, result, device_code, interval, expires_in) -> None:
        timeout_seconds = float(self.settings.get("timeout_seconds", 300))
        deadline = time.monotonic() + min(expires_in, timeout_seconds)
        interval = max(interval, 1)
        i = 0

        while time.monotonic() < deadline:
            time.sleep(interval)
            i += 1
            poll = self.client.poll_device_token(self.config.client_id, device_code)
            result.calls.append({
                "step": f"poll_{i}",
                "http_status": poll.http_status,
                "error": poll.error,
                "elapsed_ms": poll.elapsed_ms,
            })

            if poll.ok:
                self.log.info("  poll %d -> SUCCESS (token issued)", i)
                self._record_success(result, poll)
                return

            err = poll.error
            self.log.info("  poll %d -> %s", i, err or f"HTTP {poll.http_status}")

            if err == "authorization_pending":
                continue
            if err == "slow_down":
                interval += 5
                continue
            if err in _TERMINAL_ERRORS:
                msg = f"sign-in not completed: {_TERMINAL_ERRORS[err]} ({err})"
                result.notes.append(msg)
                self.log.warning("  %s", msg)
                return
            # Unknown error - stop rather than hammer the endpoint.
            result.notes.append(f"unexpected poll error: {err}")
            return

        result.notes.append(
            "timed out waiting for the device-code sign-in to complete "
            "(no token issued within the configured window)."
        )
        self.log.warning("  device-code completion timed out.")

    def _record_success(self, result, poll) -> None:
        """Capture NON-SENSITIVE proof of a live session. Never logs the token."""
        body = poll.body or {}
        access_token = body.get("access_token", "")
        fingerprint = (
            hashlib.sha256(access_token.encode()).hexdigest()[:12]
            if access_token else None
        )

        result.artifacts["result"] = "SUCCESS"
        result.artifacts["session"] = {
            "token_type": body.get("token_type"),
            "granted_scope": body.get("scope"),
            "expires_in": body.get("expires_in"),
            "refresh_token_issued": bool(body.get("refresh_token")),
            "access_token_sha256_prefix": fingerprint,
        }
        result.notes.append(
            "SUCCESS: a live session was established via device-code auth - "
            "this is the session the 'Revoke Active Sessions' response should kill."
        )
        self.log.info(
            "  session established: token_type=%s scopes=[%s] expires_in=%ss",
            body.get("token_type"), body.get("scope"), body.get("expires_in"),
        )

        if bool(self.settings.get("verify_session", True)) and access_token:
            self._verify_session(result, access_token)

    def _verify_session(self, result, access_token) -> None:
        who = self.client.graph_get(
            "https://graph.microsoft.com/v1.0/me", access_token
        )
        result.calls.append({
            "step": "verify_session_graph_me",
            "http_status": who.http_status,
            "error": who.error,
            "elapsed_ms": who.elapsed_ms,
        })
        if who.ok:
            body = who.body or {}
            signed_in_as = body.get("userPrincipalName") or body.get("displayName")
            result.artifacts["verified_identity"] = signed_in_as
            self.log.info("  session verified live - Graph /me returned: %s", signed_in_as)
        else:
            self.log.info("  session verify call returned HTTP %s", who.http_status)
