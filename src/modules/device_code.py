# Device-code authorisation telemetry
# 
# Initiates the OAuth 2.0 device authorisation flow (POST /devicecode) to
# validate cross-device authentication logging. Optionally polls /token to
# demonstrate the authorisation_pending lifecycle. The engine only *initiates*
# the flow against your own test tenant; it does not deliver codes to anyone.

from __future__ import annotations

import time

from .base import ModuleResult, TelemetryModule

class DeviceCodeModule(TelemetryModule):
    key = "device_code"
    expected_event = "IAM Event - Cross-Device Code Auth"
    remediation = "Revoke Active Sessions"

    def run(self) -> list[ModuleResult]:
        scope = self.settings.get(
            "scope", "https://graph.microsoft.com/.default offline_access"
        )
        do_poll = bool(self.settings.get("poll", False))
        poll_seconds = float(self.settings.get("poll_seconds", 5))
        max_polls = int(self.settings.get("max_polls", 3))

        result = self._new_result()
        start = time.monotonic()

        self.log.info("device_code: requesting device authorisation")
        resp = self.client.request_device_code(self.config.client_id, scope)
        result.calls.append({
            "step": "devicecode",
            "http_status": resp.http_status,
            "error": resp.error,
            "elapsed_ms": resp.elapsed_ms,
        })

        if resp.ok:
            device_code = resp.body.get("device_code")
            result.artifacts["user_code"] = resp.body.get("user_code")
            result.artifacts["verification_uri"] = resp.body.get("verification_uri")
            result.artifacts["expires_in"] = resp.body.get("expires_in")
            self.log.info(
                "  device flow started: user_code=%s verification_uri=%s",
                resp.body.get("user_code"), resp.body.get("verification_uri"),
            )

            if do_poll and device_code:
                for i in range(1, max_polls + 1):
                    time.sleep(poll_seconds)

                    poll = self.client.poll_device_token(
                        self.config.client_id, device_code
                    )

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

                    if poll.error != "authorisation_pending":
                        break
        else:
            result.notes.append(
                f"device authorisation request failed: {resp.error}"
            )
            self.log.warning("  device authorisation failed: %s", resp.error)

        result.duration_seconds = round(time.monotonic() - start, 3)
        return [result]
