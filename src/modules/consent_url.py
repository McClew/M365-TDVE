# OAuth consent-URL telemetry
# 
# Constructs a valid OAuth 2.0 /authorise URL carrying extended Graph scopes
# (e.g. Mail.ReadWrite, Files.ReadWrite.All). The engine only *builds and prints*
# the URL - you (an authorised admin/test user) open it yourself in the test
# tenant to generate the "OAuth app consented" policy event. Nothing is sent to
# any third party.

from __future__ import annotations

import time
from urllib.parse import urlencode

from .base import ModuleResult, TelemetryModule

class ConsentUrlModule(TelemetryModule):
    key = "consent_url"
    expected_event = "Policy Event - OAuth App Consented"
    remediation = "Revoke Enterprise App"

    def build_url(self) -> tuple[str, list[str]]:
        """Return (authorise_url, scopes). Pure string construction."""

        scopes = list(self.settings.get(
            "scopes", ["Mail.ReadWrite", "Files.ReadWrite.All", "offline_access"]
        ))

        params = {
            "client_id": self.config.client_id,
            "response_type": "code",
            "redirect_uri": self.config.redirect_uri,
            "response_mode": "query",
            "scope": " ".join(scopes),
            "state": self.settings.get("state", "tdve-consent-validation"),
            "prompt": "consent",
        }

        url = f"{self.client.authorise_url}?{urlencode(params)}"

        return url, scopes

    def run(self) -> list[ModuleResult]:
        result = self._new_result()
        start = time.monotonic()

        url, scopes = self.build_url()
        result.artifacts["authorise_url"] = url
        result.artifacts["scopes"] = scopes
        result.notes.append(
            "Open this URL as an authorised test user in the test tenant to "
            "generate the consent policy event. The URL is not transmitted "
            "anywhere by this tool."
        )

        self.log.info("consent_url: built authorise URL with scopes: %s",
                      ", ".join(scopes))
        
        self.log.info("  %s", url)

        result.duration_seconds = round(time.monotonic() - start, 3)
        
        return [result]
