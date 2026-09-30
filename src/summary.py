# Writes structured JSON summary statistics and prints a human-readable module -> expected CDR event mapping table

from __future__ import annotations

import json
from pathlib import Path

# Static traceability matrix for the closing report
TRACEABILITY = {
    "auth_failure": ("IAM Event - Multiple Auth Failures", "Smart Lockout / IP Review"),
    "device_code": ("IAM Event - Cross-Device Code Auth", "Revoke Active Sessions"),
    "mfa_prompt": ("IAM Event - Multiple MFA Prompts", "Force Passkey / FIDO2"),
    "consent_url": ("Policy Event - OAuth App Consented", "Revoke Enterprise App"),
}


def write_summary(results, config, path: str | Path) -> None:
    payload = {
        "engine": "M365 Telemetry & Detection Validation Engine",
        "version": "1.0.0",
        "tenant": config.tenant,
        "module_results": [r.to_dict() for r in results],
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def print_report(results, logger) -> None:
    logger.info("=" * 70)
    logger.info("EXECUTION SUMMARY - expected CDR detections")
    logger.info("=" * 70)

    for r in results:
        target = f" [{r.target_user}]" if r.target_user else ""
        logger.info("Module: %s%s", r.module, target)
        logger.info("  Expected event : %s", r.expected_saas_alerts_event)
        logger.info("  Remediation    : %s", r.target_remediation)
        logger.info("  Calls made     : %d", len(r.calls))
        logger.info("  Duration       : %.2fs", r.duration_seconds)

        for note in r.notes:
            logger.info("  Note           : %s", note)
        
    logger.info("=" * 70)
