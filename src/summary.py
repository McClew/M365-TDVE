# Writes structured JSON summary statistics and prints a human-readable module -> expected CDR event mapping table

from __future__ import annotations

import json
from pathlib import Path

from .training import REFERENCE_LIBRARY

# Static traceability matrix for the closing report, sourced from the reference
# library so it stays in step with the detection cards.
TRACEABILITY = {
    key: (ref.saas_alerts_event, ref.remediation)
    for key, ref in REFERENCE_LIBRARY.items()
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
        ref = REFERENCE_LIBRARY.get(r.module)
        if ref:
            logger.info("  MITRE          : %s (%s)", ref.mitre_technique, ref.mitre_name)
            logger.info("  Reference card : %s.md (see --emit-cards)", r.module)
        logger.info("  Calls made     : %d", len(r.calls))
        logger.info("  Duration       : %.2fs", r.duration_seconds)

        for note in r.notes:
            logger.info("  Note           : %s", note)

    logger.info("=" * 70)
