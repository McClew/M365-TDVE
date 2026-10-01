# Sequence runner - executes a chain of modules one after another.
#
# This is the orchestration layer for running a whole simulation: give it an
# ordered list of module keys and it runs each in turn, optionally spacing them
# out, and records a combined execution timeline (what ran, when, and with what
# outcome). It runs whatever is registered in MODULE_REGISTRY - a key that isn't
# registered yet (e.g. a post-exploitation module you haven't built) is reported
# as "not built" and skipped, so a chain stays runnable while it's still being
# filled in.
#
# The runner performs no attack logic itself; it only invokes existing modules.

from __future__ import annotations

import json
import time
from pathlib import Path

from .modules import MODULE_REGISTRY


def run_sequence(keys, config, client, logger, step_delay: float = 0.0):
    """Run `keys` (ordered module keys) in sequence.

    Returns (all_results, timeline):
      all_results - flattened list[ModuleResult] from every module that ran.
      timeline    - list of per-step records (module, offset, status, ...).
    """
    total = len(keys)
    sim_start = time.monotonic()
    logger.info("Simulation: %d step(s) queued: %s", total, " -> ".join(keys))

    all_results = []
    timeline = []

    for i, key in enumerate(keys, start=1):
        offset = round(time.monotonic() - sim_start, 2)
        entry = {
            "step": i,
            "module": key,
            "offset_seconds": offset,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }

        if key not in MODULE_REGISTRY:
            entry["status"] = "skipped"
            entry["reason"] = "module not registered (not built yet)"
            logger.warning("--- step %d/%d: %s SKIPPED - not built yet ---",
                           i, total, key)
            timeline.append(entry)
            continue

        logger.info("--- step %d/%d: running module '%s' (T+%.1fs) ---",
                    i, total, key, offset)
        try:
            results = MODULE_REGISTRY[key](config, client, logger).run()
            all_results.extend(results)
            entry["status"] = "ran"
            entry["result_count"] = len(results)
            entry["calls"] = sum(len(r.calls) for r in results)
        except Exception as exc:  # keep the chain going across a failed step
            entry["status"] = "error"
            entry["error"] = str(exc)
            logger.error("  step %d module '%s' failed: %s", i, key, exc)

        timeline.append(entry)

        if step_delay and i < total:
            logger.info("  waiting %.1fs before next step...", step_delay)
            time.sleep(step_delay)

    logger.info("Simulation complete: %d step(s), %.1fs elapsed.",
                total, round(time.monotonic() - sim_start, 1))
    return all_results, timeline


def write_timeline(timeline, config, keys, step_delay, path: str | Path) -> None:
    """Persist the execution timeline as structured JSON."""
    payload = {
        "engine": "M365 Telemetry & Detection Validation Engine",
        "tenant": config.tenant,
        "planned_sequence": keys,
        "step_delay_seconds": step_delay,
        "executed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "timeline": timeline,
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def print_timeline(timeline, logger) -> None:
    logger.info("=" * 70)
    logger.info("SIMULATION TIMELINE")
    logger.info("=" * 70)
    for e in timeline:
        status = e.get("status", "?")
        detail = ""
        if status == "ran":
            detail = f"{e.get('result_count', 0)} result(s), {e.get('calls', 0)} call(s)"
        elif status == "skipped":
            detail = e.get("reason", "")
        elif status == "error":
            detail = e.get("error", "")
        logger.info("  T+%-6.1fs  step %d  %-18s %-8s %s",
                    e.get("offset_seconds", 0.0), e["step"], e["module"],
                    status.upper(), detail)
    logger.info("=" * 70)
