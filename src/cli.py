# Command-line entry point
# Usage:
#    python -m src.cli --config config/config.yaml --module auth_failure
#
# Modules: auth_failure, device_code, mfa_prompt, consent_url, all

from __future__ import annotations

import argparse
import sys

import json
from pathlib import Path

from . import __version__
from .auth_client import AuthClient
from .config_loader import ConfigError, TrainingConfig, load_config
from .logger import get_logger
from .modules import MODULE_REGISTRY
from .runner import print_timeline, run_sequence, write_timeline
from .summary import print_report, write_summary
from .training import (
    REFERENCE_LIBRARY,
    SCENARIO_LIBRARY,
    build_timeline,
    render_scenario,
    write_all_cards,
)

_MODULE_CHOICES = list(MODULE_REGISTRY.keys()) + ["all"]

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m365-tdve",
        description=(
            "M365 Telemetry & Detection Validation Engine - generates "
            "deterministic identity/app audit telemetry in an authorised TEST "
            "tenant to validate cloud detection & response."
        ),
    )

    parser.add_argument("--config",             default="config/config.yaml", help="Path to config.yaml / config.json")
    parser.add_argument("--tenant",             help="Override tenant (GUID or *.onmicrosoft.com domain)")
    parser.add_argument("--user",               help="Restrict targeting to a single test UPN")
    parser.add_argument("--client-id",          help="Override public client (app) ID")
    parser.add_argument("--delegated-auth",      choices=["ropc", "device_code"], help="Delegated-token flow for post-breach modules (device_code handles MFA; default: ropc / config)")
    parser.add_argument("--module",             choices=_MODULE_CHOICES, default="all", help="Telemetry module to run (default: all)")
    parser.add_argument("--verbose",            action="store_true", help="Enable debug-level console output")
    parser.add_argument("--version",            action="version", version=f"m365-tdve {__version__}")

    # Multi-module simulation: run a chain of modules one after another.
    # Precedence when several are given: --chain > --sequence > --module.
    sim = parser.add_argument_group("simulation (run modules in sequence)")
    sim.add_argument("--sequence",   help="Comma-separated module keys to run in order, e.g. 'auth_failure,mfa_prompt,inbox_rule'")
    sim.add_argument("--chain",      choices=list(SCENARIO_LIBRARY.keys()), help="Run a named attack-chain scenario's modules in order")
    sim.add_argument("--step-delay", type=float, default=0.0, help="Seconds to wait between steps in a --sequence/--chain run (default: 0)")

    # SOC training / detection-reference layer (no tenant contact required).
    training = parser.add_argument_group("training & detection reference")
    training.add_argument("--emit-cards",       action="store_true", help="Write the attack reference cards + scenario timelines, then exit")
    training.add_argument("--list-techniques",  action="store_true", help="List the attack techniques in the reference library, then exit")
    training.add_argument("--list-scenarios",   action="store_true", help="List the documented attack-chain scenarios, then exit")
    training.add_argument("--cards-dir",        help="Override the output directory for --emit-cards")

    return parser


def _list_techniques(logger) -> int:
    logger.info("Attack reference library (%d techniques):", len(REFERENCE_LIBRARY))
    for r in REFERENCE_LIBRARY.values():
        logger.info("  %-18s %-13s %s [%s]", r.key, r.mitre_technique, r.title, r.phase)
    return 0


def _list_scenarios(logger) -> int:
    logger.info("Attack-chain scenarios (%d):", len(SCENARIO_LIBRARY))
    for s in SCENARIO_LIBRARY.values():
        chain = " -> ".join(step.technique_key for step in s.steps)
        logger.info("  %-20s %s", s.key, s.title)
        logger.info("       %s", chain)
    return 0


def _emit_cards(cards_dir: str, logger) -> int:
    out = Path(cards_dir)
    written = write_all_cards(out)
    logger.info("Wrote %d reference cards to %s/", len(written) - 1, out)

    # Scenario write-ups + a combined machine-readable timeline.
    scen_dir = out / "scenarios"
    scen_dir.mkdir(parents=True, exist_ok=True)
    timelines = []
    for s in SCENARIO_LIBRARY.values():
        (scen_dir / f"{s.key}.md").write_text(render_scenario(s), encoding="utf-8")
        timelines.append(build_timeline(s))
    (scen_dir / "timelines.json").write_text(
        json.dumps({"scenarios": timelines}, indent=2), encoding="utf-8")
    logger.info("Wrote %d scenario write-ups + timelines.json to %s/",
                len(timelines), scen_dir)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    overrides = {
        "tenant": args.tenant,
        "user": args.user,
        "client_id": args.client_id,
        "delegated_auth": args.delegated_auth,
    }
    overrides = {k: v for k, v in overrides.items() if v}

    # Bootstrap logger early (file target refined after config loads)
    logger = get_logger("tdve", verbose=args.verbose)

    # Info / reference commands work without a valid tenant config.
    if args.list_techniques:
        return _list_techniques(logger)
    if args.list_scenarios:
        return _list_scenarios(logger)
    if args.emit_cards:
        # Prefer the configured cards_dir; fall back to a sensible default so the
        # reference material can be produced even before a tenant is configured.
        cards_dir = args.cards_dir
        if not cards_dir:
            try:
                cfg = load_config(args.config, cli_overrides=overrides)
                cards_dir = cfg.training.cards_dir
            except Exception:
                cards_dir = TrainingConfig().cards_dir
        return _emit_cards(cards_dir, logger)

    try:
        config = load_config(
            args.config,
            cli_overrides=overrides,
        )
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        return 2
    except Exception as exc:  # pragma: no cover - unexpected
        logger.error("Failed to load config: %s", exc)
        return 2

    # Reconfigure logging to the file declared in config
    logger = get_logger("tdve", log_file=config.log_file, verbose=args.verbose)
    logger.info("M365 TDVE %s starting", __version__)
    logger.info("Target tenant: %s", config.tenant)

    client = AuthClient(config.authority, logger)

    # Resolve the ordered list of modules to run. Precedence: chain > sequence > module.
    is_sim = bool(args.chain or args.sequence)
    if args.chain:
        selected = [step.technique_key for step in SCENARIO_LIBRARY[args.chain].steps]
        logger.info("Running attack-chain scenario: %s", args.chain)
    elif args.sequence:
        selected = [k.strip() for k in args.sequence.split(",") if k.strip()]
    elif args.module == "all":
        selected = list(MODULE_REGISTRY)
    else:
        selected = [args.module]

    all_results, timeline = run_sequence(
        selected, config, client, logger, step_delay=args.step_delay,
    )

    print_report(all_results, logger)
    write_summary(all_results, config, config.summary_json)
    logger.info("Summary written to %s", config.summary_json)

    # A multi-step run also produces an execution timeline for the simulation.
    if is_sim:
        print_timeline(timeline, logger)
        timeline_path = "simulation_timeline.json"
        write_timeline(timeline, config, selected, args.step_delay, timeline_path)
        logger.info("Simulation timeline written to %s", timeline_path)

    return 0

if __name__ == "__main__":
    sys.exit(main())
