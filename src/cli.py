# Command-line entry point
# Usage:
#    python -m src.cli --config config/config.yaml --module auth_failure
#
# Modules: auth_failure, device_code, mfa_prompt, consent_url, all

from __future__ import annotations

import argparse
import sys

from . import __version__
from .auth_client import AuthClient
from .config_loader import ConfigError, load_config
from .logger import get_logger
from .modules import MODULE_REGISTRY
from .summary import print_report, write_summary

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
    parser.add_argument("--module",             choices=_MODULE_CHOICES, default="all", help="Telemetry module to run (default: all)")
    parser.add_argument("--verbose",            action="store_true", help="Enable debug-level console output")
    parser.add_argument("--version",            action="version", version=f"m365-tdve {__version__}")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    overrides = {
        "tenant": args.tenant,
        "user": args.user,
        "client_id": args.client_id,
    }
    overrides = {k: v for k, v in overrides.items() if v}

    # Bootstrap logger early (file target refined after config loads)
    logger = get_logger("tdve", verbose=args.verbose)

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

    selected = (list(MODULE_REGISTRY) if args.module == "all"
                else [args.module])

    all_results = []

    for key in selected:
        module = MODULE_REGISTRY[key](config, client, logger)
        logger.info("--- Running module: %s ---", key)

        try:
            all_results.extend(module.run())
        except Exception as exc:  # keep going across modules
            logger.error("Module %s failed: %s", key, exc)

    print_report(all_results, logger)
    write_summary(all_results, config, config.summary_json)
    logger.info("Summary written to %s", config.summary_json)

    return 0

if __name__ == "__main__":
    sys.exit(main())
