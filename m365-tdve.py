#!/usr/bin/env python3
# M365 Telemetry & Detection Validation Engine - single-file entry point.
#
# Usage:
#     python m365-tdve.py --config config/config.yaml --module auth_failure
#     python m365-tdve.py --module all
#
# This is a thin launcher for the src/ package so the tool can be run as one
# named file from the project directory. All behaviour lives in src/cli.py.

from __future__ import annotations

import os
import sys


def _main() -> int:
    # Ensure this script's directory is importable so `src` resolves as a
    # package regardless of the caller's current working directory.
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)

    from src.cli import main

    return main()


if __name__ == "__main__":
    sys.exit(_main())
