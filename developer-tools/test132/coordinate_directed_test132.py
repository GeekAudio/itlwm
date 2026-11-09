#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Test132 uses the validated Test130 two-packet wire contract and peer."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "developer-tools/test130"))
import coordinate_directed_test130 as runner

def main():
    private = runner.BASE / "RuntimeTest132/research/preparation-private"
    overrides = {
        "BUILD": "25G416-Test132",
        "ARCHIVE_NAME": "AirportItlwm-Test132.zip",
        "PRIVATE": private,
        "BUILD_RECEIPT": private / "test132-build-private.json",
        "SOURCE_MANIFEST": private / "build-input-before-private.json",
        "DEPLOYMENT_RECEIPT": private.parent / "test132-deployment-private.json",
        "TARGET_REVIEW_RECEIPT": private / "test132-target-os-review-private.json",
        "TARGET_REVIEW_SCHEMA": "test132-target-os-review/v1",
        "TOOLS": private / "tools",
        "HELPER_RECEIPT": private / "tools/test130-helper-build-private.json",
    }
    saved = {key: getattr(runner, key) for key in overrides}
    try:
        for key, value in overrides.items():
            setattr(runner, key, value)
        return runner.main()
    finally:
        for key, value in saved.items():
            setattr(runner, key, value)

if __name__ == "__main__":
    raise SystemExit(main())
