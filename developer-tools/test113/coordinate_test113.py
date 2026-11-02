#!/usr/bin/env python3
"""Test113 entry point; reuse the existing bounded echo protocol."""
from pathlib import Path
import sys

SHARED = Path(__file__).resolve().parents[1] / "test111"
sys.path.insert(0, str(SHARED))
import coordinate_test111 as shared

BUILD_ID = shared.TEST113_BUILD_ID


def main(argv=None):
    return shared.main(argv, build_id=BUILD_ID)


if __name__ == "__main__":
    raise SystemExit(main())
