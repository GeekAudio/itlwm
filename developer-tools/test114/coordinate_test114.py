#!/usr/bin/env python3
"""Test114 entry point for the bounded native UDP echo diagnostic."""
from pathlib import Path
import sys

SHARED = Path(__file__).resolve().parents[1] / "test111"
sys.path.insert(0, str(SHARED))
import coordinate_test111 as shared


def main(argv=None):
    return shared.main(argv, build_id=shared.TEST114_BUILD_ID)


if __name__ == "__main__":
    raise SystemExit(main())
