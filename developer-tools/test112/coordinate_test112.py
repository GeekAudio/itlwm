#!/usr/bin/env python3
"""Test112 entry point reusing the strict Test111 coordinator contract."""
from __future__ import annotations

from pathlib import Path
import sys

TEST111_TOOLS = Path(__file__).resolve().parents[1] / "test111"
if str(TEST111_TOOLS) not in sys.path:
    sys.path.insert(0, str(TEST111_TOOLS))

import coordinate_test111 as shared  # noqa: E402

BUILD_ID = shared.TEST112_BUILD_ID


def main(argv: list[str] | None = None) -> int:
    return shared.main(argv, build_id=BUILD_ID)


if __name__ == "__main__":
    raise SystemExit(main())
