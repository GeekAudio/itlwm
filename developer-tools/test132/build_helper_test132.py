#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the shared two-packet helper under the exact Test132 profile."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "developer-tools/test130"))
from build_helper_test130 import main

if __name__ == "__main__":
    main(build_id="25G416-Test132", private_dir=ROOT.parent.parent / "RuntimeTest132/research/preparation-private")
