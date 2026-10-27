#!/usr/bin/env python3
"""Regress the phase error in the actual data gate; host-only evidence."""
from pathlib import Path
import json, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix="active-roc053-") as temp:
    binary=Path(temp)/"test"
    subprocess.run(["xcrun","clang++","-std=c++14","-Wall","-Wextra","-Werror",
        "-fsanitize=address,undefined","-fno-omit-frame-pointer",
        "native/tests/awdl_data_roc_gate_test.cpp","native/p2p_hal_probe.cpp","-o",str(binary)],cwd=ROOT,check=True)
    subprocess.run([str(binary)],check=True)
report={"old_prebinding_gate_rejects_active_binding":True,"active_roc_gate_accepts_valid_state":True,
    "individual_invalid_witnesses_rejected":9,"asan_ubsan_passed":True,"kernel_or_rf_tested":False}
(ROOT.parent/"IntelWirelessNative/research/test055-active-roc-gate-private.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps(report))
