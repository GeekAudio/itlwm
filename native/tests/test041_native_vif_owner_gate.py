#!/usr/bin/env python3
"""Check the 25G332 native AWDL pointer setter/getter ownership boundary.

This offline gate is tied to the retained, non-loadable linked-analysis image.
It proves that setAwdlInterface stores its argument without a call in the
setter body; it does not prove the complete object lifetime or runtime path.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
ART = REPO.parent / "IntelWirelessNative"
IMAGE = ART / "research/test037-upgrade-private/IO80211Family-25G332.linked-analysis.macho"
EXPECTED_SHA256 = "8732ea8838331d115e16697acefa22ca5b3d0c516c48293de2e2ebbaf891d047"
GETTER = "__ZN17IO80211Controller16getAwdlInterfaceEv"
SETTER = "__ZN17IO80211Controller16setAwdlInterfaceEP23IO80211VirtualInterface"


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def symbol_address(symbol: str) -> int:
    for line in run("xcrun", "nm", "-arch", "x86_64", str(IMAGE)).splitlines():
        fields = line.split()
        if fields and fields[-1] == symbol:
            return int(fields[0], 16)
    raise RuntimeError(f"missing symbol: {symbol}")


def body(symbol: str) -> str:
    dump = run("xcrun", "llvm-objdump", f"--disassemble-symbols={symbol}", str(IMAGE))
    marker = f"<{symbol}>:"
    start = dump.find(marker)
    if start < 0:
        raise RuntimeError(f"missing disassembly body: {symbol}")
    end = dump.find("\n\n", start)
    return dump[start:end if end >= 0 else None]


def main() -> int:
    if not IMAGE.is_file():
        raise FileNotFoundError(f"missing retained analysis image: {IMAGE}")
    actual_sha256 = digest(IMAGE)
    if actual_sha256 != EXPECTED_SHA256:
        raise RuntimeError(f"linked-analysis image hash mismatch: {actual_sha256}")

    setter_body = body(SETTER)
    getter_body = body(GETTER)
    setter_lines = [" ".join(" ".join(line.split("\t")[-2:]).split())
                    for line in setter_body.splitlines()[1:] if "\t" in line]
    getter_lines = [" ".join(" ".join(line.split("\t")[-2:]).split())
                    for line in getter_body.splitlines()[1:] if "\t" in line]

    # On the current x86_64 linked image the setter is a plain pointer store;
    # there is no call or inline refcount instruction in its complete body.
    if not any("movq %rsi, 0x190(%rax)" in line for line in setter_lines):
        raise RuntimeError("setter no longer stores the supplied interface pointer")
    if not any("movq 0x120(%rdi), %rax" in line for line in setter_lines):
        raise RuntimeError("setter controller-state base changed")
    if any(re.search(r"\b(callq?|lock)\b", line) for line in setter_lines):
        raise RuntimeError("setter acquired a call/atomic instruction; re-audit ownership")
    if not any("movq 0x120(%rdi), %rax" in line for line in getter_lines):
        raise RuntimeError("getter controller-state base changed")
    if not any("movq 0x190(%rax), %rax" in line for line in getter_lines):
        raise RuntimeError("getter no longer reads the setter's pointer slot")

    report = {
        "schema": "test041-native-vif-owner-gate/v1",
        "result": "PASS_RAW_POINTER_SLOT_CONFIRMED",
        "scope": "Offline disassembly check against a retained non-loadable 25G332 linked-analysis image.",
        "image": {
            "path": str(IMAGE),
            "sha256": actual_sha256,
            "loadable": False,
        },
        "symbols": {
            "setter": {"name": SETTER, "address": f"0x{symbol_address(SETTER):x}"},
            "getter": {"name": GETTER, "address": f"0x{symbol_address(GETTER):x}"},
        },
        "evidence": {
            "setter_state_base_load": "movq 0x120(%rdi), %rax",
            "setter_pointer_store": "movq %rsi, 0x190(%rax)",
            "getter_state_base_load": "movq 0x120(%rdi), %rax",
            "getter_pointer_load": "movq 0x190(%rax), %rax",
            "setter_calls_or_lock_prefixes": 0,
        },
        "implication": "Controller get/set access the same stored interface pointer. The setter itself does not retain or release the supplied interface; its owner must keep the object alive until the controller slot is identity-checked and cleared.",
        "limitations": [
            "This gate does not establish ownership performed by callers, attach/start, or other framework code.",
            "It does not prove a concrete subclass, publication sequence, runtime awdl0, firmware scheduling, packet path, or AirDrop.",
            "The image is static analysis material and was not loaded or instantiated.",
        ],
    }
    target = ART / "research/test041-native-vif-gate-private.json"
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + "\n")
    target.chmod(0o600)
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
