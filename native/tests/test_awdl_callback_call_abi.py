#!/usr/bin/env python3
"""Check selected 25G241 AWDL wrapper-to-callback tail-call paths.

This reads pinned local linked-analysis images. It does not copy, link, or
execute Apple code and does not assert undocumented source typedefs.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
IO_IMAGE = (
    ROOT.parent
    / "SkywalkLegacyCompat/src/awdl_compat/evidence/native-IO80211-linked-25G241/"
    / "IO80211Family.linked-analysis.macho"
)
BCM_IMAGE = (
    ROOT.parent
    / "SkywalkLegacyCompat/research/evidence/native-BCMWLANCoreMac-linked-25G241/"
    / "AppleBCMWLANCoreMac.linked-analysis.macho"
)
EXPECTED_HASHES = {
    "IO80211Family": "26abad781208e382ba0dffe3c3bc8cc3fe820aea2cacb5083b1d25a6240202fa",
    "AppleBCMWLANCoreMac": "d54e7c68a34cea817900e587a1653f52c38c5d5df93c0701f1161d1e78f2afa9",
}

# (wrapper demangled prefix, wrapper virtual slot byte offset, request value)
CALLBACKS = (
    ("apple80211getAWDL_SYNC_ENABLED(", 0xFF0, 0x75),
    ("apple80211setAWDL_SYNC_ENABLED(", 0x10B8, 0x75),
    ("apple80211setAWDL_OOB_REQUEST(", 0x1110, 0x95),
    ("apple80211setAWDL_SYNC_FRAME_TEMPLATE(", 0x1118, 0x97),
)


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def digest(path: Path) -> str:
    value = hashlib.sha256(path.read_bytes()).hexdigest()
    return value


def symbols(image: Path) -> dict[str, int]:
    rows: list[tuple[int, str]] = []
    for line in run("xcrun", "nm", "-nm", str(image)).splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] != "undefined" and re.fullmatch(
            r"[0-9a-fA-F]+", fields[0]
        ):
            rows.append((int(fields[0], 16), fields[-1]))
    names = subprocess.check_output(
        ["c++filt"], input="\n".join(raw for _, raw in rows), text=True
    ).splitlines()
    if len(names) != len(rows):
        raise RuntimeError("demangler output count differs from nm symbols")
    return {name: address for (address, _), name in zip(rows, names)}


def disassembly(image: Path) -> tuple[list[str], dict[int, int]]:
    lines = run("xcrun", "otool", "-tv", str(image)).splitlines()
    index: dict[int, int] = {}
    for line_number, line in enumerate(lines):
        match = re.match(r"([0-9a-f]{16})\t", line)
        if match:
            index[int(match.group(1), 16)] = line_number
    return lines, index


def function_block(lines: list[str], index: dict[int, int], address: int) -> list[str]:
    start = index.get(address)
    if start is None:
        return []
    result: list[str] = []
    for line in lines[start:]:
        if result and line.endswith(":") and not re.match(r"[0-9a-f]{16}\t", line):
            break
        result.append(line)
    return result


def check_image(label: str, path: Path) -> None:
    actual = digest(path)
    if actual != EXPECTED_HASHES[label]:
        raise RuntimeError(f"{label} linked-analysis hash mismatch: {actual}")


def main() -> int:
    check_image("IO80211Family", IO_IMAGE)
    check_image("AppleBCMWLANCoreMac", BCM_IMAGE)
    io_symbols = symbols(IO_IMAGE)
    io_lines, io_index = disassembly(IO_IMAGE)

    errors: list[str] = []
    for prefix, slot_offset, request in CALLBACKS:
        matches = [(name, address) for name, address in io_symbols.items()
                   if name.startswith(prefix)]
        if len(matches) != 1:
            errors.append(f"{prefix}: expected one wrapper symbol, found {len(matches)}")
            continue
        name, address = matches[0]
        block = function_block(io_lines, io_index, address)
        text = "\n".join(block)
        request_pattern = rf"movl\s+\$0x{request:x},\s*%esi"
        slot_pattern = rf"movq\s+0x{slot_offset:x}\(%rax\),\s*%rax"
        if not re.search(request_pattern, text):
            errors.append(f"{name}@{address:#x}: missing request immediate {request:#x}")
        if not re.search(slot_pattern, text):
            errors.append(f"{name}@{address:#x}: missing vtable slot offset {slot_offset:#x}")
        slot_position = next(
            (i for i, line in enumerate(block) if re.search(slot_pattern, line)), -1
        )
        tail_position = next(
            (i for i, line in enumerate(block)
             if i > slot_position and re.search(r"jmpq\s+\*%rax", line)), -1
        )
        if slot_position < 0 or tail_position <= slot_position:
            errors.append(f"{name}@{address:#x}: missing indirect tail jump after slot load")
            continue
        restored = "\n".join(block[slot_position:tail_position])
        for register in ("%rbx", "%r14", "%rbp"):
            if not re.search(rf"popq\s+{register}\b", restored):
                errors.append(
                    f"{name}@{address:#x}: tail path does not restore {register}"
                )

    if errors:
        raise RuntimeError("\n".join(errors))
    print(
        "PASS: four selected 25G241 AWDL wrappers load the pinned vtable offsets "
        "and tail-jump to the callback after restoring their frames. This confirms "
        "return forwarding at these callsites only; it does not identify the source typedef."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
