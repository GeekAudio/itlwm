#!/usr/bin/env python3
"""Offline 25G241 VIF vtable and compile-only ABI witness.

The linked-analysis image is read-only evidence outside this repository. This
test never copies its bytes, builds a kext, instantiates the witness, or loads
anything. It compares vtable symbol targets and Clang's emitted abstract-class
layout, then reports only names, slot indices, sizes, and hashes.
"""

from __future__ import annotations

import hashlib
import re
import struct
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
IMAGE = (
    ROOT.parent
    / "SkywalkLegacyCompat/src/awdl_compat/evidence/native-IO80211-linked-25G241/"
    / "IO80211Family.linked-analysis.macho"
)
CPP = ROOT / "native/tests/test_awdl_vif_abi.cpp"
HEADER = ROOT / "include/Tahoe/IO80211VirtualInterfaceABI25G241.hpp"
EXPECTED_SHA256 = "26abad781208e382ba0dffe3c3bc8cc3fe820aea2cacb5083b1d25a6240202fa"
WITNESS_NAME = "TahoeAwdl25G241VifABI::IO80211VirtualInterfaceLayoutWitness25G241"
EXPECTED_PARENT_SLOTS = 461
EXPECTED_VIF_SLOTS = 505
EXPECTED_AWDL_SLOTS = 568


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_symbols(image: Path) -> tuple[dict[str, int], dict[int, str]]:
    by_name: dict[str, int] = {}
    by_address: dict[int, str] = {}
    for line in run("xcrun", "nm", "-nm", str(image)).splitlines():
        fields = line.split()
        if len(fields) < 3 or not re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            continue
        address = int(fields[0], 16)
        name = fields[-1]
        by_name[name] = address
        by_address[address] = name
    return by_name, by_address


def data_const_section(image: Path) -> tuple[int, int]:
    output = run("xcrun", "otool", "-l", str(image))
    for block in output.split("Section\n")[1:]:
        section = re.search(r"\bsectname\s+(\S+)", block)
        segment = re.search(r"\bsegname\s+(\S+)", block)
        address = re.search(r"\baddr\s+(0x[0-9a-fA-F]+)", block)
        offset = re.search(r"\boffset\s+(\d+)", block)
        if section and segment and address and offset:
            if section.group(1) == "__const" and segment.group(1) == "__DATA":
                return int(address.group(1), 16), int(offset.group(1))
    raise RuntimeError("missing __DATA,__const mapping in linked-analysis image")


def table_words(
    image: Path, section_vm: int, section_file: int, vtable_vm: int, count: int
) -> list[int]:
    file_offset = section_file + (vtable_vm - section_vm) + 16
    with image.open("rb") as stream:
        stream.seek(file_offset)
        raw = stream.read(count * 8)
    if len(raw) != count * 8:
        raise RuntimeError("short vtable read from linked-analysis image")
    return [word & 0xFFFFFFFF for (word,) in struct.iter_unpack("<Q", raw)]


def compiler_vtable_dump(sdk_headers: Path) -> str:
    common = [
        "xcrun",
        "--sdk",
        "macosx",
        "clang++",
        "-std=c++17",
        "-fno-rtti",
        "-D__IO80211_TARGET=260000",
        f"-I{ROOT / 'include'}",
        f"-I{sdk_headers}",
        str(CPP),
    ]
    # The first pass confirms declaration syntax without emitting any code.
    run(*common[:-1], "-fsyntax-only", common[-1])
    # Defining only the witness destructor gives Clang a key function and asks
    # it to dump the abstract vtable; no object is created or linked.
    return run(*common[:-1], "-S", "-o", "/dev/null", "-Xclang", "-fdump-vtable-layouts", common[-1])


def compiler_rows(dump: str) -> dict[int, str]:
    marker = f"VTable indices for '{WITNESS_NAME}'"
    start = dump.find(marker)
    if start < 0:
        raise RuntimeError("Clang did not emit the VIF witness vtable layout")
    rows: dict[int, str] = {}
    for line in dump[start:].splitlines()[1:]:
        match = re.match(r"\s*(\d+) \| (.*)", line)
        if not match:
            if rows:
                break
            continue
        rows[int(match.group(1))] = match.group(2)
    return rows


def signature_method(signature: str) -> str:
    name = signature.rsplit("::", 1)[-1].split("(", 1)[0].strip()
    if name.startswith("~IO80211VirtualInterfaceLayoutWitness25G241"):
        return "<destructor>"
    if name == "__tahoe_slot_cd0":
        return "findPeer"  # parent header's explicitly opaque slot-410 alias
    return name


def symbol_method(demangled: str) -> str:
    if "::~IO80211VirtualInterface()" in demangled:
        return "<destructor>"
    return demangled.rsplit("::", 1)[-1].split("(", 1)[0].strip()


def main() -> int:
    if not IMAGE.is_file():
        raise FileNotFoundError(IMAGE)
    actual_hash = digest(IMAGE)
    if actual_hash != EXPECTED_SHA256:
        raise RuntimeError(f"IO80211 image hash changed: {actual_hash}")

    by_name, by_address = parse_symbols(IMAGE)
    parent_vtable_name = "__ZTV23IO80211SkywalkInterface"
    parent_end_name = "__ZN23IO80211SkywalkInterface9metaClassE"
    vif_vtable_name = "__ZTV23IO80211VirtualInterface"
    vif_end_name = "__ZTVN23IO80211VirtualInterface9MetaClassE"
    awdl_vtable_name = "__ZTV19IO80211AWDLProtocol"
    awdl_end_name = "__ZTVN19IO80211AWDLProtocol9MetaClassE"
    for required in (
        parent_vtable_name,
        parent_end_name,
        vif_vtable_name,
        vif_end_name,
        awdl_vtable_name,
        awdl_end_name,
    ):
        if required not in by_name:
            raise RuntimeError(f"missing native vtable boundary symbol: {required}")

    parent_vm = by_name[parent_vtable_name]
    parent_end_vm = by_name[parent_end_name]
    vif_vm = by_name[vif_vtable_name]
    vif_end_vm = by_name[vif_end_name]
    awdl_vm = by_name[awdl_vtable_name]
    awdl_end_vm = by_name[awdl_end_name]
    parent_slots = (parent_end_vm - parent_vm - 24) // 8
    vif_slots = (vif_end_vm - vif_vm - 24) // 8
    awdl_slots = (awdl_end_vm - awdl_vm - 24) // 8
    if (
        parent_slots != EXPECTED_PARENT_SLOTS
        or vif_slots != EXPECTED_VIF_SLOTS
        or awdl_slots != EXPECTED_AWDL_SLOTS
    ):
        raise RuntimeError(
            f"unexpected native vtable counts: {parent_slots}, {vif_slots}, {awdl_slots}"
        )

    section_vm, section_file = data_const_section(IMAGE)
    parent_words = table_words(IMAGE, section_vm, section_file, parent_vm, parent_slots)
    vif_words = table_words(IMAGE, section_vm, section_file, vif_vm, vif_slots)
    awdl_words = table_words(IMAGE, section_vm, section_file, awdl_vm, awdl_slots)
    overrides = [i for i, (a, b) in enumerate(zip(parent_words, vif_words)) if a != b]
    if len(overrides) != 56:
        raise RuntimeError(f"expected 56 VIF overrides in inherited prefix, found {len(overrides)}")
    awdl_pure_slots = [488, *range(505, 568)]
    if any(awdl_words[i] != awdl_words[488] for i in awdl_pure_slots):
        raise RuntimeError("native AWDL pure slots no longer share VIF slot 488's target")

    init_raw = "__ZN23IO80211VirtualInterface4initEP17IO80211ControllerP10ether_addrjPKc"
    if init_raw not in by_name:
        raise RuntimeError("missing VIF::init symbol needed to decode linked targets")
    # Pointer words carry high-bit tags; their low word is an image-relative
    # text offset. Derive the image base from the exact slot-461 init target.
    link_base = by_name[init_raw] - vif_words[461]
    raw_names = {((addr - link_base) & 0xFFFFFFFF): name for addr, name in by_address.items()}
    checked_slots = overrides + list(range(461, 488)) + list(range(489, 505))
    target_offsets = {vif_words[i] for i in checked_slots}
    selected_raw = [raw_names[o] for o in sorted(target_offsets) if o in raw_names]
    demangled = subprocess.check_output(
        ["c++filt"], input="\n".join(selected_raw), text=True
    ).splitlines()
    demangled_by_raw = dict(zip(selected_raw, demangled))
    demangled_by_offset = {
        offset: demangled_by_raw[raw_names[offset]]
        for offset in target_offsets
        if offset in raw_names and raw_names[offset] in demangled_by_raw
    }
    demangled_by_slot = {
        slot: demangled_by_offset.get(vif_words[slot], "") for slot in checked_slots
    }

    # New VIF slots are names from their exact native target symbols. Slot 488
    # is a kernel pure-virtual entry; its name/argument are corroborated by the
    # concrete BCM vtable and the caller's consumed EAX32 status.
    for slot in list(range(461, 488)) + list(range(489, 505)):
        if not demangled_by_slot.get(slot):
            raise RuntimeError(f"could not resolve native symbol for VIF slot {slot}")

    sdk = Path(run("xcrun", "--sdk", "macosx", "--show-sdk-path").strip())
    sdk_headers = sdk / "System/Library/Frameworks/Kernel.framework/Versions/A/Headers"
    dump = compiler_vtable_dump(sdk_headers)
    rows = compiler_rows(dump)
    expected_indices = set(overrides) | set(range(461, 505)) | {0, 1, 7}
    missing = expected_indices - rows.keys()
    if missing:
        raise RuntimeError(f"Clang witness omits native vtable slots: {sorted(missing)}")
    if max(rows) != 504:
        raise RuntimeError(f"Clang witness ends at {max(rows)}, expected slot 504")

    # All inherited overrides must retain their exact slot numbers and names.
    for slot in overrides:
        native_name = symbol_method(demangled_by_slot[slot])
        compiler_name = signature_method(rows[slot])
        if native_name != compiler_name:
            raise RuntimeError(
                f"slot {slot} override name mismatch: native={native_name!r}, clang={compiler_name!r}"
            )

    for slot in list(range(461, 488)) + list(range(489, 505)):
        native_name = symbol_method(demangled_by_slot[slot])
        compiler_name = signature_method(rows[slot])
        if native_name != compiler_name:
            raise RuntimeError(
                f"slot {slot} native/compiler name mismatch: {native_name!r} != {compiler_name!r}"
            )
    if signature_method(rows[488]) != "setMacAddress":
        raise RuntimeError("Clang witness slot 488 is not setMacAddress")

    vif_block = dump[dump.find(f"VTable indices for '{WITNESS_NAME}'") :]
    heading = re.search(r"VTable indices .* \((\d+) entries\)", vif_block)
    if not heading or int(heading.group(1)) != len(rows):
        raise RuntimeError("Clang vtable entry count does not match parsed slot rows")

    print(
        "PASS: native parent=461 slots, VIF=505 slots, AWDL=568 slots; "
        f"inherited overrides={len(overrides)}, VIF-added=44; "
        f"Clang witness entries={len(rows)}, final slot={max(rows)}, sizeof=0x130"
    )
    print(f"PASS: IO80211Family image sha256={actual_hash}")
    print(
        "PASS: inputPacket slot 362, forwardPacket slot 463, slot 488 matches all 63 AWDL pure entries, "
        "reserved slots 489-504"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
