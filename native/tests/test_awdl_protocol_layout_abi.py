#!/usr/bin/env python3
"""Offline compile/layout check for the AWDLProtocol slots on 25G241.

The test reads local linked-analysis images and compiles only the abstract
layout witness. It never creates, links, registers, or loads an AWDL object.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
IO80211_IMAGE = (
    ROOT.parent
    / "SkywalkLegacyCompat/src/awdl_compat/evidence/native-IO80211-linked-25G241/"
    / "IO80211Family.linked-analysis.macho"
)
BCM_IMAGE = (
    ROOT.parent
    / "SkywalkLegacyCompat/research/evidence/native-BCMWLANCoreMac-linked-25G241/"
    / "AppleBCMWLANCoreMac.linked-analysis.macho"
)
CPP = ROOT / "native/tests/test_awdl_protocol_abi.cpp"
HEADER = ROOT / "include/Tahoe/IO80211AWDLProtocolLayoutABI25G241.hpp"
EVIDENCE = ROOT / "include/Tahoe/evidence/awdl-vtable-25G241.md"
EXPECTED_HASHES = {
    "IO80211Family": "26abad781208e382ba0dffe3c3bc8cc3fe820aea2cacb5083b1d25a6240202fa",
    "AppleBCMWLANCoreMac": "d54e7c68a34cea817900e587a1653f52c38c5d5df93c0701f1161d1e78f2afa9",
}
WITNESS_NAME = (
    "TahoeAwdl25G241AwdlABI::IO80211AWDLProtocolLayoutWitness25G241"
)
AWDL_SLOTS = range(505, 568)
PURE_SLOTS = [488, *AWDL_SLOTS]
EXACT_IOReturn_METHODS = {
    "setAWDL_OOB_REQUEST",
    "setAWDL_SYNC_FRAME_TEMPLATE",
}


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


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
    for block in run("xcrun", "otool", "-l", str(image)).split("Section\n")[1:]:
        section = re.search(r"\bsectname\s+(\S+)", block)
        segment = re.search(r"\bsegname\s+(\S+)", block)
        address = re.search(r"\baddr\s+(0x[0-9a-fA-F]+)", block)
        offset = re.search(r"\boffset\s+(\d+)", block)
        if section and segment and address and offset:
            if section.group(1) == "__const" and segment.group(1) == "__DATA":
                return int(address.group(1), 16), int(offset.group(1))
    raise RuntimeError("missing __DATA,__const section")


def table_words(
    image: Path, section_vm: int, section_file: int, table_vm: int, count: int
) -> list[int]:
    file_offset = section_file + (table_vm - section_vm) + 16
    with image.open("rb") as stream:
        stream.seek(file_offset)
        raw = stream.read(count * 8)
    if len(raw) != count * 8:
        raise RuntimeError("short read while checking native vtable")
    return [int.from_bytes(raw[i : i + 8], "little") & 0xFFFFFFFF
            for i in range(0, len(raw), 8)]


def native_vtable(
    image: Path,
    symbols: dict[str, int],
    table_symbol: str,
    end_symbol: str,
    expected_count: int,
) -> tuple[int, list[int]]:
    if table_symbol not in symbols or end_symbol not in symbols:
        raise RuntimeError(f"missing vtable boundary symbols {table_symbol}/{end_symbol}")
    start = symbols[table_symbol]
    end = symbols[end_symbol]
    count = (end - start - 24) // 8
    if count != expected_count:
        raise RuntimeError(f"{table_symbol} has {count} slots, expected {expected_count}")
    section_vm, section_file = data_const_section(image)
    return start, table_words(image, section_vm, section_file, start, count)


def compiler_vtable_dump(sdk_headers: Path) -> str:
    base = [
        "xcrun", "--sdk", "macosx", "clang++", "-std=c++17", "-fno-rtti",
        "-D__IO80211_TARGET=260000", f"-I{ROOT / 'include'}",
        f"-I{sdk_headers}", str(CPP),
    ]
    run(*base[:-1], "-fsyntax-only", base[-1])
    return run(
        *base[:-1], "-S", "-o", "/dev/null", "-Xclang",
        "-fdump-vtable-layouts", base[-1],
    )


def compiler_rows(dump: str) -> dict[int, str]:
    marker = f"VTable indices for '{WITNESS_NAME}'"
    start = dump.find(marker)
    if start < 0:
        raise RuntimeError("Clang did not emit the AWDL witness vtable")
    rows: dict[int, str] = {}
    for line in dump[start:].splitlines()[1:]:
        match = re.match(r"\s*(\d+) \| (.*)", line)
        if not match:
            if rows:
                break
            continue
        rows[int(match.group(1))] = match.group(2)
    return rows


def compiler_method(signature: str) -> str:
    return signature.rsplit("::", 1)[-1].split("(", 1)[0].strip()


def normalize_type(value: str) -> str:
    return re.sub(r"\s+", "", value)


def witness_declarations() -> dict[str, tuple[str, str]]:
    text = HEADER.read_text()
    start = text.index("class IO80211AWDLProtocolLayoutWitness25G241")
    end = text.index("\n};", start)
    class_text = text[start:end]
    pattern = re.compile(
        r"virtual\s+(Status32|IOReturn)\s+(\w+)\s*\(([^)]*)\)\s*=\s*0\s*;",
        re.S,
    )
    return {
        name: (return_type, normalize_type(arguments))
        for return_type, name, arguments in pattern.findall(class_text)
    }


def symbol_signature(demangled: str) -> tuple[str, str]:
    match = re.search(r"::(\w+)\((.*)\)$", demangled)
    if not match:
        raise RuntimeError(f"could not parse concrete vtable symbol: {demangled}")
    name, arguments = match.groups()
    return name, normalize_type(arguments)


def main() -> int:
    if not IO80211_IMAGE.is_file() or not BCM_IMAGE.is_file():
        raise FileNotFoundError("25G241 linked-analysis images are not available")
    hashes = {
        "IO80211Family": digest(IO80211_IMAGE),
        "AppleBCMWLANCoreMac": digest(BCM_IMAGE),
    }
    if hashes != EXPECTED_HASHES:
        raise RuntimeError(f"linked-image hash mismatch: {hashes}")

    io_symbols, _ = parse_symbols(IO80211_IMAGE)
    _, awdl_words = native_vtable(
        IO80211_IMAGE,
        io_symbols,
        "__ZTV19IO80211AWDLProtocol",
        "__ZTVN19IO80211AWDLProtocol9MetaClassE",
        568,
    )
    if any(awdl_words[slot] != awdl_words[488] for slot in PURE_SLOTS):
        raise RuntimeError("native AWDL pure-slot target sequence changed")

    bcm_symbols, bcm_by_address = parse_symbols(BCM_IMAGE)
    _, bcm_words = native_vtable(
        BCM_IMAGE,
        bcm_symbols,
        "__ZTV30AppleBCMWLANProximityInterface",
        "__ZTVN30AppleBCMWLANProximityInterface9MetaClassE",
        571,
    )
    mac_raw = next(
        (name for name in bcm_symbols if name.endswith(
            "AppleBCMWLANProximityInterface13setMacAddressER10ether_addr"
        )),
        None,
    )
    if not mac_raw:
        raise RuntimeError("missing BCM concrete setMacAddress symbol")
    link_base = bcm_symbols[mac_raw] - bcm_words[488]
    raw_by_offset = {
        (address - link_base) & 0xFFFFFFFF: name
        for address, name in bcm_by_address.items()
    }
    raw = [raw_by_offset.get(bcm_words[slot], "") for slot in AWDL_SLOTS]
    if any(not name for name in raw):
        missing = [slot for slot, name in zip(AWDL_SLOTS, raw) if not name]
        raise RuntimeError(f"unresolved BCM concrete symbols at slots {missing}")
    demangled = subprocess.check_output(
        ["c++filt"], input="\n".join(raw), text=True
    ).splitlines()
    if len(demangled) != len(raw):
        raise RuntimeError("c++filt output count does not match vtable targets")

    declarations = witness_declarations()
    if len(declarations) != 63:
        raise RuntimeError(f"witness declares {len(declarations)} AWDL callbacks, expected 63")
    native_signatures = [symbol_signature(name) for name in demangled]
    if len({name for name, _ in native_signatures}) != 63:
        raise RuntimeError("native AWDL callback names are not unique")
    for slot, (name, arguments) in zip(AWDL_SLOTS, native_signatures):
        declaration = declarations.get(name)
        if declaration is None:
            raise RuntimeError(f"witness omits native slot {slot} method {name}")
        if declaration[1] != arguments:
            raise RuntimeError(
                f"slot {slot} {name} argument mismatch: witness={declaration[1]} native={arguments}"
            )
        expected_return = "IOReturn" if name in EXACT_IOReturn_METHODS else "Status32"
        if declaration[0] != expected_return:
            raise RuntimeError(
                f"slot {slot} {name} return ABI label {declaration[0]}, expected {expected_return}"
            )

    sdk = Path(run("xcrun", "--sdk", "macosx", "--show-sdk-path").strip())
    headers = sdk / "System/Library/Frameworks/Kernel.framework/Versions/A/Headers"
    dump = compiler_vtable_dump(headers)
    rows = compiler_rows(dump)
    expected_indices = {0, 1, 7, *AWDL_SLOTS}
    if set(rows) != expected_indices:
        raise RuntimeError(
            "Clang AWDL witness method indices differ: "
            f"missing={sorted(expected_indices - rows.keys())}, "
            f"unexpected={sorted(rows.keys() - expected_indices)}"
        )
    for slot, (native_name, _) in zip(AWDL_SLOTS, native_signatures):
        if compiler_method(rows[slot]) != native_name:
            raise RuntimeError(
                f"slot {slot} compiler/native mismatch: "
                f"{compiler_method(rows[slot])!r} != {native_name!r}"
            )
    heading = re.search(r"VTable indices .* \((\d+) entries\)", dump[dump.find(
        f"VTable indices for '{WITNESS_NAME}'"
    ):])
    if not heading or int(heading.group(1)) != len(expected_indices):
        raise RuntimeError(
            "Clang AWDL vtable index heading does not report the expected "
            f"{len(expected_indices)} overridden/appended methods"
        )

    print(
        "PASS: native AWDLProtocol=568 slots, inherited setMacAddress=488, "
        "63 concrete method names/parameters match BCM vtable, Clang AWDL slots=505..567"
    )
    print("PASS: AWDL witness sizeof=0x130, abstract; no object or implementation emitted")
    print(f"PASS: IO80211Family sha256={hashes['IO80211Family']}")
    print(f"PASS: AppleBCMWLANCoreMac sha256={hashes['AppleBCMWLANCoreMac']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
