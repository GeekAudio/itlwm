#!/usr/bin/env python3
"""Offline compile/reloc-link gate for a reconstructed 25G332 AWDL child.

The test emits only a temporary object. It does not build or load a kext, create
an interface, publish an IO80211Controller pointer, or exercise radio hardware.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
IMAGE = (
    ROOT.parent
    / "IntelWirelessNative/research/test037-upgrade-private/"
    / "IO80211Family-25G332.linked-analysis.macho"
)
CPP = ROOT / "native/awdl_native_concrete_25G332.cpp"
HEADER = ROOT / "native/awdl_native_concrete_25G332.hpp"
CLASS = "ItlAwdlNativeConcreteGate25G332"
EXPECTED_IMAGE_SHA256 = "8732ea8838331d115e16697acefa22ca5b3d0c516c48293de2e2ebbaf891d047"
EXPECTED_NATIVE = {
    "__ZTV23IO80211VirtualInterface",
    "__ZTVN23IO80211VirtualInterface9MetaClassE",
    "__ZN23IO80211VirtualInterface10gMetaClassE",
    "__ZTV19IO80211AWDLProtocol",
    "__ZTVN19IO80211AWDLProtocol9MetaClassE",
    "__ZN19IO80211AWDLProtocol10gMetaClassE",
    "__ZN19IO80211AWDLProtocolC2EPK11OSMetaClass",
    "__ZN19IO80211AWDLProtocolD2Ev",
    "__ZNK19IO80211AWDLProtocol9MetaClass5allocEv",
}


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def parse_symbols(image: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in run("xcrun", "nm", "-nm", str(image)).splitlines():
        fields = line.split()
        if len(fields) < 3 or not re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            continue
        result[fields[-1]] = int(fields[0], 16)
    return result


def const_section(image: Path) -> tuple[int, int]:
    for block in run("xcrun", "otool", "-l", str(image)).split("Section\n")[1:]:
        section = re.search(r"\bsectname\s+(\S+)", block)
        segment = re.search(r"\bsegname\s+(\S+)", block)
        address = re.search(r"\baddr\s+(0x[0-9a-fA-F]+)", block)
        offset = re.search(r"\boffset\s+(\d+)", block)
        if section and segment and address and offset:
            if section.group(1) == "__const" and segment.group(1) == "__DATA":
                return int(address.group(1), 16), int(offset.group(1))
    raise RuntimeError("25G332 analysis image has no __DATA,__const section")


def native_vtable(
    image: Path, symbols: dict[str, int], name: str, meta_vtable: str, slots: int
) -> list[int]:
    if name not in symbols or meta_vtable not in symbols:
        raise RuntimeError(f"missing native vtable boundary: {name}")
    start, end = symbols[name], symbols[meta_vtable]
    count = (end - start - 24) // 8
    if count != slots:
        raise RuntimeError(f"{name} has {count} slots, expected {slots}")
    section_vm, section_file = const_section(image)
    offset = section_file + (start - section_vm) + 16
    with image.open("rb") as stream:
        stream.seek(offset)
        raw = stream.read(slots * 8)
    if len(raw) != slots * 8:
        raise RuntimeError(f"short read from {name}")
    return [int.from_bytes(raw[i : i + 8], "little") & 0xFFFFFFFF
            for i in range(0, len(raw), 8)]


def vtable_rows(dump: str) -> dict[int, str]:
    marker = f"VTable indices for '{CLASS}'"
    start = dump.find(marker)
    if start < 0:
        raise RuntimeError("Clang did not emit the concrete gate vtable")
    rows: dict[int, str] = {}
    for line in dump[start:].splitlines()[1:]:
        match = re.match(r"\s*(\d+) \| (.*)", line)
        if not match:
            if rows:
                break
            continue
        rows[int(match.group(1))] = match.group(2)
    return rows


def method_signature(row: str) -> tuple[str, str]:
    match = re.search(r"::(\w+)\((.*)\)$", row)
    if not match:
        raise RuntimeError(f"could not parse vtable row: {row}")
    return match.group(1), re.sub(r"\s+", "", match.group(2))


def function_block(disassembly: str, symbol: str) -> str:
    marker = f"{symbol}:"
    start = disassembly.find(marker)
    if start < 0:
        raise RuntimeError(f"missing disassembly for {symbol}")
    tail = disassembly[start + len(marker) :]
    next_symbol = re.search(r"^__\S+:$", tail, re.M)
    return tail[: next_symbol.start()] if next_symbol else tail


def main() -> int:
    if digest(IMAGE) != EXPECTED_IMAGE_SHA256:
        raise RuntimeError("preserved 25G332 IO80211Family image hash mismatch")
    symbols = parse_symbols(IMAGE)
    missing_native = EXPECTED_NATIVE - symbols.keys()
    if missing_native:
        raise RuntimeError(f"missing 25G332 native symbols: {sorted(missing_native)}")

    vif = native_vtable(
        IMAGE,
        symbols,
        "__ZTV23IO80211VirtualInterface",
        "__ZTVN23IO80211VirtualInterface9MetaClassE",
        505,
    )
    awdl = native_vtable(
        IMAGE,
        symbols,
        "__ZTV19IO80211AWDLProtocol",
        "__ZTVN19IO80211AWDLProtocol9MetaClassE",
        568,
    )
    differences = [i for i, pair in enumerate(zip(vif, awdl)) if pair[0] != pair[1]]
    if differences != [0, 1, 7]:
        raise RuntimeError(f"AWDL/VIF prefix changed at slots {differences}")
    if any(awdl[i] != awdl[488] for i in [488, *range(505, 568)]):
        raise RuntimeError("native abstract AWDL slot map changed")

    native_disassembly = run(
        "xcrun", "llvm-objdump", "--macho", "--disassemble",
        "--symbolize-operands", str(IMAGE),
    )
    metaclass_body = function_block(
        native_disassembly, "__ZN19IO80211AWDLProtocol9MetaClassC2Ev"
    )
    if (
        '"IO80211AWDLProtocol"' not in metaclass_body
        or "IO80211VirtualInterface::gMetaClass" not in metaclass_body
        or "movl\t$0x130, %ecx" not in metaclass_body
    ):
        raise RuntimeError("25G332 AWDL metaclass parent/name/instance-size disassembly changed")
    alloc_body = function_block(
        native_disassembly, "__ZNK19IO80211AWDLProtocol9MetaClass5allocEv"
    )
    if "xorl\t%eax, %eax" not in alloc_body or "retq" not in alloc_body:
        raise RuntimeError("25G332 abstract AWDL metaclass allocator no longer returns null")
    awdl_ctor = function_block(
        native_disassembly, "__ZN19IO80211AWDLProtocolC2EPK11OSMetaClass"
    )
    lea = re.search(
        r"([0-9a-f]{16}):\s+([0-9a-f ]+)\s+leaq\s+0x([0-9a-f]+)\(%rip\), %rax",
        awdl_ctor,
    )
    if not lea:
        raise RuntimeError("25G332 AWDL constructor vptr initialization is not visible")
    instruction = lea.group(2).split()
    vptr_target = (
        int(lea.group(1), 16) + len(instruction) + int(lea.group(3), 16)
    )
    if vptr_target != symbols["__ZTV19IO80211AWDLProtocol"] + 16:
        raise RuntimeError("25G332 AWDL constructor no longer installs the native vtable")

    sdk = Path(run("xcrun", "--sdk", "macosx", "--show-sdk-path").strip())
    kernel_headers = (
        sdk / "System/Library/Frameworks/Kernel.framework/Versions/A/Headers"
    )
    common = [
        "xcrun", "--sdk", "macosx", "clang++",
        "-target", "x86_64-apple-macosx26.0",
        "-std=c++17", "-fapple-kext", "-fno-rtti", "-fno-exceptions",
        "-D__IO80211_TARGET=260000",
        f"-I{ROOT / 'include'}", f"-I{kernel_headers}",
    ]

    with tempfile.TemporaryDirectory(prefix="test042-awdl-concrete-") as tmp:
        obj = Path(tmp) / "awdl-concrete.o"
        linked = Path(tmp) / "awdl-concrete-linked.o"
        run(*common, "-c", str(CPP), "-o", str(obj))
        run("xcrun", "ld", "-r", "-arch", "x86_64", "-o", str(linked), str(obj))
        dump = run(
            *common, "-S", "-o", "/dev/null", "-Xclang",
            "-fdump-vtable-layouts", str(CPP),
        )
        rows = vtable_rows(dump)
        required_slots = {0, 1, 7, 488, *range(505, 568)}
        if rows.keys() != required_slots:
            raise RuntimeError(
                f"concrete gate overrides {len(rows)} unexpected vtable slots"
            )
        if f"{CLASS}::~{CLASS}() [complete]" not in rows[0]:
            raise RuntimeError("slot 0 is not the concrete complete destructor")
        if f"{CLASS}::~{CLASS}() [deleting]" not in rows[1]:
            raise RuntimeError("slot 1 is not the concrete deleting destructor")
        if f"{CLASS}::getMetaClass() const" not in rows[7]:
            raise RuntimeError("slot 7 is not the OSMetaClass getMetaClass override")
        if method_signature(rows[488])[0] != "setMacAddress":
            raise RuntimeError("slot 488 is not the inherited pure setMacAddress")

        awdl_header = HEADER.read_text()
        awdl_start = awdl_header.index("class IO80211AWDLProtocol\n")
        child_start = awdl_header.index(f"class {CLASS}")
        declarations = awdl_header[awdl_start:child_start]
        pure = re.findall(
            r"virtual\s+(?:Status32|IOReturn)\s+(\w+)\s*\(([^)]*)\)\s*=\s*0\s*;",
            declarations,
            re.S,
        )
        if len(pure) != 63:
            raise RuntimeError(f"expected 63 protocol declarations, found {len(pure)}")
        for slot, (name, args) in zip(range(505, 568), pure):
            actual_name, actual_args = method_signature(rows[slot])
            if (actual_name, actual_args) != (name, re.sub(r"\s+", "", args)):
                raise RuntimeError(f"slot {slot}: {actual_name}{actual_args} != {name}{args}")

        linked_symbols = run("xcrun", "nm", "-u", str(linked))
        unresolved = set(re.findall(r"^\s*(__Z\S+)$", linked_symbols, re.M))
        native_names = symbols.keys()
        native_parent_refs = {
            name for name in unresolved if name.startswith("__ZN23IO80211VirtualInterface")
        }
        if len(native_parent_refs) != 96 or native_parent_refs - native_names:
            raise RuntimeError(
                f"expected 96 VIF refs, all resolved in 25G332 image; "
                f"found {len(native_parent_refs)}, missing "
                f"{sorted(native_parent_refs - native_names)}"
            )
        required_link_refs = {
            "__ZN19IO80211AWDLProtocol10gMetaClassE",
            "__ZN19IO80211AWDLProtocolC2EPK11OSMetaClass",
            "__ZN19IO80211AWDLProtocolD2Ev",
        }
        if not required_link_refs <= unresolved:
            raise RuntimeError(
                f"native OSMetaClass/base-constructor linkage missing: "
                f"{sorted(required_link_refs - unresolved)}"
            )
        relocations = run("xcrun", "otool", "-rv", str(linked))
        if "GOT_LD  False     __ZN19IO80211AWDLProtocol10gMetaClassE" not in relocations:
            raise RuntimeError("child MetaClass parent relocation is not native AWDL gMetaClass")

        disassembly = run(
            "xcrun", "llvm-objdump", "--macho", "--disassemble",
            "--symbolize-operands", str(linked),
        )
        alloc_symbol = f"__ZNK{len(CLASS)}{CLASS}9MetaClass5allocEv:"
        alloc_start = disassembly.find(alloc_symbol)
        if alloc_start < 0:
            raise RuntimeError("missing concrete gate MetaClass::alloc implementation")
        alloc_body = disassembly[alloc_start : alloc_start + 600]
        if "xorl\t%eax, %eax" not in alloc_body or "retq" not in alloc_body:
            raise RuntimeError("gate MetaClass::alloc does not return null")
        # The prototype may be a compile input for the explicit init-only
        # observation. An ordinary Tahoe build must still emit no class/code.
        dormant = Path(tmp) / "ordinary-tahoe.o"
        run(*common, "-DAIRPORT_TAHOE=1", "-c", str(CPP), "-o", str(dormant))
        if CLASS in run("xcrun", "nm", str(dormant)):
            raise RuntimeError("native observation prototype leaked into ordinary Tahoe")

    source = CPP.read_text()
    bodies = re.findall(
        rf"^(Status32|IOReturn) {CLASS}::(\w+)\(([^)]*)\) \{{\s*"
        r"return (kIOReturnNotReady|kIOReturnUnsupported);\s*\}",
        source,
        re.M,
    )
    if len(bodies) != 64:
        raise RuntimeError(f"expected 64 fail-closed bodies, found {len(bodies)}")
    for _, name, args, result in bodies:
        if args.strip() and re.search(r"\b[a-zA-Z_]\w*\s*(?:\*|&)?\s*$", args):
            # Parameter declarations intentionally omit names: stubs do not
            # inspect or write request/output buffers.
            if not re.fullmatch(r"(?:[A-Za-z_]\w*(?:\s*::\s*\w+)?|(?:const\s+)?[A-Za-z_]\w*)(?:\s*[*&])?", args.strip()):
                raise RuntimeError(f"gate stub has a named or unexpected parameter: {name}")
        expected = "kIOReturnNotReady" if name.startswith("get") or name == "setMacAddress" else "kIOReturnUnsupported"
        if result != expected:
            raise RuntimeError(f"{name} returns {result}, expected {expected}")
    if "setAwdlInterface" in source or "attachVirtualInterface" in source or "VIRTUAL_IF_CREATE" in source:
        raise RuntimeError("offline gate contains an interface allocation/publication path")

    print(
        "PASS: 25G332 image ABI 505/568 slots, 0x130 AWDL/VIF parent layouts, "
        "native C2/gMetaClass symbols, exact child vtable indices, and relocatable link"
    )
    print(
        "PASS: native disassembly confirms AWDL parent IO80211VirtualInterface, "
        "instance size 0x130, native vptr initialization, and abstract alloc()==null"
    )
    print(
        f"PASS: child overrides 64 pure slots; {len(native_parent_refs)} inherited VIF "
        "symbols match the preserved image; child MetaClass parent is native AWDL; alloc() returns null"
    )
    print("PASS: all 64 stubs return NotReady/Unsupported without touching request buffers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
