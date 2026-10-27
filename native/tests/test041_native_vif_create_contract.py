#!/usr/bin/env python3
"""Offline 25G332 check of role-6 VIRTUAL_IF_CREATE request/result semantics.

The script reads the currently installed BootKC, extracts the AppleBCMWLANCoreMac
fileset child into a temporary analysis-only image, then checks its disassembly.
It never loads a kext or instantiates/creates an interface.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
ART = REPO.parent / "IntelWirelessNative"
BOOTKC = Path("/System/Library/KernelCollections/BootKernelExtensions.kc")
EXPECTED_BOOTKC_SHA256 = "96c12f421a8e99580b5015dfd39877df38ecde9b9e056b8ccd28f15847bca35c"
IO80211_IMAGE = ART / "research/test037-upgrade-private/IO80211Family-25G332.linked-analysis.macho"
EXPECTED_IO80211_SHA256 = "8732ea8838331d115e16697acefa22ca5b3d0c516c48293de2e2ebbaf891d047"
EXPECTED_BUILD = "25G332"
BUNDLE = "com.apple.driver.AppleBCMWLANCoreMac"
CORE_SET = "__ZN16AppleBCMWLANCore20setVIRTUAL_IF_CREATEEP30apple80211_virt_if_create_data"
CORE_CREATE = "__ZN16AppleBCMWLANCore19createProxInterfaceEP30apple80211_virt_if_create_data"
PROX_WITH_OPTIONS = "__ZN30AppleBCMWLANProximityInterface11withOptionsEP16AppleBCMWLANCoreP10ether_addrPc"
BCM_WRAPPER = "__ZN25AppleBCMWLANInfraProtocol20setVIRTUAL_IF_CREATEEP30apple80211_virt_if_create_data"
IO80211_SET = "__Z30apple80211setVIRTUAL_IF_CREATEP23IO80211SkywalkInterfaceP30apple80211_virt_if_create_data"


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def section_file_mapping(image: bytes, ncmds: int, sizeofcmds: int) -> tuple[int, int]:
    cursor = 32
    text_vm = text_file = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", image, cursor)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = image[cursor + 8 : cursor + 24].split(b"\0", 1)[0]
            nsects = struct.unpack_from("<I", image, cursor + 64)[0]
            for index in range(nsects):
                section = cursor + 72 + index * 80
                sectname = image[section : section + 16].split(b"\0", 1)[0]
                section_seg = image[section + 16 : section + 32].split(b"\0", 1)[0]
                if segname == b"__TEXT" and section_seg == b"__TEXT" and sectname == b"__cstring":
                    text_vm = struct.unpack_from("<Q", image, section + 32)[0]
                    text_file = struct.unpack_from("<I", image, section + 48)[0]
        cursor += cmdsize
    if cursor != 32 + sizeofcmds or text_vm is None or text_file is None:
        raise RuntimeError("could not verify the __TEXT,__cstring mapping")
    return text_vm, text_file


def extract_core_image(tempdir: Path) -> tuple[Path, dict]:
    build = run("/usr/bin/sw_vers", "-buildVersion").strip()
    if build != EXPECTED_BUILD:
        raise RuntimeError(f"expected {EXPECTED_BUILD}, found {build}")
    inspect = run(
        "kmutil", "inspect", "--boot-path", str(BOOTKC), "--bundle-identifier", BUNDLE,
        "--show-mach-header", "--show-fileset-entries", "--verbose", "--no-authorization",
    )
    entry = re.search(
        r"LC_FILESET_ENTRY[^\n]*fileoff:(\d+) entry:" + re.escape(BUNDLE), inspect
    )
    child_header = re.search(
        r"entry:" + re.escape(BUNDLE) + r"\n\s+\|\[macho\] header: magic: 0xfeedfacf ncmds: (\d+) sizeofcmds: (\d+) filetype: 0xb",
        inspect,
    )
    child_uuid = re.search(r"\|\[macho\] cmd 0x1B 'LC_UUID' cmdsize:24 ([0-9A-Fa-f-]{36})", inspect)
    if not entry or not child_header or not child_uuid:
        raise RuntimeError("kmutil did not expose a complete CoreMach fileset entry")

    raw = BOOTKC.read_bytes()
    boot_hash = sha256(raw)
    if boot_hash != EXPECTED_BOOTKC_SHA256:
        raise RuntimeError(f"BootKC hash changed: {boot_hash}")
    offset = int(entry.group(1))
    ncmds, sizeofcmds = map(int, child_header.groups())
    fields = struct.unpack_from("<IiiIIIII", raw, offset)
    magic, cpu, subtype, filetype, actual_ncmds, actual_sizecmds, _flags, _reserved = fields
    if (magic, cpu, subtype, filetype, actual_ncmds, actual_sizecmds) != (
        0xFEEDFACF, 0x01000007, 3, 0xB, ncmds, sizeofcmds
    ):
        raise RuntimeError("fileset child header differs from kmutil's entry")

    child_uuid_bytes = bytes.fromhex(child_uuid.group(1).replace("-", ""))
    cursor = offset + 32
    found_uuid = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", raw, cursor)
        if cmdsize < 8 or cursor + cmdsize > len(raw):
            raise RuntimeError("malformed fileset load command")
        if cmd == 0x1B:
            found_uuid = raw[cursor + 8 : cursor + 24]
        cursor += cmdsize
    if cursor != offset + 32 + sizeofcmds or found_uuid != child_uuid_bytes:
        raise RuntimeError("fileset child UUID/load command boundary mismatch")

    # Keep the original collection byte layout so absolute file offsets in the
    # child load commands, sections and symbol table remain valid.
    image_path = tempdir / "AppleBCMWLANCoreMac-analysis-only.macho"
    shutil.copyfile(BOOTKC, image_path)
    with image_path.open("r+b") as stream:
        stream.seek(0)
        stream.write(raw[offset : offset + 32 + sizeofcmds])
    image_bytes = image_path.read_bytes()
    text_vm, text_file = section_file_mapping(image_bytes, ncmds, sizeofcmds)
    metadata = {
        "bootkc_path": str(BOOTKC),
        "bootkc_sha256": boot_hash,
        "bootkc_build": build,
        "bundle_identifier": BUNDLE,
        "child_file_offset": offset,
        "child_uuid": child_uuid.group(1).upper(),
        "child_header": {"magic": hex(magic), "ncmds": ncmds, "sizeofcmds": sizeofcmds},
        "analysis_image_sha256": sha256(image_bytes),
        "analysis_image_loadable": False,
        "cstring_section": {"vmaddr": f"0x{text_vm:x}", "fileoff": text_file},
    }
    return image_path, metadata


def disassembly(image: Path, symbol: str) -> str:
    result = run("xcrun", "llvm-objdump", f"--disassemble-symbols={symbol}", str(image))
    if f"<{symbol}>:" not in result:
        raise RuntimeError(f"missing method body for {symbol}")
    return result


def main() -> int:
    compile_source = '''
#include <stddef.h>
#include "Airport/apple80211_ioctl.h"
static_assert(sizeof(apple80211_virt_if_create_data) == 32);
static_assert(offsetof(apple80211_virt_if_create_data, version) == 0);
static_assert(offsetof(apple80211_virt_if_create_data, mac) == 4);
static_assert(offsetof(apple80211_virt_if_create_data, unk1) == 10);
static_assert(offsetof(apple80211_virt_if_create_data, role) == 12);
static_assert(offsetof(apple80211_virt_if_create_data, bsd_name) == 16);
'''
    with tempfile.TemporaryDirectory(prefix="test041-native-vif-create-") as temp:
        tempdir = Path(temp)
        cpp = tempdir / "request-layout.cpp"
        cpp.write_text(compile_source)
        run(
            "xcrun", "--sdk", "macosx", "clang++", "-std=c++17",
            "-D__IO80211_TARGET=260000", f"-I{REPO / 'include'}", "-fsyntax-only", str(cpp),
        )
        image, source = extract_core_image(tempdir)
        setter = disassembly(image, CORE_SET)
        creator = disassembly(image, CORE_CREATE)
        with_options = disassembly(image, PROX_WITH_OPTIONS)
        wrapper = disassembly(image, BCM_WRAPPER)
        io80211_hash = sha256(IO80211_IMAGE.read_bytes())
        if io80211_hash != EXPECTED_IO80211_SHA256:
            raise RuntimeError(f"25G332 IO80211 linked-analysis hash changed: {io80211_hash}")
        io_dispatch = disassembly(IO80211_IMAGE, IO80211_SET)

        required_setter = [
            "movl\t0xc(%rsi), %eax",  # role field at +12
            "movl\t$0x6, %eax",       # AWDL route
            "callq\t0xffffff8001661cee <" + CORE_CREATE + ">",
            "movl\t%eax, %r15d",      # preserve helper status
            "movl\t%r15d, %eax",       # return status in EAX
        ]
        if not all(item in setter for item in required_setter):
            raise RuntimeError("25G332 role-6 dispatch/status path changed")
        if "addq\t$0x4, %rsi" not in creator:
            raise RuntimeError("creator no longer passes the request MAC at offset +4")
        if "0xffffff8001719a16 <" + PROX_WITH_OPTIONS + ">" not in creator:
            raise RuntimeError("creator no longer constructs its native proximity interface")
        if "movl\t$0x6, %ecx" not in with_options:
            raise RuntimeError("native interface initializer no longer uses AWDL role 6")
        if "movl\t$0x2, 0x14(%r12)" not in creator or "callq\t*0xcf8(%rax)" not in creator:
            raise RuntimeError("could not verify the native registration/start path")
        if "movq\t%rbx, %rsi" not in creator or "movq\t%r12, %rdx" not in creator:
            raise RuntimeError("creator start call arguments changed")
        if "0xffffff8001661f18 <" not in creator:
            raise RuntimeError("creator return path changed")

        # Resolve the literal actually passed as the interface name.
        name_target = re.search(r"leaq\s+0x13980a\(%rip\).*## (0x[0-9a-f]+)", creator)
        if not name_target:
            raise RuntimeError("could not resolve the interface-name literal")
        text_vm = int(source["cstring_section"]["vmaddr"], 16)
        text_file = source["cstring_section"]["fileoff"]
        name_offset = text_file + int(name_target.group(1), 16) - text_vm
        with image.open("rb") as stream:
            stream.seek(name_offset)
            name_bytes = stream.read(32).split(b"\0", 1)[0]
        if name_bytes != b"awdl":
            raise RuntimeError(f"unexpected interface name literal: {name_bytes!r}")

        # The branch for a second role-6 create clears request bytes +16..+31,
        # then copies a 16-byte string from the existing object's method result.
        duplicate_return = "movl\t$0x11, %r15d" in setter
        name_output = all(item in setter for item in [
            "leaq\t0x10(%r14), %r12",
            "movq\t%rax, 0x18(%r14)",
            "movq\t%rax, 0x10(%r14)",
            "movl\t$0x10, %edx",
            "movq\t%r12, %rdi",
            "movq\t%rax, %rsi",
        ])
        if not duplicate_return or not name_output:
            raise RuntimeError("duplicate-create name/status behavior changed")

        # Both the Apple protocol wrapper and IO80211 request dispatcher tail-
        # call the handler, so its integer return is the syscall status result.
        if "jmpq\t*%rax" not in wrapper:
            raise RuntimeError("Apple protocol wrapper no longer forwards its status")
        if not all(item in io_dispatch for item in [
            "movq\t0x1160(%rax), %rax",
            "movq\t%rbx, %rsi",
            "jmpq\t*%rax",
        ]):
            raise RuntimeError("IO80211 request dispatcher no longer forwards handler/status")

        report = {
            "schema": "test041-native-vif-create-contract/v1",
            "result": "PASS_ROLE6_MAC_NAME_AND_STATUS_PATH_CONFIRMED",
            "scope": "Read-only static analysis of the active 25G332 BootKC fileset child; no driver was loaded and no interface was created.",
            "source": source,
            "io80211_dispatch": {
                "analysis_image_path": str(IO80211_IMAGE),
                "analysis_image_sha256": io80211_hash,
                "symbol": IO80211_SET,
                "address": "0xffffff800226d788",
                "effect": "passes the unchanged request pointer to protocol slot 0x1160 and tail-returns the handler result",
            },
            "request_layout": {
                "size": 32,
                "version": {"offset": 0, "role6_path_read": False},
                "mac": {"offset": 4, "length": 6, "role6_path_use": "address passed to native withOptions"},
                "reserved_unk1": {"offset": 10, "size": 2, "role6_path_read": False},
                "role": {"offset": 12, "size": 4, "role6_value": 6},
                "bsd_name": {
                    "offset": 16,
                    "length": 16,
                    "first_create_input": "not passed to the AWDL creator",
                    "duplicate_create_output": "cleared, then populated with up to 16 bytes from existing interface method result",
                },
            },
            "role6_create_path": {
                "set_handler_symbol": CORE_SET,
                "set_handler_address": "0xffffff800167c924",
                "creator_symbol": CORE_CREATE,
                "creator_address": "0xffffff8001661cee",
                "with_options_symbol": PROX_WITH_OPTIONS,
                "with_options_address": "0xffffff8001719a16",
                "bsd_name_prefix_literal": "awdl",
                "initializer_role": 6,
                "result_contract": "setVIRTUAL_IF_CREATE returns the 32-bit helper status in EAX; it does not return an interface pointer or numeric interface index.",
                "duplicate_create_status": "0x11 (raw status; no errno meaning assigned)",
                "ownership_observation": "creator stores its object in the AppleBCMWLANCore extension, attaches it to that core, builds RegistrationInfo and calls start; caller receives only status.",
            },
            "confirmed_boundary": [
                "The public request layout and role-6 dispatch prove the field offsets and creation inputs for this Apple BCM implementation.",
                "On first create, the name is supplied internally as the literal awdl; no interface index or name is returned through a dedicated output pointer.",
                "On the already-created path, request bytes +16..+31 are written with a 16-byte name result and status 0x11 is returned.",
                "The Apple BCM creator is hardware-specific evidence for the native request contract; it does not establish an Intel AWDL implementation or promise identical internal ownership.",
            ],
            "limitations": [
                "No runtime behavior or user-visible awdl0 index assignment was tested.",
                "The role-6 code path does not read version/reserved fields, but this does not rule out validation by an earlier caller.",
                "The name result source is verified as an indirect return copied to the field; its private method semantic is not inferred here.",
                "The successful-start branch does not test the native start return value before returning from createProxInterface.",
            ],
        }
        target = ART / "research/test041-native-vif-create-contract-private.json"
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_text(json.dumps(report, indent=2) + "\n")
        target.chmod(0o600)
        print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
