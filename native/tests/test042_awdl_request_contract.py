#!/usr/bin/env python3
"""Offline ABI/data-flow gate for AWDL ioctl selectors 149 and 151.

This reads the preserved 25G332 IO80211 image and extracts the
AppleBCMWLANCoreMac fileset child to a temporary, non-loadable analysis image.
It also compares the same callbacks with the preserved 25G241 BCM image.
No kext is built or loaded and no interface or radio operation is performed.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
ART = REPO.parent / "IntelWirelessNative"
IO80211_25G332 = ART / "research/test037-upgrade-private/IO80211Family-25G332.linked-analysis.macho"
BCM_25G241 = (
    REPO.parent
    / "SkywalkLegacyCompat/research/evidence/native-BCMWLANCoreMac-linked-25G241/"
    "AppleBCMWLANCoreMac.linked-analysis.macho"
)
REPORT = ART / "research/test042-native-awdl-request-contract-private.json"
EXPECTED_IO80211_25G332_SHA256 = "8732ea8838331d115e16697acefa22ca5b3d0c516c48293de2e2ebbaf891d047"
EXPECTED_BCM_25G241_SHA256 = "d54e7c68a34cea817900e587a1653f52c38c5d5df93c0701f1161d1e78f2afa9"
EXPECTED_BOOTKC_SHA256 = "96c12f421a8e99580b5015dfd39877df38ecde9b9e056b8ccd28f15847bca35c"

IOCTL_149 = "__Z29apple80211setAWDL_OOB_REQUESTP23IO80211SkywalkInterfaceP27apple80211_awdl_oob_request"
IOCTL_151 = "__Z37apple80211setAWDL_SYNC_FRAME_TEMPLATEP23IO80211SkywalkInterfaceP35apple80211_awdl_sync_frame_template"
BCM_OOB = "__ZN30AppleBCMWLANProximityInterface19setAWDL_OOB_REQUESTEP27apple80211_awdl_oob_request"
BCM_SYNC_TEMPLATE = "__ZN30AppleBCMWLANProximityInterface27setAWDL_SYNC_FRAME_TEMPLATEEP35apple80211_awdl_sync_frame_template"
BCM_SYNC_PARAMS = "__ZN30AppleBCMWLANProximityInterface13setSyncParamsEv"
BCM_IOVAR_HELPER = "__ZN30AppleBCMWLANProximityInterface19sendIOVarSetCommandEP5iovecjPKc"
COMMANDER_SEND_VIRTUAL = (
    "__ZN21AppleBCMWLANCommander19sendVirtualIOVarSetEhPKcRK16CommandTxPayload"
    "RK17CommandRxExpectedRK17CommandCompletion20CommandBusPreference"
)
COMMANDER_ISSUE = (
    "__ZN21AppleBCMWLANCommander12issueCommandERK9CommandIDRK16CommandTxPayload"
    "P16CommandRxPayloadRK17CommandRxExpectedRK17CommandCompletion20CommandBusPreference"
)
COMMAND_PREPARE = (
    "__ZN19AppleBCMWLANCommand7prepareERK9CommandIDtRK16CommandTxPayload"
    "P16CommandRxPayloadRK17CommandRxExpectedRK17CommandCompletion20CommandBusPreference"
)


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_test041_helpers():
    helper_path = REPO / "native/tests/test041_native_vif_create_contract.py"
    spec = importlib.util.spec_from_file_location("test041_native_vif_create_contract", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the pinned 25G332 fileset extractor")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(body: str, fragments: tuple[str, ...], what: str) -> None:
    missing = [item for item in fragments if item not in body]
    if missing:
        raise RuntimeError(f"{what}: missing disassembly evidence: {missing}")


def address_for(image: Path, symbol: str) -> str:
    lines = run("xcrun", "nm", "-nm", str(image)).splitlines()
    for line in lines:
        if line.rstrip().endswith(" " + symbol):
            return line.split()[0]
    raise RuntimeError(f"missing symbol {symbol}")


def check_request_layout() -> None:
    source = r'''
#include <stddef.h>
#include "Airport/apple80211_ioctl.h"
struct apple80211_awdl_oob_request_native_prefix_candidate {
    uint32_t version;
    uint32_t unk1;
    uint32_t unk2;
    uint32_t unk3;
    uint32_t unk4;
    uint16_t pad1;
    uint32_t unk5;
    uint16_t unk6;
    uint32_t pad2;
    uint32_t unk7;
    uint32_t pad3;
    uint16_t data_len;
    uint32_t pad4;
    uint16_t unk9;
    const uint8_t *data;
} __attribute__((packed));
static_assert(sizeof(apple80211_awdl_sync_frame_template) == 16);
static_assert(offsetof(apple80211_awdl_sync_frame_template, version) == 0);
static_assert(offsetof(apple80211_awdl_sync_frame_template, payload_len) == 4);
static_assert(offsetof(apple80211_awdl_sync_frame_template, payload) == 8);
static_assert(sizeof(apple80211_awdl_oob_request) == 1830);
static_assert(offsetof(apple80211_awdl_oob_request, version) == 0);
static_assert(offsetof(apple80211_awdl_oob_request, unk1) == 4);
static_assert(offsetof(apple80211_awdl_oob_request, unk2) == 8);
static_assert(offsetof(apple80211_awdl_oob_request, unk3) == 12);
static_assert(offsetof(apple80211_awdl_oob_request, unk4) == 16);
static_assert(offsetof(apple80211_awdl_oob_request, pad1) == 20);
static_assert(offsetof(apple80211_awdl_oob_request, unk5) == 22);
static_assert(offsetof(apple80211_awdl_oob_request, unk6) == 26);
static_assert(offsetof(apple80211_awdl_oob_request, pad2) == 28);
static_assert(offsetof(apple80211_awdl_oob_request, unk7) == 32);
static_assert(offsetof(apple80211_awdl_oob_request, pad3) == 36);
static_assert(offsetof(apple80211_awdl_oob_request, data_len) == 40);
static_assert(offsetof(apple80211_awdl_oob_request, pad4) == 42);
static_assert(offsetof(apple80211_awdl_oob_request, unk9) == 46);
static_assert(offsetof(apple80211_awdl_oob_request, data) == 48);
static_assert(sizeof(apple80211_awdl_oob_request_native_prefix_candidate) == 56);
static_assert(offsetof(apple80211_awdl_oob_request_native_prefix_candidate, data) == 48);
'''
    with tempfile.TemporaryDirectory(prefix="test042-awdl-request-layout-") as tmp:
        path = Path(tmp) / "layout.cpp"
        path.write_text(source)
        run(
            "xcrun", "--sdk", "macosx", "clang++", "-std=c++17",
            "-D__IO80211_TARGET=260000", f"-I{REPO / 'include'}", "-fsyntax-only", str(path),
        )


def run_prefix_contract_tests() -> None:
    source = REPO / "native/tests/awdl_request_contract_25G332_test.cpp"
    header = REPO / "native/awdl_request_contract_25G332.hpp"
    header_text = header.read_text()
    if re.search(r"\b(?:malloc|calloc|realloc|memcpy|memmove)\s*\(", header_text):
        raise RuntimeError("request-view header must not allocate or dereference/copy payload data")
    with tempfile.TemporaryDirectory(prefix="test042-awdl-prefix-view-") as tmp:
        binary = Path(tmp) / "awdl-request-view-test"
        run(
            "xcrun", "--sdk", "macosx", "clang++", "-std=c++17",
            "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary),
        )
        subprocess.check_call([str(binary)])


def check_version_ignored(body: str, label: str) -> None:
    # A direct access to request byte zero appears as a bare (%rsi) operand;
    # the field accesses at +4/+8/etc. remain separately validated below.
    # This does not exclude earlier copyin or validation outside the callback.
    if re.search(r"(?<![\w.])\(%rsi\)", body):
        raise RuntimeError(f"{label}: callback now reads the request version at +0")


def main() -> int:
    helpers = load_test041_helpers()
    io_hash = sha256(IO80211_25G332)
    bcm241_hash = sha256(BCM_25G241)
    if io_hash != EXPECTED_IO80211_25G332_SHA256:
        raise RuntimeError(f"25G332 IO80211 image changed: {io_hash}")
    if bcm241_hash != EXPECTED_BCM_25G241_SHA256:
        raise RuntimeError(f"25G241 BCM image changed: {bcm241_hash}")

    check_request_layout()
    run_prefix_contract_tests()
    io149 = helpers.disassembly(IO80211_25G332, IOCTL_149)
    io151 = helpers.disassembly(IO80211_25G332, IOCTL_151)

    with tempfile.TemporaryDirectory(prefix="test042-awdl-request-contract-") as tmp:
        bcm332, bcm332_source = helpers.extract_core_image(Path(tmp))
        if bcm332_source["bootkc_sha256"] != EXPECTED_BOOTKC_SHA256:
            raise RuntimeError("25G332 BootKC hash differs from the pinned Test041 source")
        oob = helpers.disassembly(bcm332, BCM_OOB)
        sync = helpers.disassembly(bcm332, BCM_SYNC_TEMPLATE)
        sync_params = helpers.disassembly(bcm332, BCM_SYNC_PARAMS)
        iovar_helper = helpers.disassembly(bcm332, BCM_IOVAR_HELPER)
        send_virtual = helpers.disassembly(bcm332, COMMANDER_SEND_VIRTUAL)
        issue = helpers.disassembly(bcm332, COMMANDER_ISSUE)
        prepare = helpers.disassembly(bcm332, COMMAND_PREPARE)

        # 25G332 IO80211 forwards the unchanged request pointer to selector 149/151.
        require(io149, ("movl\t$0x95, %esi", "movq\t0x1110(%rax), %rax", "movq\t%rbx, %rsi", "jmpq\t*%rax"), "selector 149 dispatch")
        require(io151, ("movl\t$0x97, %esi", "movq\t0x1118(%rax), %rax", "movq\t%rbx, %rsi", "jmpq\t*%rax"), "selector 151 dispatch")

        # Selector 151: null/zero length/null payload checks, 2-byte LE length,
        # then exact payload bytes. The 0xAAAA marker is beyond iovec[0].len=2.
        check_version_ignored(sync, "selector 151")
        require(sync, (
            "testq\t%rsi, %rsi", "movl\t0x4(%rsi), %eax", "testq\t%rax, %rax",
            "movq\t0x8(%rsi), %rcx", "testq\t%rcx, %rcx",
            "movw\t$0xaaaa, 0x2(%rdx)", "movw\t%ax, (%rdx)",
            "movq\t$0x2, -0x38(%rbp)", "movq\t%rcx, -0x30(%rbp)",
            "movq\t%rax, -0x28(%rbp)", "sendIOVarSetCommandEP5iovecjPKc",
        ), "selector 151 request conversion")

        # Selector 149: prove the input-to-output byte map, the opaque data
        # pointer/length, the 38-byte fixed header, and dynamic command bound.
        check_version_ignored(oob, "selector 149")
        require(oob, (
            "movl\t0x4(%rsi), %eax", "movl\t0x16(%rsi), %eax",
            "movzwl\t0x8(%rsi), %eax", "movzwl\t0x1a(%rsi), %eax",
            "movzwl\t0x14(%rsi), %eax", "movzwl\t0x28(%rsi), %eax",
            "movw\t%ax, -0x6e(%rbp)", "movl\t%eax, -0x72(%rbp)",
            "movl\t%eax, -0x78(%rbp)", "movw\t%ax, -0x74(%rbp)",
            "movw\t%ax, -0x54(%rbp)", "movl\t%eax, -0x64(%rbp)",
            "movq\t0x30(%rbx), %rax", "movq\t$0x26, -0x48(%rbp)",
            "leaq\t0x26(%rbx), %r14", "addq\t$0x31, %rbx",
            "getMaxCmdTxPayloadEv", "cmpq\t%rax, %rbx", "jae\t", "callq\t0xffffff8000101080",
            "handleOobAfIovarAsyncCallBack", "sendVirtualIOVarSet",
        ), "selector 149 request conversion")
        if re.search(r"cmp[a-z]*\s+\$0x6f6", oob):
            raise RuntimeError("selector 149 unexpectedly gained a fixed 1782-byte bound; review report")

        # The helper gathers the iovec bytes into temporary storage, then the
        # command path copies Tx bytes to command-owned storage before enqueue.
        require(iovar_helper, (
            "movq\t0x18(%rsi), %rbx", "addq\t0x8(%rsi), %rbx",
            "getMaxCmdTxPayloadEv", "jae\t", "callq\t0xffffff8000101080",
            "movw\t%bx, 0x8(%rcx)",
            "sendVirtualIOVarSet",
        ), "set-iovar temporary-copy path")
        require(send_virtual, ("issueCommand",), "virtual-iovar command dispatch")
        require(issue, ("AppleBCMWLANCommand7prepare", "enqueueCommand"), "prepared command ownership")
        require(prepare, (
            "movzwl\t0x8(%r13), %edx", "movq\t(%r13), %rsi",
            "callq\t0xffffff8000101080",
        ), "command Tx payload copy")

        # setSyncParams is a separate native path: fixed 36-byte blob assembled
        # from interface IVars; it is not a timestamp member of selector 151.
        require(sync_params, (
            "movw\t$0x24, %r13w", "movw\t%r13w, 0x1(%r12)",
            "movzwl\t0x2d8(%rax), %ecx", "movzwl\t0x2e4(%rax), %ecx",
            "movzwl\t0x2dc(%rax), %ecx", "movzwl\t0x2d4(%rax), %ecx",
            "movb\t0x2b0(%rax), %cl", "sendVirtualIOVarSet",
        ), "separate native sync-parameter path")

        # The 25G241 preserved concrete callback and the local Tahoe ABI
        # witness corroborate signatures/field dataflow, but the 25G332 BootKC
        # body above remains the primary contract source.
        oob241 = helpers.disassembly(BCM_25G241, BCM_OOB)
        sync241 = helpers.disassembly(BCM_25G241, BCM_SYNC_TEMPLATE)
        require(oob241, ("movl\t0x4(%rsi), %eax", "movl\t0x16(%rsi), %eax", "movzwl\t0x28(%rsi), %eax", "movq\t0x30(%rbx), %rax", "sendVirtualIOVarSet"), "25G241 selector 149 comparison")
        require(sync241, ("movl\t0x4(%rsi), %eax", "movq\t0x8(%rsi), %rcx", "movq\t$0x2, -0x38(%rbp)", "sendIOVarSetCommand"), "25G241 selector 151 comparison")

        strings = run("/usr/bin/strings", "-a", str(bcm332)).splitlines()
        expected_iovars = {"awdl_payload", "awdl_oob_af", "awdl_sync_params"}
        if not expected_iovars.issubset(set(strings)):
            raise RuntimeError("25G332 BCM image is missing one or more AWDL iovar names")

        source_code = run("/usr/bin/sw_vers", "-buildVersion").strip()
        if source_code != "25G332":
            raise RuntimeError(f"expected running 25G332 source, got {source_code}")

        report = {
            "schema": "test042-native-awdl-request-contract/v1",
            "result": "PASS_OFFLINE_25G332_REQUEST_LAYOUT_AND_COPY_BOUNDARIES",
            "scope": "Read-only static analysis and compile-time layout checks. No kext load, interface creation, EFI write, firmware operation, or RF test.",
            "source": {
                "running_build": source_code,
                "bootkc_path": bcm332_source["bootkc_path"],
                "bootkc_sha256": bcm332_source["bootkc_sha256"],
                "fileset_child_bundle": bcm332_source["bundle_identifier"],
                "fileset_child_offset": bcm332_source["child_file_offset"],
                "fileset_child_uuid": bcm332_source["child_uuid"],
                "analysis_child_sha256": bcm332_source["analysis_image_sha256"],
                "analysis_child_loadable": False,
                "io80211_image": str(IO80211_25G332),
                "io80211_image_sha256": io_hash,
                "bcm_25g241_image": str(BCM_25G241),
                "bcm_25g241_image_sha256": bcm241_hash,
            },
            "layout": {
                "sync_frame_template": {
                    "size": 16,
                    "fields": {"version": {"offset": 0, "size": 4}, "payload_len": {"offset": 4, "size": 4}, "payload": {"offset": 8, "size": 8}},
                    "source": "include/Airport/apple80211_ioctl.h, compile-time static_asserts, and 25G332 callback loads.",
                },
                "oob_request": {
                    "current_header_declaration": {
                    "declared_size": 1830,
                    "data_declaration": {"offset": 48, "kind": "inline array", "length": 1782},
                    "fields": {
                        "version": {"offset": 0, "size": 4},
                        "unk1": {"offset": 4, "size": 4},
                        "unk2": {"offset": 8, "size": 4},
                        "unk3": {"offset": 12, "size": 4},
                        "unk4": {"offset": 16, "size": 4},
                        "pad1": {"offset": 20, "size": 2},
                        "unk5": {"offset": 22, "size": 4},
                        "unk6": {"offset": 26, "size": 2},
                        "pad2": {"offset": 28, "size": 4},
                        "unk7": {"offset": 32, "size": 4},
                        "pad3": {"offset": 36, "size": 4},
                        "data_len": {"offset": 40, "size": 2},
                        "pad4": {"offset": 42, "size": 4},
                        "unk9": {"offset": 46, "size": 2},
                        "data": {"offset": 48, "size": 1782},
                    },
                    "header_comment_correction": "The existing header comment says unk9 is at +44; packed layout and compile assert place it at +46.",
                    },
                    "native_read_contract": {
                        "minimum_request_prefix_bytes_observed": 56,
                        "offset_48_use": "The callback loads an 8-byte value from request +48 and uses it as the external data buffer base; it does not take the address of inline bytes at +48.",
                        "payload_extent": "data_len bytes are read from the external buffer addressed by the pointer value at +48.",
                        "candidate_prefix_overlay_size": 56,
                        "candidate_pointer_offset": 48,
                        "declaration_conflict": "The local header's inline-array declaration at +48 conflicts with the native pointer load. Treat 1830 as the local declaration size, not as a verified 25G332 callback input size. Total caller allocation/copyin size remains unknown.",
                    },
                },
            },
            "dispatch": [
                {
                    "selector": 149,
                    "io80211_symbol": IOCTL_149,
                    "io80211_address": address_for(IO80211_25G332, IOCTL_149),
                    "protocol_vtable_byte_offset": "0x1110",
                    "native_symbol": BCM_OOB,
                    "native_address": address_for(bcm332, BCM_OOB),
                    "request_pointer": "RSI is saved and passed unchanged to the virtual method; wrapper does not marshal request fields.",
                },
                {
                    "selector": 151,
                    "io80211_symbol": IOCTL_151,
                    "io80211_address": address_for(IO80211_25G332, IOCTL_151),
                    "protocol_vtable_byte_offset": "0x1118",
                    "native_symbol": BCM_SYNC_TEMPLATE,
                    "native_address": address_for(bcm332, BCM_SYNC_TEMPLATE),
                    "request_pointer": "RSI is saved and passed unchanged to the virtual method; wrapper does not marshal request fields.",
                },
            ],
            "selector_151_sync_template": {
                "minimum_request_extent": 16,
                "read_fields": ["payload_len at +4, uint32", "payload pointer at +8, pointer-sized"],
                "not_read_by_callback": ["version at +0"],
                "guards": ["request pointer non-null", "payload_len nonzero", "payload pointer non-null"],
                "iovar": "awdl_payload",
                "wire_iovec": [
                    {"index": 0, "length": 2, "bytes": "little-endian low 16 bits of payload_len"},
                    {"index": 1, "length": "full uint32 payload_len", "bytes": "payload pointer contents"},
                ],
                "control_bytes": "The callback writes 0xAAAA at stack bytes +2..+3 after the 2-byte length, but iovec[0] length is exactly 2; those bytes are not serialized by this path.",
                "length_bound": "payload_len is loaded as unsigned uint32 and zero-extended into the data iovec length. The separate 2-byte length prefix truncates it to the low 16 bits. sendIOVarSetCommand checks the full-width total against dynamic getMaxCmdTxPayload(), then stores the CommandTxPayload length as uint16; the runtime maximum was not resolved. Any itlwm MCLBYTES bound must be checked independently before copying.",
                "timestamp_or_schedule": "No timestamp, AWDL availability window, or schedule field is parsed/added by selector 151. Separate setSyncParams sends a 36-byte awdl_sync_params blob assembled from interface IVars; field semantics are not established here.",
                "ownership": "The IO80211 wrapper borrows and forwards the request pointer unchanged. The BCM callback borrows payload pointer +8 only during the call. sendIOVarSetCommand copies iovec bytes to a temporary buffer; issueCommand calls AppleBCMWLANCommand::prepare, which copies Tx bytes into command-owned storage before enqueue. No caller request/payload pointer is retained after the copy/submission path.",
            },
            "selector_149_oob_request": {
                "read_fields": [
                    {"input": "+4 unk1 uint32", "used": "header +6..+9", "instructions": ["0xffffff800172a4fd: movl 0x4(%rsi), %eax", "0xffffff800172a500: movl %eax, -0x72(%rbp)"]},
                    {"input": "+8 unk2 uint32", "used": "low 16 bits at header +10..+11", "instructions": ["0xffffff800172a4f5: movzwl 0x8(%rsi), %eax", "0xffffff800172a4f9: movw %ax, -0x6e(%rbp)"]},
                    {"input": "+20 pad1 uint16", "used": "zero-extended to uint32 at header +20..+23", "instructions": ["0xffffff800172a519: movzwl 0x14(%rsi), %eax", "0xffffff800172a51d: movl %eax, -0x64(%rbp)"]},
                    {"input": "+22 unk5 uint32", "used": "header +0..+3", "instructions": ["0xffffff800172a503: movl 0x16(%rsi), %eax", "0xffffff800172a506: movl %eax, -0x78(%rbp)"]},
                    {"input": "+26 unk6 uint16", "used": "header +4..+5", "instructions": ["0xffffff800172a509: movzwl 0x1a(%rsi), %eax", "0xffffff800172a50d: movw %ax, -0x74(%rbp)"]},
                    {"input": "+40 data_len uint16", "used": "header +36..+37 and zero-extended data iovec length", "instructions": ["0xffffff800172a511: movzwl 0x28(%rsi), %eax", "0xffffff800172a515: movw %ax, -0x54(%rbp)", "0xffffff800172a56d: movzwl 0x28(%rbx), %ebx"]},
                    {"input": "+48 pointer-sized field", "used": "loaded as the external data iovec base; not treated as an inline-array address", "instructions": ["0xffffff800172a565: movq 0x30(%rbx), %rax"]},
                ],
                "not_read_by_callback": ["version at +0", "unk3 +12", "unk4 +16", "pad2 +28", "unk7 +32", "pad3 +36", "pad4 +42", "unk9 +46"],
                "output_iovar": "awdl_oob_af",
                "output_iovecs": [
                    {"index": 0, "length": 38, "meaning": "constructed header; bytes +12..+19 and +24..+35 are zeroed"},
                    {"index": 1, "length": "data_len uint16, zero-extended", "meaning": "opaque bytes from the external buffer addressed by request field +48"},
                ],
                "minimum_request_extent": "56 bytes are required for the highest native field read (8-byte value at +48); the outer request allocation/copyin length is not proven here. The pointed-to payload range must separately contain data_len bytes.",
                "length_bound": "data_len is uint16 and zero-extended. The callback allocates 38 + data_len bytes and checks 49 + data_len < getMaxCmdTxPayload() (38-byte header plus 11-byte iovar name). It has no explicit <=1782 check. The dynamic firmware/transport limit does not prove the caller buffer extent or an independent driver MCLBYTES bound.",
                "control_or_timestamp_fields": "The binary establishes byte offsets and forwarding only. The unk fields' meanings, timestamp encoding, control bits, and expected payload grammar remain unknown; no semantic labels are inferred.",
                "null_validation": "Unlike selector 151, this callback body has no visible request-pointer null check before field loads, and no explicit nested data pointer check before a nonzero copy. Any earlier validation/copyin guarantee is outside the evidence captured here.",
                "ownership": "The IO80211 wrapper borrows and forwards the request pointer unchanged. The BCM callback reads the pointer at +48 and borrows the external payload only while copying it into a temporary combined buffer. Command::prepare then copies that buffer into command-owned storage before enqueue; the completion context retains the native interface object, not either caller pointer. The temporary buffer is freed after sendVirtualIOVarSet returns.",
            },
            "disassembly_evidence": [
                {
                    "build": "25G332 IO80211Family",
                    "function": IOCTL_149,
                    "function_address": address_for(IO80211_25G332, IOCTL_149),
                    "instructions": [
                        {"address": "0xffffff800226de66", "instruction": "movl $0x95, %esi", "proves": "selector 149"},
                        {"address": "0xffffff800226de91", "instruction": "movq 0x1110(%rax), %rax", "proves": "native protocol slot byte offset 0x1110"},
                        {"address": "0xffffff800226de9b", "instruction": "movq %rbx, %rsi", "proves": "unchanged request pointer is forwarded"},
                        {"address": "0xffffff800226dea2", "instruction": "jmpq *%rax", "proves": "tail dispatch to callback"},
                    ],
                },
                {
                    "build": "25G332 IO80211Family",
                    "function": IOCTL_151,
                    "function_address": address_for(IO80211_25G332, IOCTL_151),
                    "instructions": [
                        {"address": "0xffffff800226dec6", "instruction": "movl $0x97, %esi", "proves": "selector 151"},
                        {"address": "0xffffff800226def1", "instruction": "movq 0x1118(%rax), %rax", "proves": "native protocol slot byte offset 0x1118"},
                        {"address": "0xffffff800226defb", "instruction": "movq %rbx, %rsi", "proves": "unchanged request pointer is forwarded"},
                        {"address": "0xffffff800226df02", "instruction": "jmpq *%rax", "proves": "tail dispatch to callback"},
                    ],
                },
                {
                    "build": "25G332 AppleBCMWLANCoreMac",
                    "function": BCM_SYNC_TEMPLATE,
                    "function_address": address_for(bcm332, BCM_SYNC_TEMPLATE),
                    "instructions": [
                        {"address": "0xffffff8001721ad8", "instruction": "movl 0x4(%rsi), %eax", "proves": "uint32 payload_len at +4"},
                        {"address": "0xffffff8001721ae4", "instruction": "movq 0x8(%rsi), %rcx", "proves": "payload pointer at +8"},
                        {"address": "0xffffff8001721af8", "instruction": "movw $0xaaaa, 0x2(%rdx)", "proves": "canary bytes written after prefix"},
                        {"address": "0xffffff8001721afe", "instruction": "movw %ax, (%rdx)", "proves": "only low 16 bits form prefix"},
                        {"address": "0xffffff8001721b05", "instruction": "movq $0x2, -0x38(%rbp)", "proves": "prefix iovec length is exactly 2"},
                        {"address": "0xffffff8001721b11", "instruction": "movq %rax, -0x28(%rbp)", "proves": "full zero-extended uint32 payload_len is data iovec length"},
                        {"address": "0xffffff8001721bb9", "instruction": "call sendIOVarSetCommand", "proves": "template is sent as awdl_payload iovar"},
                    ],
                },
                {
                    "build": "25G332 AppleBCMWLANCoreMac",
                    "function": BCM_OOB,
                    "function_address": address_for(bcm332, BCM_OOB),
                    "instructions": [
                        {"address": "0xffffff800172a4f5", "instruction": "movzwl 0x8(%rsi), %eax", "proves": "request +8 low 16 bits"},
                        {"address": "0xffffff800172a4fd", "instruction": "movl 0x4(%rsi), %eax", "proves": "request +4"},
                        {"address": "0xffffff800172a503", "instruction": "movl 0x16(%rsi), %eax", "proves": "request +22"},
                        {"address": "0xffffff800172a509", "instruction": "movzwl 0x1a(%rsi), %eax", "proves": "request +26"},
                        {"address": "0xffffff800172a511", "instruction": "movzwl 0x28(%rsi), %eax", "proves": "unsigned data_len at +40"},
                        {"address": "0xffffff800172a519", "instruction": "movzwl 0x14(%rsi), %eax", "proves": "request +20 low 16 bits"},
                        {"address": "0xffffff800172a4e2", "instruction": "movq %rax, -0x6c(%rbp)", "proves": "zero-initializes OOB header bytes +12..+19"},
                        {"address": "0xffffff800172a4e6", "instruction": "movq %rax, -0x64(%rbp)", "proves": "zero-initializes header bytes +20..+27 before pad1 overwrite"},
                        {"address": "0xffffff800172a4ea", "instruction": "movq %rax, -0x5c(%rbp)", "proves": "zero-initializes header bytes +28..+35"},
                        {"address": "0xffffff800172a4ee", "instruction": "movl $0, -0x55(%rbp)", "proves": "zero-initializes through header end"},
                        {"address": "0xffffff800172a565", "instruction": "movq 0x30(%rbx), %rax", "proves": "loads an 8-byte external payload pointer from request +48"},
                        {"address": "0xffffff800172a55d", "instruction": "movq $0x26, -0x48(%rbp)", "proves": "fixed output header length 38"},
                        {"address": "0xffffff800172a61d", "instruction": "call memcpy", "proves": "copies the pointed-to data bytes into scratch storage"},
                        {"address": "0xffffff800172a58d", "instruction": "addq $0x31, %rbx", "proves": "dynamic-limit candidate length 49 + data_len"},
                        {"address": "0xffffff800172a59f", "instruction": "call getMaxCmdTxPayload", "proves": "dynamic native command payload limit"},
                        {"address": "0xffffff800172a5a4", "instruction": "cmpq %rax, %rbx", "proves": "full-width bound check before copy/submit"},
                        {"address": "0xffffff800172a832", "instruction": "call sendVirtualIOVarSet", "proves": "asynchronous command submission after scratch copy"},
                        {"address": "0xffffff800172a887", "instruction": "call free", "proves": "frees OOB scratch after sendVirtualIOVarSet returns"},
                    ],
                },
                {
                    "build": "25G332 AppleBCMWLANCoreMac",
                    "function": BCM_IOVAR_HELPER,
                    "function_address": address_for(bcm332, BCM_IOVAR_HELPER),
                    "instructions": [
                        {"address": "0xffffff800172168b", "instruction": "movq 0x18(%rsi), %rbx", "proves": "reads second iovec length"},
                        {"address": "0xffffff800172168f", "instruction": "addq 0x8(%rsi), %rbx", "proves": "adds first iovec length"},
                        {"address": "0xffffff8001721716", "instruction": "call memcpy", "proves": "copies iovec bytes to a temporary combined buffer"},
                        {"address": "0xffffff80017218f3", "instruction": "movw %bx, 0x8(%rcx)", "proves": "narrows total CommandTxPayload length to uint16"},
                        {"address": "0xffffff8001721916", "instruction": "call sendVirtualIOVarSet", "proves": "submits copied command payload"},
                        {"address": "0xffffff800172195f", "instruction": "call free", "proves": "frees temporary payload after submission returns"},
                    ],
                },
                {
                    "build": "25G332 AppleBCMWLANCoreMac",
                    "function": COMMAND_PREPARE,
                    "function_address": address_for(bcm332, COMMAND_PREPARE),
                    "instructions": [
                        {"address": "0xffffff80016c0664", "instruction": "movzwl 0x8(%r13), %edx", "proves": "reads uint16 command payload size"},
                        {"address": "0xffffff80016c066f", "instruction": "movq (%r13), %rsi", "proves": "reads payload source pointer"},
                        {"address": "0xffffff80016c0693", "instruction": "call memcpy", "proves": "copies into command-owned payload before issueCommand enqueues it"},
                        {"address": "0xffffff8001763d96", "instruction": "call enqueueCommand", "proves": "the prepared copied command is queued"},
                    ],
                },
            ],
            "cross_version": {
                "25g241_concrete_callbacks": "Selector 149/151 field reads, pointer-valued request +48, 38-byte OOB header, 2-byte sync length prefix, IOVAR names, dynamic bound, and temporary-copy shape match the preserved 25G241 BCM disassembly.",
                "legacy_brcm_pointer_corroboration": "The preserved 25G241 AirPort_BrcmNIC::setAWDL_OOB_AUTO_REQUEST disassembly loads request +0x30 as a source pointer, checks data_len < 0x6f6 (1782), and memmoves that external buffer. This corroborates pointer semantics for that older auto-request path; it does not add a 1782-byte check to the 25G332 native selector 149 path.",
                "tahoe_abi_header": "The 25G241 Tahoe witness declares each method as a pointer argument and the callback slot offsets; it does not define these request payload field semantics.",
            },
            "tests": {
                "test042_awdl_request_contract.py": "PASS: compile-time 16-byte sync / local 1830-byte legacy OOB declaration / 56-byte native OOB pointer-prefix assertions; 25G332 selector dispatch and callback field/copy/bound checks; 25G241 comparison; separate sync-parameter route; command-owned payload copy check.",
                "awdl_request_contract_25G332_test.cpp": "PASS: pure view-only parser boundary tests for short prefixes, exact native max boundary, independent cap, zero and null addresses, uint32-to-uint16 sync-prefix truncation, arithmetic overflow, and ignored version. Test uses fake pointer values and never dereferences payload pointers.",
                "new_contract_active_project_integration": False,
                "kext_built_or_loaded": False,
                "efi_written": False,
                "rf_or_firmware_operation": False,
            },
            "unknowns": [
                "No earlier Apple80211 user-client copyin or nested-pointer validation was established; the native IO80211 wrapper forwards the pointer unchanged.",
                "Neither callback reads version in its body; an earlier request validation layer could still inspect it.",
                "The current local OOB struct declares an inline 1782-byte array, but the native callbacks dereference a pointer-sized value at +48. The earlier user-client copyin/structure shape that makes this pointer valid is not established.",
                "The dynamic OOB MaxCmdTxPayload limit was not resolved to a runtime value. It does not prove the pointed-to allocation extent or a future itlwm MCLBYTES bound; those must be checked independently before copying.",
                "OOB unk/pad field semantics and data grammar are unknown; no byte values should be synthesized from these names.",
                "The 36-byte awdl_sync_params blob is separate from selector 151; its private field semantics and timestamp units are not established.",
                "The complete request copyin size and the lifetime guarantee for the external OOB payload pointer before the callback copies it are unknown.",
            ],
        }

    REPORT.write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: saved {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
