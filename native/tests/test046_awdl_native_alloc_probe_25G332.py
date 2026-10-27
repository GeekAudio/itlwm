#!/usr/bin/env python3
"""Offline compile and relocatable-link gate for the 25G332 alloc candidate.

This gate does not load the object or execute MetaClass::alloc/release. It
checks the candidate's numeric-only interface and forbidden-call boundary,
then emits the exact unresolved imports left for the native kernel image.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ART = ROOT.parent / "IntelWirelessNative/research"
IMAGE = ART / "test037-upgrade-private/IO80211Family-25G332.linked-analysis.macho"
CONCRETE_CPP = ROOT / "native/awdl_native_concrete_25G332.cpp"
CONCRETE_HEADER = ROOT / "native/awdl_native_concrete_25G332.hpp"
PROBE_CPP = ROOT / "native/awdl_native_alloc_probe_25G332.cpp"
PROBE_HEADER = ROOT / "native/awdl_native_alloc_probe_25G332.hpp"
PROJECT = ROOT / "itlwm.xcodeproj/project.pbxproj"
REPORT = ART / "test046-native-alloc-probe-private.json"
VARIANT = "ITL_AWDL_ALLOCATOR_VARIANT_25G332"
IMAGE_SHA256 = "8732ea8838331d115e16697acefa22ca5b3d0c516c48293de2e2ebbaf891d047"
PROHIBITED = re.compile(
    r"\b(?:init|attach|start|open|registerService|setAWDLInterface)\s*\("
)
EXPECTED_NATIVE_IMPORTS = {
    "__ZN19IO80211AWDLProtocol10gMetaClassE",
    "__ZN19IO80211AWDLProtocolC2EPK11OSMetaClass",
    "__ZN19IO80211AWDLProtocolD2Ev",
}


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def undefined_symbols(path: Path) -> list[str]:
    lines = run("xcrun", "nm", "-u", str(path)).splitlines()
    return sorted({line.split()[-1] for line in lines if line.split()})


def function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise RuntimeError(f"missing candidate function: {signature}")
    opening = source.find("{", start)
    if opening < 0:
        raise RuntimeError("candidate function has no body")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise RuntimeError("candidate function body is not balanced")


def main() -> int:
    if sha256(IMAGE) != IMAGE_SHA256:
        raise RuntimeError("preserved IO80211Family image is not exact 25G332")
    if VARIANT in PROJECT.read_text():
        raise RuntimeError("allocator variant define leaked into the active Xcode project")

    candidate = PROBE_CPP.read_text()
    public_header = PROBE_HEADER.read_text()
    concrete_header = CONCRETE_HEADER.read_text()
    body = function_body(candidate, "ItlAwdlNativeAllocReleaseProbe25G332(void)")
    if PROHIBITED.search(body):
        raise RuntimeError("candidate crossed the alloc-only lifecycle boundary")
    if "object->release();" not in body:
        raise RuntimeError("candidate does not release its private allocation")
    if body.find("object->release();") < max(
        body.find("object->getMetaClass()"), body.find("object->getRetainCount()")
    ):
        raise RuntimeError("candidate releases before both pre-release metadata checks")
    if "return object" in body or "static OSObject" in candidate:
        raise RuntimeError("candidate publishes or stores the native object pointer")
    if "uint32_t ItlAwdlNativeAllocReleaseProbe25G332(void)" not in public_header:
        raise RuntimeError("public probe result is not a plain numeric C ABI")
    if f"#if defined({VARIANT})" not in CONCRETE_CPP.read_text():
        raise RuntimeError("concrete allocator remains unavailable as an explicit variant")
    if f"#if defined({VARIANT})" not in concrete_header:
        raise RuntimeError("concrete header does not guard the allocator variant")
    if "ITL_AWDL_ALLOCATOR_VARIANT_25G332" in PROJECT.read_text():
        raise RuntimeError("candidate is active in Xcode project settings")

    sdk = Path(run("xcrun", "--sdk", "macosx", "--show-sdk-path").strip())
    kernel_headers = sdk / "System/Library/Frameworks/Kernel.framework/Versions/A/Headers"
    common = [
        "xcrun", "--sdk", "macosx", "clang++",
        "-target", "x86_64-apple-macosx26.0", "-std=c++17", "-fapple-kext",
        "-fno-rtti", "-fno-exceptions", "-D__IO80211_TARGET=260000",
        f"-I{ROOT / 'include'}", f"-I{kernel_headers}",
        f"-D{VARIANT}=1",
    ]

    with tempfile.TemporaryDirectory(prefix="test046-awdl-alloc-probe-") as temp_name:
        temp = Path(temp_name)
        concrete_obj = temp / "concrete.o"
        probe_obj = temp / "alloc-probe.o"
        linked_obj = temp / "alloc-probe-linked.o"
        run(*common, "-c", str(CONCRETE_CPP), "-o", str(concrete_obj))
        run(*common, "-c", str(PROBE_CPP), "-o", str(probe_obj))
        run("xcrun", "ld", "-r", "-arch", "x86_64", "-o", str(linked_obj),
            str(concrete_obj), str(probe_obj))
        imports = undefined_symbols(linked_obj)

    missing_native = sorted(EXPECTED_NATIVE_IMPORTS - set(imports))
    if missing_native:
        raise RuntimeError(f"expected native AWDL imports missing: {missing_native}")

    result = {
        "schema": "test046-awdl-native-alloc-probe/v1",
        "result": "PASS_OFFLINE_COMPILE_AND_RELOCATABLE_LINK",
        "candidate_only": True,
        "runtime_execution_performed": False,
        "active_xcode_target_changed": False,
        "kext_or_efi_built_or_loaded": False,
        "radio_touched": False,
        "witness": {
            "os_build": "25G332",
            "io80211_analysis_image_sha256": IMAGE_SHA256,
        },
        "probe_contract": {
            "numeric_return": "uint32_t C ABI bitmask",
            "allocation": "ItlAwdlNativeConcreteGate25G332::metaClass->alloc()",
            "pre_release_checks": [
                "child MetaClass parent == native IO80211AWDLProtocol MetaClass",
                "MetaClass class size == sizeof(child) == 0x130",
                "instance getMetaClass() equals child MetaClass",
                "getRetainCount() == 1",
            ],
            "release": "exactly one release() call after all instance checks; no object access afterward",
            "prohibited_lifecycle_calls": [
                "init", "attach", "start", "open", "registerService", "setAWDLInterface",
            ],
            "pointer_publication": False,
        },
        "unresolved_native_imports": imports,
        "runtime_gate": {
            "status": "BLOCKED_PENDING_FRESH_ALLOC_FREE_PROOF",
            "reason": (
                "Exact 25G332 OSObject::C2 writes only the vptr and retain count at +0x8; the concrete "
                "operator new calls kalloc_ext with flags 0x41004, but the evidence does not establish "
                "that all 0x130 bytes are zeroed. IO80211VirtualInterface::free reads the child-private "
                "pointer at this+0x128; IO80211SkywalkInterface::free dereferences this+0x120+0xb8 "
                "before checking whether this+0x120 is null. The constructors do not initialize these "
                "slots. Bare alloc->release can therefore enter a free chain that dereferences unknown "
                "memory and must remain offline."
            ),
            "exact_25G332_binary_evidence": {
                "OSObject::operator new": "BootKernelExtensions kernel symbol 0xffffff8000936620 calls _kalloc_ext with size and flags 0x41004; no full-object clearing is shown in this body.",
                "OSObject::C2(OSMetaClass const*)": "kernel symbol 0xffffff80009367c0 writes the base vptr at +0x0 and retain count 1 at +0x8 only.",
                "IO80211AWDLProtocol::C2": "IO80211Family symbol 0xffffff800219ddf8 calls its parent C2 then writes its vptr at +0x0.",
                "IO80211SkywalkInterface::C2": "IO80211Family symbol 0xffffff80022f9f7c calls its parent constructor then writes its vptr at +0x0; it does not write the private slot at +0x120.",
                "IO80211VirtualInterface::C2": "IO80211Family symbol 0xffffff800233549e calls its parent constructor then writes its vptr at +0x0; it does not write the private slot at +0x128.",
                "IO80211VirtualInterface::free": "0xffffff8002335fec loads this+0x128 and branches around child cleanup only when that pointer is null; otherwise it dereferences child fields at +0xe0, +0x200, and +0x208.",
                "IO80211SkywalkInterface::free": "0xffffff80022fafe4 loads this+0x120, immediately dereferences [that pointer+0xb8], and only later tests this+0x120 at 0xffffff80022fb026; the later null branch does not protect the initial dereference."
            },
        },
        "scope": "temporary Mach-O relocatable objects only",
        "candidate_sources": {
            str(PROBE_CPP.relative_to(ROOT)): sha256(PROBE_CPP),
            str(PROBE_HEADER.relative_to(ROOT)): sha256(PROBE_HEADER),
        },
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "result": result["result"],
        "candidate_only": result["candidate_only"],
        "runtime_gate": result["runtime_gate"]["status"],
        "unresolved_native_import_count": len(imports),
        "unresolved_native_imports_report": str(REPORT),
        "required_native_awdl_imports": sorted(EXPECTED_NATIVE_IMPORTS),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
