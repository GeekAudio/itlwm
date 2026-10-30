#!/usr/bin/env python3
"""Execute captured and patched ELF function bodies in isolated Unicorn ARM64.

This is a userspace instruction/ABI-shape simulation only. ELF relocation
instructions are resolved in the emulator to synthetic module/data addresses;
no kernel, router, RF path, or installed module is used.
"""
from __future__ import annotations

import hashlib
import argparse
import json
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from build_offline_candidates import ELF64, sha
PACKAGE = HERE.parent

try:
    from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL, UC_HOOK_CODE
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X20, UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X30,
        UC_ARM64_REG_SP, UC_ARM64_REG_PC,
    )
except Exception as exc:
    raise SystemExit("Unicorn is required; install a pinned wheel in an isolated target and set IWN_UNICORN_PATH") from exc

CORE_BASE = 0x01000000
CONNAC_BASE = 0x02000000
DATA_BASE = 0x03000000
PHY_BASE = 0x04000000
VIF_BASE = 0x05000000
CTX_BASE = 0x06000000
PHY_CHAN_BASE = 0x07000000
CTX_CHAN_BASE = 0x07100000
STACK_BASE = 0x08000000
STOP_ADDR = 0x09000000
PAGE = 0x1000

INPUT_HASHES = json.loads((PACKAGE / "PATCH-MANIFEST.json").read_text())["exact_elf_inputs_for_instruction_candidate"]


def align_page(n: int) -> int:
    return (n + PAGE - 1) & ~(PAGE - 1)


def put32(uc: Uc, addr: int, value: int) -> None:
    uc.mem_write(addr, struct.pack("<I", value & 0xffffffff))


def put64(uc: Uc, addr: int, value: int) -> None:
    uc.mem_write(addr, struct.pack("<Q", value & 0xffffffffffffffff))


def encode_adrp(rd: int, pc: int, target: int) -> int:
    delta = (target >> 12) - (pc >> 12)
    if not -(1 << 20) <= delta < (1 << 20):
        raise ValueError("emulator ADRP target out of range")
    imm = delta & 0x1fffff
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5) | rd


def encode_add_lo12(rd: int, rn: int, target: int) -> int:
    imm = target & 0xfff
    return 0x91000000 | (imm << 10) | (rn << 5) | rd


def encode_bl(pc: int, target: int) -> int:
    delta = target - pc
    if delta & 3 or not -(1 << 27) <= delta < (1 << 27):
        raise ValueError("emulator BL target out of range/alignment")
    return 0x94000000 | ((delta >> 2) & 0x03ffffff)


def load_image(path: Path, expected_hash: str):
    raw = path.read_bytes()
    if sha(raw) != expected_hash:
        raise ValueError(f"image hash mismatch: {path.name}")
    elf = ELF64(raw)
    text = raw[elf.text.offset:elf.text.offset + elf.text.size]
    return raw, elf, text


def make_machine(core_text: bytes, core_base: int, data: bytes,
                 connac_text: bytes | None = None):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    map_info = []

    def map_code(base: int, contents: bytes):
        size = align_page(len(contents))
        uc.mem_map(base, size, UC_PROT_ALL)
        uc.mem_write(base, contents)
        return size

    map_info.append({"region": "core_text", "size": map_code(CORE_BASE, core_text)})
    if connac_text is not None:
        map_info.append({"region": "connac_text", "size": map_code(CONNAC_BASE, connac_text)})
        # Resolve the saved R_AARCH64_CALL26 to the matching core helper in emulator memory.
        bl = encode_bl(CONNAC_BASE + 0x54dc, CORE_BASE + 0x32c4)
        put32(uc, CONNAC_BASE + 0x54dc, bl)
    uc.mem_map(DATA_BASE, align_page(max(len(data), 1)), UC_PROT_ALL)
    uc.mem_write(DATA_BASE, data)
    # Resolve the unchanged ADRP/ADD relocation pair for mt76_rates only in emulated memory.
    put32(uc, CORE_BASE + 0x32cc, encode_adrp(3, CORE_BASE + 0x32cc, DATA_BASE))
    put32(uc, CORE_BASE + 0x32d0, encode_add_lo12(3, 3, DATA_BASE))

    for base, length, label in [
        (PHY_BASE, PAGE, "phy"), (VIF_BASE, PAGE, "vif"),
        (CTX_BASE, PAGE, "ctx"), (PHY_CHAN_BASE, PAGE, "phy_chan"),
        (CTX_CHAN_BASE, PAGE, "ctx_chan"), (STACK_BASE, 0x10000, "stack"),
        (STOP_ADDR, PAGE, "stop"),
    ]:
        uc.mem_map(base, length, UC_PROT_ALL)
        map_info.append({"region": label, "size": length})
    put32(uc, STOP_ADDR, 0xd65f03c0)  # ret; normally emulation stops before this sentinel.
    return uc, map_info


def init_radio_memory(uc: Uc, phy_band: int, vif_present: bool,
                      ctx_band: int | None) -> None:
    put64(uc, PHY_BASE + 0x70, PHY_CHAN_BASE)
    put32(uc, PHY_CHAN_BASE, phy_band)
    put64(uc, VIF_BASE + 0x430, CTX_BASE if ctx_band is not None else 0)
    if ctx_band is not None:
        put64(uc, CTX_BASE, CTX_CHAN_BASE)
        put32(uc, CTX_CHAN_BASE, ctx_band)


def run_core(core_text: bytes, data: bytes, *, vif_present: bool,
             phy_band: int, ctx_band: int | None, rateidx: int):
    uc, maps = make_machine(core_text, CORE_BASE, data)
    init_radio_memory(uc, phy_band, vif_present, ctx_band)
    uc.reg_write(UC_ARM64_REG_X0, PHY_BASE)
    uc.reg_write(UC_ARM64_REG_X1, VIF_BASE if vif_present else 0)
    uc.reg_write(UC_ARM64_REG_X2, rateidx & 0xffffffff)
    uc.reg_write(UC_ARM64_REG_SP, STACK_BASE + 0x8000)
    uc.reg_write(UC_ARM64_REG_X30, STOP_ADDR)
    fault = None
    try:
        uc.emu_start(CORE_BASE + 0x32c4, STOP_ADDR, count=256)
    except UcError as exc:
        fault = {"type": type(exc).__name__, "message": str(exc),
                 "pc": hex(uc.reg_read(UC_ARM64_REG_PC))}
    pc = uc.reg_read(UC_ARM64_REG_PC)
    return {"ok": fault is None and pc == STOP_ADDR,
            "value": uc.reg_read(UC_ARM64_REG_X0) & 0xffff,
            "x2": hex(uc.reg_read(UC_ARM64_REG_X2)),
            "x3": hex(uc.reg_read(UC_ARM64_REG_X3)),
            "pc": hex(pc), "fault": fault, "maps": maps}


def run_connac(connac_text: bytes, core_text: bytes, data: bytes, *, phy_band: int,
               beacon: int, mcast: int):
    uc, maps = make_machine(core_text, CORE_BASE, data, connac_text)
    init_radio_memory(uc, phy_band, False, None)
    uc.reg_write(UC_ARM64_REG_X0, PHY_BASE)
    uc.reg_write(UC_ARM64_REG_X1, 0)
    uc.reg_write(UC_ARM64_REG_X2, beacon)
    uc.reg_write(UC_ARM64_REG_X3, mcast)
    uc.reg_write(UC_ARM64_REG_SP, STACK_BASE + 0x8000)
    uc.reg_write(UC_ARM64_REG_X30, STOP_ADDR)
    fault = None
    try:
        uc.emu_start(CONNAC_BASE + 0x5450, STOP_ADDR, count=1024)
    except UcError as exc:
        fault = {"type": type(exc).__name__, "message": str(exc),
                 "pc": hex(uc.reg_read(UC_ARM64_REG_PC))}
    pc = uc.reg_read(UC_ARM64_REG_PC)
    return {"ok": fault is None and pc == STOP_ADDR,
            "value": uc.reg_read(UC_ARM64_REG_X0) & 0xffffffff,
            "pc": hex(pc), "fault": fault, "maps": maps}


def source_default_rate(data: bytes, band: int, rateidx: int) -> int:
    offset = 0 if band == 0 else 4
    index = rateidx if rateidx >= 0 else 0
    index += offset
    if index >= 12:
        index = offset
    return struct.unpack_from("<H", data, index * 12 + 6)[0]


def connac_source_value(hw_value: int) -> int:
    mode = hw_value >> 8
    idx = hw_value & 0xff
    return ((mode & 0xf) << 6) | (idx & 0x3f)


def get_text(elf: ELF64, raw: bytes) -> bytes:
    return raw[elf.text.offset:elf.text.offset + elf.text.size]


def main() -> int:
    parser = argparse.ArgumentParser(description="Simulate the hash-pinned AArch64 functions in Unicorn; no kernel/RF access.")
    parser.add_argument("--core-input", type=Path, required=True, help="original mt76.ko ELF")
    parser.add_argument("--connac-input", type=Path, required=True, help="original mt76-connac-lib.ko ELF")
    parser.add_argument("--core-candidate", type=Path, required=True, help="generated mt76 candidate ELF")
    parser.add_argument("--connac-candidate", type=Path, required=True, help="generated connac candidate ELF")
    parser.add_argument("--manifest", type=Path, required=True, help="candidate-manifest.json from the generator")
    parser.add_argument("--report", type=Path, required=True, help="new output JSON path; must not already exist")
    args = parser.parse_args()
    report_path = args.report.expanduser().absolute()
    if report_path.exists():
        raise FileExistsError(f"refusing to overwrite report: {report_path}")
    if not report_path.parent.is_dir():
        raise FileNotFoundError(f"report parent directory does not exist: {report_path.parent}")
    candidate_manifest = json.loads(args.manifest.read_text())
    patch_manifest = json.loads((PACKAGE / "PATCH-MANIFEST.json").read_text())
    if candidate_manifest.get("status") != "OFFLINE_CANDIDATE_FOR_REVIEW_ONLY_NOT_FOR_INSTALL":
        raise ValueError("candidate manifest is not an offline review artifact")
    if candidate_manifest.get("base_commit") != patch_manifest["base_commit"]:
        raise ValueError("candidate manifest base commit does not match this source package")
    expected_patch_hashes = {
        row["patch"]: row["patch_sha256"] for row in patch_manifest["source_files"]
    }
    if candidate_manifest.get("source_patch_sha256") != expected_patch_hashes:
        raise ValueError("candidate manifest does not match the published source patches")
    base_core_raw, base_core_elf, base_core_text = load_image(args.core_input, INPUT_HASHES["mt76.ko"])
    base_conn_raw, base_conn_elf, base_conn_text = load_image(args.connac_input, INPUT_HASHES["mt76-connac-lib.ko"])
    cand_core_raw, cand_core_elf, cand_core_text = load_image(
        args.core_candidate,
        candidate_manifest["changes"]["mt76.ko"]["candidate_sha256"])
    cand_conn_raw, cand_conn_elf, cand_conn_text = load_image(
        args.connac_candidate,
        candidate_manifest["changes"]["mt76-connac-lib.ko"]["candidate_sha256"])
    data_sec = base_core_elf.by_name[".data"]
    data = base_core_raw[data_sec.offset:data_sec.offset + data_sec.size]
    rates_count = 12
    rates_stride = 12
    cases = []
    rate_indexes = [-(1 << 31), -1, 0, 1, 7, 8, 11, 12, (1 << 31) - 1]
    scenarios = [
        (False, 0, None, "null-vif/phy-2g"),
        (False, 1, None, "null-vif/phy-5g"),
        (False, 2, None, "null-vif/phy-non2g"),
        (True, 0, None, "nonnull-vif/ctx-null/phy-2g"),
        (True, 1, None, "nonnull-vif/ctx-null/phy-5g"),
        (True, 2, None, "nonnull-vif/ctx-null/phy-non2g"),
        (True, 1, 0, "nonnull-vif/ctx-2g/phy-5g"),
        (True, 0, 1, "nonnull-vif/ctx-5g/phy-2g"),
        (True, 2, 2, "nonnull-vif/ctx-non2g/phy-2g"),
    ]
    for vif, phy_band, ctx_band, label in scenarios:
        selected_band = ctx_band if vif and ctx_band is not None else phy_band
        for rateidx in rate_indexes:
            expected = source_default_rate(data, selected_band, rateidx)
            cand = run_core(cand_core_text, data, vif_present=vif,
                            phy_band=phy_band, ctx_band=ctx_band, rateidx=rateidx)
            base = None
            if vif:
                base = run_core(base_core_text, data, vif_present=vif,
                                phy_band=phy_band, ctx_band=ctx_band, rateidx=rateidx)
            passed = cand["ok"] and cand["value"] == expected and (base is None or (base["ok"] and base["value"] == expected))
            if not passed:
                raise AssertionError(f"core mismatch {label} rateidx={rateidx}: expected={expected}, candidate={cand}, baseline={base}")
            cases.append({"group": "core_rate", "scenario": label, "rateidx_signed": rateidx,
                          "expected_hw_value": expected, "candidate_hw_value": cand["value"],
                          "baseline_hw_value": None if base is None else base["value"], "passed": True})

    # The unpatched core must fault on NULL before the saved source guard; candidate must return source value.
    for phy_band in (0, 1, 2):
        base = run_core(base_core_text, data, vif_present=False,
                        phy_band=phy_band, ctx_band=None, rateidx=0)
        if base["fault"] is None or base["pc"] != hex(CORE_BASE + 0x32c4):
            raise AssertionError(f"baseline null-vif did not fault at original dereference: {base}")
        expected = source_default_rate(data, phy_band, 0)
        cand = run_core(cand_core_text, data, vif_present=False,
                        phy_band=phy_band, ctx_band=None, rateidx=0)
        if not cand["ok"] or cand["value"] != expected:
            raise AssertionError(f"candidate core NULL guard failed for band={phy_band}: {cand}")
        cases.append({"group": "core_null_fault_control", "scenario": f"phy-band-{phy_band}",
                      "baseline_fault_pc": base["pc"], "candidate_hw_value": cand["value"],
                      "expected_hw_value": expected, "passed": True})

    # Real connac ELF path: early branch reaches existing legacy label and calls emulated core helper.
    connac_cases = []
    for phy_band in (0, 1, 2):
        hw = source_default_rate(data, phy_band, 0)
        expected = connac_source_value(hw)
        for beacon in (0, 1):
            for mcast in (0, 1):
                base = run_connac(base_conn_text, base_core_text, data,
                                  phy_band=phy_band, beacon=beacon, mcast=mcast)
                if base["fault"] is None or base["pc"] != hex(CONNAC_BASE + 0x5470):
                    raise AssertionError(f"baseline connac null-vif did not fault at first dereference: {base}")
                cand = run_connac(cand_conn_text, cand_core_text, data,
                                  phy_band=phy_band, beacon=beacon, mcast=mcast)
                if not cand["ok"] or cand["value"] != expected:
                    raise AssertionError(f"candidate connac NULL path mismatch: band={phy_band}, beacon={beacon}, mcast={mcast}: {cand}")
                row = {"phy_band": phy_band, "beacon": beacon, "mcast": mcast,
                       "expected_source_value": expected, "candidate_value": cand["value"],
                       "baseline_fault_pc": base["pc"], "passed": True}
                connac_cases.append(row)
                cases.append({"group": "connac_null_path", **row})

    # The moved prefix must preserve all observed non-NULL channel selection before the rest of the
    # original function begins. Stop just before the is_mt7921/device-specific logic at +0x38.
    prefix_cases = []
    for phy_band, ctx_band in ((0, None), (1, None), (0, 1), (1, 0), (2, 0)):
        def prefix_run(text: bytes):
            uc, _ = make_machine(base_core_text, CORE_BASE, data, text)
            init_radio_memory(uc, phy_band, True, ctx_band)
            uc.reg_write(UC_ARM64_REG_X0, PHY_BASE)
            uc.reg_write(UC_ARM64_REG_X1, VIF_BASE)
            uc.reg_write(UC_ARM64_REG_X2, 0)
            uc.reg_write(UC_ARM64_REG_X3, 0)
            uc.reg_write(UC_ARM64_REG_SP, STACK_BASE + 0x8000)
            uc.reg_write(UC_ARM64_REG_X30, STOP_ADDR)
            hit = {"stopped": False}
            def stop_hook(engine, address, size, user_data):
                if address == CONNAC_BASE + 0x5488:
                    user_data["stopped"] = True
                    engine.emu_stop()
            hook = uc.hook_add(UC_HOOK_CODE, stop_hook, hit)
            fault = None
            try:
                uc.emu_start(CONNAC_BASE + 0x5450, STOP_ADDR, count=128)
            except UcError as exc:
                fault = str(exc)
            return {"hit": hit["stopped"], "fault": fault,
                    "x0": uc.reg_read(UC_ARM64_REG_X0),
                    "w23": uc.reg_read(UC_ARM64_REG_X23) & 0xffffffff,
                    "pc": uc.reg_read(UC_ARM64_REG_PC)}
        base = prefix_run(base_conn_text)
        cand = prefix_run(cand_conn_text)
        expected_band = ctx_band if ctx_band is not None else phy_band
        if not base["hit"] or not cand["hit"] or base["fault"] or cand["fault"] or base["w23"] != expected_band or cand["w23"] != expected_band:
            raise AssertionError(f"non-NULL connac prefix did not preserve band: {phy_band=} {ctx_band=} {base=} {cand=}")
        prefix_cases.append({"phy_band": phy_band, "ctx_band": ctx_band,
                             "baseline_w23": base["w23"], "candidate_w23": cand["w23"],
                             "expected_band": expected_band, "passed": True})

    report = {
        "schema": "mt76-offline-elf-simulation/v1",
        "status": "PASS_OFFLINE_INSTRUCTION_SIMULATION_ONLY",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "emulator": {"name": "Unicorn Engine", "version": getattr(sys.modules.get("unicorn"), "__version__", "unknown"),
                     "isa": "AArch64 ARM mode"},
        "inputs": {"mt76_ko_sha256": sha(base_core_raw),
                   "mt76_connac_lib_ko_sha256": sha(base_conn_raw),
                   "core_candidate_sha256": sha(cand_core_raw),
                   "connac_candidate_sha256": sha(cand_conn_raw),
                   "mt76_rates_data_sha256": hashlib.sha256(data).hexdigest()},
        "test_counts": {"core_rate_semantic_cases": len(scenarios) * len(rate_indexes),
                        "core_null_fault_controls": 3, "connac_null_path_cases": len(connac_cases),
                        "connac_nonnull_prefix_cases": len(prefix_cases),
                        "total_passed": len(cases) + len(prefix_cases)},
        "core_cases": [x for x in cases if x["group"].startswith("core")],
        "connac_null_cases": connac_cases,
        "connac_nonnull_prefix_cases": prefix_cases,
        "scope_limits": [
            "This executes the captured AArch64 ELF function bodies in a user-space CPU emulator with synthetic PHY/VIF/channel memory and the captured mt76_rates table.",
            "Only the saved ADRP/ADD and CALL26 relocations needed by these simulated paths are resolved in emulator memory; candidate ELF relocation sections are byte-identical to baseline.",
            "This is not a Kbuild build, kernel module load, ABI/package validation, router test, RF test, or deployment evidence.",
        ],
    }
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"report_name": report_path.name, "status": report["status"],
                      "test_counts": report["test_counts"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"SIMULATION_FAIL: {exc}", file=sys.stderr)
        raise SystemExit(2)
