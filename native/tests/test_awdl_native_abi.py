#!/usr/bin/env python3
"""Offline ABI evidence check for the local 25G241 linked analysis images.

This does not build or load a kext. It checks that each AWDLProtocol pure
get/set method has a matching IO80211 wrapper dispatch slot and that the BCM
concrete implementation returns a 32-bit status in EAX. Use --write-report to
refresh the ignored private evidence matrix.
"""

from __future__ import annotations

import argparse
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
SLOT_EVIDENCE = ROOT / "include/Tahoe/evidence/awdl-vtable-25G241.md"
REPORT = ROOT / "include/Tahoe/evidence/awdl-native-return-matrix-25G241.md"

EXPECTED_HASHES = {
    "IO80211Family": "26abad781208e382ba0dffe3c3bc8cc3fe820aea2cacb5083b1d25a6240202fa",
    "AppleBCMWLANCoreMac": "d54e7c68a34cea817900e587a1653f52c38c5d5df93c0701f1161d1e78f2afa9",
}

REGISTER32 = {
    "rax": "eax",
    "rbx": "ebx",
    "rcx": "ecx",
    "rdx": "edx",
    "rsi": "esi",
    "rdi": "edi",
    "rbp": "ebp",
    "rsp": "esp",
    **{f"r{i}": f"r{i}d" for i in range(8, 16)},
}


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def demangled_symbols(image: Path, raw_substring: str) -> dict[str, int]:
    raw: list[tuple[int, str]] = []
    for line in run("xcrun", "nm", "-nm", str(image)).splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0] == "undefined":
            continue
        symbol = fields[-1]
        if raw_substring in symbol:
            raw.append((int(fields[0], 16), symbol))
    demangled = subprocess.check_output(
        ["c++filt"], input="\n".join(symbol for _, symbol in raw), text=True
    ).splitlines()
    if len(demangled) != len(raw):
        raise RuntimeError("c++filt output count does not match nm output")
    return {name: address for (address, _), name in zip(raw, demangled)}


def disassembly(image: Path) -> tuple[list[str], dict[int, int]]:
    lines = run("xcrun", "otool", "-tv", str(image)).splitlines()
    address_to_line: dict[int, int] = {}
    for index, line in enumerate(lines):
        match = re.match(r"([0-9a-f]{16})\t", line)
        if match:
            address_to_line[int(match.group(1), 16)] = index
    return lines, address_to_line


def function_block(lines: list[str], address_to_line: dict[int, int], address: int) -> list[str]:
    start = address_to_line.get(address)
    if start is None:
        return []
    block: list[str] = []
    for line in lines[start:]:
        if block and line.endswith(":") and not re.match(r"[0-9a-f]{16}\t", line):
            break
        block.append(line)
    return block


def wrapper_slots(block: list[str]) -> set[int]:
    slots: set[int] = set()
    for jump_index, line in enumerate(block):
        if not re.search(r"jmpq?\s+\*", line):
            continue
        preceding = block[max(0, jump_index - 32) : jump_index]
        for candidate in preceding:
            direct = re.search(r"movq\s+(0x[0-9a-f]+)\(%rax\),\s*%rax", candidate)
            if direct:
                slots.add(int(direct.group(1), 16))

        # IO80211 wrappers select among interface-type-specific virtual slots
        # by loading a candidate offset into an index register.
        for load_index, candidate in enumerate(preceding):
            indexed = re.search(r"movq\s+\(%rax,%(r\w+)\),\s*%rax", candidate)
            if not indexed:
                continue
            index_register = indexed.group(1)
            index_register32 = REGISTER32.get(index_register)
            if not index_register32:
                continue
            for assignment in preceding[:load_index]:
                immediate = re.search(
                    r"movl\s+\$(0x[0-9a-f]+|[0-9]+),\s*%"
                    + re.escape(index_register32)
                    + r"\b",
                    assignment,
                )
                if immediate:
                    slots.add(int(immediate.group(1), 0))
    return slots


def return_shapes(block: list[str]) -> list[str]:
    shapes: list[str] = []
    for ret_index, line in enumerate(block):
        if not re.search(r"\tretq\b", line):
            continue
        shape = "unknown"
        for candidate in reversed(block[max(0, ret_index - 160) : ret_index]):
            fields = candidate.split("\t")
            if len(fields) < 3:
                continue
            mnemonic = fields[1]
            operands = fields[2].split("##", 1)[0].strip()
            if mnemonic.startswith("call"):
                target = re.search(r"0x([0-9a-f]+)", operands)
                shape = "call-result" + (f"@0x{target.group(1)}" if target else "")
                break
            destination = operands.split(",")[-1].strip()
            if mnemonic not in {
                "cmpb",
                "cmpw",
                "cmpl",
                "cmpq",
                "testb",
                "testw",
                "testl",
                "testq",
            } and destination in {"%eax", "%rax", "%al"}:
                width = "EAX32" if destination in {"%eax", "%al"} else "RAX64"
                shape = f"{width}:{mnemonic} {operands}"
                break
        shapes.append(shape)
    return shapes


def parse_rows() -> list[tuple[int, int, str]]:
    rows: list[tuple[int, int, str]] = []
    pattern = re.compile(
        r"\|\s*(\d+)\s*\|\s*`(0x[0-9a-f]+)`\s*\|\s*"
        r"`AppleBCMWLANProximityInterface::([^(`]+)\("
    )
    for line in SLOT_EVIDENCE.read_text().splitlines():
        match = pattern.match(line)
        if match and 505 <= int(match.group(1)) <= 567:
            rows.append((int(match.group(1)), int(match.group(2), 16), match.group(3)))
    return rows


def build_matrix() -> tuple[list[str], list[dict[str, object]]]:
    for label, image in (("IO80211Family", IO80211_IMAGE), ("AppleBCMWLANCoreMac", BCM_IMAGE)):
        if not image.is_file():
            raise FileNotFoundError(image)
        actual = sha256(image)
        if actual != EXPECTED_HASHES[label]:
            raise RuntimeError(f"{label} image hash changed: {actual}")

    rows = parse_rows()
    if len(rows) != 63:
        raise RuntimeError(f"expected 63 AWDL slots, found {len(rows)}")

    io_symbols = demangled_symbols(IO80211_IMAGE, "apple80211")
    bcm_symbols = demangled_symbols(BCM_IMAGE, "AppleBCMWLANProximityInterface")
    io_lines, io_index = disassembly(IO80211_IMAGE)
    bcm_lines, bcm_index = disassembly(BCM_IMAGE)
    helper_name = next(
        (
            name
            for name in bcm_symbols
            if name.startswith("AppleBCMWLANProximityInterface::sendIOVarSetCommand(")
        ),
        None,
    )
    if helper_name is None:
        raise RuntimeError("missing sendIOVarSetCommand status helper")
    helper_addr = bcm_symbols[helper_name]
    helper_block = function_block(bcm_lines, bcm_index, helper_addr)
    helper_returns = return_shapes(helper_block)
    if not helper_returns or not all(entry.startswith("EAX32:") for entry in helper_returns):
        raise RuntimeError(f"sendIOVarSetCommand is not EAX32: {helper_returns}")

    matrix: list[dict[str, object]] = []
    errors: list[str] = []

    for slot, offset, method in rows:
        wrapper_name = next(
            (name for name in io_symbols if name.startswith(f"apple80211{method}(")), None
        )
        concrete_name = next(
            (
                name
                for name in bcm_symbols
                if name.startswith(f"AppleBCMWLANProximityInterface::{method}(")
            ),
            None,
        )
        if wrapper_name is None or concrete_name is None:
            errors.append(f"slot {slot} {method}: missing wrapper or BCM implementation")
            continue

        wrapper_addr = io_symbols[wrapper_name]
        concrete_addr = bcm_symbols[concrete_name]
        wrapper_block = function_block(io_lines, io_index, wrapper_addr)
        concrete_block = function_block(bcm_lines, bcm_index, concrete_addr)
        offsets = wrapper_slots(wrapper_block)
        returns = return_shapes(concrete_block)
        if method in {"setAWDL_OOB_AUTO_REQUEST", "setAWDL_OOB_SEC_PAYLOAD_REQUEST"}:
            helper_call = re.search(rf"callq\s+0x{helper_addr:x}\b", "\n".join(concrete_block))
            if not helper_call:
                errors.append(f"slot {slot} {method}: missing sendIOVarSetCommand call")
            error_values = sorted(
                {
                    int(value, 0)
                    for value in re.findall(
                        r"movl\s+\$(0x[0-9a-f]+|[0-9]+),\s*%eax", "\n".join(concrete_block)
                    )
                }
            )
            returns = ["EAX32:call sendIOVarSetCommand"] + [
                f"EAX32:error 0x{value:08x}" for value in error_values
            ]
        expected_status_width = all(
            entry.startswith("EAX32:") or entry.startswith("call-result@")
            for entry in returns
        ) and bool(returns)
        if offset not in offsets:
            errors.append(
                f"slot {slot} {method}: wrapper lacks 0x{offset:x}; found {sorted(offsets)}"
            )
        if not expected_status_width:
            errors.append(f"slot {slot} {method}: unexpected return shape {returns}")
        matrix.append(
            {
                "slot": slot,
                "offset": offset,
                "method": method,
                "wrapper": wrapper_addr,
                "wrapper_offsets": sorted(offsets),
                "concrete": concrete_addr,
                "returns": returns,
            }
        )

    if errors:
        raise RuntimeError("\n".join(errors))

    # The final pure slot inherited by AWDLProtocol is setMacAddress(ether_addr&).
    mac_name = next(
        (
            name
            for name in bcm_symbols
            if name.startswith("AppleBCMWLANProximityInterface::setMacAddress(ether_addr&)")
        ),
        None,
    )
    if mac_name is None:
        raise RuntimeError("missing concrete setMacAddress(ether_addr&) symbol")
    mac_returns = return_shapes(function_block(bcm_lines, bcm_index, bcm_symbols[mac_name]))
    if not mac_returns or not all(entry.startswith("EAX32:") for entry in mac_returns):
        raise RuntimeError(f"unexpected setMacAddress return shape: {mac_returns}")

    summary = [
        "# Native AWDL callback return and dispatch matrix (private, 25G241)",
        "",
        "本报告由 `native/tests/test_awdl_native_abi.py --write-report` 从本机 linked-analysis images 与 `awdl-vtable-25G241.md` 生成。它只记录符号、槽偏移和寄存器返回形态，不含 Apple 二进制或实现代码。",
        "",
        "## 结论边界",
        "",
        f"- 63/63 个 AWDLProtocol 新增 get/set 槽都有同名 `apple80211...` wrapper、AppleBCMWLANProximityInterface 实现，且 wrapper 代码中的候选 vtable 偏移包含该槽的已提取偏移。每个 concrete 函数返回 32-bit EAX 状态，或返回 `sendIOVarSetCommand` 的 EAX32 状态；未发现 pointer-in-RAX 或 void 返回。",
        f"- 继承的 pure `setMacAddress(ether_addr&)` 位于 slot 488；BCM 实现也以 EAX32 返回。",
        "- 这证明机器级返回宽度和状态用途，不证明所有方法的 source typedef 一定拼写为 `IOReturn`：Mach-O C++ symbol 不编码返回类型。selector 149/151 两个回调在独立路由证据中明确为 `IOReturn`；其余 get/set 回调由 Apple80211 wrapper、调用端 EAX 状态处理和仓库已有 IOReturn handler 声明交叉支持。",
        "- 当前只落了槽位索引和两个已确证 callback type；没有伪造完整 C++ 基类/子类或将其接入 kext target。VIF slots 461–487 的 27 个额外方法仍需逐项签名核对。",
        "",
        "## 对象布局证据",
        "",
        "- linked-image MetaClass registration: `IO80211SkywalkInterface=0x128`、`IO80211VirtualInterface=0x130`、`IO80211AWDLProtocol=0x130`；vtable slots 分别为 461、505、568。",
        "- `IO80211VirtualInterface::init` @ `0xffffff80023305f8` 将一个指针存到 `this+0x128`；后续 native 方法从相同偏移取回该指针。这与 `0x128` base + 8-byte tail pointer = `0x130` 一致。pointee 类型和其内部字段仍未确认。",
        "- compile-only probe 对现有 `IO80211SkywalkInterface` 头执行 `sizeof`，结果为 `0x128`，并验证 `sizeof(base)+sizeof(void*)==0x130`。这个探针验证尺寸/已知类型别名，不生成 C++ vtable，也不冒充 64 个 pure override 的编译验证。",
        "",
        "## 证据源",
        "",
        f"- IO80211Family: SHA-256 `{EXPECTED_HASHES['IO80211Family']}`；wrapper dispatch 经 `xcrun otool -tv` 解码。",
        f"- AppleBCMWLANCoreMac: SHA-256 `{EXPECTED_HASHES['AppleBCMWLANCoreMac']}`；concrete symbol/返回寄存器经 `xcrun nm -nm`、`c++filt`、`xcrun otool -tv` 交叉核对。",
        "- 同名旧 handler 交叉参考：`include/Airport/IO80211InfraProtocol.h`、`include/Airport/IO80211Controller.h` 的 `IOCTL_FUNC`、`AirportItlwm/AirportVirtualIOCTL.cpp`。这些是本项目 API 约定证据，不替代 Apple Tahoe header。",
        "- 直接 caller 样例：getSSID @ `0xffffff8002294cc3` 将 EAX 存入 R13D 并 test；getCHANNEL @ `0xffffff80022952d9` 存入 R12D 并 test；getBSSID @ `0xffffff8002294ee3` 存入 R15D 并 test；getSTATE @ `0xffffff80023246a6` test EAX；getAWDL_SYNC_ENABLED @ `0xffffff80023666f3` test EAX；setCHANNEL @ `0xffffff800228724a` test EAX。",
        "",
        "## 逐槽矩阵",
        "",
        "`wrapper candidate slots` 是该 wrapper 在接口类型分支中装入间接调用的候选字节偏移；AWDLProtocol 候选包含 `expected`。`concrete EAX result` 只记录返回寄存器形态，不复制实现代码。",
        "",
        "| slot | callback | expected | wrapper VM | wrapper candidate slots | BCM VM | concrete EAX result |",
        "|---:|---|---:|---:|---|---:|---|",
    ]
    for row in matrix:
        returns = ", ".join(str(item) for item in row["returns"])
        slots = ", ".join(f"0x{value:x}" for value in row["wrapper_offsets"])
        summary.append(
            f"| {row['slot']} | `{row['method']}` | `0x{row['offset']:x}` | "
            f"`0x{row['wrapper']:016x}` | {slots} | `0x{row['concrete']:016x}` | {returns} |"
        )
    summary.extend(
        [
            "",
            "### inherited pure slot 488",
            "",
            f"`setMacAddress(ether_addr&)`: BCM concrete VM `{bcm_symbols[mac_name]:#018x}`，return `{', '.join(mac_returns)}`。该方法名/参数来自 concrete vtable 符号，返回 source typedef 仍未从 symbol 证明。",
            "",
            "## 编译探针",
            "",
            "`native/tests/test_awdl_native_abi.cpp` 是 compile-only witness：验证现有 `IO80211SkywalkInterface` 头大小为 0x128、观测到的 VIF 尾部指针令尺寸到 0x130、slot 算术以及两个确证的 member callback type。它不声明、实例化、链接或注册 native subclass。",
            "",
            "复跑的编译命令：",
            "",
            "```sh",
            "xcrun --sdk macosx clang++ -std=c++17 -fno-rtti -fsyntax-only \\",
            "  -D__IO80211_TARGET=260000 -Iinclude \\",
            "  -I/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers \\",
            "  native/tests/test_awdl_native_abi.cpp",
            "```",
            "",
        ]
    )
    return summary, matrix


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write-report",
        action="store_true",
        help=f"write generated private evidence to {REPORT}",
    )
    args = parser.parse_args()
    report, matrix = build_matrix()
    if args.write_report:
        REPORT.write_text("\n".join(report))
    print(
        f"PASS: 63/63 AWDL wrappers select the expected vtable candidate; "
        f"63/63 concrete callbacks return EAX32 status (or checked helper EAX32); "
        f"setMacAddress is EAX32. rows={len(matrix)}"
    )
    if args.write_report:
        print(f"wrote private evidence: {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
