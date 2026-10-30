#!/usr/bin/env python3
"""Create hash-pinned offline AArch64 instruction-patch candidates for review.

This tool only copies the captured ELF relocatable objects and changes verified
.text words. It never installs, loads, signs, or sends anything to a device.
"""
from __future__ import annotations

import hashlib
import argparse
import json
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import tempfile

PACKAGE = Path(__file__).resolve().parents[1]
PATCH_MANIFEST = PACKAGE / "PATCH-MANIFEST.json"
PACKAGE_MANIFEST = json.loads(PATCH_MANIFEST.read_text())
INPUT_HASHES = PACKAGE_MANIFEST["exact_elf_inputs_for_instruction_candidate"]


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    typ: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    align: int
    entsize: int


class ELF64:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("expected ELF64 little-endian input")
        h = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
        self.etype, self.machine = h[1], h[2]
        if self.etype != 1 or self.machine != 183:
            raise ValueError("expected ET_REL AArch64 ELF")
        shoff, shentsize, shnum, shstrndx = h[6], h[11], h[12], h[13]
        if shentsize != 64 or shstrndx >= shnum:
            raise ValueError("unexpected section header layout")
        raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
               for i in range(shnum)]
        names_raw = raw[shstrndx]
        names = data[names_raw[4]:names_raw[4] + names_raw[5]]

        def cstr(blob: bytes, pos: int) -> str:
            if pos >= len(blob):
                raise ValueError("section string offset out of range")
            end = blob.find(b"\0", pos)
            if end < 0:
                raise ValueError("unterminated section name")
            return blob[pos:end].decode("ascii")

        self.sections = []
        for i, x in enumerate(raw):
            self.sections.append(Section(i, cstr(names, x[0]), x[1], x[2], x[3],
                                         x[4], x[5], x[6], x[7], x[8], x[9]))
        by_name = {s.name: s for s in self.sections}
        self.by_name = by_name
        self.text = by_name[".text"]
        if self.text.typ != 1:
            raise ValueError(".text must be PROGBITS")

    def symbols(self):
        symtab = self.by_name.get(".symtab")
        if not symtab or symtab.entsize != 24:
            raise ValueError("missing expected ELF64 symbol table")
        strtab = self.sections[symtab.link]
        strings = self.data[strtab.offset:strtab.offset + strtab.size]
        rows = {}
        for pos in range(symtab.offset, symtab.offset + symtab.size, 24):
            nameoff, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.data, pos)
            end = strings.find(b"\0", nameoff)
            if end < 0:
                raise ValueError("bad symbol string")
            name = strings[nameoff:end].decode("utf-8", "replace") if nameoff else ""
            rows[name] = {"info": info, "other": other, "shndx": shndx,
                          "value": value, "size": size}
        return rows

    def relocs(self):
        result = []
        for s in self.sections:
            if s.typ == 4 and s.entsize == 24:  # SHT_RELA
                for pos in range(s.offset, s.offset + s.size, s.entsize):
                    roff, info, addend = struct.unpack_from("<QQq", self.data, pos)
                    result.append((s.name, roff, info >> 32, info & 0xffffffff, addend))
        return result

    def section_signature(self):
        return [(s.name, s.typ, s.flags, s.addr, s.offset, s.size, s.link,
                 s.info, s.align, s.entsize) for s in self.sections]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def word(hexword: str) -> bytes:
    return struct.pack("<I", int(hexword, 16))


PATCHES = {
    "mt76-connac-lib.ko": {
        "input_sha256": INPUT_HASHES["mt76-connac-lib.ko"],
        "function": "mt76_connac2_mac_tx_rate_val",
        "function_offset": 0x5450,
        "function_size": 0x240,
        "words": [
            (0x5470, "f9421821", "b4000ab4"),  # cbz x20, function+0x174 (legacy)
            (0x5474, "f100003f", "f9421821"),
            (0x5478, "9a810000", "f100003f"),
            (0x547c, "f9400000", "9a810000"),
            (0x5480, "b9400017", "f9400000"),
            (0x5484, "b4000a14", "b9400017"),
        ],
        "branch_semantics": "The NULL-vif branch moves ahead of the first vif->drv_priv/context dereference and lands on the existing legacy label at .text+0x55c4. The prologue and x20/x22 argument saves have already run; that label sets rateidx=0 and calls mt76_calculate_default_rate(mphy, NULL, 0).",
    },
    "mt76.ko": {
        "input_sha256": INPUT_HASHES["mt76.ko"],
        "function": "mt76_calculate_default_rate",
        "function_offset": 0x32c4,
        "function_size": 0x54,
        "words": [
            (0x32c4, "f9421821", "f100003f"),  # cmp x1, #0
            (0x32d4, "f100003f", "54000040"),  # b.eq .text+0x32dc
            (0x32d8, "9a810000", "f9421821"),  # guarded vif dereference
            (0x32dc, "f9400000", "f100003f"),  # cmp ctx, #0
            (0x32e0, "b9400000", "9a810000"),  # select phy/ctx chandef
            (0x32e4, "7100001f", "f9400000"),  # chandef->chan
            (0x32e8, "1a9f07e0", "b9400000"),  # chan->band
            (0x32ec, "7100005f", "7100001f"),  # cmp band, #0
            (0x32f0, "1a9fa042", "1a9f07e0"),  # offset bit
            (0x32f4, "531e7400", "0aa27c42"),  # max(s32 rateidx, 0): bic w2,w2,w2,asr #31
            (0x32f8, "0b000042", "531e7400"),  # preserve scaled offset 0 or 4
            (0x32fc, "7100305f", "0b000042"),  # rateidx += offset
            (0x3300, "1a803042", "7100305f"),  # cmp rateidx, #12
            (0x3304, "937f7c40", "1a803042"),  # preserve clamp-to-offset csel
            (0x3308, "8b22c002", "8b224860"),  # x0 = base + 4*index; preserve w2 index
            (0x330c, "8b020862", "8b224c02"),  # x2 = x0 + 8*index, total 12*index
        ],
        "unchanged_words": [
            (0x32c8, "9101c000"), (0x32cc, "90000003"), (0x32d0, "91000063"),
            (0x3310, "79400c40"), (0x3314, "d65f03c0"),
        ],
        "branch_semantics": "The NULL-vif branch executes after the preserved ADRP/ADD table relocation pair, with x0 already set to phy+0x70 and compare flags from cmp vif still live. It skips only the guarded vif load and joins the ctx-null fallback selection. To fit the two new NULL-guard instructions without changing the 0x54-byte function symbol, BIC replaces the two-instruction signed-negative clamp with max(s32 rateidx, 0), and two UXTW additions replace the three-instruction 12*index calculation while keeping w2 as the index until both scaled additions are complete. The existing scaled band offset (0 or 4), rate-index addition, unsigned >=12 fallback, halfword load, and RET remain semantically intact.",
    },
}


def make_candidate(filename: str, spec: dict, src: Path, out_dir: Path) -> dict:
    base = src.read_bytes()
    if sha(base) != spec["input_sha256"]:
        raise ValueError(f"captured input SHA mismatch: {filename}")
    elf = ELF64(base)
    syms = elf.symbols()
    sym = syms.get(spec["function"])
    if not sym or sym["shndx"] != elf.text.index or sym["value"] != spec["function_offset"] or sym["size"] != spec["function_size"]:
        raise ValueError(f"function identity/size mismatch: {filename}:{spec['function']}")

    out = bytearray(base)
    file_ranges = []
    text_relocs = [r for r in elf.relocs() if r[0] == ".rela.text" and
                   spec["function_offset"] <= r[1] < spec["function_offset"] + spec["function_size"]]
    for pos, expected, new in spec["words"]:
        if pos < spec["function_offset"] or pos + 4 > spec["function_offset"] + spec["function_size"]:
            raise ValueError("patch word lies outside target function")
        off = elf.text.offset + pos
        if base[off:off + 4] != word(expected):
            raise ValueError(f"instruction guard failed at .text+0x{pos:x}: expected {expected}, got {base[off:off+4].hex()} ")
        if any(pos <= r[1] < pos + 4 for r in text_relocs):
            raise ValueError(f"refusing to alter relocation-bearing instruction .text+0x{pos:x}")
        out[off:off + 4] = word(new)
        file_ranges.append((off, off + 4))

    for pos, expected in spec.get("unchanged_words", []):
        off = elf.text.offset + pos
        if base[off:off + 4] != word(expected) or out[off:off + 4] != word(expected):
            raise ValueError(f"required unchanged word mismatch at .text+0x{pos:x}")

    patched = ELF64(bytes(out))
    psym = patched.symbols()[spec["function"]]
    if patched.section_signature() != elf.section_signature():
        raise ValueError("ELF section layout/size metadata changed")
    if psym != sym:
        raise ValueError("target function symbol changed")
    if patched.relocs() != elf.relocs():
        raise ValueError("relocation entries changed")
    if len(out) != len(base):
        raise ValueError("file size changed")
    allowed = bytearray(len(base))
    for lo, hi in file_ranges:
        allowed[lo:hi] = b"\1" * (hi - lo)
    for i, (a, b) in enumerate(zip(base, out)):
        if a != b and not allowed[i]:
            raise ValueError(f"unexpected byte change outside patch words at file+0x{i:x}")
    for sec in elf.sections:
        if sec.name == ".text" or sec.typ == 8:  # .text, or SHT_NOBITS
            continue
        if base[sec.offset:sec.offset + sec.size] != out[sec.offset:sec.offset + sec.size]:
            raise ValueError(f"non-text section changed: {sec.name}")

    target = out_dir / f"{filename}.offline-candidate"
    if target.exists():
        raise FileExistsError(f"candidate already exists; refusing overwrite: {target}")
    target.write_bytes(out)
    target.chmod(0o600)
    return {
        "input_name": filename, "input_sha256": sha(base),
        "candidate_name": target.name, "candidate_sha256": sha(bytes(out)),
        "file_size_bytes": len(out), "text_section_size": elf.text.size,
        "function": spec["function"], "function_offset": hex(sym["value"]),
        "function_size": hex(sym["size"]), "changed_instruction_words": len(spec["words"]),
        "relocations_in_function": len(text_relocs),
        "relocation_entries_unchanged": True, "section_and_symbol_metadata_unchanged": True,
        "all_non_text_bytes_unchanged": True,
        "null_guard_plan": spec["branch_semantics"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Create review-only candidates from exact hash-pinned mt76 ELF inputs.")
    parser.add_argument("--core", type=Path, required=True, help="original mt76.ko ELF input")
    parser.add_argument("--connac", type=Path, required=True, help="original mt76-connac-lib.ko ELF input")
    parser.add_argument("--out-dir", type=Path, required=True, help="new output directory; must not already exist")
    args = parser.parse_args()

    inputs = {"mt76.ko": args.core, "mt76-connac-lib.ko": args.connac}
    for filename, path in inputs.items():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"input must be a regular non-symlink file: {filename}")
    out_dir = args.out_dir.expanduser().absolute()
    if out_dir.exists():
        raise FileExistsError(f"refusing existing output directory: {out_dir}")
    if not out_dir.parent.is_dir():
        raise FileNotFoundError(f"output parent directory does not exist: {out_dir.parent}")

    package_manifest = PACKAGE_MANIFEST
    patch_hashes = {}
    for row in package_manifest["source_files"]:
        patch_path = PACKAGE / row["patch"]
        if not patch_path.is_file():
            raise FileNotFoundError(f"source patch missing: {row['patch']}")
        actual_patch_hash = sha(patch_path.read_bytes())
        if actual_patch_hash != row["patch_sha256"]:
            raise ValueError(f"source patch hash mismatch: {row['patch']}")
        patch_hashes[row["patch"]] = actual_patch_hash

    with tempfile.TemporaryDirectory(prefix=".mt76-candidate-", dir=out_dir.parent) as tmp:
        stage = Path(tmp)
        results = {name: make_candidate(name, spec, inputs[name], stage)
                   for name, spec in PATCHES.items()}
        manifest = {
            "schema": "mt76-offline-minipatch-candidate/v1",
            "status": "OFFLINE_CANDIDATE_FOR_REVIEW_ONLY_NOT_FOR_INSTALL",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "base_commit": package_manifest["base_commit"],
            "source_patch_sha256": patch_hashes,
            "changes": results,
            "scope_limit": "No Kbuild, kernel loader, module install/load, RF, or functional device test was performed. The ELF objects remain relocatable ET_REL inputs and require target-specific build/ABI/package and module-load review before any deployment decision.",
        }
        manifest_path = stage / "candidate-manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        manifest_path.chmod(0o600)
        stage.replace(out_dir)
    print(json.dumps({"status": manifest["status"], "out_dir_name": out_dir.name,
                      "candidate_hashes": {name: row["candidate_sha256"]
                                           for name, row in results.items()}}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL_CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
