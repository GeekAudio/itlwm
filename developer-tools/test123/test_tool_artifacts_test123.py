#!/usr/bin/env python3
"""Offline security regressions for Test123 build-artifact receipts."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


VALIDATOR_PATH = Path(__file__).with_name("tool_artifacts_test123.py")
SPEC = importlib.util.spec_from_file_location("tool_artifacts_test123_under_test",
                                               VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_file(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)


def make_binary(kind: str) -> bytes:
    raw = bytearray(64)
    if kind == "sender":
        raw[:6] = b"\x7fELF\x02\x01"
        raw[18:20] = (183).to_bytes(2, "little")
    else:
        raw[:4] = b"\xcf\xfa\xed\xfe"
        raw[4:8] = (0x01000007).to_bytes(4, "little")
    return bytes(raw)


class ToolArtifactReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="test123-artifact-")
        # macOS exposes the temporary directory through /var -> /private/var;
        # bind fixtures to the canonical path expected by the validator.
        base = Path(self.temp.name).resolve(strict=True)
        self.repo = base / "repo"
        self.private = base / "private"
        self.repo.mkdir(mode=0o700)
        self.private.mkdir(mode=0o700)
        self.receipts = self.private / "receipts"
        self.receipts.mkdir(mode=0o700)
        self.binaries = self.private / "binaries"
        self.binaries.mkdir(mode=0o700)
        self.zig = self.private / "toolchain" / "zig"
        write_file(self.zig, b"offline fixture compiler; never executed\n", 0o700)
        self.uid = os.getuid()
        self.receipt_paths = {}
        self.binary_paths = {}
        self.receipt_values = {}
        self._write_repo_inputs()
        for kind in VALIDATOR.COMPONENTS:
            self._write_component(kind)

    def tearDown(self):
        self.temp.cleanup()

    def _write_repo_inputs(self):
        paths = set()
        for spec in VALIDATOR.COMPONENTS.values():
            paths.add(spec["source"])
            paths.add(spec["protocol"])
            paths.update(spec["dependencies"])
        paths.add(VALIDATOR.CODEC)
        for relative in paths:
            write_file(self.repo / relative, ("fixture:" + relative + "\n").encode())

    def _write_component(self, kind: str):
        spec = VALIDATOR.COMPONENTS[kind]
        binary = self.binaries / f"{kind}-artifact"
        write_file(binary, make_binary(kind), 0o755)
        receipt = {
            "schema": f"test123-{kind}-build-private/v1",
            "tool_id": "Tool123",
            "candidate": "25G332-Test122",
            "running_kernel_test": "Test122",
            "status": "built_offline",
            "rf_tested": False,
            "exit_code": 0,
            "target": spec["target"],
            "source_path": str(self.repo / spec["source"]),
            "source_sha256": digest((self.repo / spec["source"]).read_bytes()),
            "protocol_source_path": str(self.repo / spec["protocol"]),
            "protocol_source_sha256": digest((self.repo / spec["protocol"]).read_bytes()),
            "compiled_dependency_sha256": {
                relative: digest((self.repo / relative).read_bytes())
                for relative in spec["dependencies"]
            },
            "binary_path": str(binary),
            "binary_sha256": digest(binary.read_bytes()),
        }
        parser_dir = self.repo / "developer-tools/test089/txstatus-observer"
        if kind == "sender":
            compiler = self.zig
            command = [str(compiler), "cc", "-target", "aarch64-linux-musl",
                       "-static", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
                       "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-I",
                       str(parser_dir), str(self.repo / spec["source"]),
                       str(parser_dir / "radiotap_parser.c"), "-o", str(binary)]
        else:
            compiler = Path("/usr/bin/clang")
            command = [str(compiler), "-std=c11", "-arch", "x86_64", "-O2",
                       "-Wall", "-Wextra", "-Werror", "-fstack-protector-strong",
                       str(self.repo / spec["source"]), "-o", str(binary)]
        receipt["compiler_sha256"] = digest(compiler.read_bytes())
        receipt["command"] = command
        if kind == "sender":
            receipt["codec_source_path"] = str(self.repo / VALIDATOR.CODEC)
            receipt["codec_source_sha256"] = digest(
                (self.repo / VALIDATOR.CODEC).read_bytes())
        receipt_path = self.receipts / f"{kind}.json"
        self._save_receipt(kind, receipt, receipt_path)
        self.receipt_paths[kind] = receipt_path
        self.binary_paths[kind] = binary
        self.receipt_values[kind] = receipt

    def _save_receipt(self, kind: str, value: dict, path: Path | None = None):
        path = path or self.receipt_paths[kind]
        write_file(path, json.dumps(value, sort_keys=True).encode(), 0o600)
        path.parent.chmod(0o700)
        return path

    def _validate(self, kind: str, path: Path | None = None):
        return VALIDATOR.validate_build_receipt(
            path or self.receipt_paths[kind], kind=kind,
            repo_root=self.repo, private_root=self.private)

    def test_accepts_valid_sender_and_listener_receipts(self):
        for kind in ("sender", "listener"):
            with self.subTest(kind=kind):
                result = self._validate(kind)
                self.assertEqual(result["schema"],
                                 f"test123-{kind}-build-private/v1")
                self.assertEqual(result["validated_build_receipt_sha256"],
                                 digest(self.receipt_paths[kind].read_bytes()))

    def test_rejects_binary_change_after_receipt(self):
        path = self.binary_paths["sender"]
        changed = bytearray(path.read_bytes())
        changed[-1] ^= 1
        path.write_bytes(changed)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_binary_mismatch"):
            self._validate("sender")

    def test_rejects_dependency_source_change_after_receipt(self):
        path = self.repo / "developer-tools/test123/router-status/router_sender_schedule_test123.h"
        path.write_bytes(path.read_bytes() + b"\nchanged\n")
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "compiled_dependency_hash_mismatch"):
            self._validate("sender")

    def test_rejects_protocol_source_change_after_receipt(self):
        path = self.repo / VALIDATOR.COMPONENTS["listener"]["protocol"]
        path.write_bytes(path.read_bytes() + b"\nchanged\n")
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_source_mismatch:protocol_source"):
            self._validate("listener")

    def test_rejects_wrong_binary_architecture_even_with_updated_hash(self):
        path = self.binary_paths["sender"]
        wrong = bytearray(path.read_bytes())
        wrong[18:20] = (62).to_bytes(2, "little")
        write_file(path, bytes(wrong), 0o755)
        receipt = dict(self.receipt_values["sender"])
        receipt["binary_sha256"] = digest(bytes(wrong))
        self._save_receipt("sender", receipt)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_binary_architecture_mismatch"):
            self._validate("sender")

    def test_rejects_wrong_candidate_and_target(self):
        receipt = dict(self.receipt_values["sender"])
        receipt["candidate"] = "25G331-Test121"
        self._save_receipt("sender", receipt)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_receipt_contract_mismatch"):
            self._validate("sender")
        receipt["candidate"] = "25G332-Test122"
        receipt["target"] = "x86_64-linux-musl"
        self._save_receipt("sender", receipt)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_receipt_contract_mismatch"):
            self._validate("sender")

    def test_rejects_non_private_receipt_permissions(self):
        receipt = self.receipt_paths["sender"]
        receipt.chmod(0o644)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError, "receipt_not_private"):
            self._validate("sender")

    def test_rejects_symlink_receipt_and_binary(self):
        receipt_link = self.receipts / "sender-link.json"
        receipt_link.symlink_to(self.receipt_paths["sender"])
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_path_not_absolute_regular"):
            self._validate("sender", receipt_link)

        binary_link = self.binaries / "sender-link"
        binary_link.symlink_to(self.binary_paths["sender"])
        receipt = dict(self.receipt_values["sender"])
        receipt["binary_path"] = str(binary_link)
        self._save_receipt("sender", receipt)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_path_not_absolute_regular"):
            self._validate("sender")

    def test_rejects_build_command_missing_source_or_output(self):
        receipt = dict(self.receipt_values["listener"])
        receipt["command"] = ["true", "-o", receipt["binary_path"]]
        self._save_receipt("listener", receipt)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_build_command_mismatch"):
            self._validate("listener")

    def test_rejects_false_compiler_target_and_missing_critical_flags(self):
        receipt = dict(self.receipt_values["listener"])
        command = list(receipt["command"])
        command[0] = "/usr/bin/true"
        receipt["command"] = command
        receipt["compiler_sha256"] = digest(Path("/usr/bin/true").read_bytes())
        self._save_receipt("listener", receipt)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_build_compiler_or_target_mismatch"):
            self._validate("listener")

        receipt = dict(self.receipt_values["sender"])
        command = list(receipt["command"])
        command[command.index("aarch64-linux-musl")] = "x86_64-linux-musl"
        receipt["command"] = command
        self._save_receipt("sender", receipt)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_build_compiler_or_target_mismatch"):
            self._validate("sender")

        receipt = dict(self.receipt_values["sender"])
        receipt["command"] = [arg for arg in receipt["command"] if arg != "-static"]
        self._save_receipt("sender", receipt)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_build_compiler_or_target_mismatch"):
            self._validate("sender")

        receipt = dict(self.receipt_values["sender"])
        receipt["command"] = [arg for arg in receipt["command"] if arg != "-Wall"]
        self._save_receipt("sender", receipt)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_build_flags_mismatch"):
            self._validate("sender")

    def test_rejects_duplicate_output_argument(self):
        receipt = dict(self.receipt_values["listener"])
        receipt["command"] = [*receipt["command"], "-o", receipt["binary_path"]]
        self._save_receipt("listener", receipt)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError,
                                   "artifact_build_command_mismatch"):
            self._validate("listener")

    def test_rejects_duplicate_json_key(self):
        receipt_path = self.receipt_paths["sender"]
        raw = receipt_path.read_text()
        raw = raw.replace('"candidate": "25G332-Test122"',
                          '"candidate": "25G332-Test122", "candidate": "25G332-Test122"',
                          1)
        receipt_path.write_text(raw)
        receipt_path.chmod(0o600)
        with self.assertRaisesRegex(VALIDATOR.ArtifactError, "receipt_duplicate_key"):
            self._validate("sender")


if __name__ == "__main__":
    unittest.main()
