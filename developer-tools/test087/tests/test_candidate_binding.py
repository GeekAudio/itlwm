from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import sys
import tempfile
import unittest
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[3]
TOOL_DIR = REPO_ROOT / "developer-tools/test087"
sys.path.insert(0, str(TOOL_DIR))
import candidate_binding


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


coordinator = load_module(
    "candidate_binding_coordinator_under_test",
    TOOL_DIR / "controlled_run_coordinator.py")
worker = load_module(
    "candidate_binding_worker_under_test",
    TOOL_DIR / "native_controlled_capture.py")
finalizer = load_module(
    "candidate_binding_finalizer_under_test",
    TOOL_DIR / "finalize_test087_runtime_binding.py")
protocol = load_module(
    "candidate_binding_protocol_under_test",
    TOOL_DIR / "test087_controlled.py")


class CandidateFixture:
    CANDIDATE = "25G332-Test091"
    BASELINE = "25G332-Test090"
    UUID = "F12DAA90-1183-4C72-AB15-3E30721E5E91"

    def __init__(self, root: Path):
        self.root = root
        self.research = root / "research"
        self.research.mkdir(mode=0o700)
        self.archive = root / "AirportItlwm-Test091-fixture.zip"
        self.binary = b"offline candidate binary fixture"
        self.info = b"offline candidate Info.plist fixture"
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_STORED) as package:
            package.writestr("AirportItlwm.kext/Contents/MacOS/AirportItlwm", self.binary)
            package.writestr("AirportItlwm.kext/Contents/Info.plist", self.info)
        self.source_map = {
            "native/p2p_rx149_data_input.hpp": self._sha(
                REPO_ROOT / "native/p2p_rx149_data_input.hpp"),
            "native/rx_preowner_observation.hpp": self._sha(
                REPO_ROOT / "native/rx_preowner_observation.hpp"),
        }
        baseline = {
            "candidate": self.BASELINE,
            "status": "built_offline",
            "installed": False,
        }
        self.baseline_raw = self._json(baseline)
        self.baseline_path = candidate_binding.default_build_receipt_path(
            root, self.BASELINE)
        self._write_private(self.baseline_path, self.baseline_raw)
        self.build = {
            "candidate": self.CANDIDATE,
            "baseline": self.BASELINE,
            "baseline_build_report_sha256": hashlib.sha256(
                self.baseline_raw).hexdigest(),
            "status": "built_offline",
            "installed": False,
            "rf_tested": False,
            "full_build_passed": True,
            "strict_signature_passed": True,
            "source_freeze_matches": True,
            "mach_o_uuid": self.UUID,
            "binary_sha256": self._sha_bytes(self.binary),
            "info_plist_sha256": self._sha_bytes(self.info),
            "archive": str(self.archive),
            "archive_sha256": self._sha(self.archive),
            "source_sha256": self.source_map,
            "source_file_count": len(self.source_map),
            "profile": candidate_binding.SUPPORTED_PROFILE,
            "rx149_data_input_contract": {
                "artifact_enabled": True,
                "host_management_or_data_tx_allowed": False,
                "session_duration_ms": 100,
                "channel": 149,
                "source_header": "native/p2p_rx149_data_input.hpp",
                "source_header_sha256": self.source_map[
                    "native/p2p_rx149_data_input.hpp"],
            },
            "rx_preowner_observation_contract": {
                "window_us": 4_000_000,
                "numeric_only": True,
                "rx_policy_changed": False,
                "tx_policy_changed": False,
                "schema_version": 1,
                "snapshot_property": "NativeRxPreOwnerSnapshot",
                "source_header_sha256": self.source_map[
                    "native/rx_preowner_observation.hpp"],
            },
        }
        self.build_raw = self._json(self.build)
        self.build_path = candidate_binding.default_build_receipt_path(
            root, self.CANDIDATE)
        self._write_private(self.build_path, self.build_raw)
        self.metadata = finalizer.build_metadata(
            minimum_boot_epoch_exclusive=1793400000,
            iwn_root=root,
            candidate=self.CANDIDATE,
            build_receipt=self.build_path,
            baseline_receipt=self.baseline_path,
        )
        self.private_root = candidate_binding.runtime_private_root(
            root, self.CANDIDATE)
        self.private_root.mkdir(mode=0o700)
        self.metadata_path = self.private_root / "native-controlled-probe-private.json"
        self._write_private(self.metadata_path, self._json(self.metadata))

    @staticmethod
    def _sha(path: Path) -> str:
        return CandidateFixture._sha_bytes(path.read_bytes())

    @staticmethod
    def _sha_bytes(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    @staticmethod
    def _json(value: dict) -> bytes:
        return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

    @staticmethod
    def _write_private(path: Path, raw: bytes) -> None:
        path.write_bytes(raw)
        path.chmod(0o600)

    def rewrite_metadata(self, updates: dict) -> None:
        current = json.loads(self.metadata_path.read_text())
        current.update(updates)
        self._write_private(self.metadata_path, self._json(current))


class CandidateBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="candidate-binding-host-")
        self.root = Path(self.temp.name)
        self.fixture = CandidateFixture(self.root)
        self._old_iwn = (coordinator.IWN_ROOT, worker.IWN_ROOT)
        coordinator.IWN_ROOT = self.root
        worker.IWN_ROOT = self.root

    def tearDown(self):
        coordinator.IWN_ROOT, worker.IWN_ROOT = self._old_iwn
        self.temp.cleanup()

    def test_test091_receipt_loads_through_coordinator_and_native_worker(self):
        metadata, build, receipt_sha, build_path = coordinator._validate_bundle(
            self.fixture.metadata_path, os.getuid(), protocol)
        self.assertEqual(metadata["candidate"], self.fixture.CANDIDATE)
        self.assertEqual(build["candidate"], self.fixture.CANDIDATE)
        self.assertEqual(metadata["expected_loaded_uuid"], self.fixture.UUID)
        self.assertEqual(receipt_sha, hashlib.sha256(self.fixture.build_raw).hexdigest())
        self.assertEqual(build_path, self.fixture.build_path)
        loaded = worker._load_private_bundle(
            self.fixture.metadata_path, pwd.getpwuid(os.getuid()))
        self.assertEqual(loaded[0]["candidate"], self.fixture.CANDIDATE)
        self.assertEqual(loaded[5]["binary_sha256"], self.fixture.build["binary_sha256"])

    def test_cross_candidate_metadata_is_rejected_before_claim(self):
        self.fixture.rewrite_metadata({"candidate": "25G332-Test090"})
        with self.assertRaises(coordinator.CoordinatorError) as error:
            coordinator._validate_bundle(self.fixture.metadata_path, os.getuid(), protocol)
        self.assertEqual(error.exception.code, "CONTROLLED_METADATA_PATH_INVALID")
        self.assertFalse((self.root / "claims").exists())

    def test_uuid_and_binary_sha_mismatches_fail_closed_at_load_entry(self):
        wrong_uuid = "A12DAA90-1183-4C72-AB15-3E30721E5E91"
        self.fixture.rewrite_metadata({"expected_loaded_uuid": wrong_uuid})
        with self.assertRaises(coordinator.CoordinatorError) as error:
            coordinator._validate_bundle(self.fixture.metadata_path, os.getuid(), protocol)
        self.assertEqual(error.exception.code, "CANDIDATE_BINDING_FAILED")
        with self.assertRaises(worker.NativeCaptureError) as error:
            worker._load_private_bundle(
                self.fixture.metadata_path, pwd.getpwuid(os.getuid()))
        self.assertEqual(error.exception.code, "CANDIDATE_BINDING_FAILED")
        self.assertFalse((self.root / "claims").exists())

        self.fixture.rewrite_metadata({"expected_loaded_uuid": self.fixture.UUID})
        metadata = json.loads(self.fixture.metadata_path.read_text())
        metadata["source_binding"]["expected_binary_sha256"] = "f" * 64
        CandidateFixture._write_private(
            self.fixture.metadata_path, CandidateFixture._json(metadata))
        with self.assertRaises(coordinator.CoordinatorError) as error:
            coordinator._validate_bundle(self.fixture.metadata_path, os.getuid(), protocol)
        self.assertEqual(error.exception.code, "CANDIDATE_BINDING_FAILED")

    def test_replacing_same_tag_baseline_receipt_is_rejected(self):
        replacement = {
            "candidate": self.fixture.BASELINE,
            "status": "built_offline",
            "installed": False,
            "replacement": True,
        }
        CandidateFixture._write_private(
            self.fixture.baseline_path, CandidateFixture._json(replacement))
        with self.assertRaises(ValueError):
            finalizer.validate_receipts(
                iwn_root=self.root, candidate=self.fixture.CANDIDATE,
                build_receipt=self.fixture.build_path,
                baseline_receipt=self.fixture.baseline_path)

    def test_finalizer_rejects_same_tag_receipt_with_wrong_binary_sha(self):
        mutated = dict(self.fixture.build)
        mutated["binary_sha256"] = "f" * 64
        CandidateFixture._write_private(
            self.fixture.build_path, CandidateFixture._json(mutated))
        with self.assertRaisesRegex(ValueError, "archive contents differ"):
            finalizer.validate_receipts(
                iwn_root=self.root, candidate=self.fixture.CANDIDATE,
                build_receipt=self.fixture.build_path,
                baseline_receipt=self.fixture.baseline_path)

    def test_actual_shared_boot_claim_rejects_a_second_claim(self):
        capture = worker.capture_module()
        account = type("Account", (), {
            "pw_uid": os.getuid(), "pw_dir": str(self.root),
        })()
        boot_epoch = 1793400001
        self.assertTrue(worker._claim_availability(capture, account, boot_epoch)["available"])
        capture.consume_boot_claim(
            capture._claim_directory(account), boot_epoch,
            "0123456789abcdef0123456789abcdef")
        with self.assertRaises(worker.NativeCaptureError) as error:
            worker._claim_availability(capture, account, boot_epoch)
        self.assertEqual(error.exception.code, "SHARED_BOOT_CLAIM_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
