#!/usr/bin/env python3
"""Test119 wrapper around the frozen Test104 controlled-capture worker.

It reuses the one-use Test104 RX149 arm/START gate and sender/collector flow,
changes only the runtime metadata root to Test119, and adds same-ioreg-snapshot
early-RX counters. It does not contact OpenWrt itself or arm until invoked by
the candidate-bound coordinator after its explicit --run gate.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import pwd
import sys


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
TEST104_WORKER_PATH = REPO_ROOT / "developer-tools/test104/native_controlled_capture_test104.py"
TEST104_DIR = REPO_ROOT / "developer-tools/test104"
TEST104_HELPER = REPO_ROOT / "developer-tools/test104/arm_p2p_rx149_test104.swift"
EARLY_RX_PATH = TOOL_DIR / "early_rx_stage_test119.py"
IWN_ROOT: Path | None = None
METADATA_PATH: Path | None = None

# The parent coordinator has Test104 on its own sys.path, but this worker is a
# new Python process. Add the import directory here before dynamically loading
# the frozen Test104 worker, whose top-level imports include hcmd_rx_trace.
if str(TEST104_DIR) not in sys.path:
    sys.path.insert(0, str(TEST104_DIR))


def _load(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("TEST119_COMPONENT_UNAVAILABLE:" + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST119_COMPONENT_UNAVAILABLE:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _instrument_worker(module, iwn_root: Path) -> None:
    early = _load("test119_early_rx_stage", EARLY_RX_PATH)
    binding = _load("test119_worker_binding", TOOL_DIR / "rx149_binding_test119.py")
    original_run = module._run_worker_with_deferred_terminal
    original_append = module._atomic_append_hcmd_report

    def run_with_test119_counters(worker_namespace, worker_main, publish_report,
                                  **kwargs):
        if "sampler" in kwargs:
            raise RuntimeError("TEST119_SAMPLER_OVERRIDE_NOT_ALLOWED")
        return original_run(
            worker_namespace, worker_main, publish_report,
            sampler=early.sample_once, **kwargs)

    def append_with_test119_counters(output_dir, evidence):
        samples = evidence.get("samples") if isinstance(evidence, dict) else None
        if not isinstance(samples, list):
            raise RuntimeError("TEST119_COUNTER_SAMPLES_MISSING")
        evidence["early_rx_stage_observation"] = early.summarize(samples)
        evidence["early_rx_observer_sha256"] = hashlib.sha256(
            EARLY_RX_PATH.read_bytes()).hexdigest()
        return original_append(output_dir, evidence)

    module._run_worker_with_deferred_terminal = run_with_test119_counters
    module._atomic_append_hcmd_report = append_with_test119_counters
    original_configure = module.configure_worker

    def configure_test119_worker(namespace: dict, *, iwn_root: Path):
        original_configure(namespace, iwn_root=iwn_root)
        metadata_path = METADATA_PATH or binding.METADATA
        private_root = metadata_path.parent
        namespace["PRIVATE_ROOT"] = private_root
        namespace["DEFAULT_METADATA"] = metadata_path
        namespace["HELPER_SOURCE"] = TEST104_HELPER
        old_load = namespace.get("_load_module")
        if not callable(old_load):
            raise RuntimeError("TEST119_WORKER_MODULE_LOADER_UNAVAILABLE")

        def load_with_test119_metadata(name, path):
            loaded = old_load(name, path)
            if Path(path).name == "test087_controlled.py":
                loaded.IWN_ROOT = iwn_root
                loaded.PRIVATE_ROOT = private_root
                loaded.DEFAULT_METADATA = (
                    private_root / "native-controlled-probe-private.json")
                loaded.HELPER_SOURCE = TEST104_HELPER
            return loaded

        namespace["_load_module"] = load_with_test119_metadata

    original_load_worker = module.load_test087_worker

    def load_test119_worker():
        worker = original_load_worker()
        worker.HELPER_SOURCE = TEST104_HELPER
        metadata_path = METADATA_PATH or binding.METADATA
        worker.DEFAULT_METADATA = metadata_path
        worker.PRIVATE_ROOT = metadata_path.parent

        def metadata_path_allowed(path):
            path = Path(path)
            return (path.is_absolute() and path == metadata_path and
                    path.name == "native-controlled-probe-private.json")

        def load_private_bundle(path, account):
            if Path(path) != metadata_path:
                raise worker.NativeCaptureError("TEST119_METADATA_PATH_MISMATCH")
            try:
                metadata, build, build_raw, build_path = binding.validate_bundle(path)
            except Exception as error:
                raise worker.NativeCaptureError(
                    "TEST119_BUNDLE_REJECTED:" + str(error)[:80]) from error
            source_binding = metadata["source_binding"]
            frozen = {
                "expected_loaded_uuid": build["mach_o_uuid"],
                "expected_binary_sha256": build["binary_sha256"],
                "expected_info_plist_sha256": build["info_plist_sha256"],
                "build_report": str(build_path),
                "source_sha256": source_binding["production_freeze_source_sha256"],
            }
            return (metadata, source_binding, frozen, build_path,
                    binding.DEPLOYMENT_RECEIPT, build, build_raw,
                    binding.sha256(build_raw))

        def native_preflight(template, source_binding, frozen_metadata,
                             build_path, deployment_path, boot_epoch, account,
                             capture, protocol, build_receipt, build_receipt_raw):
            if (template.get("candidate") != binding.CANDIDATE or
                    template.get("profile") != binding.PROFILE or
                    template.get("status") != "prepared_disarmed" or
                    template.get("armed") is not False or
                    template.get("retry_allowed") is not False or
                    template.get("minimum_boot_epoch_exclusive", boot_epoch) >= boot_epoch or
                    template.get("expected_loaded_uuid") != build_receipt.get("mach_o_uuid") or
                    binding.sha256(build_receipt_raw) != source_binding.get("build_receipt_sha256")):
                raise worker.NativeCaptureError("TEST119_DISARMED_METADATA_GATE_FAILED")
            try:
                identity_receipt = binding._verify_archive(build_receipt)
                loaded_text = worker.subprocess.check_output(
                    ["/usr/bin/kmutil", "showloaded", "--list-only"],
                    text=True, stderr=worker.subprocess.DEVNULL, timeout=10)
                loaded_uuids = worker.re.findall(
                    r"org\.geekaudio\.AirportItlwm \([^)]*\) ([0-9A-F-]{36})",
                    loaded_text)
            except Exception as error:
                raise worker.NativeCaptureError("TEST119_ARCHIVE_OR_LOADED_IDENTITY_FAILED") from error
            expected_uuid = build_receipt.get("mach_o_uuid")
            if loaded_uuids != [expected_uuid]:
                raise worker.NativeCaptureError("TEST119_LOADED_UUID_MISMATCH")
            identity = {
                "archive_uuid": identity_receipt["mach_o_uuid"],
                "loaded_uuid": loaded_uuids[0],
                "loaded_uuid_matches_receipt": True,
                "archive_binary_sha256_verified": True,
                "archive_info_plist_sha256_verified": True,
                "expected_archive_binary_sha256": build_receipt["binary_sha256"],
            }
            capture.HELPER_SOURCE = TEST104_HELPER
            try:
                wrapper = capture.properties("IOPCIEDeviceWrapper")
                if wrapper.get("NativeTestBuild") != binding.CANDIDATE:
                    raise worker.NativeCaptureError("TEST119_WRAPPER_BUILD_MISMATCH")
                initial = capture.properties("AirportItlwm")
                if capture.profile_problems(initial, selected=False):
                    raise worker.NativeCaptureError("TEST119_RX149_PROFILE_NOT_READY")
                if (initial.get("NativeTestBuild") != binding.CANDIDATE or
                        initial.get("NativePowerReady") != 1 or
                        initial.get("NativeRxPreOwnerObservation") is not True):
                    raise worker.NativeCaptureError("TEST119_DRIVER_PROFILE_NOT_READY")
                for key in ("NativeP2PManualArmed", "NativeP2PProbeAttempted",
                            "NativeP2PProbeResourceMayExist"):
                    if type(initial.get(key)) is not int or initial[key] != 0:
                        raise worker.NativeCaptureError("TEST119_ONE_SHOT_ALREADY_USED")
                for key in (worker.PREOWNER_ARM_ACCEPTED_KEY,
                            worker.PREOWNER_PUBLISHED_KEY):
                    if initial.get(key) not in (None, 0):
                        raise worker.NativeCaptureError("TEST119_PREOWNER_ALREADY_USED")
                if (initial.get(worker.DATA_TX_PENDING) != 0 or
                        initial.get("NativeAwdlDataTxSubmitted") != 0):
                    raise worker.NativeCaptureError("TEST119_HOST_DATA_TX_NOT_ZERO")
                if capture.awdl_data_rx_snapshot(initial).get("complete") is not True:
                    raise worker.NativeCaptureError("TEST119_RX_COUNTERS_UNAVAILABLE")
                rx_receipt = capture.awdl_data_rx149_receipt_snapshot(initial)
                if capture.receipt_preflight_problem(rx_receipt):
                    raise worker.NativeCaptureError("TEST119_RX149_RECEIPT_PREFLIGHT_FAILED")
                p2p_tx_zero = capture.tx_zero_evidence(initial, initial)
                if p2p_tx_zero.get("valid") is not True:
                    raise worker.NativeCaptureError("TEST119_P2P_TX_NOT_ZERO")
                host_tx_zero = worker._validate_tx_zero(capture, initial)
                if host_tx_zero.get("valid") is not True:
                    raise worker.NativeCaptureError("TEST119_HOST_TX_NOT_ZERO")
                claim = worker._claim_availability(capture, account, boot_epoch)
            except worker.NativeCaptureError:
                raise
            except Exception as error:
                raise worker.NativeCaptureError("TEST119_NATIVE_PREFLIGHT_FAILED") from error
            return {"identity": identity, "initial": initial,
                    "p2p_tx_zero": p2p_tx_zero,
                    "host_tx_zero": host_tx_zero, "claim": claim,
                    "configured_armed": False,
                    "legacy_validation_copy_armed": False}

        worker._metadata_path_allowed = metadata_path_allowed
        worker._load_private_bundle = load_private_bundle
        worker._native_preflight = native_preflight
        return worker

    module.load_test087_worker = load_test119_worker

    module.configure_worker = configure_test119_worker


def main() -> int:
    global METADATA_PATH
    args = list(sys.argv[1:])
    if "--metadata" in args:
        metadata_index = args.index("--metadata")
        if metadata_index + 1 < len(args):
            METADATA_PATH = Path(args[metadata_index + 1]).expanduser()
    if "--iwn-root" not in args:
        print("IWN_ROOT_REQUIRED", file=sys.stderr)
        return 2
    index = args.index("--iwn-root")
    if index + 1 >= len(args):
        print("IWN_ROOT_REQUIRED", file=sys.stderr)
        return 2
    root = Path(args[index + 1]).expanduser()
    del args[index:index + 2]
    if not root.is_absolute() or root.is_symlink():
        print("IWN_ROOT_INVALID", file=sys.stderr)
        return 2
    try:
        root = root.resolve(strict=True)
        worker = _load("test119_test104_capture_worker", TEST104_WORKER_PATH)
        _instrument_worker(worker, root)
    except (OSError, RuntimeError) as error:
        print(str(error)[:120], file=sys.stderr)
        return 2
    # Test104 worker main keeps its existing one-use token/terminal protocol;
    # only the candidate-private metadata path and same-cut sampler differ.
    sys.argv = [sys.argv[0], *args, "--iwn-root", str(root)]
    return int(worker.main())


if __name__ == "__main__":
    raise SystemExit(main())
