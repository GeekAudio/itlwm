#!/usr/bin/env python3
"""Bind Test126 artifacts, then reuse the unchanged bounded Test111 runner.

Test126 built the enabled profile, not the 72-profile legacy matrix. Validate
its actual archive and deployment receipt without rewriting that build history.
The unchanged Test124 echo binary is reused with its original source receipt.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "developer-tools/test124"))
import coordinate_directed_test124 as previous

shared = previous.shared
BASE = ROOT.parent.parent
PRIVATE = BASE / "RuntimeTest126/research/preparation-private"
PEER_DIR = BASE / "RuntimeTest124/research/preparation-private/tools"
BUILD = "25G416-Test126"
UUID = "1FED8332-59C2-3FA2-B01E-E1C44D90413C"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_receipt(path):
    return previous._private_json(path, private_dir=path.parent, max_bytes=65536)


def validate(config_path):
    build, raw = read_receipt(PRIVATE / "test126-build-private.json")
    deployment, _ = read_receipt(PRIVATE.parent / "test126-deployment-private.json")
    if (build.get("candidate") != BUILD or build.get("mach_o_uuid") != UUID or
            build.get("full_enabled_profile_build_passed") is not True or
            build.get("strict_signature_passed") is not True or
            build.get("independent_firmware_review_passed") is not True):
        raise ValueError("Test126 build evidence mismatch")
    if (deployment.get("candidate") != BUILD or deployment.get("mach_o_uuid") != UUID or
            deployment.get("status") != "deployed_waiting_reboot_disarmed" or
            deployment.get("build_report_sha256") != digest(raw) or
            deployment.get("binary_sha256") != build.get("binary_sha256") or
            deployment.get("remount_readback_verified") is not True or
            deployment.get("config_unchanged") is not True or
            deployment.get("automatic_reboot") is not False or
            deployment.get("rf_triggered") is not False):
        raise ValueError("Test126 deployment binding mismatch")
    archive = PRIVATE / "AirportItlwm-Test126.zip"
    if archive.is_symlink() or digest(archive.read_bytes()) != build.get("archive_sha256"):
        raise ValueError("Test126 archive changed")
    with zipfile.ZipFile(archive) as z:
        binary = z.read("AirportItlwm.kext/Contents/MacOS/AirportItlwm")
        info_raw = z.read("AirportItlwm.kext/Contents/Info.plist")
    info = plistlib.loads(info_raw)
    if (digest(binary) != build.get("binary_sha256") or
            digest(info_raw) != build.get("info_plist_sha256") or
            previous._macho_uuids(binary) != {UUID} or
            info.get("AirportTahoeBuild") != BUILD or
            info.get("CFBundleIdentifier") != "org.geekaudio.AirportItlwm"):
        raise ValueError("Test126 archive identity mismatch")
    profile = info["IOKitPersonalities"]["NetworkController"]
    for key in ("NativeP2PProbe", "NativeP2PManualTrigger", "NativeAwdlResidentEnabled",
                "NativeP2PRx149ObservationOnly", "NativeP2PRx149DataInputExperiment",
                "NativeP2PDirectedPrepareCompiled", "NativeP2PDirectedPrepareEnabled",
                "NativeP2PDirectedDataCompiled", "NativeP2PDirectedDataEnabled"):
        if profile.get(key) is not True:
            raise ValueError("Test126 enabled profile mismatch: " + key)
    for key in ("NativeP2PTxProbe", "NativeAwdlReplyShadowEnabled",
                "NativeAwdlDiscoveryExperimentEnabled", "NativeAwdlTxEvidenceEnabled"):
        if profile.get(key) is not False:
            raise ValueError("Test126 competing profile enabled: " + key)
    sources = build.get("source_files_sha256", {})
    for name in ("itlwm/hal_iwx/ItlIwx.cpp", "itlwm/hal_iwx/ItlIwx.hpp",
                 "itlwm/hal_iwx/ItlIwxP2PProbe.cpp", "itlwm/hal_iwx/ItlIwxP2PAction.cpp",
                 "itlwm/hal_iwx/ItlIwxP2PData.hpp", "itlwm/hal_iwx/if_iwxvar.h",
                 "native/iwx_mcc_refresh_policy.hpp", "native/p2p_directed_data_rx_input.hpp",
                 "native/awdl_native_bsd_data_25G332.cpp",
                 "AirportItlwm/AirportItlwm-Tahoe-Info.plist"):
        if digest((ROOT / name).read_bytes()) != sources.get(name):
            raise ValueError("Test126 committed driver source changed")
    config = shared.read_private_config(config_path)
    config, _ = shared.validate_config(config, build_id=BUILD)
    if config["expected_uuid"] != UUID:
        raise ValueError("Test126 runtime UUID mismatch")
    helper, _ = read_receipt(PRIVATE / "tools/test126-helper-build-private.json")
    for receipt, schema, candidate, paths, key in (
        (helper, "test126-mode4-helper-build/v1", BUILD, previous.HELPER_SOURCES, "helper"),
    ):
        binary_key = "helper_path_resolved" if key == "helper" else "peer_binary_path_resolved"
        hash_key = "helper_sha256" if key == "helper" else "peer_sha256"
        if (receipt.get("schema") != schema or receipt.get("candidate") != candidate or
                receipt.get("status") != "built_offline" or
                receipt.get("binary_path") != config[binary_key] or
                receipt.get("binary_sha256") != config[hash_key] or
                set(receipt.get("source_hashes", {})) != set(paths)):
            raise ValueError(key + " build receipt mismatch")
        if any(digest((ROOT / name).read_bytes()) != receipt["source_hashes"][name] for name in paths):
            raise ValueError(key + " source dependency changed")
    # This is the unchanged Test124 peer. Keep its original wire/ELF contract
    # and build receipt, instead of relabelling the binary for Test126.
    previous._validate_peer_receipt(
        PEER_DIR / "test124-peer-build-private.json", config,
        private_dir=PEER_DIR.parent)
    return config


def verify_target_os():
    # Review is recorded separately: the deployed build receipt is immutable
    # and did not claim a new ABI review or a 72-profile matrix build.
    review, _ = read_receipt(PRIVATE / "test126-target-os-review-private.json")
    build_raw = (PRIVATE / "test126-build-private.json").read_bytes()
    build = json.loads(build_raw)
    deployment_raw = (PRIVATE.parent / "test126-deployment-private.json").read_bytes()
    base, base_raw = read_receipt(PEER_DIR.parent / "test124-build-private.json")
    abi_report = Path(base["abi_review_report_path"])
    if (review.get("schema") != "test126-target-os-review/v1" or
            review.get("candidate") != BUILD or review.get("mach_o_uuid") != UUID or
            review.get("target_os_build") != "25G416" or
            review.get("review_passed") is not True or
            review.get("build_receipt_sha256") != digest(build_raw) or
            review.get("deployment_receipt_sha256") != digest(deployment_raw) or
            review.get("source_commit") != build.get("source_commit") or
            review.get("binary_sha256") != build.get("binary_sha256") or
            review.get("base_build_receipt_sha256") != digest(base_raw) or
            review.get("base_source_commit") != base.get("source_commit") or
            base.get("target_os_build") != "25G416" or
            base.get("target_os_abi_review_passed") is not True or
            review.get("base_abi_report_sha256") != base.get("abi_review_report_sha256") or
            digest(abi_report.read_bytes()) != base.get("abi_review_report_sha256")):
        raise ValueError("Test126 target OS review binding mismatch")
    actual_os = subprocess.check_output(
        ["/usr/sbin/sysctl", "-n", "kern.osversion"], text=True).strip()
    if actual_os != review["target_os_build"]:
        raise ValueError("Test126 OS build mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    config = validate(args.config)
    if args.run:
        verify_target_os()
        result = shared.execute_run(config, build_id=BUILD)
    else:
        result = shared.make_plan(config, build_id=BUILD)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if not args.run or result.get("orchestration_completed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
