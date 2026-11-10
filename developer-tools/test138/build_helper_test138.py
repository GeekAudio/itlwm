#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate the bound, one-shot Test138 helper without installing a kext."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_ID = "25G416-Test138"
BUNDLE_ID = "org.geekaudio.AirportItlwm"
DEFAULT_OUTPUT_DIR = (
    REPO_ROOT.parent.parent / "RuntimeTest138/research/preparation-private/tools"
)
_GENERATOR_PATH = REPO_ROOT / "developer-tools/test137/build_helper_test137.py"
_SPEC = importlib.util.spec_from_file_location(
    "build_helper_test137_for_test138", _GENERATOR_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("Test137 helper generator is unavailable")
_TEST137 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_TEST137)
UUID_PATTERN = _TEST137.UUID_PATTERN


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_x86_64_uuid(output: str) -> str:
    matches = UUID_PATTERN.findall(output)
    if len(matches) != 1:
        raise ValueError("expected exactly one x86_64 Mach-O UUID")
    return matches[0].upper()


def inspect_kext(bundle: Path, *, dwarfdump_output: str | None = None,
                 dwarfdump: str = "xcrun") -> tuple[str, str, Path]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("kext bundle must be an existing non-symlink directory")
    info_path = bundle / "Contents/Info.plist"
    if info_path.is_symlink() or not info_path.is_file():
        raise ValueError("kext Info.plist is missing or is a symlink")
    info = plistlib.loads(info_path.read_bytes())
    if info.get("CFBundleIdentifier") != BUNDLE_ID:
        raise ValueError("unexpected kext bundle identifier")
    personality = info.get("IOKitPersonalities", {}).get("NetworkController", {})
    if personality.get("NativeTestBuild") != BUILD_ID:
        raise ValueError("kext is not tagged for 25G416-Test138")
    expected_flags = {
        "NativeAwdlDiscoveryExperimentEnabled": True,
        "NativeAwdlDiscoveryMifCurrentSlotEnabled": True,
        "NativeAwdlDiscoveryRxInputEnabled": True,
        "NativeAwdlDiscoveryCurrentAwFallbackEnabled": True,
        "NativeAwdlQmNoKnownAnswerCompiled": True,
        "NativeAwdlQmNormalPriorityCompiled": False,
    }
    bad_flags = [key for key, expected in expected_flags.items()
                 if personality.get(key) is not expected]
    if bad_flags:
        raise ValueError("Test138 personality flags mismatch: " + ", ".join(bad_flags))
    executable_name = info.get("CFBundleExecutable") or "AirportItlwm"
    if not isinstance(executable_name, str) or Path(executable_name).name != executable_name:
        raise ValueError("invalid CFBundleExecutable")
    executable = bundle / "Contents/MacOS" / executable_name
    if executable.is_symlink() or not executable.is_file():
        raise ValueError("kext executable is missing or is a symlink")
    if dwarfdump_output is None:
        result = subprocess.run(
            [dwarfdump, "dwarfdump", "--uuid", str(executable)],
            check=True, capture_output=True, text=True)
        dwarfdump_output = result.stdout
    return BUILD_ID, extract_x86_64_uuid(dwarfdump_output), executable


def render_helper(template: str, expected_uuid: str) -> str:
    try:
        normalized_uuid = str(__import__("uuid").UUID(expected_uuid)).upper()
    except (ValueError, AttributeError) as error:
        raise ValueError("invalid helper UUID") from error

    source = _TEST137.render_helper(template, normalized_uuid)
    source = source.replace('private let expectedBuild = "25G416-Test137"',
                            f'private let expectedBuild = "{BUILD_ID}"')
    if source.count(f'private let expectedBuild = "{BUILD_ID}"') != 1:
        raise ValueError("Test137 build binding changed")

    enabled_old = ('    "NativeAwdlDiscoveryRxInputEnabled",\n'
                   '    "NativeAwdlDiscoveryCurrentAwFallbackEnabled",\n]')
    enabled_new = ('    "NativeAwdlDiscoveryRxInputEnabled",\n'
                   '    "NativeAwdlDiscoveryCurrentAwFallbackEnabled",\n'
                   '    "NativeAwdlQmNoKnownAnswerCompiled",\n]')
    if source.count(enabled_old) != 1:
        raise ValueError("Test137 enabled profile changed")
    source = source.replace(enabled_old, enabled_new, 1)

    scope_old = "Test137 current-AW fallback-on manual ARM"
    scope_new = "Test138 no-Known-Answer manual ARM"
    if source.count(scope_old) != 1:
        raise ValueError("Test137 helper scope marker changed")
    source = source.replace(scope_old, scope_new, 1)
    source = source.replace("Test137", "Test138")
    return source


def _prepare_private_directory(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError("private output directory may not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def build_helper(bundle: Path, output_dir: Path) -> dict:
    build_id, expected_uuid, _executable = inspect_kext(bundle)
    template = _TEST137.TEMPLATE.read_bytes()
    generated = render_helper(template.decode("utf-8"), expected_uuid)
    _prepare_private_directory(output_dir)
    source_path = output_dir / "query_capture_test138.generated.swift"
    source_staged = output_dir / "query_capture_test138.generated.building.swift"
    binary_path = output_dir / "query_capture_test138"
    binary_staged = output_dir / "query_capture_test138.building"
    log_path = output_dir / "helper-build.log"
    receipt_path = output_dir / "test138-helper-build-private.json"
    for path in (source_path, source_staged, binary_path, binary_staged,
                 log_path, receipt_path):
        if path.is_symlink():
            raise ValueError("private output file may not be a symlink")

    source_staged.write_text(generated, encoding="utf-8")
    source_staged.chmod(0o600)
    command = ["xcrun", "swiftc", str(source_staged), "-o", str(binary_staged)]
    try:
        with log_path.open("w", encoding="utf-8") as log:
            log.write(json.dumps(command) + "\n")
            log.flush()
            subprocess.run(command, cwd=REPO_ROOT, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
        if _TEST137.TEMPLATE.read_bytes() != template:
            raise RuntimeError("Test137 helper template changed during generation")
        source_staged.replace(source_path)
        source_path.chmod(0o600)
        binary_staged.replace(binary_path)
        binary_path.chmod(0o700)
        log_path.chmod(0o600)
    except Exception:
        source_staged.unlink(missing_ok=True)
        binary_staged.unlink(missing_ok=True)
        raise

    compiler = subprocess.run(["xcrun", "swiftc", "--version"],
                              capture_output=True, text=True, check=True).stdout.strip()
    receipt = {
        "schema": "test138-one-shot-helper-build/v1",
        "candidate": build_id,
        "expected_uuid": expected_uuid,
        "source_template": str(_TEST137.TEMPLATE),
        "source_template_sha256": hashlib.sha256(template).hexdigest(),
        "generated_source_path": str(source_path),
        "generated_source_sha256": sha256(source_path),
        "binary_path": str(binary_path),
        "binary_sha256": sha256(binary_path),
        "compiler": compiler,
        "profile_binding": {
            "NativeAwdlDiscoveryMifCurrentSlotEnabled": True,
            "NativeAwdlDiscoveryCurrentAwFallbackEnabled": True,
            "NativeAwdlQmNoKnownAnswerCompiled": True,
            "NativeAwdlQmNormalPriorityCompiled": False,
        },
        "arm_requested": False,
        "installed": False,
        "rf_tested": False,
    }
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
    receipt_path.chmod(0o600)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kext", required=True, help="frozen Test138 kext bundle")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help="private helper output directory")
    args = parser.parse_args(argv)
    try:
        receipt = build_helper(Path(args.kext), args.output_dir)
    except (OSError, ValueError, subprocess.CalledProcessError, RuntimeError) as error:
        parser.exit(1, f"Test138 helper build failed: {error}\n")
    print(json.dumps({
        "status": "built_offline",
        "receipt_path": str(args.output_dir / "test138-helper-build-private.json"),
        "binary_path": receipt["binary_path"],
        "binary_sha256": receipt["binary_sha256"],
        "expected_uuid": receipt["expected_uuid"],
        "arm_requested": False,
        "installed": False,
        "rf_tested": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
