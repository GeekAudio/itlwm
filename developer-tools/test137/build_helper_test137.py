#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate and compile the one-shot Test137 helper from a frozen kext."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = REPO_ROOT / "developer-tools/test136/query_capture_test136.swift"
BUILD_ID = "25G416-Test137"
DEFAULT_OUTPUT_DIR = (
    REPO_ROOT.parent.parent / "RuntimeTest137/research/preparation-private/tools"
)
BUNDLE_ID = "org.geekaudio.AirportItlwm"
UUID_PATTERN = re.compile(
    r"^UUID: ([0-9A-Fa-f-]{36}) \(x86_64\)(?:[ \t].*)?$", re.MULTILINE)
TERMINAL_FIELDS = (
    "ContextGeneration", "PowerGeneration", "StationGeneration",
    "RocGeneration", "DriverGeneration", "BeginResult", "CloseResult",
    "ObserverState", "PublishFirstStatus", "PublishStatus", "Published",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_x86_64_uuid(dwarfdump_output: str) -> str:
    matches = UUID_PATTERN.findall(dwarfdump_output)
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
        raise ValueError("kext is not tagged for 25G416-Test137")
    executable_name = info.get("CFBundleExecutable") or "AirportItlwm"
    if not isinstance(executable_name, str) or Path(executable_name).name != executable_name:
        raise ValueError("invalid CFBundleExecutable")
    executable = bundle / "Contents/MacOS" / executable_name
    if executable.is_symlink() or not executable.is_file():
        raise ValueError("kext executable is missing or is a symlink")

    if dwarfdump_output is None:
        result = subprocess.run(
            [dwarfdump, "dwarfdump", "--uuid", str(executable)],
            check=True, capture_output=True, text=True,
        )
        dwarfdump_output = result.stdout
    return BUILD_ID, extract_x86_64_uuid(dwarfdump_output), executable


def render_helper(template: str, expected_uuid: str) -> str:
    try:
        normalized_uuid = str(__import__("uuid").UUID(expected_uuid)).upper()
    except (ValueError, AttributeError) as error:
        raise ValueError("invalid helper UUID") from error

    build_old = 'private let expectedBuild = "25G416-Test136"'
    build_new = f'private let expectedBuild = "{BUILD_ID}"'
    if template.count(build_old) != 1:
        raise ValueError("Test136 template build binding changed")
    result = template.replace(build_old, build_new, 1)

    uuid_binding = re.compile(
        r'private let expectedUUID = "[0-9A-Fa-f-]{36}"')
    if len(uuid_binding.findall(result)) != 1:
        raise ValueError("Test136 template UUID binding changed")
    result = uuid_binding.sub(
        f'private let expectedUUID = "{normalized_uuid}"', result, count=1)

    enabled_old = '    "NativeAwdlDiscoveryRxInputEnabled",\n]'
    enabled_new = ('    "NativeAwdlDiscoveryRxInputEnabled",\n'
                   '    "NativeAwdlDiscoveryCurrentAwFallbackEnabled",\n]')
    disabled_old = ('    "NativeAwdlDiscoveryCurrentAwFallbackEnabled",\n'
                    '    "NativeAwdlQmNormalPriorityCompiled",')
    disabled_new = '    "NativeAwdlQmNormalPriorityCompiled",'
    if result.count(enabled_old) != 1 or result.count(disabled_old) != 1:
        raise ValueError("Test136 template discovery profile changed")
    result = result.replace(enabled_old, enabled_new, 1)
    result = result.replace(disabled_old, disabled_new, 1)

    terminal_fields_source = (
        "private let discoveryRxTerminalFields = [\n" +
        "    " + ", ".join(f'\"{field}\"' for field in TERMINAL_FIELDS) +
        ",\n]\n\n"
    )
    marker = "private func diagnosticPropertyKeys() -> [String] {"
    if result.count(marker) != 1:
        raise ValueError("Test136 template diagnostic key function changed")
    result = result.replace(marker, terminal_fields_source + marker, 1)

    key_marker = ('    keys.append(contentsOf: discoveryRxWindowFields.map {\n'
                  '        "NativeAwdlDiscoveryRxWindow" + $0\n'
                  '    })\n    return keys')
    key_replacement = ('    keys.append(contentsOf: discoveryRxWindowFields.map {\n'
                       '        "NativeAwdlDiscoveryRxWindow" + $0\n'
                       '    })\n'
                       '    keys.append(contentsOf: discoveryRxTerminalFields.map {\n'
                       '        "NativeAwdlDiscoveryRxWindowTerminal" + $0\n'
                       '    })\n    return keys')
    if result.count(key_marker) != 1:
        raise ValueError("Test136 template RX field collector changed")
    result = result.replace(key_marker, key_replacement, 1)

    receipt_marker = '        "expected_uuid": expectedUUID,\n'
    if result.count(receipt_marker) != 1:
        raise ValueError("Test136 template receipt identity field changed")
    result = result.replace(
        receipt_marker,
        receipt_marker + '        "current_aw_fallback_profile_enabled": true,\n', 1)
    scope_old = ('"scope": "One Bonjour IncludeP2P | IncludeAWDL browse plus one '
                 'Test136 manual ARM; local driver and ifnet receipts only.",')
    scope_new = ('"scope": "One Bonjour IncludeP2P | IncludeAWDL browse plus one '
                 'Test137 current-AW fallback-on manual ARM; local driver and '
                 'ifnet receipts only.",')
    if result.count(scope_old) != 1:
        raise ValueError("Test136 template scope marker changed")
    result = result.replace(scope_old, scope_new, 1)
    result = result.replace("Test136", "Test137")
    return result


def _prepare_private_directory(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError("private output directory may not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def build_helper(bundle: Path, output_dir: Path) -> dict:
    build_id, expected_uuid, _executable = inspect_kext(bundle)
    template_bytes = TEMPLATE.read_bytes()
    template_text = template_bytes.decode("utf-8")
    generated = render_helper(template_text, expected_uuid)

    _prepare_private_directory(output_dir)
    source_path = output_dir / "query_capture_test137.generated.swift"
    source_staged = output_dir / "query_capture_test137.generated.building.swift"
    binary_path = output_dir / "query_capture_test137"
    binary_staged = output_dir / "query_capture_test137.building"
    log_path = output_dir / "helper-build.log"
    receipt_path = output_dir / "test137-helper-build-private.json"
    for path in (source_path, source_staged, binary_path, binary_staged, log_path,
                 receipt_path):
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
        if TEMPLATE.read_bytes() != template_bytes:
            raise RuntimeError("Test136 helper template changed during generation")
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
        "schema": "test137-one-shot-helper-build/v1",
        "candidate": build_id,
        "uuid_source": "x86_64 Mach-O UUID from frozen kext executable",
        "expected_uuid": expected_uuid,
        "profile_delta_from_test136": {
            "NativeAwdlDiscoveryCurrentAwFallbackEnabled": True,
        },
        "collector_delta": [
            "NativeAwdlDiscoveryRxWindowTerminal" + field
            for field in TERMINAL_FIELDS
        ],
        "legacy_abi_decoder": "developer-tools/test136/test136_diagnostics.py",
        "binary_path": str(binary_path),
        "binary_sha256": sha256(binary_path),
        "generated_source_path": str(source_path),
        "generated_source_sha256": sha256(source_path),
        "template_path": str(TEMPLATE),
        "template_sha256": hashlib.sha256(template_bytes).hexdigest(),
        "build_command": command,
        "compiler": compiler,
        "installed": False,
        "arm_requested": False,
        "rf_tested": False,
    }
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
    receipt_path.chmod(0o600)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kext", required=True,
                        help="frozen Test137 AirportItlwm.kext bundle")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help="private helper output directory")
    args = parser.parse_args(argv)
    try:
        receipt = build_helper(Path(args.kext), args.output_dir)
    except (OSError, ValueError, subprocess.CalledProcessError, RuntimeError) as error:
        parser.exit(1, f"Test137 helper build failed: {error}\n")
    print(json.dumps({
        "status": "built_offline",
        "receipt_path": str(args.output_dir / "test137-helper-build-private.json"),
        "binary_path": receipt["binary_path"],
        "binary_sha256": receipt["binary_sha256"],
        "expected_uuid": receipt["expected_uuid"],
        "installed": False,
        "arm_requested": False,
        "rf_tested": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
