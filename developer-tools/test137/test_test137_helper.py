#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline Test137 tool binding and receipt-stage regressions."""

from __future__ import annotations

import importlib.util
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "build_helper_test137_under_test", HERE / "build_helper_test137.py")
assert SPEC is not None and SPEC.loader is not None
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
D_SPEC = importlib.util.spec_from_file_location(
    "test137_diagnostics_under_test", HERE / "test137_diagnostics.py")
assert D_SPEC is not None and D_SPEC.loader is not None
D = importlib.util.module_from_spec(D_SPEC)
D_SPEC.loader.exec_module(D)


class TestTest137Helper(unittest.TestCase):
    def test_x86_uuid_is_unique_and_arch_specific(self):
        text = (
            "UUID: 11111111-1111-1111-1111-111111111111 (arm64)\n"
            "UUID: 22222222-2222-2222-2222-222222222222 (x86_64) /tmp/AirportItlwm\n"
        )
        self.assertEqual(
            B.extract_x86_64_uuid(text),
            "22222222-2222-2222-2222-222222222222",
        )
        with self.assertRaises(ValueError):
            B.extract_x86_64_uuid(text.splitlines()[0])
        with self.assertRaises(ValueError):
            B.extract_x86_64_uuid(text + text.splitlines()[1] + "\n")

    def test_kext_identity_requires_exact_test137_tag_and_bundle(self):
        with tempfile.TemporaryDirectory(prefix="test137-kext-fixture-") as temp:
            bundle = Path(temp) / "AirportItlwm.kext"
            contents = bundle / "Contents"
            executable = contents / "MacOS/AirportItlwm"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"offline identity fixture")
            info = {
                "CFBundleIdentifier": B.BUNDLE_ID,
                "CFBundleExecutable": "AirportItlwm",
                "IOKitPersonalities": {
                    "NetworkController": {"NativeTestBuild": B.BUILD_ID}
                },
            }
            (contents / "Info.plist").write_bytes(plistlib.dumps(info))
            uuid_text = "UUID: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE (x86_64)\n"
            identity = B.inspect_kext(bundle, dwarfdump_output=uuid_text)
            self.assertEqual(identity[0], "25G416-Test137")
            self.assertEqual(identity[1], "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
            self.assertEqual(identity[2], executable)
            info["IOKitPersonalities"]["NetworkController"]["NativeTestBuild"] = "25G416-Test136"
            (contents / "Info.plist").write_bytes(plistlib.dumps(info))
            with self.assertRaises(ValueError):
                B.inspect_kext(bundle, dwarfdump_output=uuid_text)

    def test_generated_helper_changes_only_profile_binding_and_collectors(self):
        template = B.TEMPLATE.read_text(encoding="utf-8")
        source = B.render_helper(
            template, "12345678-1234-1234-1234-1234567890ab")
        enabled_start = source.index("private let enabledFlags = [")
        disabled_start = source.index("private let disabledFlags = [")
        receipt_start = source.index("private let receiptKeys = [")
        enabled = source[enabled_start:disabled_start]
        disabled = source[disabled_start:receipt_start]
        self.assertIn('"NativeAwdlDiscoveryCurrentAwFallbackEnabled"', enabled)
        self.assertNotIn('"NativeAwdlDiscoveryCurrentAwFallbackEnabled"', disabled)
        self.assertIn('private let expectedBuild = "25G416-Test137"', source)
        self.assertIn('private let expectedUUID = "12345678-1234-1234-1234-1234567890AB"', source)
        self.assertIn('"NativeAwdlDiscoveryRxWindowTerminal" + $0', source)
        self.assertIn('"current_aw_fallback_profile_enabled": true', source)
        self.assertIn("let maximumRunSeconds: UInt64 = 20", source)
        self.assertEqual(source.count("DNSServiceBrowse(&browseRef"), 1)
        self.assertEqual(source.count('"NativeP2PArmOnce": true'), 1)
        self.assertIn("Test137 current-AW fallback-on manual ARM", source)

    @unittest.skipUnless(shutil.which("xcrun"), "Xcode command line tools unavailable")
    def test_generated_helper_compiles_and_help_is_read_only(self):
        source = B.render_helper(
            B.TEMPLATE.read_text(encoding="utf-8"),
            "12345678-1234-1234-1234-1234567890ab")
        with tempfile.TemporaryDirectory(prefix="test137-helper-compile-") as temp:
            swift = Path(temp) / "query_capture_test137.swift"
            binary = Path(temp) / "query_capture_test137"
            swift.write_text(source, encoding="utf-8")
            subprocess.run(
                ["xcrun", "swiftc", str(swift), "-o", str(binary)], check=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            help_text = subprocess.run(
                [str(binary), "--help"], check=True, capture_output=True, text=True
            ).stdout
            self.assertIn("Test137", help_text)
            self.assertIn("25G416-Test137", help_text)


    def test_terminal_publisher_codes_preserve_unknowns(self):
        prefix = D.TERMINAL_PREFIX
        values = {
            prefix + "ContextGeneration": 7,
            prefix + "BeginResult": 1,
            prefix + "CloseResult": 2,
            prefix + "ObserverState": 3,
            prefix + "PublishFirstStatus": 12,
            prefix + "PublishStatus": 6,
            prefix + "Published": 0,
        }
        result = D.terminal_snapshot(values)
        self.assertEqual(result["ContextGeneration"]["value"], 7)
        self.assertEqual(result["BeginResult"]["meaning"], "accepted")
        self.assertEqual(result["CloseResult"]["meaning"], "rejected")
        self.assertEqual(result["ObserverState"]["meaning"], "invalid")
        self.assertEqual(result["PublishFirstStatus"]["meaning"], "not_main_gate")
        self.assertEqual(result["PublishStatus"]["meaning"], "encode_failed")
        self.assertEqual(result["Published"]["meaning"],
                         "terminal_receipt_uncommitted")
        missing = D.terminal_snapshot({})
        self.assertIsNone(missing["BeginResult"]["value"])
        self.assertEqual(missing["BeginResult"]["meaning"],
                         "unknown_missing_or_non_numeric")
        boolean = D.terminal_snapshot({prefix + "Published": True})
        self.assertIsNone(boolean["Published"]["value"])

    def test_terminal_generation_join_is_exact_and_missing_stays_unknown(self):
        snapshot = {
            "NativeAwdlDiscoveryRxWindowTerminalPublished": 1,
            "NativeAwdlDiscoveryRxWindowTerminalContextGeneration": 4,
            "NativeAwdlDiscoveryRxWindowTerminalPowerGeneration": 7,
            "NativeAwdlDiscoveryRxWindowTerminalStationGeneration": 18,
            "NativeAwdlDiscoveryRxWindowTerminalRocGeneration": 4,
            "NativeP2PProbeContextGeneration": 4,
            "NativeP2PProbePowerGeneration": 7,
            "NativeP2PProbeStationGeneration": 18,
            "NativeP2PRocGeneration": 4,
        }
        joined = D.terminal_generation_match(snapshot)
        self.assertEqual(joined["status"], "exact_generation_match")
        snapshot["NativeAwdlDiscoveryRxWindowTerminalContextGeneration"] = 3
        self.assertEqual(D.terminal_generation_match(snapshot)["status"],
                         "generation_mismatch")
        del snapshot["NativeP2PRocGeneration"]
        self.assertEqual(D.terminal_generation_match(snapshot)["status"],
                         "generation_mismatch")
        snapshot["NativeAwdlDiscoveryRxWindowTerminalContextGeneration"] = 4
        self.assertEqual(D.terminal_generation_match(snapshot)["status"],
                         "unknown_generation_missing_or_invalid")

    def test_terminal_generation_join_requires_committed_terminal_receipt(self):
        snapshot = {
            "NativeAwdlDiscoveryRxWindowTerminalPublished": 0,
            "NativeAwdlDiscoveryRxWindowTerminalContextGeneration": 4,
            "NativeAwdlDiscoveryRxWindowTerminalPowerGeneration": 7,
            "NativeAwdlDiscoveryRxWindowTerminalStationGeneration": 18,
            "NativeAwdlDiscoveryRxWindowTerminalRocGeneration": 4,
            "NativeP2PProbeContextGeneration": 4,
            "NativeP2PProbePowerGeneration": 7,
            "NativeP2PProbeStationGeneration": 18,
            "NativeP2PRocGeneration": 4,
        }
        self.assertEqual(D.terminal_generation_match(snapshot)["status"],
                         "unknown_uncommitted")
        del snapshot["NativeAwdlDiscoveryRxWindowTerminalPublished"]
        self.assertEqual(D.terminal_generation_match(snapshot)["status"],
                         "unknown_uncommitted")

    def test_decoder_requires_candidate_identity_and_fallback_profile(self):
        receipt = {
            "expected_build": "25G416-Test137",
            "expected_uuid": "12345678-1234-1234-1234-1234567890AB",
            "loaded_uuid_matches_after": True,
            "preflight": {"NativeAwdlDiscoveryCurrentAwFallbackEnabled": True},
            "before_arm": {"NativeAwdlDiscoveryCurrentAwFallbackEnabled": True},
            "final": {},
        }
        summary = D.decode_test137_receipt(receipt)
        self.assertTrue(summary["test137_profile"]["profile_match"])
        receipt["before_arm"]["NativeAwdlDiscoveryCurrentAwFallbackEnabled"] = False
        self.assertFalse(D.decode_test137_receipt(receipt)["test137_profile"]["profile_match"])
        receipt["before_arm"]["NativeAwdlDiscoveryCurrentAwFallbackEnabled"] = True
        receipt["loaded_uuid_matches_after"] = False
        self.assertFalse(D.decode_test137_receipt(receipt)["test137_profile"]["profile_match"])

    def test_late_terminal_commit_joins_frozen_cleanup_probe_identity(self):
        final = {
            "NativeAwdlDiscoveryRxWindowTerminalPublished": 1,
            "NativeAwdlDiscoveryRxWindowTerminalContextGeneration": 4,
            "NativeAwdlDiscoveryRxWindowTerminalPowerGeneration": 7,
            "NativeAwdlDiscoveryRxWindowTerminalStationGeneration": 18,
            "NativeAwdlDiscoveryRxWindowTerminalRocGeneration": 4,
            "NativeP2PProbeContextGeneration": 4,
            "NativeP2PProbePowerGeneration": 7,
            "NativeP2PProbeStationGeneration": 18,
            "NativeP2PRocGeneration": 4,
        }
        cleanup = {**final, "NativeAwdlDiscoveryRxWindowTerminalPublished": 0}
        snapshots = {"terminal_cleanup_snapshot": cleanup, "final": final}
        receipt = {
            "terminal_identity_valid": True,
            "context_changed_for_run": True,
            "context_generation_before_arm": 3,
            "terminal_context_generation": 4,
        }

        def current():
            matches = {name: D.terminal_generation_match(snapshot)
                       for name, snapshot in snapshots.items()}
            return D.terminal_current_run_match(receipt, snapshots, matches)

        self.assertEqual(current(), {"status": "exact_current_run_match",
                                     "cleanup_status": "unknown_uncommitted"})
        final["NativeP2PProbeStationGeneration"] = 19
        final["NativeAwdlDiscoveryRxWindowTerminalStationGeneration"] = 19
        self.assertEqual(current()["status"], "stale_baseline")

    def test_old_committed_terminal_tuple_is_not_current_run_evidence(self):
        old_snapshot = {
            "NativeAwdlDiscoveryRxWindowTerminalPublished": 1,
            "NativeAwdlDiscoveryRxWindowTerminalContextGeneration": 4,
            "NativeAwdlDiscoveryRxWindowTerminalPowerGeneration": 7,
            "NativeAwdlDiscoveryRxWindowTerminalStationGeneration": 18,
            "NativeAwdlDiscoveryRxWindowTerminalRocGeneration": 4,
            "NativeP2PProbeContextGeneration": 4,
            "NativeP2PProbePowerGeneration": 7,
            "NativeP2PProbeStationGeneration": 18,
            "NativeP2PRocGeneration": 4,
        }
        snapshots = {
            "terminal_cleanup_snapshot": old_snapshot,
            "final": old_snapshot,
        }
        same_snapshot = {
            name: D.terminal_generation_match(snapshot)
            for name, snapshot in snapshots.items()
        }
        self.assertEqual(same_snapshot["final"]["status"],
                         "exact_generation_match")
        receipt = {
            "terminal_identity_valid": False,
            "context_changed_for_run": False,
            "context_generation_before_arm": 4,
            "terminal_context_generation": 4,
        }
        current = D.terminal_current_run_match(receipt, snapshots, same_snapshot)
        self.assertEqual(current["status"], "stale_baseline")


if __name__ == "__main__":
    unittest.main()
