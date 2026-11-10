#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline Test138 profile binding and production MPDU parser regressions."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


B = load_module("build_helper_test138_under_test", HERE / "build_helper_test138.py")
D = load_module("test138_diagnostics_under_test", HERE / "test138_diagnostics.py")


def production_mpdu_fixture() -> dict[str, bytes | int]:
    compiler = shutil.which("clang++") or shutil.which("c++")
    if compiler is None:
        raise RuntimeError("C++ compiler required for Test138 production MPDU fixture")
    with tempfile.TemporaryDirectory(prefix="test138-mpdu-fixture-") as temp:
        binary = Path(temp) / "test138-mpdu-fixture"
        subprocess.run([
            compiler, "-std=c++17", "-I", str(REPO / "native"),
            str(HERE / "test138_mpdu_fixture.cpp"),
            str(REPO / "native/awdl_data_frame.cpp"), "-o", str(binary),
        ], check=True, capture_output=True, text=True)
        output = subprocess.run([str(binary)], check=True, capture_output=True,
                                text=True).stdout
    values: dict[str, bytes | int] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            raise AssertionError(f"invalid fixture output: {line!r}")
        values[key] = bytes.fromhex(value) if key.endswith("_hex") else int(value)
    return values


class TestTest138Helper(unittest.TestCase):
    def test_profile_render_keeps_mif_fallback_and_no_answer_marker(self):
        template = B._TEST137.TEMPLATE.read_text(encoding="utf-8")
        source = B.render_helper(
            template, "828b2950-d350-3d24-b930-313c48c9cb49")
        enabled = source[source.index("private let enabledFlags = ["):
                         source.index("private let disabledFlags = [")]
        disabled = source[source.index("private let disabledFlags = ["):
                          source.index("private let receiptKeys = [")]
        self.assertIn('private let expectedBuild = "25G416-Test138"', source)
        self.assertIn('"NativeAwdlDiscoveryMifCurrentSlotEnabled"', enabled)
        self.assertIn('"NativeAwdlDiscoveryCurrentAwFallbackEnabled"', enabled)
        self.assertIn('"NativeAwdlQmNoKnownAnswerCompiled"', enabled)
        self.assertNotIn('"NativeAwdlQmNormalPriorityCompiled"', enabled)
        self.assertIn('"NativeAwdlQmNormalPriorityCompiled"', disabled)
        self.assertIn("let maximumRunSeconds: UInt64 = 20", source)
        self.assertEqual(source.count('"NativeP2PArmOnce": true'), 1)

    def test_profile_json_roundtrip_requires_exact_build_uuid_and_markers(self):
        uuid = "828B2950-D350-3D24-B930-313C48C9CB49"
        snapshot = {
            "NativeTestBuild": "25G416-Test138",
            "NativeAwdlDiscoveryExperimentEnabled": True,
            "NativeAwdlDiscoveryMifCurrentSlotEnabled": True,
            "NativeAwdlDiscoveryRxInputEnabled": True,
            "NativeAwdlDiscoveryCurrentAwFallbackEnabled": True,
            "NativeAwdlQmNoKnownAnswerCompiled": True,
            "NativeAwdlQmNormalPriorityCompiled": False,
        }
        receipt = json.loads(json.dumps({
            "expected_build": "25G416-Test138",
            "expected_uuid": uuid,
            "loaded_uuid_matches_after": True,
            "loaded_uuids_after": [uuid],
            "preflight": snapshot,
            "before_arm": snapshot,
            "final": snapshot,
        }))
        self.assertTrue(D._profile(receipt)["valid"])
        receipt["final"]["NativeAwdlQmNoKnownAnswerCompiled"] = False
        self.assertFalse(D._profile(receipt)["valid"])
        receipt["final"]["NativeAwdlQmNoKnownAnswerCompiled"] = True
        receipt["loaded_uuids_after"] = ["00000000-0000-0000-0000-000000000000"]
        self.assertFalse(D._profile(receipt)["valid"])

    def test_production_transform_encoder_mpdu_and_checksum_rejection(self):
        fixture = production_mpdu_fixture()
        original = fixture["original_mpdu_hex"]
        final = fixture["mpdu_hex"]
        self.assertEqual(fixture["original_ipv6_length"], 112)
        self.assertEqual(fixture["original_an_count"], 1)
        self.assertEqual(fixture["final_ipv6_length"], 85)
        self.assertEqual(fixture["final_udp_length"], 45)
        self.assertEqual(fixture["final_dns_length"], 37)
        self.assertEqual(fixture["final_an_count"], 0)
        self.assertEqual(len(original), 152)
        self.assertEqual(len(final), 125)

        decoded = D.decode_final_qm_mpdu(final)
        self.assertTrue(decoded["valid"], decoded)
        self.assertEqual(decoded["sequence_control"], 0x20)
        self.assertTrue(decoded["udp_checksum_valid"])
        self.assertEqual(decoded["dns_counts"], {"qd": 1, "an": 0, "ns": 0, "ar": 0})
        self.assertTrue(decoded["checks"]["snap_awdl_ipv6_encapsulation"])
        self.assertFalse(D.decode_final_qm_mpdu(original)["valid"])

        bad_checksum = bytearray(final)
        bad_checksum[40 + 40 + 6] ^= 1
        rejected = D.decode_final_qm_mpdu(bytes(bad_checksum))
        self.assertFalse(rejected["valid"])
        self.assertIn("udp_checksum_invalid", rejected["errors"])

    def test_does_not_present_original_an1_as_direct_receipt(self):
        final = production_mpdu_fixture()["mpdu_hex"]
        decoded = D.decode_final_qm_mpdu(final)
        self.assertEqual(decoded["dns_counts"]["an"], 0)
        self.assertNotIn("original_an_count", decoded)


if __name__ == "__main__":
    unittest.main(verbosity=2)
