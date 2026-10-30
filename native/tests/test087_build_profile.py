#!/usr/bin/env python3
"""Test087 artifact isolation and distinct native observation windows."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BUILDER_SPEC = importlib.util.spec_from_file_location(
    "tahoe_builder_test087", ROOT / "scripts/build_tahoe.py"
)
assert BUILDER_SPEC and BUILDER_SPEC.loader
builder = importlib.util.module_from_spec(BUILDER_SPEC)
BUILDER_SPEC.loader.exec_module(builder)
RX_SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PRx.cpp"

FLAGS = (
    "p2p_probe p2p_roc_probe p2p_tx_probe p2p_manual_trigger "
    "p2p_awdl_psf_observation_only p2p_awdl_mif_followup "
    "p2p_gp2_observation native_awdl_init_observation_only "
    "native_awdl_lifecycle_observation_only native_awdl_resident_data "
    "native_awdl_tx_evidence native_awdl_discovery_experiment "
    "native_awdl_discovery_mif_current_slot "
    "native_awdl_discovery_current_aw_fallback "
    "native_awdl_rx149_observation_only native_awdl_rx149_data_input "
    "native_rx_preowner_observation"
).split()


def args(**changes):
    values = dict.fromkeys(FLAGS, False)
    values.update(changes)
    return argparse.Namespace(**values)


def rx149_data_profile(*, preowner=False, **changes):
    profile = args(
        p2p_probe=True,
        p2p_manual_trigger=True,
        native_awdl_resident_data=True,
        native_awdl_rx149_observation_only=True,
        native_awdl_rx149_data_input=True,
        native_rx_preowner_observation=preowner,
    )
    for key, value in changes.items():
        setattr(profile, key, value)
    return profile


def extract_function(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line":
            if char == "\n":
                state = "code"
        elif state == "block":
            if char == "*" and following == "/":
                state = "code"
                index += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (
                state == "char" and char == "'"
            ):
                state = "code"
        else:
            if char == "/" and following == "/":
                state = "line"
                index += 1
            elif char == "/" and following == "*":
                state = "block"
                index += 1
            elif char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[start : index + 1]
        index += 1
    raise AssertionError("unterminated production helper: " + marker)


class ProfileIsolation(unittest.TestCase):
    def test_cli_and_build_configuration_use_the_real_profile_interface(self):
        help_result = subprocess.run(
            ["python3", str(ROOT / "scripts/build_tahoe.py"), "--help"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=ROOT,
        )
        self.assertIn("--native-rx-preowner-observation", help_result.stdout)

        enabled = rx149_data_profile(preowner=True)
        self.assertEqual(builder.receive149_profile_errors(enabled), [])
        flags = builder.resident_build_flags(enabled)
        self.assertIn("-DITL_NATIVE_AWDL_RX149_OBSERVATION_25G332=1", flags)
        self.assertIn("-DITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332=1", flags)
        self.assertIn("-DITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332=1", flags)

        personality = {"NativeRxPreOwnerObservation": False}
        builder.apply_artifact_profile(personality, enabled)
        self.assertIs(personality["NativeRxPreOwnerObservation"], True)
        self.assertIs(personality["NativeP2PRx149ObservationOnly"], True)
        self.assertIs(personality["NativeP2PRx149DataInputExperiment"], True)

    def test_preowner_flag_requires_rx149_data_input_and_its_manual_profile(self):
        no_data_input = args(native_rx_preowner_observation=True)
        errors = builder.receive149_profile_errors(no_data_input)
        self.assertTrue(any("RX149 data-input profile" in error for error in errors))

        no_rx149_observation = rx149_data_profile(
            preowner=True, native_awdl_rx149_observation_only=False
        )
        self.assertTrue(builder.receive149_profile_errors(no_rx149_observation))

        missing_manual_owner = rx149_data_profile(preowner=True, p2p_manual_trigger=False)
        self.assertTrue(builder.receive149_profile_errors(missing_manual_owner))
        missing_resident_interface = rx149_data_profile(
            preowner=True, native_awdl_resident_data=False
        )
        self.assertTrue(builder.receive149_profile_errors(missing_resident_interface))

        mixed_tx = rx149_data_profile(preowner=True, p2p_tx_probe=True)
        self.assertTrue(builder.receive149_profile_errors(mixed_tx))

    def test_preowner_is_not_enabled_by_old_or_normal_profiles(self):
        old_rx149 = rx149_data_profile(preowner=False)
        flags = builder.resident_build_flags(old_rx149)
        self.assertNotIn("-DITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332=1", flags)
        personality = {"NativeRxPreOwnerObservation": True}
        builder.apply_artifact_profile(personality, old_rx149)
        self.assertIs(personality["NativeRxPreOwnerObservation"], False)

        old_observation = rx149_data_profile(
            preowner=False, native_awdl_rx149_data_input=False
        )
        self.assertNotIn(
            "-DITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332=1",
            builder.resident_build_flags(old_observation),
        )

        normal = args()
        normal_profile = {"NativeRxPreOwnerObservation": True}
        builder.apply_artifact_profile(normal_profile, normal)
        self.assertIs(normal_profile["NativeRxPreOwnerObservation"], False)

    def test_observer_capture_and_roc_owner_window_are_distinct(self):
        helper = extract_function(
            RX_SOURCE.read_text(), "static bool withinRx149DiagnosticWindow("
        )
        source = r'''#include <assert.h>
#include <stdint.h>
#include "native/rx_preowner_observation.hpp"
#include "native/p2p_rx149_observation.hpp"
''' + helper + r'''
int main() {
    static_assert(NativeRxPreOwner::kWindowUs == 4000000ULL,
                  "observer capture is four seconds");
    static_assert(NativeP2PRx149Observation::kSessionDurationMs == 100,
                  "RX149 ROC is one hundred milliseconds");
    constexpr uint64_t startUs = 1000000ULL;
    assert(withinRx149DiagnosticWindow(startUs, startUs));
    assert(withinRx149DiagnosticWindow(startUs + 99999ULL, startUs));
    assert(!withinRx149DiagnosticWindow(startUs + 100000ULL, startUs));
    assert(!withinRx149DiagnosticWindow(startUs - 1ULL, startUs));
    assert(!withinRx149DiagnosticWindow(startUs, 0));
    return 0;
}
'''
        compiler = shutil.which("clang++") or shutil.which("g++")
        self.assertIsNotNone(compiler, "clang++ or g++ required")
        with tempfile.TemporaryDirectory(prefix="test087-window-profile-") as temp:
            binary = Path(temp) / "test087-window-profile"
            subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pedantic",
                    "-I",
                    str(ROOT),
                    "-x",
                    "c++",
                    "-",
                    "-o",
                    str(binary),
                ],
                input=source,
                text=True,
                check=True,
                cwd=ROOT,
            )
            subprocess.run([str(binary)], check=True, cwd=ROOT)


if __name__ == "__main__":
    unittest.main()
