#!/usr/bin/env python3
"""Offline Test098 harness for ordinary TX completion publication."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_CPP = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
PERIODIC_CPP = ROOT / "itlwm/hal_iwx/ItlIwxP2PRx.cpp"
HARNESS_CPP = ROOT / "native/tests/iwx_tx_completion_publish_test.cpp"
GROUP2_C_API = ROOT / "native/tests/group2_tx_trace_helpers_c_api_smoke.c"
DECODER_PATH = ROOT / "developer-tools/test097/txcmd_identity_completion.py"
CXX = shutil.which("clang++") or shutil.which("g++") or "c++"
CC = shutil.which("clang") or shutil.which("cc") or "cc"


def extract_function(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    i = opening
    while i < len(source):
        char = source[i]
        following = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "/" and following == "*":
                state = "block_comment"
                i += 1
            elif char == "/" and following == "/":
                state = "line_comment"
                i += 1
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[start:i + 1]
        elif state == "string":
            if char == "\\":
                i += 1
            elif char == '"':
                state = "code"
        elif state == "char":
            if char == "\\":
                i += 1
            elif char == "'":
                state = "code"
        elif state == "block_comment":
            if char == "*" and following == "/":
                state = "code"
                i += 1
        elif state == "line_comment" and char == "\n":
            state = "code"
        i += 1
    raise ValueError(f"unterminated function: {signature}")

spec = importlib.util.spec_from_file_location(
    "txcmd_identity_completion", DECODER_PATH)
decoder = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(decoder)


class Test098CompletionPublication(unittest.TestCase):
    def test_group2_helper_preserves_strict_c11_api(self):
        subprocess.run([
            CC, "-std=c11", "-pedantic-errors", "-Wall", "-Wextra",
            "-Werror", "-I", str(ROOT), "-fsyntax-only",
            str(GROUP2_C_API),
        ], check=True)

    def test_compiled_production_policy_harness(self):
        with tempfile.TemporaryDirectory(prefix="test098-completion-") as tmp:
            binary = Path(tmp) / "completion-publish-test"
            subprocess.run([
                CXX, "-std=c++17", "-O2", "-pthread",
                "-I", str(ROOT), str(HARNESS_CPP), "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True)

    def test_executes_actual_production_property_publisher(self):
        source = PRODUCTION_CPP.read_text(encoding="utf-8")
        function = extract_function(source,
            "static bool publishCompletionSnapshot(")
        harness = textwrap.dedent(r"""
            #include "native/iwx_tx_completion_publish.hpp"
            #include <cassert>
            #include <cstdint>
            #include <cstdio>
            #include <map>
            #include <string>

            class IOEthernetController {
            public:
                std::map<std::string, uint64_t> values;
                size_t calls = 0;
                size_t failAt = 0;
                bool setProperty(const char *key, uint64_t value, unsigned bits) {
                    ++calls;
                    if (failAt != 0 && calls == failAt)
                        return false;
                    assert(bits == 64);
                    values[key] = value;
                    return true;
                }
            };
        """) + "\n" + function + textwrap.dedent(r"""

            int main() {
                iwx_tx_completion_observation_snapshot snapshot{};
                snapshot.available = 1;
                snapshot.complete = 1;
                snapshot.next_serial = 1;
                snapshot.publication_serial = 1;
                snapshot.last[IWX_TX_COMPLETION_TX_RSP].event_count = 1;
                snapshot.last[IWX_TX_COMPLETION_TX_RSP].serial = 1;
                snapshot.last[IWX_TX_COMPLETION_TX_RSP].driver_generation = 9;
                snapshot.last[IWX_TX_COMPLETION_TX_RSP].output_epoch = 3;
                uint32_t version = 0;
                IOEthernetController controller;
                const bool ok = publishCompletionSnapshot(&controller, &version,
                    snapshot, 0, 9, IwxTxCompletionPublish::kOrdinaryCompletion,
                    2);
                assert(ok && version == 2);
                assert(controller.calls == 184);
                assert(controller.values["NativeStaCompletionSnapshotVersionBegin"] == 2);
                assert(controller.values["NativeStaCompletionSnapshotVersionEnd"] == 2);
                assert(controller.values["NativeStaCompletionPublicationSequence"] == 2);
                assert(controller.values["NativeStaCompletionPublicationSource"] == 1);
                assert(controller.values["NativeStaCompletionPublicationGeneration"] == 9);
                assert(controller.values["NativeStaCompletionRelatedCutLostCount"] == 2);
                assert(controller.values["NativeStaCompletionRelatedRecordDroppedCount"] == 0);
                assert(controller.values["NativeStaCompletionEvent0DriverGeneration"] == 9);

                IOEthernetController failed;
                failed.failAt = 7;
                uint32_t retryVersion = 0;
                assert(!publishCompletionSnapshot(&failed, &retryVersion,
                    snapshot, 0, 9, IwxTxCompletionPublish::kOrdinaryCompletion,
                    0));
                assert(retryVersion == 2);
                assert(failed.values["NativeStaCompletionSnapshotComplete"] == 0);
                IOEthernetController retry;
                assert(publishCompletionSnapshot(&retry, &retryVersion,
                    snapshot, 0, 9, IwxTxCompletionPublish::kOrdinaryCompletion,
                    0));
                assert(retryVersion == 4);
                assert(retry.values["NativeStaCompletionSnapshotVersionBegin"] == 4);
                assert(retry.values["NativeStaCompletionSnapshotVersionEnd"] == 4);
                assert(retry.values["NativeStaCompletionPublicationSequence"] == 4);
            }
        """)
        with tempfile.TemporaryDirectory(prefix="test098-production-publisher-") as tmp:
            cpp = Path(tmp) / "production-publisher.cpp"
            binary = Path(tmp) / "production-publisher"
            cpp.write_text(harness, encoding="utf-8")
            subprocess.run([
                CXX, "-std=c++17", "-O2", "-I", str(ROOT),
                str(cpp), "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True)

    def test_periodic_source_uses_bounded_policy_before_reset_early_return(self):
        source = PERIODIC_CPP.read_text(encoding="utf-8")
        start = source.index("void ItlIwx::tahoePublishResetTrace(")
        end = source.index("\n}\n", start) + 3
        body = source[start:end]
        call = body.index(
            "tahoePublishOrdinaryTxCompletionSnapshot(controller, &com);")
        reset_read = body.index("nativeResetTrace_.read(&snapshot)")
        self.assertLess(call, reset_read)
        self.assertIn("if (nativeResetTracePublishedOnce_", body)

        ordinary = PRODUCTION_CPP.read_text(encoding="utf-8")
        start = ordinary.index(
            "void ItlIwx::tahoePublishOrdinaryTxCompletionSnapshot(")
        end = ordinary.index("\n}\n", start) + 3
        body = ordinary[start:end]
        for marker in (
                "txCompletionPublicationStamp(sc)",
                "sc_tx_progress_pending_present",
                "tryClaimCopy(",
                "tryDiscard(",
                "publishCompletionSnapshot(",
                "commitOrdinary("):
            self.assertIn(marker, body)
        self.assertNotIn("IwxTxCompletionObservation::snapshot(", body)
        self.assertIn("kFrozenWatchdogSnapshot", ordinary)

    @staticmethod
    def publication_fixture():
        return {
            "Schema": 2,
            "SnapshotVersionBegin": 4,
            "SnapshotVersionEnd": 4,
            "SnapshotAvailable": 1,
            "SnapshotComplete": 1,
            "DroppedCount": 0,
            "NextSerial": 1,
            "RelevantSerial": 1,
            "RelatedRecordDroppedCount": 0,
            "RelatedCutLostCount": 0,
            "OwnerWatchdogSequence": 0,
            "OwnerGeneration": 9,
            "PublicationSequence": 4,
            "PublicationSource": 1,
            "PublicationGeneration": 9,
            "FirmwareResponseIdentityProven": 0,
            "PeerReceiptProven": 0,
            "Event0Present": 1,
            "Event0Count": 1,
            "Event0Serial": 1,
            "Event0Kind": 0,
            "Event0Stage": 1,
            "Event0TerminalReason": 8,
            "Event0PresenceFlags": (1 << 31) | (1 << 26) | (1 << 27),
            "Event0OutputEpoch": 3,
            "Event0DriverGeneration": 9,
            "Event0ResponseFrameControl": 0,
            "Event0ResponseSequenceControl": 0,
        }

    def test_decoder_checks_publication_sequence_and_generation_in_snapshot(self):
        values = self.publication_fixture()
        decoded = decoder.decode_scalars(values)
        self.assertEqual(decoded["publication"], {
            "sequence": 4,
            "source": "ordinary_completion",
            "generation": 9,
            "relevant_serial": 1,
        })
        self.assertEqual(decoded["related_record_dropped_count"], 0)
        self.assertEqual(decoded["related_cut_lost_count"], 0)

        torn = dict(values, PublicationSequence=6)
        with self.assertRaises(ValueError):
            decoder.decode_scalars(torn)
        wrong_generation = dict(values, PublicationGeneration=10)
        with self.assertRaises(ValueError):
            decoder.decode_scalars(wrong_generation)
        unknown_source = dict(values, PublicationSource=3)
        with self.assertRaises(ValueError):
            decoder.decode_scalars(unknown_source)

    def test_legacy_schema_two_without_new_metadata_remains_readable(self):
        values = self.publication_fixture()
        for key in ("PublicationSequence", "PublicationSource",
                    "PublicationGeneration"):
            values.pop(key)
        decoded = decoder.decode_scalars(values)
        self.assertIsNone(decoded["publication"])

    def test_live_loss_counters_do_not_mutate_versioned_snapshot_fields(self):
        source = PRODUCTION_CPP.read_text(encoding="utf-8")
        ordinary = extract_function(source,
            "void ItlIwx::tahoePublishOrdinaryTxCompletionSnapshot(")
        self.assertIn(
            '"NativeStaCompletionLiveRelatedCutLostCount"', ordinary)
        self.assertIn(
            '"NativeStaCompletionLiveRelatedRecordDroppedCount"', ordinary)
        self.assertNotIn(
            'setProperty("NativeStaCompletionRelatedCutLostCount"', ordinary)
        self.assertNotIn(
            'setProperty("NativeStaCompletionRelatedRecordDroppedCount"', ordinary)

        values = self.publication_fixture()
        properties = {
            "NativeStaCompletion" + key: value
            for key, value in values.items()
        }
        properties["NativeStaCompletionLiveRelatedCutLostCount"] = 99
        properties["NativeStaCompletionLiveRelatedRecordDroppedCount"] = 77
        decoded = decoder.decode_scalars(decoder.completion_scalars(properties))
        self.assertEqual(decoded["related_cut_lost_count"], 0)
        self.assertEqual(decoded["related_record_dropped_count"], 0)
        self.assertNotIn("live_related_cut_lost_count", decoded)
        self.assertNotIn("live_related_record_dropped_count", decoded)


if __name__ == "__main__":
    unittest.main(verbosity=2)
