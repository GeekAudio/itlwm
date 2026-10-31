#!/usr/bin/env python3
"""Offline tests for the private Test087 RX-completion telemetry collector."""

import base64
import importlib.util
import plistlib
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


capture = load_module(
    "native_controlled_capture_under_test",
    ROOT / "developer-tools/test087/native_controlled_capture.py")
decoder = load_module(
    "rx_completion_decode_under_test",
    ROOT / "developer-tools/test094/rx_completion_decode.py")


def completion_fixture(*, family=2, attempts=5, copies=3, status=1):
    blob = bytearray(decoder.WIRE_BYTES)
    decoder.HEADER.pack_into(
        blob, 0, 1, status, attempts, copies, attempts - copies, 0,
        family, 9, 4, 31, 17, 2, 123456789)
    for index in range(2):
        decoder.SAMPLE.pack_into(
            blob, decoder.HEADER_BYTES + index * decoder.SAMPLE_BYTES,
            index + 1, 9, 4, 31, 17, 0x9090 + index, 0xA5,
            123456789 + index, 44 + index)
    return bytes(blob)


class RxCompletionCaptureTests(unittest.TestCase):
    def test_wire_allowlist_matches_the_existing_strict_decoder(self):
        self.assertEqual(capture.RX_COMPLETION_WIRE_BYTES, decoder.WIRE_BYTES)

    def test_registry_reader_preserves_the_numeric_osdata_allowlist(self):
        blob = completion_fixture()
        plist = plistlib.dumps([{
            "NativeTestBuild": "25G332-Test095",
            capture.RX_COMPLETION_OBSERVATION_KEY: blob,
        }])
        with patch.object(capture.subprocess, "check_output", return_value=plist):
            values = capture._read_preowner_registry()
        self.assertEqual(
            values[capture.RX_COMPLETION_OBSERVATION_KEY], blob)
        self.assertEqual(len(values[capture.RX_COMPLETION_OBSERVATION_KEY]), 760)

    def test_stable_payload_is_separate_numeric_telemetry(self):
        blob = completion_fixture()
        calls = []

        def reader():
            calls.append(1)
            return {capture.RX_COMPLETION_OBSERVATION_KEY: blob}

        result = capture._rx_completion_observation(
            decoder, reader=reader, timeout=0, sleep_fn=lambda _: None)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result["status"], "decoded_stable")
        self.assertTrue(result["snapshot_complete"])
        self.assertEqual(result["evidence_state"], "numeric_telemetry_only")
        self.assertEqual(result["observer_attempts_observed"], 5)
        self.assertTrue(result["registry_view_copy_observed"])
        self.assertEqual(result["copy_status"], "copied")
        self.assertEqual(result["decoded"]["schemaVersion"], 1)
        self.assertEqual(result["decoded"]["family"], 2)
        self.assertEqual(len(result["raw_reads"]), 3)
        for read in result["raw_reads"]:
            self.assertEqual(read["raw_blob_length"], 760)
            self.assertEqual(base64.b64decode(read["raw_blob_base64"]), blob)
        self.assertFalse(result["evidence_limits"]["dma_ownership_proven"])
        self.assertFalse(result["evidence_limits"]["raw_freshness_proven"])
        self.assertFalse(result["evidence_limits"]["peer_or_socket_receipt_proven"])
        self.assertFalse(result["evidence_limits"]["preowner_witness_upgraded_to_data"])

    def test_missing_blob_remains_unknown(self):
        result = capture._rx_completion_observation(
            decoder,
            reader=lambda: {capture.RX_COMPLETION_OBSERVATION_KEY: None},
            timeout=0, sleep_fn=lambda _: None)
        self.assertEqual(result["status"], "not_published_or_no_attempts")
        self.assertFalse(result["snapshot_complete"])
        self.assertEqual(result["evidence_state"], "unknown")
        self.assertIsNone(result["decoded"])

    def test_unstable_reads_remain_unknown_and_preserve_private_digests(self):
        blobs = [completion_fixture(), completion_fixture(status=2),
                 completion_fixture()]

        def reader():
            blob = blobs.pop(0)
            return {capture.RX_COMPLETION_OBSERVATION_KEY: blob}

        result = capture._rx_completion_observation(
            decoder, reader=reader, timeout=0, sleep_fn=lambda _: None)
        self.assertEqual(result["status"], "unstable_reads")
        self.assertFalse(result["snapshot_complete"])
        self.assertEqual(len(result["raw_reads"]), 3)
        self.assertTrue(all(read["raw_blob_sha256"] for read in result["raw_reads"]))

    def test_decoder_missing_or_throwing_does_not_promote_evidence(self):
        blob = completion_fixture()
        reader = lambda: {capture.RX_COMPLETION_OBSERVATION_KEY: blob}
        missing = capture._rx_completion_observation(
            None, reader=reader, timeout=0, sleep_fn=lambda _: None)
        self.assertEqual(missing["status"], "decoder_unavailable")
        self.assertFalse(missing["snapshot_complete"])
        self.assertEqual(missing["evidence_state"], "unknown")
        self.assertEqual(len(missing["raw_reads"]), 3)

        class ThrowingDecoder:
            @staticmethod
            def decode(_blob):
                raise ValueError("fixture failure")

        failed = capture._rx_completion_observation(
            ThrowingDecoder, reader=reader, timeout=0,
            sleep_fn=lambda _: None)
        self.assertEqual(failed["status"], "decode_error")
        self.assertFalse(failed["snapshot_complete"])
        self.assertEqual(failed["error_type"], "ValueError")
        self.assertIsNone(failed["decoded"])

    def test_strict_decoder_rejection_remains_unknown(self):
        blob = completion_fixture()[:-1]
        reader = lambda: {capture.RX_COMPLETION_OBSERVATION_KEY: blob}
        result = capture._rx_completion_observation(
            decoder, reader=reader, timeout=0, sleep_fn=lambda _: None)
        self.assertEqual(result["status"], "decode_error")
        self.assertFalse(result["snapshot_complete"])
        self.assertEqual(result["evidence_state"], "unknown")
        self.assertEqual(result["raw_reads"][0]["raw_blob_length"], 759)

    def test_unexpected_blob_size_is_not_embedded_or_accepted(self):
        blob = completion_fixture() + b"extra"
        reader = lambda: {capture.RX_COMPLETION_OBSERVATION_KEY: blob}
        result = capture._rx_completion_observation(
            decoder, reader=reader, timeout=0, sleep_fn=lambda _: None)
        self.assertEqual(result["status"], "decode_error")
        self.assertFalse(result["snapshot_complete"])
        self.assertEqual(result["raw_reads"][0]["raw_blob_length"], 765)
        self.assertIsNone(result["raw_reads"][0]["raw_blob_base64"])

    def test_invalid_reader_result_remains_unknown(self):
        result = capture._rx_completion_observation(
            decoder, reader=lambda: None, timeout=0,
            sleep_fn=lambda _: None)
        self.assertEqual(result["status"], "collector_error")
        self.assertEqual(result["error_type"], "UnexpectedReaderResult")
        self.assertFalse(result["snapshot_complete"])
        self.assertEqual(result["evidence_state"], "unknown")

    def test_wrong_family_is_decoded_but_not_accepted_as_expected_view(self):
        blob = completion_fixture(family=3)
        reader = lambda: {capture.RX_COMPLETION_OBSERVATION_KEY: blob}
        result = capture._rx_completion_observation(
            decoder, reader=reader, timeout=0, sleep_fn=lambda _: None)
        self.assertEqual(result["status"], "decoded_unexpected_family")
        self.assertFalse(result["snapshot_complete"])
        self.assertEqual(result["decoded"]["family"], 3)
        self.assertEqual(result["evidence_state"], "unknown")


if __name__ == "__main__":
    unittest.main()
