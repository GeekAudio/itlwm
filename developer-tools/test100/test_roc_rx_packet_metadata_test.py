#!/usr/bin/env python3
"""Test100 fixed-width RX packet metadata schema and legacy decoding."""

import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
DECODER_PATH = ROOT / "developer-tools/test096/roc_rx_correlation_decode.py"
SPEC = importlib.util.spec_from_file_location("roc_rx_decoder_test100", DECODER_PATH)
decoder = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(decoder)
FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "roc_rx_decode_fixture_test100",
    ROOT / "developer-tools/test096/test_roc_rx_correlation_decode.py")
fixture_module = importlib.util.module_from_spec(FIXTURE_SPEC)
assert FIXTURE_SPEC.loader is not None
FIXTURE_SPEC.loader.exec_module(fixture_module)


HARNESS = r"""
#include <cstdio>
#include <cstdlib>
#include "native/iwx_roc_rx_correlation.hpp"

int main(int argc, char **argv) {
    using namespace NativeIwxRocRxCorrelation;
    if (argc != 2) return 1;
    const int mode = std::atoi(argv[1]);
    if (mode < 0 || mode > 3) return 2;

    Recorder recorder;
    if (!recorder.arm(1, 11, 1000)) return 3;
    RocEpoch epoch;
    epoch.contextGeneration = 6;
    epoch.powerGeneration = 11;
    epoch.stationGeneration = 23;
    epoch.rocGeneration = 6;
    epoch.sessionToken = 99;
    if (!recorder.beginRoc(epoch, 2000, 97000)) return 4;

    NativeIwxCompletionObserver::CopyResult copy;
    copy.status = NativeIwxCompletionObserver::CopyStatus::kCopied;
    copy.snapshot.incarnation = 44;
    SlotInput slot;
    slot.captureSerial = 1;
    slot.driverGeneration = 11;
    slot.ring = 0;
    slot.slot = 17;
    slot.head = 18;
    slot.copyTimeUs = 2500;
    slot.copySequence = 22;
    slot.epoch = epoch;
    Token token = recorder.beginSlot(slot, copy);
    if (!token.valid) return 5;

    Mpdu mpdu;
    mpdu.presence = kRawStatusPresent | kDescriptorSizePresent |
        kPacketOffsetPresent;
    mpdu.descriptorSize = (mode == 1 || mode == 3) ? 48 : 64;
    mpdu.rawStatus = 0x00000003;
    mpdu.extensionPresence = kPacketLenNFlagsPresent |
        kRxQueuePresent | kRssEnabledPresent | kSourceStaFoundPresent;
    if (mode == 0) {
        mpdu.rawPacketLenNFlags = (5u << 16) | (1u << 23) | (1u << 25);
        mpdu.extensionPresence |= kDescriptorVersionPresent |
            kFilterMatchPresent | kMacContextPresent | kSourceStaIdPresent;
        mpdu.rawFilterMatch = 0x12345678;
        mpdu.descriptorVersion = 3;
        mpdu.rxQueue = 5;
        mpdu.rssEnabled = 1;
        mpdu.macContext = 0xa5;
        mpdu.sourceStaFound = 1;
        mpdu.sourceStaId = 7;
        mpdu.rawStatus |= kSourceStaFoundMask | (7u << kSourceStaIdShift);
    } else if (mode == 1) {
        // Zero-valued RXQ/RSS and mac_context are present observations.
        mpdu.rawPacketLenNFlags = 0;
        mpdu.extensionPresence |= kDescriptorVersionPresent |
            kMacContextPresent;
        mpdu.descriptorVersion = 1;
        mpdu.rxQueue = 0;
        mpdu.rssEnabled = 0;
        mpdu.macContext = 0;
        mpdu.sourceStaFound = 0;
    } else if (mode == 2) {
        // Truncated descriptor: source status is known, descriptor fields are not.
        mpdu.rawPacketLenNFlags = 0;
        mpdu.extensionPresence |= kSourceStaIdPresent;
        mpdu.rxQueue = 0;
        mpdu.rssEnabled = 0;
        mpdu.sourceStaFound = 1;
        mpdu.sourceStaId = 0;
        mpdu.rawStatus |= kSourceStaFoundMask;
    } else {
        // RPA and RSS are independent packet-header bits. A zero filter_match
        // is still an observed value when RPA enables the descriptor field.
        mpdu.rawPacketLenNFlags = (2u << 16) | (1u << 25);
        mpdu.extensionPresence |= kDescriptorVersionPresent |
            kFilterMatchPresent | kMacContextPresent | kSourceStaIdPresent;
        mpdu.rawFilterMatch = 0;
        mpdu.descriptorVersion = 1;
        mpdu.rxQueue = 2;
        mpdu.rssEnabled = 0;
        mpdu.macContext = 0;
        mpdu.sourceStaFound = 1;
        mpdu.sourceStaId = 0;
        mpdu.rawStatus |= kSourceStaFoundMask;
    }
    if (!recorder.recordMpdu(token, mpdu)) return 6;
    if (!recorder.endRoc(epoch, 4000)) return 7;
    if (!recorder.finishSlot(token)) return 8;

    uint8_t wire[kWireBytes] = {};
    if (!recorder.encode(wire, sizeof(wire))) return 9;
    if (std::fwrite(wire, 1, sizeof(wire), stdout) != sizeof(wire)) return 10;
    return 0;
}
"""


class RocRxPacketMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="test100-rx-metadata-")
        temp = Path(cls.temp.name)
        source = temp / "rx_metadata.cpp"
        cls.binary = temp / "rx_metadata"
        source.write_text(HARNESS)
        subprocess.run([
            "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra",
            "-Werror", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", "-I", str(ROOT), str(source),
            "-o", str(cls.binary),
        ], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def capture(self, mode):
        result = subprocess.run([str(self.binary), str(mode)], check=True,
                                stdout=subprocess.PIPE, timeout=10)
        decoded = decoder.decode(result.stdout, require_closed=True)
        self.assertEqual(decoded["schemaVersion"], 3)
        return result.stdout, decoded["records"][0]["mpdu"]["packetMetadata"]

    def test_c1_raw_packet_and_descriptor_values_are_retained(self):
        _, metadata = self.capture(0)
        self.assertTrue(metadata["rawPacketLenNFlagsPresent"])
        self.assertEqual(metadata["rawPacketLenNFlags"],
                         (5 << 16) | (1 << 23) | (1 << 25))
        self.assertEqual(metadata["rxQueueRaw"], 5)
        self.assertEqual(metadata["rssEnabled"], 1)
        self.assertEqual(metadata["descriptorVersion"], 3)
        self.assertTrue(metadata["rawFilterMatchPresent"])
        self.assertEqual(metadata["rawFilterMatch"], 0x12345678)
        self.assertTrue(metadata["rawMacContextPresent"])
        self.assertEqual(metadata["rawMacContext"], 0xa5)
        self.assertTrue(metadata["sourceStaFound"])
        self.assertEqual(metadata["sourceStaId"], 7)

    def test_zero_values_are_distinct_from_unknown_descriptor_values(self):
        _, v1 = self.capture(1)
        self.assertTrue(v1["rxQueuePresent"])
        self.assertEqual(v1["rxQueueRaw"], 0)
        self.assertTrue(v1["rssEnabledPresent"])
        self.assertEqual(v1["rssEnabled"], 0)
        self.assertTrue(v1["rawMacContextPresent"])
        self.assertEqual(v1["rawMacContext"], 0)
        self.assertFalse(v1["rawFilterMatchPresent"])
        self.assertIsNone(v1["rawFilterMatch"])
        self.assertFalse(v1["sourceStaFound"])
        self.assertFalse(v1["sourceStaIdPresent"])
        self.assertIsNone(v1["sourceStaId"])

        _, truncated = self.capture(2)
        self.assertFalse(truncated["descriptorVersionPresent"])
        self.assertIsNone(truncated["descriptorVersion"])
        self.assertFalse(truncated["rawMacContextPresent"])
        self.assertIsNone(truncated["rawMacContext"])
        self.assertFalse(truncated["rawFilterMatchPresent"])
        self.assertIsNone(truncated["rawFilterMatch"])
        self.assertTrue(truncated["sourceStaIdPresent"])
        self.assertEqual(truncated["sourceStaId"], 0)

    def test_rpa_filter_match_is_independent_of_rss_and_zero_is_present(self):
        _, metadata = self.capture(3)
        self.assertEqual(metadata["rxQueueRaw"], 2)
        self.assertEqual(metadata["rssEnabled"], 0)
        self.assertTrue(metadata["rawFilterMatchPresent"])
        self.assertEqual(metadata["rawFilterMatch"], 0)
        self.assertEqual(metadata["rawMacContext"], 0)
        self.assertEqual(metadata["sourceStaId"], 0)

    def test_previous_schema_keeps_rx_summary_but_new_fields_are_unknown(self):
        # Construct a valid schema-2 fixture: its record tail did not carry
        # packet metadata, so the schema-3 fields must be unknown, not false.
        blob = fixture_module.fixture(schema=decoder.PREVIOUS_SCHEMA_VERSION)
        decoded = decoder.decode(blob)
        self.assertEqual(decoded["schemaVersion"], 2)
        metadata = decoded["records"][0]["mpdu"]["packetMetadata"]
        self.assertIsNone(metadata["fieldFlags"])
        self.assertIsNone(metadata["rawPacketLenNFlagsPresent"])
        self.assertIsNone(metadata["rawPacketLenNFlags"])
        self.assertIsNone(metadata["rawFilterMatchPresent"])
        self.assertIsNone(metadata["sourceStaFound"])
        self.assertTrue(decoded["rxWindowSummaryAvailable"])

    def test_decoder_rejects_presence_contradictions(self):
        blob, _ = self.capture(0)
        base = decoder.HEADER_BYTES

        absent_nonzero = bytearray(blob)
        flags = struct.unpack_from("<I", absent_nonzero, base + 156)[0]
        struct.pack_into("<I", absent_nonzero, base + 156,
                         flags & ~decoder.MPDU_FILTER_MATCH_PRESENT)
        with self.assertRaisesRegex(decoder.DecodeError, "without presence"):
            decoder.decode(bytes(absent_nonzero))

        filter_without_rpa = bytearray(blob)
        raw = struct.unpack_from("<I", filter_without_rpa, base + 160)[0]
        struct.pack_into("<I", filter_without_rpa, base + 160,
                         raw & ~decoder.PACKET_RPA_ENABLED_MASK)
        with self.assertRaisesRegex(decoder.DecodeError, "without RPA"):
            decoder.decode(bytes(filter_without_rpa))

    def test_source_wires_header_and_descriptor_metadata_without_gate_changes(self):
        source = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
        rx_start = source.index("iwx_rx_mpdu_mq(struct iwx_softc *sc")
        rx_end = source.index("// The RX notification declares its actual payload length separately", rx_start)
        observe = source[rx_start:rx_end]
        self.assertIn("uint32_t rawPacketLenNFlags", observe)
        self.assertIn("entry.rawPacketLenNFlags = rawPacketLenNFlags", observe)
        self.assertIn("if (inspection.filterMatchPresent)", observe)
        self.assertIn("entry.rawFilterMatch = inspection.filterMatch", observe)
        self.assertIn("if (inspection.macContextPresent)", observe)
        self.assertIn("entry.macContext = static_cast<uint8_t>(inspection.macContext)", observe)
        self.assertIn("if (inspection.statusPresent)", observe)
        self.assertIn("kSourceStaFoundMask", observe)
        self.assertIn("le32toh(pkt->len_n_flags)", source)


if __name__ == "__main__":
    unittest.main()
