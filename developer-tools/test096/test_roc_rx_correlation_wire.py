#!/usr/bin/env python3
"""Compile the candidate writer and decode its actual bytes offline."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "roc_rx_correlation_decode", HERE / "roc_rx_correlation_decode.py")
decoder = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(decoder)


HARNESS = r"""
#include <cstdio>
#include <cstdint>
#include "native/iwx_roc_rx_correlation.hpp"

int main() {
    using namespace NativeIwxRocRxCorrelation;
    Recorder recorder;
    if (!recorder.arm(1, 11, 1000)) return 1;
    RocEpoch epoch;
    epoch.contextGeneration = 6;
    epoch.powerGeneration = 11;
    epoch.stationGeneration = 23;
    epoch.rocGeneration = 6;
    epoch.sessionToken = 99;
    if (!recorder.beginRoc(epoch, 2000, 97000)) return 2;
    recorder.observeRxInterrupt(2100, false);
    recorder.observeRxDrain(2200);
    recorder.observeRxRingSlot(2300, 188, 189);
    recorder.observeRxNotification(2400, RxNotificationStage::kSeen);
    recorder.observeRxNotification(2490,
        RxNotificationStage::kRxMpduNotificationValidated);

    NativeIwxCompletionObserver::CopyResult copy;
    copy.status = NativeIwxCompletionObserver::CopyStatus::kCopied;
    copy.snapshot.incarnation = 44;
    for (size_t i = 0; i < sizeof(copy.snapshot.bytes); ++i)
        copy.snapshot.bytes[i] = static_cast<uint8_t>(i);

    SlotInput slot;
    slot.captureSerial = 1;
    slot.driverGeneration = 11;
    slot.ring = 0;
    slot.slot = 188;
    slot.head = 189;
    slot.copyTimeUs = 2500;
    slot.copySequence = 66;
    slot.epoch = epoch;
    Token token = recorder.beginSlot(slot, copy);
    if (!token.valid) return 3;

    Notification note;
    note.qid = 137;
    note.index = 234;
    note.code = 0x1001;
    note.packetOffset = 0;
    note.payloadLength = 96;
    note.packetLength = 106;
    note.outcome = static_cast<uint8_t>(NotificationOutcome::kMpduDispatch);
    if (!recorder.recordNotification(token, note)) return 4;

    Mpdu mpdu;
    mpdu.presence = kChannelPresent | kRawMacPhyPresent |
        kDecodeModePresent | kFrameControlPresent | kSequenceControlPresent |
        kRawStatusPresent | kMpduLengthPresent | kDescriptorSizePresent |
        kPacketOffsetPresent | kHostTimePresent;
    mpdu.channel = 149;
    mpdu.rawMacPhyIndex = 0x11;
    mpdu.decodeMode = 2;
    mpdu.frameControl = 0x80;
    mpdu.sequenceControl = 0x1234;
    mpdu.mpduLength = 287;
    mpdu.descriptorSize = 64;
    mpdu.packetOffset = 0;
    mpdu.qid = 137;
    mpdu.index = 234;
    mpdu.rawStatus = 0x101b;
    mpdu.hostRxMonotonicUs = 3000;
    if (!recorder.recordMpdu(token, mpdu)) return 5;
    if (!recorder.setParseFlags(token, kParseValidated)) return 6;
    if (!recorder.endRoc(epoch, 4000)) return 7;
    if (!recorder.finishSlot(token)) return 8;

    uint8_t wire[kWireBytes] = {};
    if (!recorder.encode(wire, sizeof(wire))) return 9;
    if (std::fwrite(wire, 1, sizeof(wire), stdout) != sizeof(wire)) return 10;
    return 0;
}
"""


class RocCorrelationWireTests(unittest.TestCase):
    def test_compiled_writer_matches_python_decoder_layout(self):
        with tempfile.TemporaryDirectory(prefix="test096-roc-wire-") as temp:
            temp = Path(temp)
            source = temp / "wire.cpp"
            binary = temp / "wire"
            source.write_text(HARNESS)
            subprocess.run([
                "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra",
                "-Werror", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(ROOT), str(source), "-o", str(binary),
            ], check=True)
            result = subprocess.run([str(binary)], check=True,
                                    stdout=subprocess.PIPE, timeout=10)
            self.assertEqual(len(result.stdout), decoder.WIRE_BYTES)
            decoded = decoder.decode(result.stdout, require_closed=True,
                                     expected_identity={
                                         "captureSerial": 1,
                                         "driverGeneration": 11,
                                         "contextGeneration": 6,
                                         "powerGeneration": 11,
                                         "stationGeneration": 23,
                                         "rocGeneration": 6,
                                         "sessionToken": 99,
                                         "armUs": 1000,
                                         "startUs": 2000,
                                         "deadlineUs": 97000,
                                     })
            self.assertTrue(decoded["coverageComplete"])
            self.assertEqual(decoded["rxWindowStage"], 7)
            self.assertEqual(decoded["rxWindowStageName"],
                             "rx_mpdu_notification_validated_seen")
            self.assertEqual(decoded["rxInterruptHandlerCalls"], 1)
            self.assertEqual(decoded["rxDrainCalls"], 1)
            self.assertEqual(decoded["rxRingSlots"], 1)
            self.assertEqual(decoded["rxMpduNotificationValidated"], 1)
            record = decoded["records"][0]
            self.assertEqual(record["sequence"], 1)
            self.assertEqual(record["completionSequence"], 66)
            self.assertEqual(record["slot"], 188)
            self.assertEqual(record["completionBytes"], "0001020304050607")
            self.assertEqual(record["notifications"][0]["index"], 234)
            self.assertEqual(record["mpdu"]["channel"], 149)
            self.assertEqual(record["mpdu"]["rawMacPhy"], 0x11)
            self.assertEqual(record["mpdu"]["hostRxUs"], 3000)


if __name__ == "__main__":
    unittest.main()
