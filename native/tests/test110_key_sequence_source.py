"""Static and firmware-TLV checks for Test110 CCMP key sequence support."""
from pathlib import Path
import struct
import unittest


ROOT = Path(__file__).resolve().parents[2]
DRIVER = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
FW_SOURCE = (ROOT / "native/iwx_fw_diagnostics.hpp").read_text()
RECEIPT = (ROOT / "native/iwx_sta_auth_trace.h").read_text()
HELPER = (ROOT / "native/iwx_sta_key_rx_pn.hpp").read_text()
FIRMWARE = ROOT / "itlwm/firmware/iwlwifi-so-a0-hr-b0-68.ucode"


def firmware_add_sta_key_api(path):
    data = path.read_bytes()
    if len(data) < 88 or struct.unpack_from("<II", data) != (0, 0x0A4C5749):
        raise AssertionError("invalid firmware TLV header")
    offset = 88
    matches = []
    tables = 0
    while offset + 8 <= len(data):
        tlv_type, length = struct.unpack_from("<II", data, offset)
        offset += 8
        end = offset + length
        if end > len(data):
            raise AssertionError("truncated firmware TLV")
        if tlv_type == 48:
            tables += 1
            if length % 4:
                raise AssertionError("CMD_VERSIONS entry tail")
            for entry in range(offset, end, 4):
                command, group, version, notification = struct.unpack_from(
                    "<4B", data, entry)
                if (command, group) == (0x17, 0x01):
                    matches.append((version, notification))
        offset = (end + 3) & ~3
    if offset != len(data) or tables != 1 or len(matches) != 1:
        raise AssertionError("firmware CMD_VERSIONS table missing or ambiguous")
    return matches[0]


class Test110KeySequenceSource(unittest.TestCase):
    def test_runtime_so_hr68_firmware_reports_api3(self):
        self.assertEqual(firmware_add_sta_key_api(FIRMWARE), (3, 0))

    def test_actual_payload_layout_is_asserted(self):
        for declaration in (
            "sizeof(struct iwx_add_sta_key_common) == 52",
            "offsetof(struct iwx_add_sta_key_common, rx_secur_seq_cnt) == 36",
            "sizeof(struct iwx_add_sta_key_cmd) == 76",
            "offsetof(struct iwx_add_sta_key_cmd, transmit_seq_cnt) == 68",
        ):
            self.assertIn(declaration, DRIVER)

    def test_key_submit_uses_firmware_version_and_host_rsc(self):
        start = DRIVER.index("static int iwx_set_key_with_receipt(")
        end = DRIVER.index("int ItlIwx::\niwx_set_key(", start)
        key_path = DRIVER[start:end]
        self.assertIn("iwx_lookup_cmd_ver(\n        sc, IWX_LONG_GROUP, IWX_ADD_STA_KEY)", key_path)
        self.assertIn("encodeCcmp(\n        k->k_rsc, IEEE80211_NUM_TID, keyApiVersion", key_path)
        self.assertIn("memcpy(cmd.common.rx_secur_seq_cnt, rxSequence.bytes", key_path)
        self.assertIn("const uint64_t transmitSequencePn = k->k_tsc;", key_path)
        self.assertIn("receipt->key_sequence_tx_pn = transmitSequencePn", key_path)
        self.assertIn("cmd.transmit_seq_cnt = htole64(transmitSequencePn)", key_path)
        self.assertEqual(key_path.count("k->k_tsc"), 1,
                         "payload and receipt must share one TSC sample")
        self.assertIn("Status::kReady", key_path)
        self.assertIn("return EINVAL;", key_path)
        self.assertIn("Unknown/unsupported command versions leave", key_path)

    def test_key_counter_observation_is_driver_owned_and_secret_free(self):
        start = DRIVER.index("if (receipt != nullptr &&\n        receipt->state == IWX_STA_SUBMIT_LOCAL_ENQUEUE")
        end = DRIVER.index("if (!async)", start)
        record = DRIVER[start:end]
        self.assertIn("KeyRxSequenceSubmitted", record)
        self.assertIn("KeyTxSequenceSubmitted", record)
        self.assertIn("KeySequenceUnavailable", record)
        self.assertIn("receipt->queue_id", record)
        self.assertIn("receipt->queue_index", record)
        self.assertIn("tahoeRecordFirmwareMetadata(sc, sequenceEntry)", record)
        self.assertNotIn("k_key", record)
        self.assertNotIn("memcpy", record)
        self.assertIn("KeyRxSequenceSubmitted = 14", FW_SOURCE)
        self.assertIn("KeyTxSequenceSubmitted = 15", FW_SOURCE)
        self.assertIn("key_sequence_rx_pn", RECEIPT)
        self.assertIn("key_sequence_tx_pn", RECEIPT)

    def test_key_sequence_rows_keep_submission_generation_across_reset_race(self):
        send_start = DRIVER.index(
            "iwx_send_cmd(struct iwx_softc *sc, struct iwx_host_cmd *hcmd,")
        send_end = DRIVER.index(
            "int ItlIwx::\niwx_send_cmd_pdu(", send_start)
        send_path = DRIVER[send_start:send_end]
        self.assertIn(
            "receipt->driver_generation = static_cast<uint32_t>(generation);",
            send_path,
        )

        sequence_start = DRIVER.index(
            "const auto recordKeySequence = [this, sc, receipt,\n"
            "                                        commandSubmitSerial](")
        sequence_end = DRIVER.index("if (!async)", sequence_start)
        sequence_path = DRIVER[sequence_start:sequence_end]
        self.assertIn(
            "sequenceEntry.driver_generation = receipt->driver_generation;",
            sequence_path,
        )
        self.assertIn("kOriginGenerationPresent", sequence_path)
        self.assertIn("kOriginSubmitSerialPresent", sequence_path)
        self.assertIn("sequenceEntry.packet_length", sequence_path)
        self.assertIn("sequenceEntry.payload_length", sequence_path)

        recorder_start = DRIVER.index(
            "uint64_t ItlIwx::tahoeRecordFirmwareMetadata(")
        recorder_end = DRIVER.index(
            "void ItlIwx::tahoeFreezeFirmwareMetadata(", recorder_start)
        self.assertIn(
            "IwxFirmwareDiagnostics::applyMetadataGeneration(",
            DRIVER[recorder_start:recorder_end],
        )
        self.assertIn("kOriginGenerationChangedBeforeRecord", FW_SOURCE)

    def test_helper_fails_closed_for_unknown_versions_and_bounds_pn(self):
        self.assertIn("apiVersion != 2 && apiVersion != 3", HELPER)
        self.assertIn("kPnOutOfRange", HELPER)
        self.assertIn("const size_t hole = apiVersion >= 3 ? 0 : 2", HELPER)


if __name__ == "__main__":
    unittest.main()
