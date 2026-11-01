#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()


def main():
    rx_start = SOURCE.index("iwx_rx_pkt(struct iwx_softc *sc,")
    rx_end = SOURCE.index("\nvoid ItlIwx::", rx_start)
    rx_source = SOURCE[rx_start:rx_end]

    length_guard = rx_source.index(
        "if (len < minsz || len > (IWX_RBUF_SIZE - offset))")
    failed_response = rx_source.index(
        "if ((pkt->hdr.group_id & IWX_CMD_FAILED_MSK) != 0", length_guard)
    no_buffer = rx_source.index(
        "if (sc->sc_cmd_resp_pkt[idx] == NULL)", failed_response)
    no_buffer_end = rx_source.index("\n                }", no_buffer)
    no_buffer_source = rx_source[no_buffer:no_buffer_end]

    assert length_guard < failed_response < no_buffer
    failed_source = rx_source[failed_response:no_buffer]
    for required in (
        "commandRing->data != nullptr",
        "qid == IWX_DQA_CMD_QUEUE",
        "pkt->hdr.cmd == IWX_ADD_STA_KEY",
        "IwxAddStaKeyStatus::isPendingCommandQueueIndex(",
        "commandRing->queued",
        "hostCommand->hdr_wide.group_id == IWX_LONG_GROUP",
        "hostCommand->hdr_wide.cmd == IWX_ADD_STA_KEY",
        "hostCommand->hdr_wide.qid == IWX_DQA_CMD_QUEUE",
        "hostCommand->hdr_wide.idx == idx",
        "responseGroup == IWX_LONG_GROUP",
        "code = IWX_ADD_STA_KEY",
    ):
        assert required in failed_source, required

    assert "IwxAddStaKeyStatus::decode(" in no_buffer_source
    for required in (
        "static_cast<uint32_t>(code)",
        "IWX_ADD_STA_KEY",
        "static_cast<uint32_t>(qid)",
        "IWX_DQA_CMD_QUEUE",
        "IWX_CMD_FAILED_MSK",
        "pkt->data",
        "payloadLength",
        "IWX_RBUF_SIZE - offset - minsz",
        "kFirmwareStatusPresent",
        "kFirmwareStatusUnavailable",
        "kCommandResponseFailed",
        "diagnosticEntry.result = keyStatus.status",
    ):
        assert required in no_buffer_source, required

    assert "NativeHcmdRxTrace" in SOURCE
    publish_begin = SOURCE.index("NativeHcmdRxTracePublishRevisionBegin", SOURCE.index("tahoePublishFirmwareDiagnostics("))
    latest_key = SOURCE.index('setKeyResponse32("Present"', publish_begin)
    publish_end = SOURCE.index("NativeHcmdRxTracePublishRevisionEnd", latest_key)
    assert publish_begin < latest_key < publish_end
    for required in (
        'setKeyResponse32("Stable"',
        'setKeyResponse64("DroppedSerial"',
        'setKeyResponse64("Serial"',
        'setKeyResponse64("MonotonicNs"',
        'setKeyResponse32("DriverGeneration"',
        'setKeyResponse32("FirmwareGeneration"',
        'setKeyResponse32("Phase"',
        'setKeyResponse32("Flags"',
        'setKeyResponse32("Result"',
        'setKeyResponse64("TraceVersionBegin"',
        'setKeyResponse64("TraceVersionEnd"',
    ):
        assert required in SOURCE, required
    print("Test101 ADD_STA_KEY status hook source checks: PASS")


if __name__ == "__main__":
    main()
