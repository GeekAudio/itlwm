#!/usr/bin/env python3
"""Check Test103's TX_RSP observation stays in the existing bounded path."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def body(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise AssertionError(f"unterminated function: {marker}")


def main() -> None:
    source = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
    facts = body(source, "txCompletionSetTxRspRetryFacts(")
    kind_guard = facts.index("event->kind != IWX_TX_COMPLETION_TX_RSP")
    frame_count_guard = facts.index("event->frame_count != 1", kind_guard)
    length = facts.index("const size_t oneFrameRequiredLength", frame_count_guard)
    decode = facts.index("decodeSingleFrameV1(", length)
    version = facts.index("event->tx_rsp_retry_stats_version =", decode)
    assert kind_guard < frame_count_guard < length < decode < version
    assert "IWX_TX_COMPLETION_HAS_FRAME_COUNT" in facts[:length]
    assert "IWX_TX_COMPLETION_HAS_PAYLOAD_LENGTH" in facts[:length]
    assert "payloadLength,\n            oneFrameRequiredLength, &retryStats" in facts[decode:version]
    assert "retryStats.bt_kill_count" in facts[version:]
    assert "retryStats.failure_rts" in facts[version:]
    assert "retryStats.failure_frame" in facts[version:]
    sta_handler = body(source, "iwx_rx_tx_cmd(struct iwx_softc *sc,")
    invalid_index = sta_handler.index("if (!responseIndexValid)")
    invalid_return = sta_handler.index("return;", invalid_index)
    accepted_retry = sta_handler.index("txCompletionSetTxRspRetryFacts(")
    assert accepted_retry > invalid_return
    assert source.count("txCompletionSetTxRspRetryFacts(") == 2
    p2p_dispatch = source[
        source.index("case IWX_TX_CMD:"):
        source.index("iwx_rx_tx_cmd(struct iwx_softc *sc,")]
    assert "txCompletionSetTxRspRetryFacts(" not in p2p_dispatch
    assert "IWX_TX_COMPLETION_TX_RSP" in source[
        source.index("static iwx_tx_completion_event_input txCompletionRxInput("):]

    publisher = body(source, "publishCompletionSnapshot(IOEthernetController *controller,")
    assert "scalar(\"Schema\", 5)" in publisher
    for field in (
        'PUBLISH_COMPLETION_FIELD("TxRspRetryStatsVersion",',
        'PUBLISH_COMPLETION_FIELD("TxRspBtKillCount",',
        'PUBLISH_COMPLETION_FIELD("TxRspFailureRts",',
        'PUBLISH_COMPLETION_FIELD("TxRspFailureFrame",',
    ):
        assert field in publisher, field

    header = (ROOT / "native/iwx_tx_completion_observation.hpp").read_text()
    assert "sizeof(iwx_tx_completion_event_record) == 240" not in header
    assert "sizeof(iwx_tx_completion_event_record) <= 240" in header
    for member, padding in (
        ("tx_rsp_bt_kill_count", 1),
        ("tx_rsp_failure_rts", 2),
        ("tx_rsp_failure_frame", 3),
    ):
        assert f"host_origin_state) + {padding}" in header
        assert member in header
    assert "host_origin_index) ==" in header
    print("Test103 TX_RSP retry hook source checks: PASS")


if __name__ == "__main__":
    main()
