#!/usr/bin/env python3
"""Focused offline tests for Test099's single-slot TXCMD identity observation."""
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile


REPO = Path(__file__).resolve().parents[2]


def test_cpp_contract() -> None:
    source = Path(__file__).with_name("tx_identity_observation_test.cpp")
    with tempfile.TemporaryDirectory(prefix="itlwm-test099-tx-id-") as tmp:
        binary = Path(tmp) / "tx_identity_observation_test"
        subprocess.run(
            [
                "clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                f"-I{REPO}", str(source), "-o", str(binary),
            ],
            check=True,
            cwd=REPO,
        )
        subprocess.run([str(binary)], check=True, cwd=REPO)


def test_live_scanner_records_only_single_readable_slot() -> None:
    source = (REPO / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
    scanner_start = source.index("static void txCompletionScanLiveTxCommands(")
    scanner_end = source.index("\n}\n#endif", scanner_start) + 2
    scanner = source[scanner_start:scanner_end]
    assert "iwx_txcmd_identity_scan_record" in scanner
    assert "iwx_txcmd_identity_scan_has_single_observed_slot_header(&scan)" in scanner
    assert "scan.first_observed_candidate" in scanner
    assert "IWX_TX_COMPLETION_HAS_SINGLE_SLOT_TXCMD_HEADER" in scanner
    assert "single_slot_txcmd_header" in scanner
    assert "iwx_txcmd_identity_scan_has_unique_candidate(&scan)" in scanner


def test_exact_completion_match_and_ack_claim_are_unchanged() -> None:
    source = (REPO / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
    assert "le16toh(tx_resp->frame_ctrl), le16toh(tx_resp->seq_ctl)," in source
    assert 'scalar("FirmwareResponseIdentityProven", 0)' in source
    assert 'scalar("PeerReceiptProven", 0)' in source


def test_response_metadata_never_uses_exclusive_boundary_slot() -> None:
    source = (REPO / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
    start = source.index("/*\n         * SSN's checkedIndex is an exclusive reclaim boundary.")
    end = source.index("iwx_rx_tx_cmd_single(sc, pkt, completionTxd);", start)
    selection = source[start:end]
    assert "iwx_tx_response_single_reclaim_metadata_index" in selection
    assert "responseOldTail" in selection and "checkedIndex" in selection
    assert "candidate->m != nullptr" in selection
    assert "&ring->data[idx]" not in selection
    consumer_start = source.index("iwx_rx_tx_cmd_single(struct iwx_softc *sc")
    consumer_end = source.index("\n}\n", consumer_start) + 2
    consumer = source[consumer_start:consumer_end]
    assert "txd != nullptr ? txd->type : -1" in consumer
    assert "txd != nullptr && txd->type == IEEE80211_FC0_TYPE_MGT" in consumer
    assert "ifp->netStat->outputErrors++" in consumer


def test_ax201_gen2_path_does_not_request_firmware_seq_override() -> None:
    source = (REPO / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
    fill_start = source.index("iwx_tx_fill_cmd(struct iwx_softc *sc")
    fill_end = source.index("\n}\n", fill_start) + 2
    fill = source[fill_start:fill_end]
    tx_start = source.index("iwx_tx(struct iwx_softc *sc")
    tx_end = source.index("\n}\n", tx_start) + 2
    tx = source[tx_start:tx_end]
    assert "IWX_TX_FLAGS_CMD_RATE" in fill
    assert "IWX_TX_FLAGS_ENCRYPT_DIS" in tx
    assert "IWX_TX_CMD_FLG_SEQ_CTL" not in fill + tx
    assert "IWX_TX_CMD_FLG_KEEP_SEQ_CTL" not in fill + tx
    assert "tx_gen2->flags = htole32(flags);" in tx
    assert "tx_gen3->flags = htole16(flags);" in tx


def main() -> None:
    test_cpp_contract()
    test_live_scanner_records_only_single_readable_slot()
    test_exact_completion_match_and_ack_claim_are_unchanged()
    test_response_metadata_never_uses_exclusive_boundary_slot()
    test_ax201_gen2_path_does_not_request_firmware_seq_override()
    print("Test099 TX identity focused tests passed.")


if __name__ == "__main__":
    main()
