#!/usr/bin/env python3
"""Exercise the production TX_CMD producer bytes against the live scanner."""

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PRODUCTION = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
P2P_PRODUCTION = ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp"
CXX = shutil.which("clang++") or shutil.which("g++") or "c++"


def braced_source(source: str, marker_at: int) -> tuple[str, int]:
    opening = source.index("{", marker_at)
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "line-comment":
            if char == "\n":
                state = "code"
        elif state == "block-comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif ((state == "string" and char == '"') or
                  (state == "char" and char == "'")):
                state = "code"
        else:
            if char == "/" and next_char == "/":
                state = "line-comment"
                index += 1
            elif char == "/" and next_char == "*":
                state = "block-comment"
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
                    return source[marker_at:index + 1], index + 1
        index += 1
    raise AssertionError("unterminated production block")


def extract_function(source: str, signature: str) -> str:
    marker_at = source.index(signature)
    return braced_source(source, marker_at)[0]


def extract_if_else(source: str, marker: str, after: int) -> str:
    marker_at = source.index(marker, after)
    if_body, end = braced_source(source, marker_at)
    cursor = end
    while cursor < len(source) and source[cursor].isspace():
        cursor += 1
    if source[cursor:cursor + 4] != "else":
        raise AssertionError("production TX command payload branch lost its else")
    else_at = cursor + 4
    else_body, end = braced_source(source, else_at)
    return source[marker_at:end]


CPP_PREFIX = r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "native/iwx_tx_completion_observation.hpp"
#include "native/iwx_txcmd_identity_observation.hpp"

#define IWX_TX_CMD 0x1c
#define IWX_LONG_GROUP 1
#define IWX_DEVICE_FAMILY_AX210 3
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_CTL 0x04
#define nitems(value) (sizeof(value) / sizeof((value)[0]))
#define __packed __attribute__((packed))

static uint16_t le16toh(uint16_t value) { return value; }
static uint32_t le32toh(uint32_t value) { return value; }
static uint16_t htole16(uint16_t value) { return value; }
static uint32_t htole32(uint32_t value) { return value; }

struct __packed ieee80211_frame {
    uint8_t i_fc[2];
    uint8_t i_dur[2];
    uint8_t i_addr1[6];
    uint8_t i_addr2[6];
    uint8_t i_addr3[6];
    uint8_t i_seq[2];
};
struct __packed iwx_dram_sec_info {
    uint32_t pn_low;
    uint16_t pn_high;
    uint16_t aux_info;
};
struct __packed iwx_tx_cmd_gen2 {
    uint16_t len;
    uint16_t offload_assist;
    uint32_t flags;
    iwx_dram_sec_info dram_info;
    uint32_t rate_n_flags;
    ieee80211_frame hdr[0];
};
struct __packed iwx_tx_cmd_gen3 {
    uint16_t len;
    uint16_t flags;
    uint32_t offload_assist;
    iwx_dram_sec_info dram_info;
    uint32_t rate_n_flags;
    uint64_t ttl;
    ieee80211_frame hdr[0];
};
struct iwx_cmd_header {
    uint8_t cmd;
    uint8_t group_id;
    uint8_t idx;
    uint8_t qid;
};
struct iwx_device_cmd {
    iwx_cmd_header hdr;
    uint8_t data[320];
};
struct iwx_tx_data { void *m; };
struct iwx_tx_ring {
    uint32_t qid;
    uint32_t ring_count;
    iwx_tx_data data[1024];
    iwx_device_cmd *cmd;
};
struct iwx_softc {
    uint32_t sc_device_family;
    iwx_tx_ring txq[4];
};
struct iwx_tx_resp {
    uint16_t frame_ctrl;
    uint16_t seq_ctl;
};

static_assert(sizeof(ieee80211_frame) == 24, "802.11 header size");
static_assert(sizeof(iwx_tx_cmd_gen2) == 20, "Gen2 TX command header size");
static_assert(sizeof(iwx_tx_cmd_gen3) == 28, "Gen3 TX command header size");
"""


def main() -> int:
    source = PRODUCTION.read_text(encoding="utf-8")
    p2p_source = P2P_PRODUCTION.read_text(encoding="utf-8")

    scanner = extract_function(source, "static void txCompletionScanLiveTxCommands(")
    tx_body = extract_function(source, "int ItlIwx::\niwx_tx(")
    writer_start = tx_body.index("cmd->hdr.cmd = IWX_TX_CMD;")
    writer_end = tx_body.index("\n    rinfo = iwx_tx_fill_cmd", writer_start)
    producer_header = tx_body[writer_start:writer_end]
    payload = extract_if_else(
        tx_body,
        "if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)",
        writer_end,
    )
    m_assignment = tx_body.index("data->m = m;", tx_body.index(payload) + len(payload))
    producer_m_assignment = tx_body[m_assignment:m_assignment + len("data->m = m;")]
    tx_fill_rate = extract_function(source, "const struct iwx_rate *ItlIwx::\niwx_tx_fill_cmd(")

    # API lookup uses the wide API-table namespace; the emitted TX_CMD wire
    # header uses group 0. P2P's independent TX producer follows the same wire.
    assert "iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_TX_CMD)" in tx_fill_rate
    assert "cmd->hdr.group_id = 0;" in producer_header
    assert "deviceCommand->hdr.group_id = 0;" in p2p_source
    assert "command->hdr.group_id == 0" in scanner
    assert "command->hdr.idx == (index & UINT8_MAX)" in scanner
    assert "command->hdr.group_id == IWX_LONG_GROUP" not in scanner

    cpp = CPP_PREFIX + "\n" + scanner + "\n" + r"""
static void produceActualTxCommand(iwx_softc *sc, iwx_tx_ring *ring,
                                   int index, ieee80211_frame *wh)
{
    int qid = static_cast<int>(ring->qid);
    int idx = index;
    iwx_device_cmd *cmd = &ring->cmd[idx];
    iwx_tx_data *data = &ring->data[idx];
    iwx_tx_cmd_gen2 *tx_gen2 = nullptr;
    iwx_tx_cmd_gen3 *tx_gen3 = nullptr;
    uint32_t flags = 0x12345;
    uint32_t rate_n_flags = 0x0c;
    uint16_t offload_assist = 0x0c00;
    uint16_t cmd_size = 0;
    int totlen = sizeof(*wh);
    uint32_t hdrlen = sizeof(*wh);
    void *m = wh;
""" + producer_header + "\n" + payload + "\n" + producer_m_assignment + r"""
}

static void testActualProducerAndScanner(uint32_t family, uint32_t api,
                                         int firstIndex, int targetIndex)
{
    iwx_softc sc{};
    sc.sc_device_family = family;
    iwx_tx_ring &ring = sc.txq[1];
    iwx_device_cmd commands[1024]{};
    ring.qid = 1;
    ring.ring_count = 1024;
    ring.cmd = commands;

    ieee80211_frame first{};
    first.i_fc[0] = 0x08;
    first.i_fc[1] = 0x41;
    first.i_seq[0] = 0x40;
    first.i_seq[1] = 0x05;
    ieee80211_frame target = first;
    target.i_seq[0] = 0x80;

    // This runs the exact header and GEN2/GEN3 command-payload producer code
    // lifted from iwx_tx(), then passes those bytes to the exact production
    // completion scanner. It does not fabricate scanner candidates.
    produceActualTxCommand(&sc, &ring, firstIndex, &first);
    produceActualTxCommand(&sc, &ring, targetIndex, &target);
    assert(ring.cmd[firstIndex].hdr.group_id == 0 &&
           ring.cmd[targetIndex].hdr.group_id == 0);
    assert(ring.cmd[firstIndex].hdr.cmd == IWX_TX_CMD &&
           ring.cmd[targetIndex].hdr.cmd == IWX_TX_CMD);
    assert(ring.cmd[firstIndex].hdr.qid == 1 &&
           ring.cmd[targetIndex].hdr.qid == 1);
    assert(ring.cmd[firstIndex].hdr.idx == (firstIndex & 0xff));
    assert(ring.cmd[targetIndex].hdr.idx == (targetIndex & 0xff));

    iwx_tx_resp response{};
    response.frame_ctrl = 0x4108;
    response.seq_ctl = 0x0580;
    iwx_tx_completion_event_input event{};
    const uint32_t reclaimBoundary =
        (static_cast<uint32_t>(targetIndex) + 1) % ring.ring_count;
    txCompletionScanLiveTxCommands(&event, &sc, &ring, 1,
                                   firstIndex, 2, reclaimBoundary,
                                   &response, 7);
    assert(event.presence_flags & IWX_TX_COMPLETION_HAS_TXCMD_SCAN);
    assert(event.presence_flags & IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE);
    assert(event.txcmd_scan_status == IWX_TXCMD_IDENTITY_SCAN_COMPLETE);
    assert(event.txcmd_expected_count == 2 && event.txcmd_scanned_count == 2);
    assert(event.txcmd_candidate_count == 1 &&
           event.txcmd_candidate_index == static_cast<uint32_t>(targetIndex));
    assert(event.txcmd_api_generation == api && event.txcmd_command_version == 7);
    assert(event.txcmd_offload_assist == 0x0c00);

    // A descriptor whose narrow header index no longer matches its physical
    // 1024-entry slot must make the interval incomplete, never unique.
    ring.cmd[targetIndex].hdr.idx =
        static_cast<uint8_t>(ring.cmd[targetIndex].hdr.idx + 1);
    iwx_tx_completion_event_input mismatchedIndex{};
    txCompletionScanLiveTxCommands(&mismatchedIndex, &sc, &ring, 1,
                                   firstIndex, 2, reclaimBoundary,
                                   &response, 7);
    assert(mismatchedIndex.txcmd_scan_status ==
           IWX_TXCMD_IDENTITY_SCAN_INCOMPLETE);
    assert(mismatchedIndex.txcmd_candidate_count == 0);
    assert((mismatchedIndex.presence_flags &
            IWX_TX_COMPLETION_HAS_TXCMD_UNIQUE_CANDIDATE) == 0);
}

int main()
{
    testActualProducerAndScanner(2, 2, 256, 257); // Gen2; 8-bit index wraps.
    testActualProducerAndScanner(2, 2, 1022, 1023); // Gen2; top of 1024 ring.
    testActualProducerAndScanner(3, 3, 256, 257); // Gen3; 8-bit index wraps.
    testActualProducerAndScanner(3, 3, 1022, 1023); // Gen3; top of 1024 ring.
}
"""

    with tempfile.TemporaryDirectory(prefix="test097-txcmd-identity-") as tmp:
        source_path = Path(tmp) / "txcmd_producer_scanner.cpp"
        binary_path = Path(tmp) / "txcmd_producer_scanner"
        source_path.write_text(cpp, encoding="utf-8")
        subprocess.run(
            [CXX, "-std=c++17", "-O0", "-I", str(ROOT), str(source_path),
             "-o", str(binary_path)],
            check=True,
        )
        subprocess.run([str(binary_path)], check=True)
    print("PASS production TX_CMD producer bytes join through the production scanner (Gen2/Gen3)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
