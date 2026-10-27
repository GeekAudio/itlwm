#!/usr/bin/env python3
"""ASan/UBSan host fault-injection for the extracted production STA TXPATH_FLUSH handler."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ART = ROOT.parent / "IntelWirelessNative" / "research"
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def extract_function(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    end = opening + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


source = SOURCE.read_text()
production = extract_function(source, "int ItlIwx::\niwx_flush_sta_tids(")
# These assertions ensure the test remains bound to the production safety gates.
assert "qid >= nitems(sc->txq) || tid >= nitems(sc->sc_tid_data)" in production
assert production.index("tid >= nitems(sc->sc_tid_data)") < production.index(
    "sc->sc_tid_data[tid].qid")
assert production.index("iwx_tahoe_p2p_tvqm_queue_owned") < production.index(
    "txq = &sc->txq[qid]")

cases = r"""
int main() {
    ItlIwx owner{}; iwx_softc sc{};

    // Firmware TID and qid bounds must be checked before indexing host tables.
    resetFixture(owner, sc); gResponse.num_flushed_queues = 1;
    setQueue(0, 17, 2, 3); sc.sc_tid_data[17 - 1].qid = 2;
    run(owner, sc, 0, 0);
    resetFixture(owner, sc); gResponse.num_flushed_queues = 1;
    setQueue(0, 1, 8, 3); sc.sc_tid_data[1].qid = 8;
    run(owner, sc, 0, 0);

    // An owned P2P qid is skipped and reported without touching its ring.
    resetFixture(owner, sc); gResponse.num_flushed_queues = 1;
    owner.nativeP2pTxQueue_ = {true, 3};
    setQueue(0, 15, 3, 4); sc.sc_tid_data[15].qid = 3;
    const int ownedTail = sc.txq[3].tail;
    run(owner, sc, EBUSY, 0);
    assert(sc.txq[3].tail == ownedTail);

    // Mixed responses may reclaim only the ordinary STA queue.
    resetFixture(owner, sc); gResponse.num_flushed_queues = 2;
    owner.nativeP2pTxQueue_ = {true, 3};
    setQueue(0, 2, 1, 5); sc.sc_tid_data[2].qid = 1;
    setQueue(1, 15, 3, 4); sc.sc_tid_data[15].qid = 3;
    run(owner, sc, EBUSY, 1);
    assert(gLastAdvancedQid == 1 && gLastAdvancedIndex == 5);
    assert(sc.txq[3].tail == 0);

    // Invalid ring shape/identity and mismatched TID mapping are not advanced.
    resetFixture(owner, sc); gResponse.num_flushed_queues = 1;
    setQueue(0, 1, 2, 3); sc.sc_tid_data[1].qid = 2;
    sc.txq[2].ring_count = 0;
    run(owner, sc, 0, 0);
    resetFixture(owner, sc); gResponse.num_flushed_queues = 1;
    setQueue(0, 1, 2, 3); sc.sc_tid_data[1].qid = 2;
    sc.txq[2].qid = 4;
    run(owner, sc, 0, 0);
    resetFixture(owner, sc); gResponse.num_flushed_queues = 1;
    setQueue(0, 1, 2, 3); sc.sc_tid_data[1].qid = 4;
    run(owner, sc, 0, 0);

    // Non-power-of-two ring sizes make the production SSN mask invalid.
    resetFixture(owner, sc); gResponse.num_flushed_queues = 1;
    setQueue(0, 1, 2, 3); sc.sc_tid_data[1].qid = 2;
    sc.txq[2].ring_count = 6;
    run(owner, sc, 0, 0);

    // A response for another station must fail before any reclaim.
    resetFixture(owner, sc); gResponse.sta_id = 1;
    gResponse.num_flushed_queues = 1;
    setQueue(0, 1, 2, 3); sc.sc_tid_data[1].qid = 2;
    run(owner, sc, EIO, 0);

    // The ordinary valid STA case still advances exactly to read_after_flush.
    resetFixture(owner, sc); gResponse.num_flushed_queues = 1;
    setQueue(0, 4, 2, 6); sc.sc_tid_data[4].qid = 2;
    run(owner, sc, 0, 1);
    assert(gLastAdvancedQid == 2 && gLastAdvancedIndex == 6);
    return 0;
}
"""


def main() -> None:
    cpp = r"""
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#define AIRPORT_TAHOE 1
#define IWX_CMD_FAILED_MSK 0x80
#define IWX_CMD_WANT_RESP 1
#define IWX_TXPATH_FLUSH 0x1234
#define IWX_TX_FLUSH_QUEUE_RSP 16
#define IWX_TFD_QUEUE_SIZE_MAX 256
#define IWX_INVALID_QUEUE 0xffff
#define nitems(a) (sizeof(a) / sizeof((a)[0]))
#define IWX_AGG_SSN_TO_TXQ_IDX(ssn, count) ((ssn) & ((count) - 1))
static uint16_t hostLittle16(uint16_t v) { return v; }
static uint32_t hostLittle32(uint32_t v) { return v; }
#define htole16(v) hostLittle16(static_cast<uint16_t>(v))
#define htole32(v) hostLittle32(static_cast<uint32_t>(v))
#define le16toh(v) hostLittle16(static_cast<uint16_t>(v))
struct iwx_tx_path_flush_cmd { uint32_t sta_id; uint16_t tid_mask; uint16_t reserved; } __attribute__((packed));
struct iwx_flush_queue_info { uint16_t tid, queue_num, read_before_flush, read_after_flush; } __attribute__((packed));
struct iwx_tx_path_flush_cmd_rsp { uint16_t sta_id, num_flushed_queues; iwx_flush_queue_info queues[IWX_TX_FLUSH_QUEUE_RSP]; } __attribute__((packed));
struct iwx_cmd_header { uint8_t group_id = 0; };
struct iwx_rx_packet { iwx_cmd_header hdr{}; uint8_t data[sizeof(iwx_tx_path_flush_cmd_rsp)]{}; size_t payloadLength = sizeof(iwx_tx_path_flush_cmd_rsp); };
struct iwx_host_cmd { uint32_t id = 0; size_t len[1]{}; void *data[1]{}; uint32_t flags = 0; size_t resp_pkt_len = 0; iwx_rx_packet *resp_pkt = nullptr; };
static size_t iwx_rx_packet_payload_len(const iwx_rx_packet *p) { return p ? p->payloadLength : 0; }
struct iwx_tx_ring { uint16_t qid = IWX_INVALID_QUEUE; uint16_t ring_count = 0; int tail = 0; };
struct iwx_tid_data { uint16_t qid = IWX_INVALID_QUEUE; };
struct iwx_softc { iwx_tx_ring txq[8]{}; iwx_tid_data sc_tid_data[17]{}; };
struct TahoeP2PTxQueueLease { bool owned = false; uint16_t qid = IWX_INVALID_QUEUE; };
static bool iwx_tahoe_p2p_tvqm_queue_owned(TahoeP2PTxQueueLease *lease, uint16_t qid) { return lease && lease->owned && lease->qid == qid; }
static iwx_rx_packet gPacket{};
static iwx_tx_path_flush_cmd_rsp gResponse{};
static size_t gPayloadLength = sizeof(iwx_tx_path_flush_cmd_rsp);
static int gSendError = 0;
static bool gResponseFailed = false;
static unsigned gFreeResponses = 0, gAdvanceCalls = 0;
static uint16_t gLastAdvancedQid = IWX_INVALID_QUEUE;
static int gLastAdvancedIndex = -1;
static iwx_softc *gCurrentSoftc = nullptr;
class ItlIwx { public:
 TahoeP2PTxQueueLease nativeP2pTxQueue_{};
 int iwx_send_cmd(iwx_softc *, iwx_host_cmd *command) { if (gSendError) return gSendError; gPacket = {}; gPacket.payloadLength = gPayloadLength; if (gPayloadLength >= sizeof(gResponse)) std::memcpy(gPacket.data, &gResponse, sizeof(gResponse)); gPacket.hdr.group_id = gResponseFailed ? IWX_CMD_FAILED_MSK : 0; command->resp_pkt = &gPacket; return 0; }
 void iwx_free_resp(iwx_softc *, iwx_host_cmd *command) { ++gFreeResponses; command->resp_pkt = nullptr; }
 void iwx_ampdu_txq_advance(iwx_softc *, iwx_tx_ring *ring, int index) { assert(ring && ring->qid < nitems(gCurrentSoftc->txq)); ++gAdvanceCalls; gLastAdvancedQid = ring->qid; gLastAdvancedIndex = index; ring->tail = index; }
 int iwx_flush_sta_tids(iwx_softc *, int, uint16_t);
};
static void resetFixture(ItlIwx &owner, iwx_softc &sc) { owner.nativeP2pTxQueue_ = {}; sc = {}; for (uint16_t q=0;q<nitems(sc.txq);++q) { sc.txq[q].qid=q; sc.txq[q].ring_count=8; } gResponse = {}; gResponse.sta_id=0; gPayloadLength=sizeof(gResponse); gSendError=0; gResponseFailed=false; gFreeResponses=0; gAdvanceCalls=0; gLastAdvancedQid=IWX_INVALID_QUEUE; gLastAdvancedIndex=-1; gCurrentSoftc=&sc; }
static void setQueue(uint16_t index,uint16_t tid,uint16_t qid,uint16_t readAfter) { assert(index<IWX_TX_FLUSH_QUEUE_RSP); gResponse.queues[index]={tid,qid,0,readAfter}; }
static void run(ItlIwx &owner,iwx_softc &sc,int expectedResult,unsigned expectedAdvances) { assert(owner.iwx_flush_sta_tids(&sc,0,0xffff)==expectedResult); assert(gAdvanceCalls==expectedAdvances); assert(gFreeResponses==1); }
""" + production + "\n" + cases
    with tempfile.TemporaryDirectory(prefix="test055-sta-flush-") as temp:
        source_file = Path(temp) / "test.cpp"
        binary = Path(temp) / "test"
        source_file.write_text(cpp)
        subprocess.run([
            "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "-Wno-unused-function", "-Wno-unused-variable", "-o", str(binary),
            str(source_file),
        ], cwd=ROOT, check=True)
        subprocess.run([str(binary)], cwd=ROOT, check=True)

    report = {
        "production_method_extracted": "iwx_flush_sta_tids",
        "host_fault_injection_cases": 10,
        "tid_qid_bounds_guarded": True,
        "owned_qid_never_advances": True,
        "mixed_sta_and_owned_response_only_advances_sta": True,
        "zero_non_power_of_two_wrong_qid_ring_rejected": True,
        "station_mismatch_rejected": True,
        "valid_sta_flush_advances_to_read_after": True,
        "asan_ubsan_passed": True,
        "kernel_runtime_or_rf_tested": False,
    }
    ART.mkdir(parents=True, exist_ok=True)
    (ART / "test055-sta-flush-guard-host-private.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report))


if __name__ == "__main__":
    main()
