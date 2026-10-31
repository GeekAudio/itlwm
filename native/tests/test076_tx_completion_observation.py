#!/usr/bin/env python3
"""Compile and run Test076's fixed-size TX completion observer on host."""

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/tests/iwx_tx_completion_observation_test.cpp"
PRODUCTION = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
XCRUN = shutil.which("xcrun")
if XCRUN:
    CXX = [XCRUN, "clang++"]
    CC = [XCRUN, "clang"]
else:
    CXX = [shutil.which("clang++") or "clang++"]
    CC = [shutil.which("clang") or "clang"]


def braced_source(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start : end + 1]
    raise AssertionError(f"unterminated production block: {marker}")


def check_production_wiring() -> tuple[str, str, str]:
    source = PRODUCTION.read_text(encoding="utf-8")
    rx_body = braced_source(source, "void ItlIwx::\niwx_rx_pkt(")
    ba_body = braced_source(
        source,
        "iwx_rx_tx_ba_notif(struct iwx_softc *sc, struct iwx_rx_packet *pkt, struct iwx_rx_data *data)",
    )
    tx_body = braced_source(source, "void ItlIwx::\niwx_rx_tx_cmd(")
    dispatch_start = source.index("case IWX_TX_CMD:")
    dispatch_end = source.index("case IWX_MISSED_BEACONS_NOTIFICATION:",
                                dispatch_start)
    dispatch = source[dispatch_start:dispatch_end]

    assert "rxParseStop.setReason(IWX_TX_COMPLETION_RX_DESCRIPTOR_INVALID)" in rx_body
    assert "rxParseStop.setReason(\n                IWX_TX_COMPLETION_RX_PACKET_LENGTH_INVALID)" in rx_body
    assert rx_body.index("rxParseStop.dismiss()") < rx_body.index("switch (code)")
    assert dispatch.index("iwx_tahoe_p2p_action_tx_response(") < dispatch.index(
        "IWX_TX_COMPLETION_TX_RSP_P2P_OWNER_CONSUMED")
    assert dispatch.index("IWX_TX_COMPLETION_TX_RSP_P2P_OWNER_CONSUMED") < dispatch.index(
        "iwx_rx_tx_cmd(sc, pkt, data);")

    for reason in (
        "PAYLOAD_TOO_SHORT", "FRAME_COUNT_ZERO", "DECLARED_LENGTH_TRUNCATED",
        "QUEUE_OR_RING_UNADDRESSABLE", "AGGREGATE_WAITING_FOR_BA",
        "SINGLE_RING_EMPTY", "SSN_INDEX_REJECTED", "SINGLE_RECLAIM_COMPLETED",
    ):
        assert f"IWX_TX_COMPLETION_TX_RSP_{reason}" in tx_body
    assert tx_body.index("bus_dmamap_sync(") < tx_body.index(
        "IwxTxWatchdog::clear(") < tx_body.index("iwx_ampdu_txq_advance(")
    assert tx_body.index("txCompletionScanLiveTxCommands(") < tx_body.index(
        "iwx_ampdu_txq_advance(")
    single_branch = tx_body[tx_body.index("} else {"):]
    assert single_branch.index("responseIndexValid") < single_branch.index(
        "IwxTxWatchdog::clear(") < single_branch.index("iwx_ampdu_txq_advance(")

    for reason in (
        "HEADER_TOO_SHORT", "TFD_ARRAY_TRUNCATED", "STA_ID_MISMATCH",
        "NOT_STA_RUN", "TFD_COUNT_ZERO", "TFD_QID_OUT_OF_RANGE",
        "TFD_P2P_OWNED", "TFD_RING_CAPACITY_REJECTED",
        "TFD_RECLAIM_COMPLETED",
    ):
        assert f"IWX_TX_COMPLETION_BA_{reason}" in ba_body
    assert ba_body.index("baCompletion.dismiss()") < ba_body.index(
        "for (i = 0; i < tfdCount; i++)")
    assert ba_body.index("iwx_ampdu_txq_advance(sc, ring, reclaimIndex)") < ba_body.index(
        "IWX_TX_COMPLETION_BA_TFD_RECLAIM_COMPLETED")
    assert "setProperty(" not in ba_body and "IORegistry" not in ba_body

    helpers_start = source.index(
        "#ifdef AIRPORT_TAHOE\nstatic iwx_tx_completion_event_input txCompletionRxInput(")
    helpers_end = source.index(
        "\n#endif\n\nvoid ItlIwx::\niwx_rx_tx_ba_notif", helpers_start) + len("\n#endif")
    helpers = source[helpers_start:helpers_end]
    record_body = braced_source(helpers, "static bool recordTxCompletionEvent(")
    assert "IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH" in record_body
    assert "event.output_epoch = __atomic_load_n(&sc->sc_tx_output_epoch," in record_body
    ring = braced_source(source, "static bool iwx_tx_response_ring(") + "\n" + \
        braced_source(source, "static bool iwx_tx_response_index(")
    sta_helpers_start = source.index(
        "#ifdef AIRPORT_TAHOE\nstatic uint64_t recordStaTxResponse(")
    sta_method_start = source.index(
        "void ItlIwx::\niwx_rx_tx_cmd", sta_helpers_start)
    sta_helpers_end = source.rfind("#endif", sta_helpers_start,
                                  sta_method_start) + len("#endif")
    assert sta_helpers_end > sta_helpers_start
    sta_helpers = source[sta_helpers_start:sta_helpers_end]
    command_scan = braced_source(
        source, "static void txCompletionScanLiveTxCommands(")
    assert "ring->data[index].m != nullptr" in command_scan
    assert "command->hdr.group_id == 0" in command_scan
    assert "command->hdr.cmd == IWX_TX_CMD" in command_scan
    assert "command->hdr.idx == (index & UINT8_MAX)" in command_scan
    assert "candidate.command_flags = le32toh(tx->flags)" in command_scan
    assert "candidate.sequence_control" in command_scan
    assert "iwx_ampdu_txq_advance" not in command_scan
    return helpers, ring, tx_body, sta_helpers


CPP_HANDLER_PREFIX = r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include "native/iwx_tx_completion_observation.hpp"
#include "native/iwx_tx_progress_observation.hpp"
#include "native/iwx_tx_ring_capacity.hpp"
#include "native/iwx_tx_response_metadata.hpp"
#include "native/iwx_sta_tx_observation.hpp"
#include "native/group2_tx_trace_helpers.h"

#define AIRPORT_TAHOE 1
#define IWX_RBUF_SIZE 2048
#define IWX_TX_CMD 0x1c
#define IWX_LONG_GROUP 1
#define BUS_DMASYNC_POSTREAD 1
#define nitems(x) (sizeof(x) / sizeof((x)[0]))
#define IWX_AGG_TX_STATE_STATUS_MSK 0x0fff
#define IWX_AGG_TX_STATE_TRY_CNT_POS 12
#define IWX_AGG_TX_STATE_TRY_CNT_MSK (0xf << IWX_AGG_TX_STATE_TRY_CNT_POS)
static void harnessLog(const char *, ...) {}
#define XYLog(...) harnessLog(__VA_ARGS__)
#define DPRINTFN(level, args) harnessLog args
#define __packed __attribute__((packed))

static bool gCompletionObservationEnabled = true;
static bool gRejectResponseIndex = false;
static std::vector<int> gBusinessCalls;
static uint64_t tahoeMonotonicNs() { return 1700000000ULL; }

static uint16_t le16toh(uint16_t value) { return value; }
static uint32_t le32toh(uint32_t value) { return value; }
static uint16_t le16_to_cpu(uint16_t value) { return value; }
static uint32_t le32_to_cpu(uint32_t value) { return value; }

struct iwx_cmd_header {
    uint8_t group_id, cmd, qid, idx;
};

struct __packed iwx_agg_tx_status {
    uint16_t status;
    uint16_t sequence;
};

struct __packed iwx_tx_resp {
    uint8_t frame_count;
    uint8_t bt_kill_count;
    uint8_t failure_rts;
    uint8_t failure_frame;
    uint32_t initial_rate;
    uint16_t wireless_media_time;
    uint8_t pa_status;
    uint8_t pa_integ_res_a[3];
    uint8_t pa_integ_res_b[3];
    uint8_t pa_integ_res_c[3];
    uint16_t measurement_req_id;
    uint8_t reduced_tpc;
    uint8_t reserved;
    uint32_t tfd_info;
    uint16_t seq_ctl;
    uint16_t byte_cnt;
    uint8_t tlc_info;
    uint8_t ra_tid;
    uint16_t frame_ctrl;
    uint16_t tx_queue;
    uint16_t reserved2;
    iwx_agg_tx_status status;
};

struct __packed iwx_compressed_ba_tfd {
    uint16_t q_num;
    uint16_t tfd_index;
    uint8_t scd_queue;
    uint8_t tid;
    uint8_t reserved[2];
};

struct __packed iwx_compressed_ba_notif {
    uint32_t flags;
    uint8_t sta_id;
    uint8_t reduced_txp;
    uint8_t tlc_rate_info;
    uint8_t retry_cnt;
    uint32_t query_byte_cnt;
    uint16_t query_frame_cnt;
    uint16_t txed;
    uint16_t done;
    uint16_t reserved;
    uint32_t wireless_time;
    uint32_t tx_rate;
    uint16_t tfd_cnt;
    uint16_t ra_tid_cnt;
    uint8_t ra_tid[1];
    iwx_compressed_ba_tfd tfd[1];
};

struct iwx_rx_packet {
    uint32_t rx_packet_length;
    size_t payload_length;
    iwx_cmd_header hdr;
    uint8_t data[128];
};

static uint32_t iwx_rx_packet_len(const iwx_rx_packet *pkt) {
    return pkt->rx_packet_length;
}
static size_t iwx_rx_packet_payload_len(const iwx_rx_packet *pkt) {
    return pkt->payload_length;
}

struct iwx_tx_data { void *m = nullptr; };
struct iwx_tx_ring {
    int qid;
    size_t ring_count;
    int queued;
    int cur;
    int tail;
    iwx_tx_data data[1024];
};
struct iwx_rx_data { void *map; };
struct iwx_softc {
    iwx_tx_ring txq[4];
    struct {
        struct {
            IwxGroup2TxTrace group2_tx;
        } ic_tahoe_auth_trace;
    } sc_ic;
    int sc_tx_timer;
    void *sc_dmat;
    int sc_generation;
    uint32_t sc_tx_output_epoch;
    iwx_sta_tx_observation_state sc_sta_tx_observation{};
    iwx_tx_completion_observation_state sc_tx_completion_observation{};
    iwx_tx_progress_observation_state sc_tx_progress_observation{};
};
struct ItlIwx {
    void iwx_rx_tx_cmd(iwx_softc *, iwx_rx_packet *, iwx_rx_data *);
    void tahoeStoreRelatedTxCompletionSnapshot(
        const iwx_tx_completion_observation_snapshot *) {}
};
static uint32_t iwx_lookup_cmd_ver(iwx_softc *, uint8_t, uint8_t) { return 7; }
static void txCompletionScanLiveTxCommands(
    iwx_tx_completion_event_input *, iwx_softc *, iwx_tx_ring *, uint32_t,
    uint32_t, uint32_t, uint32_t, const iwx_tx_resp *, uint32_t) {}

namespace IwxTxWatchdog {
static void clear(int *) { gBusinessCalls.push_back(2); }
}
static void recordTxTimerClear(iwx_softc *, uint32_t, uint32_t) {
    gBusinessCalls.push_back(3);
}
static void recordTxProgressEvent(iwx_softc *, uint32_t, uint32_t,
    uint32_t = 0, uint32_t = 0, uint32_t = 0, uint32_t = 0,
    uint32_t = 0, uint32_t = 0, uint32_t = 0, bool = false) {}
static void bus_dmamap_sync(void *, void *, int, size_t, int) {
    gBusinessCalls.push_back(1);
}
static void iwx_rx_tx_cmd_single(iwx_softc *, iwx_rx_packet *, iwx_tx_data *) {
    gBusinessCalls.push_back(4);
}
static void iwx_ampdu_txq_advance(iwx_softc *, iwx_tx_ring *ring, int index) {
    gBusinessCalls.push_back(5);
    while (ring->tail != index) {
        --ring->queued;
        ring->tail = (ring->tail + 1) % ring->ring_count;
    }
}
static void iwx_clear_oactive(iwx_softc *, iwx_tx_ring *) {
    gBusinessCalls.push_back(6);
}
static const char *iwx_get_agg_tx_status(uint16_t) { return "stub"; }
enum : uint32_t { kTxTimerClearFirmwareResponse = 1 };

static bool txResponseIndexForHarness(uint32_t qid, int ringQid,
    size_t ringCount, size_t storageCapacity, uint32_t ssn, uint16_t *out) {
    if (gRejectResponseIndex)
        return false;
    return IwxTxRingCapacity::responseIndex(qid, ringQid, ringCount,
                                             storageCapacity, ssn, out);
}
"""


CPP_HANDLER_TESTS = r"""
enum Scenario {
    PayloadTooShort,
    FrameCountZero,
    DeclaredLengthTruncated,
    QueueOutOfRange,
    RingNotAddressable,
    RingEmpty,
    ForcedSsnIndexReject,
    AggregateWaitsForBa,
    SingleReclaim
};

struct Outcome {
    std::vector<int> calls;
    int queued;
    int tail;
    uint32_t terminalReason;
    uint32_t outputEpoch;
};

static Outcome runScenario(Scenario scenario, bool observe) {
    gCompletionObservationEnabled = observe;
    gRejectResponseIndex = scenario == ForcedSsnIndexReject;
    gBusinessCalls.clear();

    iwx_softc sc{};
    sc.sc_tx_output_epoch = 17;
    for (uint32_t i = 0; i < nitems(sc.txq); ++i) {
        sc.txq[i].qid = static_cast<int>(i);
        sc.txq[i].ring_count = 1024;
        sc.txq[i].queued = 4;
        sc.txq[i].cur = 8;
        sc.txq[i].tail = 0;
    }
    iwx_rx_data rxData{};
    iwx_rx_packet pkt{};
    pkt.hdr.group_id = 1;
    pkt.hdr.cmd = 2;
    pkt.hdr.qid = 3;
    pkt.hdr.idx = 4;

    uint8_t frameCount = 1;
    uint16_t queueId = 1;
    size_t payloadLength = offsetof(iwx_tx_resp, status) +
        sizeof(iwx_agg_tx_status) + sizeof(uint32_t);
    if (scenario == PayloadTooShort)
        payloadLength = 0;
    else if (scenario == FrameCountZero)
        frameCount = 0;
    else if (scenario == DeclaredLengthTruncated)
        payloadLength = offsetof(iwx_tx_resp, status) + sizeof(uint16_t);
    else if (scenario == QueueOutOfRange)
        queueId = 4;
    else if (scenario == RingNotAddressable)
        sc.txq[1].ring_count = 1000;
    else if (scenario == RingEmpty)
        sc.txq[1].queued = 0;
    else if (scenario == AggregateWaitsForBa) {
        frameCount = 2;
        payloadLength = offsetof(iwx_tx_resp, status) +
            2 * sizeof(iwx_agg_tx_status) + sizeof(uint32_t);
    }

    pkt.payload_length = payloadLength;
    pkt.rx_packet_length = static_cast<uint32_t>(sizeof(pkt.hdr) + payloadLength);
    if (payloadLength >= sizeof(uint8_t)) {
        auto *response = reinterpret_cast<iwx_tx_resp *>(pkt.data);
        response->frame_count = frameCount;
        response->ra_tid = 0;
        response->tx_queue = queueId;
        response->status.status = 0;
        const size_t ssnOffset = offsetof(iwx_tx_resp, status) +
            static_cast<size_t>(frameCount) * sizeof(iwx_agg_tx_status);
        if (ssnOffset <= payloadLength &&
            sizeof(uint32_t) <= payloadLength - ssnOffset) {
            const uint32_t ssn = 2;
            memcpy(pkt.data + ssnOffset, &ssn, sizeof(ssn));
        }
    }

    ItlIwx driver{};
    driver.iwx_rx_tx_cmd(&sc, &pkt, &rxData);

    Outcome result{};
    result.calls = gBusinessCalls;
    result.queued = sc.txq[1].queued;
    result.tail = sc.txq[1].tail;
    if (observe) {
        iwx_tx_completion_observation_snapshot snapshot{};
        assert(IwxTxCompletionObservation::snapshot(
            &sc.sc_tx_completion_observation, &snapshot));
        assert(snapshot.available && snapshot.complete);
        assert(snapshot.last[IWX_TX_COMPLETION_TX_RSP].event_count == 1);
        assert((snapshot.last[IWX_TX_COMPLETION_TX_RSP].presence_flags &
                IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH) != 0);
        assert(snapshot.last[IWX_TX_COMPLETION_TX_RSP].output_epoch == 17);
        result.terminalReason =
            snapshot.last[IWX_TX_COMPLETION_TX_RSP].terminal_reason;
        result.outputEpoch =
            snapshot.last[IWX_TX_COMPLETION_TX_RSP].output_epoch;
    }
    return result;
}

static void compareScenario(Scenario scenario, uint32_t expectedReason,
                            const std::vector<int> &expectedCalls) {
    const Outcome enabled = runScenario(scenario, true);
    const Outcome disabled = runScenario(scenario, false);
    assert(enabled.calls == disabled.calls);
    assert(enabled.calls == expectedCalls);
    assert(enabled.queued == disabled.queued);
    assert(enabled.tail == disabled.tail);
    assert(enabled.terminalReason == expectedReason);
    assert(enabled.outputEpoch == 17);
}

static void testProductionRecordHelperKeepsPerKindEpochs()
{
    gCompletionObservationEnabled = true;
    iwx_softc sc{};
    sc.sc_tx_output_epoch = 41;

    iwx_tx_completion_event_input tx{};
    tx.kind = IWX_TX_COMPLETION_TX_RSP;
    tx.stage = IWX_TX_COMPLETION_STAGE_TX_RSP_TERMINAL;
    tx.terminal_reason = IWX_TX_COMPLETION_TX_RSP_P2P_OWNER_CONSUMED;
    recordTxCompletionEvent(&sc, tx);

    iwx_tx_completion_event_input ba{};
    ba.kind = IWX_TX_COMPLETION_BA;
    ba.stage = IWX_TX_COMPLETION_STAGE_BA_HANDLER_TERMINAL;
    ba.terminal_reason = IWX_TX_COMPLETION_BA_TFD_COUNT_ZERO;
    recordTxCompletionEvent(&sc, ba);

    iwx_tx_completion_event_input rx{};
    rx.kind = IWX_TX_COMPLETION_RX_PARSE_STOP;
    rx.stage = IWX_TX_COMPLETION_STAGE_RX_PARSE_STOP;
    rx.terminal_reason = IWX_TX_COMPLETION_RX_DESCRIPTOR_INVALID;
    recordTxCompletionEvent(&sc, rx);

    // Stop/init advances the host output epoch but emits no new event of any
    // kind. Latest-by-kind rows must remain visibly tagged as the old epoch.
    sc.sc_tx_output_epoch = 42;
    iwx_tx_completion_observation_snapshot snapshot{};
    assert(IwxTxCompletionObservation::snapshot(
        &sc.sc_tx_completion_observation, &snapshot));
    assert(snapshot.available && snapshot.complete);
    for (uint32_t kind = 0; kind < IWX_TX_COMPLETION_KIND_COUNT; ++kind) {
        const auto &last = snapshot.last[kind];
        assert(last.event_count == 1);
        assert((last.presence_flags & IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH) != 0);
        assert(last.output_epoch == 41);
        assert(last.output_epoch != sc.sc_tx_output_epoch);
    }
}

int main() {
    assert(offsetof(iwx_tx_resp, tx_queue) == 36);
    assert(offsetof(iwx_tx_resp, status) == 40);
    compareScenario(PayloadTooShort,
        IWX_TX_COMPLETION_TX_RSP_PAYLOAD_TOO_SHORT, {});
    compareScenario(FrameCountZero,
        IWX_TX_COMPLETION_TX_RSP_FRAME_COUNT_ZERO, {});
    compareScenario(DeclaredLengthTruncated,
        IWX_TX_COMPLETION_TX_RSP_DECLARED_LENGTH_TRUNCATED, {});
    compareScenario(QueueOutOfRange,
        IWX_TX_COMPLETION_TX_RSP_QUEUE_OR_RING_UNADDRESSABLE, {});
    compareScenario(RingNotAddressable,
        IWX_TX_COMPLETION_TX_RSP_QUEUE_OR_RING_UNADDRESSABLE, {});
    compareScenario(RingEmpty,
        IWX_TX_COMPLETION_TX_RSP_SINGLE_RING_EMPTY, {1});
    compareScenario(ForcedSsnIndexReject,
        IWX_TX_COMPLETION_TX_RSP_SSN_INDEX_REJECTED, {1});
    compareScenario(AggregateWaitsForBa,
        IWX_TX_COMPLETION_TX_RSP_AGGREGATE_WAITING_FOR_BA, {1, 2, 3});
    compareScenario(SingleReclaim,
        IWX_TX_COMPLETION_TX_RSP_SINGLE_RECLAIM_COMPLETED,
        {1, 2, 3, 4, 5, 6});
    testProductionRecordHelperKeepsPerKindEpochs();
    return 0;
}
"""

with tempfile.TemporaryDirectory(prefix="iwx-tx-completion-") as temporary:
    directory = Path(temporary)
    c_probe = directory / "c-layout-probe.c"
    c_probe.write_text(
        '#include "native/iwx_tx_completion_observation.hpp"\n'
        'int main(void) { struct iwx_tx_completion_observation_state s = {0}; '
        'struct iwx_tx_completion_observation_snapshot c = {0}; '
        'return sizeof(s) > IWX_TX_COMPLETION_STATE_MAX_BYTES || '
        'sizeof(c) > IWX_TX_COMPLETION_SNAPSHOT_MAX_BYTES; }\n',
        encoding="utf-8",
    )
    subprocess.run(
        CC + ["-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
              str(c_probe), "-o", str(directory / "c-layout-probe")],
        check=True,
    )
    subprocess.run([str(directory / "c-layout-probe")], check=True)

    helpers, ring_guards, tx_handler, sta_helpers = check_production_wiring()
    record_guard = """    if (!sc)\n        return false;\n    event.presence_flags |= IWX_TX_COMPLETION_HAS_MONOTONIC_NS |\n        IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH;"""
    record_hook = """    if (!sc || !gCompletionObservationEnabled)\n        return false;\n    event.presence_flags |= IWX_TX_COMPLETION_HAS_MONOTONIC_NS |\n        IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH;"""
    assert helpers.count(record_guard) == 1
    helpers = helpers.replace(record_guard, record_hook, 1)
    assert ring_guards.count("IwxTxRingCapacity::responseIndex(") == 1
    ring_guards = ring_guards.replace(
        "IwxTxRingCapacity::responseIndex(",
        "txResponseIndexForHarness(", 1)
    harness = directory / "production-tx-rsp-handler.cpp"
    harness.write_text(
        CPP_HANDLER_PREFIX + helpers + "\n" + ring_guards + "\n" +
        sta_helpers + "\n" +
        tx_handler + "\n" + CPP_HANDLER_TESTS,
        encoding="utf-8",
    )
    handler_binary = directory / "production-tx-rsp-handler"
    subprocess.run(
        CXX + ["-std=c++14", "-O1", "-Wall", "-Wextra", "-Werror",
               "-Wno-unused-function",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               "-pthread", "-I", str(ROOT), str(harness), "-o",
               str(handler_binary)],
        check=True,
    )
    subprocess.run([str(handler_binary)], check=True)
    print("PASS: extracted production TX_RSP handler, all reachable terminal paths, observer on/off business-call equivalence")
    print("NOTE: SSN-index rejection is fault-injected at the capacity helper boundary; normal ring guards make it unreachable for a valid ring. BA is checked structurally against its actual branch sites, not represented as a live firmware parser simulation.")

    asan_binary = directory / "tx-completion-asan"
    subprocess.run(
        CXX + ["-std=c++14", "-O1", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               "-pthread", "-I", str(ROOT), str(SOURCE), "-o", str(asan_binary)],
        check=True,
    )
    subprocess.run([str(asan_binary)], check=True)

    tsan_binary = directory / "tx-completion-tsan"
    subprocess.run(
        CXX + ["-std=c++14", "-O1", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=thread", "-fno-omit-frame-pointer", "-pthread",
               "-I", str(ROOT), str(SOURCE), "-o", str(tsan_binary)],
        check=True,
    )
    tsan = subprocess.run([str(tsan_binary)], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if tsan.returncode:
        known_runtime_limits = (
            "ThreadSanitizer: unsupported" in tsan.stdout or
            "FATAL: ThreadSanitizer: unexpected memory mapping" in tsan.stdout or
            "dyld: Symbol not found" in tsan.stdout
        )
        if not known_runtime_limits:
            raise subprocess.CalledProcessError(
                tsan.returncode, [str(tsan_binary)], output=tsan.stdout)
        print("SKIP: ThreadSanitizer runtime unavailable in this environment")
    else:
        print("PASS: ThreadSanitizer concurrent writer/reader stress")

print("PASS: C-compatible layout, ASan/UBSan, fixed snapshot, strict presence, drops and full-width values")
