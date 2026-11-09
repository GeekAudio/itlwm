#!/usr/bin/env python3
"""Run the actual Test127 RX fact decoder and first-record ledger offline."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HAL = ROOT / 'itlwm/hal_iwx'
driver = (HAL / 'ItlIwx.cpp').read_text()
registers = (HAL / 'if_iwxreg.h').read_text()
probe = (HAL / 'ItlIwxP2PProbe.cpp').read_text()
action = (HAL / 'ItlIwxP2PAction.cpp').read_text()


def cut(source, first, last):
    begin = source.index(first)
    return source[begin:source.index(last, begin + len(first))]


def wire_struct(name):
    return re.search(r'^struct ' + name + r' \{.*?^\} __packed;',
                     registers, re.M | re.S)[0]


wire = '\n'.join(wire_struct(name) for name in (
    'iwx_cmd_header', 'iwx_rx_packet', 'iwx_agg_tx_status', 'iwx_tx_resp',
    'iwx_compressed_ba_tfd', 'iwx_compressed_ba_ratid',
    'iwx_compressed_ba_notif',
))
decoder = (
    cut(registers, '#define    IWX_FH_RSCSR_FRAME_SIZE_MSK', '#define IWX_MIN_DBM')
    + cut(driver, 'static iwx_tx_completion_event_input txCompletionRxInput(',
          'static void txCompletionSetRingFacts(')
    + cut(driver, 'static void txCompletionSetTxRspFacts(', '/* Tag only')
    + cut(driver, 'static void txCompletionSetBaFacts(',
          '#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332\nstatic bool readDirectedDataTxRx')
    + cut(driver, 'static bool readDirectedDataTxRx(', '\n#endif')
)

# Check the production call sites in addition to the executable decoder tests.
rx = cut(driver, 'iwx_rx_pkt(struct iwx_softc', 'iwx_notif_intr(struct iwx_softc')
assert rx.index('::kLengthRejected') < rx.index('Phase::RxValidated')
assert rx.index('Phase::RxValidated') < rx.index('const bool observeDirected')
assert rx.index('const bool observeDirected') < rx.index('switch (code)')
assert rx.index('kTxPassedThrough') < rx.index('if (directedConsumed) {\n                        iwx_tx')
assert 'targetWitness ? &passThrough : nullptr' in rx
assert rx.index('dropping notification batch') < rx.index('const bool observeDirected')
close = cut(action, 'static IOReturn directedDataCommitCloseAction(',
            'int iwx_tahoe_p2p_directed_data_close(')
assert close.index('if (!sameRun)') < close.index('rememberClose')
assert close.index('rememberClose') < close.index('kDoorbellUnknown')
publish = cut(probe, 'static void publishDirectedDataState(',
              'struct DirectedDataMccWitness')
assert publish.index('Publication::FastStateOnly') < publish.index('seal_tx_witness')
assert publish.index('seal_tx_witness') < publish.rindex('NativeP2PDirectedDataStage')
assert 'OSData::withBytes(&witness, sizeof(witness))' in publish

fixture = r'''
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "itlwm/hal_iwx/ItlIwxP2PDataTxWitness.hpp"
#include "native/iwx_tx_completion_observation.hpp"
#include "native/p2p_action_tx.hpp"
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#ifndef le16toh
#define le16toh(x) (x)
#define le32toh(x) (x)
#endif
using __le16 = uint16_t;
using __le32 = uint32_t;
using u8 = uint8_t;
constexpr uint8_t IWX_TX_CMD = 0x1c;
constexpr uint8_t IWX_BA_NOTIF = 0xc5;
static uint64_t nowNs;
static uint64_t tahoeMonotonicNs() { return (nowNs += 1000); }
''' + wire + '\n' + decoder + r'''

// Exercise the real response handler through all its early returns.
struct ItlIwx {
    bool onGate;
    bool tahoeP2pOnMainGate() const { return onGate; }
};
struct iwx_softc { int sc_dmat; };
struct iwx_rx_data { int map; };
enum class TahoeP2PStationRole { kDirectedPeerLink };
enum class TahoeP2PResourceState { kActive };
enum class TahoeP2PDirectedDataState { kInFlight };
enum class TahoeP2PDirectedDataReason { kResponseDuplicate, kResponseForeign };
struct TahoeP2PStationLease { uint64_t allocationSerial; };
struct TahoeP2PTxQueueLease {
    uint64_t allocationSerial;
    unsigned queueId, stationId;
    TahoeP2PStationRole stationRole;
    unsigned firmwareTid;
    TahoeP2PResourceState state;
};
struct TahoeP2PDirectedDataContext {
    struct Binding { uint64_t runSerial; } binding;
    struct PacketRecord {
        uint64_t doorbellUs;
        uint16_t firmwareStatus, sequenceControl, byteCount, frameControl;
        uint16_t expectedNextSsn, descriptorIndex;
        bool doorbellIssued, completionObserved, resourcesAbsent;
    } packets[2]{};
    bool doorbellIssued;
    unsigned queueId, stationId, currentSlot, packetCount;
    uint16_t ringSize;
    uint64_t queueAllocationSerial, stationAllocationSerial;
    TahoeP2PDirectedDataState state;
    IntelP2PActionTx::CompletionTracker completion{};
    bool quarantined = false;
    bool enteredLiveCompletion = false;
};
static void iwx_tahoe_p2p_directed_data_quarantine(
    TahoeP2PDirectedDataContext *context, TahoeP2PDirectedDataReason)
{
    context->quarantined = true;
}
static void bus_dmamap_sync(int, int, int, int, int) {}
constexpr int IWX_RBUF_SIZE = 4096;
constexpr int BUS_DMASYNC_POSTREAD = 1;
''' + cut(registers, '#define IWX_TX_RES_GET_TID', '/**') + cut(
    action, 'static uint16_t directedDataReadLe16(',
    'static bool directedDataSubmitHasDeadlineMargin(') + cut(
    action, 'static bool directedDataHasDoorbellHistory(',
    'static void directedDataRecordUnsubmittedSlot(') + cut(
    action, 'static bool directedDataMatchesRetiredResponse(',
    'bool iwx_tahoe_p2p_directed_data_tx_response(') + cut(
    action, 'bool iwx_tahoe_p2p_directed_data_tx_response(',
    '    struct iwx_tx_ring *ring = nullptr;'
) + r'''
    (void)currentPacket;
    context->enteredLiveCompletion = true;
    return true; // End of the tested early-return prefix.
}

using namespace TahoeP2PDirectedDataTxWitness;

template <size_t N> struct Packet {
    uint8_t bytes[sizeof(iwx_rx_packet) + N] {};
    iwx_rx_packet *get() { return reinterpret_cast<iwx_rx_packet *>(bytes); }

    Packet(uint8_t opcode, uint8_t group, uint8_t qid)
    {
        get()->len_n_flags = sizeof(iwx_cmd_header) + N;
        get()->hdr = {opcode, group, 9, qid};
    }
};

int main()
{
    Snapshot ledger{};
    Record row{};
    Packet<48> tx(IWX_TX_CMD, 1, 0xa9);
    assert(!readDirectedDataTxRx(ledger, tx.get(), 0x11c, kNotDispatched, row));
    ledger.schema = 1;
    ledger.size = sizeof(ledger);
    ledger.ownerSerial = 4;
    ledger.runSerial = 11;
    ledger.stationAllocationSerial = 25;
    ledger.queueAllocationSerial = 26;
    ledger.queue = 4;
    ledger.station = 3;
    ledger.descriptorIndex = 0;
    ledger.doorbellUs = 1;

    auto *rsp = reinterpret_cast<iwx_tx_resp *>(tx.get()->data);
    rsp->frame_count = 1;
    rsp->ra_tid = 0x30;
    rsp->frame_ctrl = 8;
    rsp->seq_ctl = 0x310;
    rsp->byte_cnt = 96;
    rsp->tx_queue = 4;
    rsp->status.status = 1;
    uint32_t rawSsn = 0x1001;
    memcpy(tx.get()->data + sizeof(iwx_tx_resp), &rawSsn, sizeof(rawSsn));
    assert(readDirectedDataTxRx(ledger, tx.get(), 0x11c, kNotDispatched, row));
    assert(row.command == IWX_TX_CMD && row.group == 1 && row.dispatchCode == 0x11c);
    assert(row.headerQueue == 0xa9 && row.headerIndex == 9);
    assert(row.queue == 4 && row.payloadLength == 48);
    assert(row.payloadLength == iwx_rx_packet_payload_len(tx.get()));
    assert(row.raTid == 0x30 && row.frameCount == 1 && row.frameControl == 8);
    assert(row.sequenceControl == 0x310 && row.byteCount == 96);
    assert(row.status == 1 && row.ssn == 1);
    assert(row.presence == (kPayloadLength | kQueue | kRaTid | kFrameCount |
        kSequenceControl | kFrameControl | kByteCount | kSsn | kStatus));
    ledger.remember(false, row);
    const uint64_t firstTxUs = row.observedUs;

    // Actual handler early exits with a target payload queue. The fixture
    // calls the handler directly to exercise its defensive off-gate guard.
    ItlIwx owner{false};
    iwx_softc sc{};
    iwx_rx_data data{};
    TahoeP2PStationLease sta{25};
    TahoeP2PTxQueueLease queue{26, 4, 3, TahoeP2PStationRole::kDirectedPeerLink,
                              0, TahoeP2PResourceState::kActive};
    TahoeP2PDirectedDataContext context{};
    context.binding.runSerial = 11;
    context.doorbellIssued = true;
    context.queueId = 4;
    context.stationId = 3;
    context.queueAllocationSerial = 26;
    context.stationAllocationSerial = 25;
    context.state = TahoeP2PDirectedDataState::kInFlight;
    TxPassThrough reason = TxPassThrough::kNone;
    const auto invoke = [&](TahoeP2PDirectedDataContext *ctx) {
        return iwx_tahoe_p2p_directed_data_tx_response(
            &owner, &sc, &sta, &queue, ctx, tx.get(), &data, &reason);
    };
    assert(!invoke(&context) && reason == TxPassThrough::kOutsideMainGate);
    assert(readDirectedDataTxRx(ledger, tx.get(), 0x1c, kNotDispatched, row));
    row.outcome = kTxPassedThrough;
    row.handlerReason = static_cast<uint32_t>(reason);
    ledger.remember(false, row);

    owner.onGate = true;
    assert(!invoke(nullptr) && reason == TxPassThrough::kInvalidArguments);
    context.doorbellIssued = false;
    context.packetCount = 1;
    context.packets[0].doorbellIssued = false;
    assert(!invoke(&context) && reason == TxPassThrough::kNoDoorbell);
    context.doorbellIssued = true;
    context.packets[0].doorbellIssued = true;
    ++queue.allocationSerial;
    rsp->ra_tid = 0x41;
    assert(!invoke(&context) && reason == TxPassThrough::kAllocationAndRaTidMismatch);
    assert(!context.quarantined);
    assert(!iwx_tahoe_p2p_directed_data_tx_response(
        &owner, &sc, &sta, &queue, &context, tx.get(), &data, nullptr));
    assert(!context.quarantined);
    rsp->ra_tid = 0x30;
    assert(invoke(&context) && context.quarantined); // Existing tombstone.

    // A delayed exact slot-zero TX_RSP must be consumed while slot one is the
    // live descriptor, even if the legacy aggregate doorbell flag is false.
    auto prepareRetiredSlotOne = [&] {
        context.quarantined = false;
        context.enteredLiveCompletion = false;
        context.doorbellIssued = false;
        queue.allocationSerial = 26;
        sta.allocationSerial = 25;
        context.packetCount = 2;
        context.currentSlot = 1;
        context.ringSize = 64;
        context.packets[0].doorbellIssued = true;
        context.packets[0].completionObserved = true;
        context.packets[0].resourcesAbsent = true;
        context.packets[0].firmwareStatus = 1;
        context.packets[0].sequenceControl = 0x310;
        context.packets[0].byteCount = 96;
        context.packets[0].frameControl = 8;
        context.packets[0].expectedNextSsn = 1;
        context.packets[1].doorbellIssued = true;
        context.state = TahoeP2PDirectedDataState::kInFlight;
        assert(context.completion.arm(7, 4, 64, 2, 0x420, 96, 8) ==
               IntelP2PActionTx::Result::kReady);
        rsp->frame_count = 1;
        rsp->ra_tid = 0x30;
        rsp->frame_ctrl = 8;
        rsp->seq_ctl = 0x310;
        rsp->byte_cnt = 96;
        rsp->tx_queue = 4;
        rsp->status.status = 1;
        rawSsn = 0x1001;
        memcpy(tx.get()->data + sizeof(iwx_tx_resp), &rawSsn,
               sizeof(rawSsn));
    };
    prepareRetiredSlotOne();
    assert(invoke(&context));
    assert(!context.quarantined && !context.enteredLiveCompletion);

    // Every truncated payload length from the status-only boundary through
    // the complete 32-bit SSN boundary must avoid the retired-slot matcher.
#define TEST_TRUNCATED_SSN(N) do { \
    Packet<N> truncated(IWX_TX_CMD, 1, 4); \
    auto *shortRsp = reinterpret_cast<iwx_tx_resp *>(truncated.get()->data); \
    shortRsp->frame_count = 1; \
    shortRsp->ra_tid = 0x30; \
    shortRsp->frame_ctrl = 8; \
    shortRsp->seq_ctl = 0x310; \
    shortRsp->byte_cnt = 96; \
    shortRsp->tx_queue = 4; \
    shortRsp->status.status = 1; \
    const size_t availableSsnBytes = (N) > sizeof(iwx_tx_resp) ? \
        (N) - sizeof(iwx_tx_resp) : 0; \
    if (availableSsnBytes) \
        memset(truncated.get()->data + sizeof(iwx_tx_resp), 0x01, \
               availableSsnBytes); \
    context.enteredLiveCompletion = false; \
    assert(iwx_tahoe_p2p_directed_data_tx_response( \
        &owner, &sc, &sta, &queue, &context, truncated.get(), &data, \
        &reason)); \
    assert(context.enteredLiveCompletion && !context.quarantined); \
} while (0)
    TEST_TRUNCATED_SSN(44);
    TEST_TRUNCATED_SSN(45);
    TEST_TRUNCATED_SSN(46);
    TEST_TRUNCATED_SSN(47);
#undef TEST_TRUNCATED_SSN

    // With no current slot doorbell and no prior slot doorbell, a response is
    // still passed through; the history check must not consume unrelated RSPs.
    context.packetCount = 2;
    context.packets[0].doorbellIssued = false;
    context.packets[1].doorbellIssued = false;
    context.enteredLiveCompletion = false;
    assert(!invoke(&context) && reason == TxPassThrough::kNoDoorbell);

    // A later consumed rejection cannot replace the first target pass-through.
    assert(readDirectedDataTxRx(ledger, tx.get(), 0x1c, kNotDispatched, row));
    row.outcome = kTxRejected;
    row.handlerReason = 18;
    ledger.remember(false, row);
    assert(ledger.records[kTxTarget].observedUs == firstTxUs);
    assert(ledger.records[kTxTarget].outcome == kNotDispatched);
    assert(ledger.records[kTxTarget].overflow == 2);
    assert(ledger.records[kFirstHandlerReject].outcome == kTxPassedThrough);
    assert(ledger.records[kFirstHandlerReject].handlerReason ==
           static_cast<uint32_t>(TxPassThrough::kOutsideMainGate));

    Packet<37> shortTx(IWX_TX_CMD, 0, 0x84);
    assert(readDirectedDataTxRx(ledger, shortTx.get(), 0x1c, kNotDispatched, row));
    assert(row.payloadLength == 37 && !(row.presence & (kQueue | kStatus | kSsn)));
    ledger.remember(false, row);
    assert(ledger.records[kTxUnresolved].headerQueue == 0x84);

    Packet<0> badLength(IWX_TX_CMD, 0, 0x84);
    badLength.get()->len_n_flags = 0x3fff;
    assert(readDirectedDataTxRx(ledger, badLength.get(), 0x1c, kLengthRejected, row));
    assert(row.presence == 0 && row.outcome == kLengthRejected);
    ledger.remember(false, row);
    assert(ledger.records[kTxUnresolved].overflow == 1);

    rsp->tx_queue = 8;
    tx.get()->hdr.qid = 0x84; // Envelope queue cannot override payload queue 8.
    assert(readDirectedDataTxRx(ledger, tx.get(), 0x1c, kNotDispatched, row));
    row.outcome = kTxPassedThrough;
    ledger.remember(false, row);
    assert(ledger.records[kTxOther].queue == 8);
    assert(ledger.records[kTxOther].headerQueue == 0x84);
    assert(ledger.records[kTxUnresolved].overflow == 1);

    constexpr size_t baPrefix = offsetof(iwx_compressed_ba_notif, tfd);
    Packet<baPrefix + 2 * sizeof(iwx_compressed_ba_tfd)> ba(IWX_BA_NOTIF, 0, 0x80);
    auto *reply = reinterpret_cast<iwx_compressed_ba_notif *>(ba.get()->data);
    reply->sta_id = 3;
    reply->tfd_cnt = 2;
    reply->tfd[0].q_num = 8;
    reply->tfd[1].q_num = 4;
    reply->tfd[1].tid = 0;
    reply->tfd[1].tfd_index = 1;
    assert(readDirectedDataTxRx(ledger, ba.get(), 0xc5, kNotDispatched, row));
    assert(row.presence == (kPayloadLength | kBaStationAndCount | kQueue | kBaTfd));
    assert(row.queue == 4 && row.baStation == 3 && row.baTfdCount == 2);
    assert(row.baTid == 0 && row.baIndex == 1);
    row.outcome = kBaRejected;
    row.handlerReason = 16;
    ledger.remember(true, row);
    assert(ledger.records[kBaTarget].outcome == kBaRejected);
    assert(ledger.records[kFirstHandlerReject].outcome == kTxPassedThrough);
    assert(ledger.records[kFirstHandlerReject].handlerReason ==
           static_cast<uint32_t>(TxPassThrough::kOutsideMainGate));
    assert(ledger.records[kFirstHandlerReject].overflow == 2);

    Packet<baPrefix + sizeof(iwx_compressed_ba_tfd)> shortBa(IWX_BA_NOTIF, 0, 0x80);
    reinterpret_cast<iwx_compressed_ba_notif *>(shortBa.get()->data)->tfd_cnt = 2;
    assert(readDirectedDataTxRx(ledger, shortBa.get(), 0xc5, kNotDispatched, row));
    assert(row.presence == (kPayloadLength | kBaStationAndCount));
    ledger.remember(true, row);
    assert(ledger.records[kBaUnresolved].baTfdCount == 2);

    reply->tfd_cnt = 1;
    assert(readDirectedDataTxRx(ledger, ba.get(), 0xc5, kNotDispatched, row));
    assert(row.queue == 8);
    ledger.remember(true, row);
    ledger.records[kBaOther].overflow = UINT32_MAX;
    ledger.remember(true, row);
    assert(ledger.records[kBaOther].overflow == UINT32_MAX);

    ledger.rememberClose(40, 18);
    ledger.rememberClose(41, 14);
    assert(ledger.preCloseUs == 40 && ledger.preCloseReason == 18);
    assert(!ledger.seal(5, 11, 42) && !ledger.seal(4, 10, 42));
    assert(ledger.active());
    assert(ledger.seal(4, 11, 43) && ledger.seal(4, 11, 44));
    assert(ledger.terminalUs == 43 && !ledger.active());
    const Snapshot published = ledger;
    assert(!readDirectedDataTxRx(ledger, tx.get(), 0x1c, kNotDispatched, row));
    ledger.remember(true, row);
    ledger.rememberClose(45, 14);
    assert(memcmp(&published, &ledger, sizeof(ledger)) == 0);
    ledger = {};
    assert(!ledger.seal(4, 11, 46)); // Fresh arm cleared the previous evidence.
}
'''

with tempfile.TemporaryDirectory(prefix='test127-directed-tx-witness-') as tmp:
    source = Path(tmp) / 'witness.cpp'
    binary = Path(tmp) / 'witness'
    source.write_text(fixture)
    subprocess.run(['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra',
                    '-Werror', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-I', str(ROOT),
                    str(source), str(ROOT / 'native/p2p_action_tx.cpp'),
                    '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('Test127: production TX_RSP/BA decode, handler early exits, immutable records and terminal seal passed')
