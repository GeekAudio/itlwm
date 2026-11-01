#include "native/iwx_tx_completion_observation.hpp"
#include "native/iwx_tx_completion_publish.hpp"
#include "native/group2_tx_trace_helpers.h"
#include "native/iwx_tx_response_metadata.hpp"
#include "tx_rsp_prefix_production.inc"

using namespace IwxTxCompletionObservation;

static iwx_rx_packet packet()
{
    iwx_rx_packet pkt{};
    // Synthetic local-layout response: SC0x160, FC0x4108, qid1, status1,
    // status.sequence0x1234, exclusive SSN21. No runtime packet bytes.
    pkt.data[0] = 1;
    pkt.data[28] = 0x60; pkt.data[29] = 1;
    pkt.data[30] = 0x12; pkt.data[31] = 0x34;
    pkt.data[33] = 0x0f;
    pkt.data[34] = 8; pkt.data[35] = 0x41;
    pkt.data[36] = 1;
    pkt.data[40] = 1;
    pkt.data[42] = 0x34; pkt.data[43] = 0x12;
    pkt.data[44] = 21; pkt.data[47] = 0x80;
    return pkt;
}

static iwx_tx_completion_event_input facts(const iwx_rx_packet &pkt,
                                          size_t length, uint8_t version)
{
    iwx_tx_completion_event_input e{};
    e.kind = IWX_TX_COMPLETION_TX_RSP;
    e.stage = IWX_TX_COMPLETION_STAGE_TX_RSP_TERMINAL;
    e.terminal_reason = IWX_TX_COMPLETION_TX_RSP_SINGLE_RECLAIM_COMPLETED;
    e.presence_flags = IWX_TX_COMPLETION_HAS_OUTPUT_EPOCH |
                       IWX_TX_COMPLETION_HAS_PAYLOAD_LENGTH;
    e.payload_length = static_cast<uint32_t>(length);
    txCompletionSetTxRspFacts(&e, &pkt, length);
    txCompletionSetTxRspPrefixFacts(&e, &pkt, length, version);
    return e;
}

static void testPrefixAndProductionHook()
{
    auto pkt = packet();
    IwxTxRspPrefixObservation::Fields d{};
    assert(IwxTxRspPrefixObservation::decodeLocalSingleV1(pkt.data, 48, &d));
    assert(d.sequence_control == 0x160 && d.byte_count == 0x3412);
    assert(d.frame_control == 0x4108 && d.queue == 1 && d.status == 1);
    assert(d.status_sequence == 0x1234 && d.raw_scd_ssn == 0x80000015);
    assert(d.ra_tid == 15);
    auto e = facts(pkt, 48, 7);
    assert(e.tx_rsp_prefix_observation_version == 1);
    assert(e.tx_rsp_notification_version == 7 && validInput(&e));
    assert(e.response_sequence_control == 0x160 && e.ssn == 21);
    for (size_t n = 0; n < 48; ++n) {
        auto shortEvent = facts(pkt, n, 7);
        assert(shortEvent.tx_rsp_prefix_observation_version == 0);
        assert(shortEvent.tx_rsp_notification_version == 0);
        auto unchanged = d;
        assert(!IwxTxRspPrefixObservation::decodeLocalSingleV1(pkt.data, n, &d));
        assert(memcmp(&unchanged, &d, sizeof(d)) == 0);
    }
    assert(!IwxTxRspPrefixObservation::decodeLocalSingleV1(nullptr, 48, &d));
    assert(!IwxTxRspPrefixObservation::decodeLocalSingleV1(pkt.data, 48, nullptr));
    for (uint8_t count : {uint8_t(0), uint8_t(2), uint8_t(255)}) {
        auto other = pkt; other.data[0] = count;
        assert(facts(other, 48, 7).tx_rsp_prefix_observation_version == 0);
    }
    auto longer = facts(pkt, sizeof(pkt.data), 7);
    assert(longer.tx_rsp_prefix_observation_version == 1);
    e.response_sequence_control ^= 0x20;
    e.tx_rsp_prefix_observation_version = e.tx_rsp_notification_version = 0;
    txCompletionSetTxRspPrefixFacts(&e, &pkt, 48, 7);
    assert(e.tx_rsp_prefix_observation_version == 0); // Typed/raw disagreement.
}

static void testVersionAndPublication()
{
    // Use the exact production lookup body: API group1 is distinct from wire0,
    // and notification7 must not be replaced by command10 or a default zero.
    const iwx_fw_cmd_version versions[] = {{0x1c, 1, 10, 7}};
    iwx_softc sc{1, versions}; ItlIwx owner;
    assert(owner.iwx_lookup_notif_ver(&sc, 1, 0x1c) == 7);
    assert(owner.iwx_lookup_notif_ver(&sc, 0, 0x1c) == 255);
    assert(owner.iwx_lookup_notif_ver(&sc, 1, 0x1d) == 255);
    sc.n_cmd_versions = 0;
    assert(owner.iwx_lookup_notif_ver(&sc, 1, 0x1c) == 255);
    const auto pkt = packet();
    for (uint8_t version : {uint8_t(0), uint8_t(7), uint8_t(255)}) {
        auto e = facts(pkt, 48, version);
        iwx_tx_completion_observation_state state{};
        assert(record(&state, &e));
        iwx_tx_completion_observation_snapshot snap{};
        assert(snapshot(&state, &snap));
        assert(snap.available && snap.complete && snap.last[0].serial == 1);
        assert(snap.last[0].tx_rsp_notification_version == version);
        assert(snap.last[0].tx_rsp_prefix_observation_version == 1);
        IOEthernetController controller;
        uint32_t revision = 0;
        assert(publishCompletionSnapshot(&controller, &revision, snap, 4, 9, 2, 0));
        const auto &out = controller.values;
        assert(out.at("NativeStaCompletionSchema") == 5);
        assert(out.at("NativeStaCompletionTxRspPrefixExtensionSchema") == 1);
        assert(out.at("NativeStaCompletionTxRspVersionLookupGroup") == 1);
        assert(out.at("NativeStaCompletionTxRspVersionLookupCommand") == 0x1c);
        assert(out.at("NativeStaCompletionEvent0TxRspNotificationVersion") == version);
        assert(out.at("NativeStaCompletionEvent0TxRspPrefixObservationVersion") == 1);
        assert(out.at("NativeStaCompletionEvent0Serial") == 1);
        assert(out.at("NativeStaCompletionEvent1TxRspPrefixObservationVersion") == 0);
        assert(out.at("NativeStaCompletionFirmwareResponseIdentityProven") == 0);
        assert(out.at("NativeStaCompletionPeerReceiptProven") == 0);
        assert(out.at("NativeStaCompletionSnapshotComplete") == 1);
        assert(out.at("NativeStaCompletionSnapshotVersionBegin") == 2);
        assert(out.at("NativeStaCompletionSnapshotVersionEnd") == 2);
    }
    auto e = facts(pkt, 48, 7);
    for (unsigned int test = 0; test < 5; ++test) {
        auto bad = e;
        if (test == 0) bad.tx_rsp_notification_version = 256;
        if (test == 1) bad.tx_rsp_prefix_observation_version = 2;
        if (test == 2) bad.tx_rsp_prefix_observation_version = 0;
        if (test == 3) bad.frame_count = 2;
        if (test == 4) bad.presence_flags &= ~IWX_TX_COMPLETION_HAS_STATUS;
        assert(!validInput(&bad));
    }
    iwx_tx_completion_observation_state state{};
    assert(record(&state, &e));
    iwx_tx_completion_observation_snapshot snap{}; assert(snapshot(&state, &snap));
    IOEthernetController failed;
    failed.failKey = "NativeStaCompletionEvent0TxRspNotificationVersion";
    uint32_t revision = 0;
    assert(!publishCompletionSnapshot(&failed, &revision, snap, 4, 9, 2, 0));
    assert(failed.values.at("NativeStaCompletionSnapshotComplete") == 0);
    assert(failed.values.at("NativeStaCompletionSnapshotVersionBegin") == 1);
}

static void testStrictIdentityAndExclusiveBoundary()
{
    IwxGroup2TxSlot slot{};
    slot.valid = 1; slot.cookie = 501; slot.attempt_id = 1;
    slot.slot_generation = 7; slot.queue_id = 1; slot.index = 20;
    slot.ring_count = 1024; slot.context_generation = 9; slot.output_epoch = 8;
    slot.source = IWX_GROUP2_TX_SOURCE_RSN;
    slot.frame_control = 0x4108; slot.sequence_control = 0x140;
    IwxGroup2TxSlot matched{}; IwxGroup2TxHostOrigin origin{};
    uint32_t related = 0;
    auto result = iwx_group2_tx_match_completion_sparse_with_origin(
        &slot, 1, 1024, 20, 1, 21, 1, 9, 8, 0x4108, 0x160,
        0, 0, 1, 20, &matched, &origin, &related);
    assert(result == IWX_GROUP2_TX_MATCH_NONE);
    assert(origin.state == IWX_GROUP2_TX_ORIGIN_UNIQUE && related == 1);
    assert(origin.slot.cookie == 501 && matched.cookie == 0);
    result = iwx_group2_tx_match_completion_sparse_with_origin(
        &slot, 1, 1024, 20, 1, 21, 1, 9, 8, 0x4108, 0x140,
        0, 0, 1, 20, &matched, &origin, &related);
    assert(result == IWX_GROUP2_TX_MATCH_UNIQUE);
    uint32_t index = UINT32_MAX;
    assert(iwx_tx_response_single_reclaim_metadata_index(1024, 20, 1, 21, 1, &index));
    assert(index == 20);
    assert(!iwx_tx_response_single_reclaim_metadata_index(1024, 20, 1, 20, 1, &index));
}

int main()
{
    static_assert(sizeof(iwx_tx_completion_event_record) == 240, "record grew");
    static_assert(sizeof(IwxTxCompletionPublish::Pending) <= 1024, "pending grew");
    testPrefixAndProductionHook();
    testVersionAndPublication();
    testStrictIdentityAndExclusiveBoundary();
    puts("TX_RSP prefix: production ABI, decode, hook, observer, publication and strict identity fixtures PASS");
}
