// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_peer_runtime_table.hpp"
#include "../awdl_mif_encode.hpp"
#include "../awdl_discovery_admitted_binding.hpp"
#include "../awdl_peer_incarnation.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

using IntelAwdlElection::LocalState;
using IntelAwdlElection::Ranking;
using IntelAwdlPeer::RuntimeEpochs;
using IntelAwdlPeerRuntime::Result;
using IntelAwdlPeerRuntime::Snapshot;
using IntelAwdlPeerRuntime::Table;
using IntelP2PRx::ActionFrameRecord;

static void setAddress(uint8_t out[6], uint8_t last)
{
    const uint8_t bytes[6] = {0x02, 0x11, 0x22, 0x33, 0x44, last};
    memcpy(out, bytes, sizeof(bytes));
}

static NativeAwdl::PsfInput validPsf(uint8_t peerId = 5,
                                    uint32_t phy = 1000,
                                    uint32_t target = 1200,
                                    uint8_t nextChannel = 6,
                                    uint16_t downCounter = 32,
                                    uint16_t nextSequence = 4,
                                    uint32_t masterMetric = 500,
                                    uint8_t height = 2)
{
    NativeAwdl::PsfInput input{};
    setAddress(input.sourceAddress, peerId);
    setAddress(input.masterAddress, 30);
    setAddress(input.syncAddress, 24);
    const uint8_t slotsForSix[16] = {6, 6, 6, 6, 44, 44, 44, 44,
                                     149, 149, 149, 149, 0, 0, 0, 0};
    const uint8_t slotsForFortyFour[16] = {44, 44, 44, 44, 149, 149, 149, 149,
                                           6, 6, 6, 6, 0, 0, 0, 0};
    assert(nextChannel == 6 || nextChannel == 44);
    const uint8_t *slots = nextChannel == 6 ? slotsForSix : slotsForFortyFour;
    memcpy(input.channelSlots, slots, sizeof(input.channelSlots));
    input.sequenceNumber = 1;
    input.phyTxTimestampUs = phy;
    input.targetTxTimestampUs = target;
    input.nextAwChannel = nextChannel;
    input.txDownCounterTu = downCounter;
    input.masterChannel = nextChannel;
    input.remainingAwLengthTu = 8;
    input.nextAwSequenceNumber = nextSequence;
    input.apAlignment = 4;
    input.masterCounter = 77;
    input.distanceToMaster = height;
    input.masterMetric = masterMetric;
    input.ownMetric = 450;
    input.ownCounter = 33;
    input.htCapabilityInfo = 0x11ce;
    input.ampduParameters = 0x1b;
    input.rxMcsMask[0] = 0xff;
    input.rxMcsLength = 1;
    input.awdlVersion = 0x34;
    input.deviceClass = 1;
    return input;
}

static RuntimeEpochs activeEpochs()
{
    RuntimeEpochs epochs{};
    epochs.contextGeneration = 9;
    epochs.powerGeneration = 10;
    epochs.stationGeneration = 11;
    epochs.active = true;
    return epochs;
}

static ActionFrameRecord makeRecordForPsf(
    const NativeAwdl::PsfInput &psf, uint64_t rxUs, uint8_t subtype,
    uint64_t context = 9, uint64_t power = 10, uint64_t station = 11,
    bool gp2Present = true, uint32_t rxGp2 = 0xfffffff0u)
{
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
    size_t length = 0;
    if (subtype == 3) {
        NativeAwdl::MifInput mif{};
        mif.psf = psf;
        mif.hostname = "peer";
        mif.hostnameLength = 4;
        assert(NativeAwdl::encodeMif(&mif, frame, sizeof(frame), &length) ==
               NativeAwdl::MifEncodeStatus::Ok);
    } else {
        assert(subtype == 0);
        assert(NativeAwdl::encodePsf(&psf, frame, sizeof(frame), &length) ==
               NativeAwdl::EncodeStatus::Ok);
    }

    ActionFrameRecord record{};
    record.generation = context;
    record.powerGeneration = power;
    record.stationGeneration = station;
    record.rxMonotonicUs = rxUs;
    record.rxGp2TimestampUs = gp2Present ? rxGp2 : 0;
    record.rxGp2TimestampPresent = gp2Present;
    record.channel = 36;
    record.length = static_cast<uint16_t>(length);
    memcpy(record.bytes, frame, length);
    assert(NativeAwdl::parseActionFrame(record.bytes, record.length,
                                        &record.awdl) ==
           NativeAwdl::ParseStatus::Ok);
    return record;
}

static ActionFrameRecord makeRecord(uint8_t peerId, uint64_t rxUs,
                                    uint8_t subtype = 3,
                                    uint64_t context = 9,
                                    uint64_t power = 10,
                                    uint64_t station = 11,
                                    bool gp2Present = true,
                                    uint32_t rxGp2 = 0xfffffff0u,
                                    uint32_t phy = 1000,
                                    uint32_t target = 1200,
                                    uint8_t nextChannel = 6,
                                    uint16_t downCounter = 32,
                                    uint16_t nextSequence = 4,
                                    uint32_t masterMetric = 500,
                                    uint8_t height = 2)
{
    const NativeAwdl::PsfInput psf = validPsf(peerId, phy, target,
        nextChannel, downCounter, nextSequence, masterMetric, height);
    return makeRecordForPsf(psf, rxUs, subtype, context, power, station,
                            gp2Present, rxGp2);
}

static void corruptMifMasterButKeepFrameParseable(ActionFrameRecord *record)
{
    assert(record != nullptr);
    size_t offset = 24 + 16;
    bool changed = false;
    while (offset + 3 <= record->length) {
        const size_t valueLength = static_cast<size_t>(record->bytes[offset + 1]) |
            (static_cast<size_t>(record->bytes[offset + 2]) << 8);
        assert(valueLength <= record->length - offset - 3);
        if (record->bytes[offset] == 24) {
            assert(valueLength == 40);
            record->bytes[offset + 3 + 5] = 0x99;
            changed = true;
            break;
        }
        offset += 3 + valueLength;
    }
    assert(changed);
    assert(NativeAwdl::parseActionFrame(record->bytes, record->length,
                                        &record->awdl) ==
           NativeAwdl::ParseStatus::Ok);
}

static void corruptExplicitSequenceButKeepFrameParseable(
    ActionFrameRecord *record)
{
    assert(record != nullptr);
    size_t offset = 24 + 16;
    bool changed = false;
    while (offset + 3 <= record->length) {
        const size_t valueLength = static_cast<size_t>(record->bytes[offset + 1]) |
            (static_cast<size_t>(record->bytes[offset + 2]) << 8);
        assert(valueLength <= record->length - offset - 3);
        if (record->bytes[offset] == 18) {
            assert(valueLength >= 6 + 1);
            assert(record->bytes[offset + 3 + 1] == 0); // Simple encoding.
            record->bytes[offset + 3 + 6] = 149;
            changed = true;
            break;
        }
        offset += 3 + valueLength;
    }
    assert(changed);
    assert(NativeAwdl::parseActionFrame(record->bytes, record->length,
                                        &record->awdl) ==
           NativeAwdl::ParseStatus::Ok);
}

static void corruptPsfSyncCounterButKeepFrameParseable(
    ActionFrameRecord *record)
{
    assert(record != nullptr && record->awdl.subtype == 0);
    constexpr size_t syncTlvOffset = 24 + 16;
    assert(record->bytes[syncTlvOffset] == 4);
    assert(record->bytes[syncTlvOffset + 3] >= 31);
    record->bytes[syncTlvOffset + 3 + 1] = 0xff;
    record->bytes[syncTlvOffset + 3 + 2] = 0;
    assert(NativeAwdl::parseActionFrame(record->bytes, record->length,
                                        &record->awdl) ==
           NativeAwdl::ParseStatus::Ok);
}

static void removeEmbeddedSequenceFromSyncTlv(ActionFrameRecord *record)
{
    assert(record != nullptr);
    constexpr size_t syncTlvOffset = 24 + 16;
    const size_t oldValueLength =
        static_cast<size_t>(record->bytes[syncTlvOffset + 1]) |
        (static_cast<size_t>(record->bytes[syncTlvOffset + 2]) << 8);
    constexpr size_t newValueLength = 31;
    assert(oldValueLength >= newValueLength);
    const size_t oldEnd = syncTlvOffset + 3 + oldValueLength;
    const size_t newEnd = syncTlvOffset + 3 + newValueLength;
    memmove(record->bytes + newEnd, record->bytes + oldEnd,
            record->length - oldEnd);
    record->length = static_cast<uint16_t>(
        record->length - (oldValueLength - newValueLength));
    record->bytes[syncTlvOffset + 1] =
        static_cast<uint8_t>(newValueLength);
    record->bytes[syncTlvOffset + 2] = 0;
    assert(NativeAwdl::parseActionFrame(record->bytes, record->length,
                                        &record->awdl) ==
           NativeAwdl::ParseStatus::Ok);
}

static void testMifWithoutEmbeddedCopyCarriesUnverifiedPeerShape()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    auto mif = makeRecord(5, 100000, 3, 9, 10, 11, true,
                          0x1111u, 0x2222u, 0x3333u);
    removeEmbeddedSequenceFromSyncTlv(&mif);
    assert(table.observe(mif, epochs, 100100) == Result::kAdmitted);

    const Snapshot state = table.snapshot(epochs, 100200);
    assert(state.freshMifPeerCount == 1 && state.latestFreshMifSlot <
           IntelAwdlPeerRuntime::kPeerCapacity);
    const auto &peer = state.peers[state.latestFreshMifSlot];
    assert(peer.hasMif && peer.syncConsistent && peer.mifFresh);
    assert(peer.syncParameterLength == 31 && peer.syncTailLength == 0);
    assert(!peer.embeddedSequencePresent &&
           !peer.embeddedSequenceRecognized &&
           !peer.embeddedSequenceVerified);
    assert(state.lastMifRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(state.lastMifRejectDiagnostics.syncParameterLength == 31 &&
           state.lastMifRejectDiagnostics.syncTailLength == 0 &&
           !state.lastMifRejectDiagnostics.embeddedSequenceVerified);
}

static void testMifOnlySnapshotCarriesExactPresenceBinding()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    assert(table.observe(makeRecord(5, 100000, 3), epochs, 100100) ==
           Result::kAdmitted);

    const auto state = table.snapshot(epochs, 100200);
    assert(state.latestFreshMifSlot < IntelAwdlPeerRuntime::kPeerCapacity);
    IntelAwdlPeerRuntime::MifPeerSnapshot mif{};
    assert(table.getMifSnapshot(state.latestFreshMifSlot, epochs, 100200,
                                &mif));
    assert(mif.tracked && mif.hasMif && !mif.hasPsf && mif.mifFresh &&
           mif.complete && mif.syncConsistent);
    assert(mif.peerIncarnation != 0 && mif.mifRevision != 0 &&
           mif.mifRxMonotonicUs == 100000 && mif.mifAgeUs == 200 &&
           mif.rxChannel == 36);

    // A MIF-only entry stays invisible to the strict PSF snapshot API.
    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(!table.getPsfSnapshot(state.latestFreshMifSlot, epochs, 100200,
                                 &psf));

    // A later same-entry PSF updates only the hasPsf marker; the MIF revision
    // and original receive tuple stay bound to the exact MIF observation.
    assert(table.observe(makeRecord(5, 100250, 0), epochs, 100300) ==
           Result::kCandidate);
    IntelAwdlPeerRuntime::MifPeerSnapshot afterPsf{};
    assert(table.getMifSnapshot(state.latestFreshMifSlot, epochs, 100300,
                                &afterPsf));
    assert(afterPsf.hasPsf && afterPsf.peerIncarnation == mif.peerIncarnation &&
           afterPsf.mifRevision == mif.mifRevision &&
           afterPsf.mifRxMonotonicUs == mif.mifRxMonotonicUs);

    assert(table.observe(makeRecord(5, 100350, 3), epochs, 100400) ==
           Result::kUpdated);
    IntelAwdlPeerRuntime::MifPeerSnapshot replaced{};
    assert(table.getMifSnapshot(state.latestFreshMifSlot, epochs, 100400,
                                &replaced));
    assert(replaced.peerIncarnation == mif.peerIncarnation &&
           replaced.mifRevision > mif.mifRevision &&
           replaced.mifRxMonotonicUs == 100350);
}

static void testPsfAndMifPairsPlusFullSchedule()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    assert(table.observe(makeRecord(5, 1000000, 0, 9, 10, 11, true,
                                   0xfffffff0u, 0xfffffff0u, 0x10u),
                        epochs, 1000100) == Result::kCandidate);
    assert(table.observe(makeRecord(5, 1010000, 0, 9, 10, 11, true,
                                   0x20u, 0x30u, 0x50u),
                        epochs, 1010100) == Result::kCandidate);
    assert(table.observe(makeRecord(5, 1020000, 3, 9, 10, 11, true,
                                   0x60u, 0x70u, 0x90u),
                        epochs, 1020100) == Result::kAdmitted);
    assert(table.observe(makeRecord(5, 1030000, 0, 9, 10, 11, true,
                                   0x80u, 0xa0u, 0xc0u),
                        epochs, 1030100) == Result::kCandidate);

    const Snapshot state = table.snapshot(epochs, 1030200);
    assert(state.freshMifPeerCount == 1 && state.trackedPeerCount == 1);
    assert(state.latestFreshMifSlot < IntelAwdlPeerRuntime::kPeerCapacity);
    const auto &peer = state.peers[state.latestFreshMifSlot];
    assert(peer.tracked && peer.hasMif && peer.mifFresh &&
           peer.syncConsistent && peer.electionV2);
    assert(peer.timingSampleCount == 3);
    assert(peer.timingSamples[0].rxMonotonicUs == 1010000 &&
           peer.timingSamples[0].rxGp2TimestampUs == 0x20u &&
           peer.timingSamples[0].peerPhyTxTimestampUs == 0x30u &&
           peer.timingSamples[0].subtype == 0);
    assert(peer.timingSamples[1].rxMonotonicUs == 1020000 &&
           peer.timingSamples[1].rxGp2TimestampUs == 0x60u &&
           peer.timingSamples[1].peerPhyTxTimestampUs == 0x70u &&
           peer.timingSamples[1].subtype == 3);
    assert(peer.timingSamples[2].rxMonotonicUs == 1030000 &&
           peer.timingSamples[2].rxGp2TimestampUs == 0x80u &&
           peer.timingSamples[2].peerPhyTxTimestampUs == 0xa0u &&
           peer.timingSamples[2].subtype == 0);

    // The MIF's descriptor GP2 is paired with that same MIF's host RX time,
    // PHY and target timestamps. It is never replaced by the newer/latest
    // value from an unrelated PSF frame.
    assert(peer.mifRxMonotonicUs == 1020000 &&
           peer.mifRxGp2TimestampPresent &&
           peer.mifRxGp2TimestampUs == 0x60u &&
           peer.phyTxTimestampUs == 0x70u &&
           peer.targetTxTimestampUs == 0x90u);
    assert(peer.mifAgeUs == 10200 && peer.frameAgeUs == 200 &&
           peer.rxChannel == 36);
    assert(peer.txDownCounterTu == 32 && peer.nextAwSequence == 4 &&
           peer.awPeriodTu == 16 && peer.actionFramePeriodTu == 110 &&
           peer.nextAwChannel == 6);
    const uint8_t expectedSlots[16] = {6, 6, 6, 6, 44, 44, 44, 44,
                                       149, 149, 149, 149, 0, 0, 0, 0};
    assert(memcmp(peer.channelSlots, expectedSlots, sizeof(expectedSlots)) ==
           0);

    assert(state.freshPsfPeerCount == 1 && state.acceptedPsfTotal == 3 &&
           state.latestFreshPsfSlot == state.latestFreshMifSlot);
    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs, 1030200,
                                &psf));
    assert(psf.hasPsf && psf.psfFresh && psf.psfRxMonotonicUs == 1030000 &&
           psf.psfRxGp2TimestampUs == 0x80u &&
           psf.phyTxTimestampUs == 0xa0u &&
           psf.targetTxTimestampUs == 0xc0u);
    assert(psf.historyCompatible);
    assert(psf.nextAwChannel == 6 && psf.syncParameterLength == 57 &&
           psf.embeddedSequenceVerified);

    // A clock wrap remains an unchanged raw value; no clock map or TX
    // schedule is exposed by the summary API.
    assert(peer.mifRxGp2TimestampUs == 0x60u);
    LocalState local{};
    setAddress(local.own.bytes, 1);
    local.ownMetric = 100;
    local.ownCounter = 1;
    IntelAwdlPeerRuntime::SelectionSummary selection{};
    assert(table.selectMaster(epochs, 1030300, local, Ranking::MetricFirst,
                              &selection));
    assert(selection.followsPeer &&
           selection.selectedSlot == state.latestFreshMifSlot &&
           selection.height == 3 && selection.masterMetric == 500);
}

static void testPsfDoesNotRefreshMifLeaseAndHistoryIsMarkedStale()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    assert(table.observe(makeRecord(5, 1000000, 3), epochs, 1000100) ==
           Result::kAdmitted);
    assert(table.observe(makeRecord(5, 6000001, 0, 9, 10, 11, true, 7, 8, 9),
                         epochs, 6000100) == Result::kCandidate);

    const Snapshot state = table.snapshot(epochs, 6000200);
    assert(state.trackedPeerCount == 1 && state.freshMifPeerCount == 0);
    assert(state.latestFreshMifSlot == 0xff);
    const auto &peer = state.peers[0];
    assert(peer.tracked && peer.hasMif && !peer.mifFresh);
    assert(peer.mifAgeUs == 5000200 && peer.frameAgeUs == 199);
    assert(peer.phyTxTimestampUs == 1000 &&
           peer.targetTxTimestampUs == 1200 &&
           peer.mifRxGp2TimestampUs == 0xfffffff0u);
    assert(state.freshPsfPeerCount == 1 && state.latestFreshPsfSlot == 0);
    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(table.getPsfSnapshot(0, epochs, 6000200, &psf));
    assert(psf.hasPsf && psf.psfFresh && psf.psfRxMonotonicUs == 6000001 &&
           psf.psfRxGp2TimestampUs == 7 && psf.phyTxTimestampUs == 8);

    LocalState local{};
    setAddress(local.own.bytes, 1);
    local.ownMetric = 2000;
    local.ownCounter = 1;
    IntelAwdlPeerRuntime::SelectionSummary selection{};
    assert(table.selectMaster(epochs, 6000300, local, Ranking::MetricFirst,
                              &selection));
    assert(!selection.followsPeer && selection.selectedSlot == 0xff);
}

static void testPsfOnlySnapshotAndIndependentLeaseBoundary()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    auto psfRecord = makeRecord(5, 1000000, 0, 9, 10, 11, true,
                                0x1234u, 0x2345u, 0x3456u, 44, 12, 9,
                                700, 4);
    removeEmbeddedSequenceFromSyncTlv(&psfRecord);
    assert(table.observe(psfRecord, epochs, 1000100) == Result::kCandidate);

    auto state = table.snapshot(epochs, 1000200);
    assert(state.trackedPeerCount == 1 && state.freshPsfPeerCount == 1 &&
           state.freshMifPeerCount == 0 && state.acceptedPsfTotal == 1 &&
           state.mifFrameTotal == 0 && state.candidateFrameTotal == 1);
    assert(state.latestFreshPsfSlot < IntelAwdlPeerRuntime::kPeerCapacity &&
           state.latestFreshMifSlot == 0xff);
    assert(state.lastPsfDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::Ok));
    assert(state.lastMifDecodeStatus == 0xff);
    const auto &mif = state.peers[state.latestFreshPsfSlot];
    assert(mif.tracked && !mif.hasMif && !mif.mifFresh &&
           !mif.syncConsistent);
    assert(mif.timingSampleCount == 1 && mif.timingSamples[0].subtype == 0 &&
           mif.timingSamples[0].rxGp2TimestampUs == 0x1234u);

    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs, 1000200,
                                &psf));
    assert(psf.tracked && psf.hasPsf && psf.psfFresh &&
           psf.psfAgeUs == 200 && psf.psfRxMonotonicUs == 1000000 &&
           psf.psfRxGp2TimestampPresent &&
           psf.psfRxGp2TimestampUs == 0x1234u &&
           psf.phyTxTimestampUs == 0x2345u &&
           psf.targetTxTimestampUs == 0x3456u);
    assert(psf.nextAwChannel == 44 && psf.txDownCounterTu == 12 &&
           psf.nextAwSequence == 9 && psf.masterMetric == 700 &&
           psf.height == 4 && psf.syncParameterLength == 31 &&
           psf.syncTailLength == 0 && !psf.embeddedSequencePresent &&
           !psf.embeddedSequenceRecognized &&
           !psf.embeddedSequenceVerified && psf.version == 0x34 &&
           psf.deviceClass == 1);
    const uint8_t slots[16] = {44, 44, 44, 44, 149, 149, 149, 149,
                               6, 6, 6, 6, 0, 0, 0, 0};
    assert(memcmp(psf.channelSlots, slots, sizeof(slots)) == 0);

    if (state.latestFreshPsfSlot + 1 <
        IntelAwdlPeerRuntime::kPeerCapacity) {
        IntelAwdlPeerRuntime::PsfPeerSnapshot absent{};
        absent.tracked = true;
        absent.hasPsf = true;
        absent.psfAgeUs = 99;
        assert(!table.getPsfSnapshot(
            static_cast<uint8_t>(state.latestFreshPsfSlot + 1), epochs,
            1000200, &absent));
        assert(!absent.tracked && !absent.hasPsf && absent.psfAgeUs == 0);
    }

    const uint64_t exactLeaseEnd =
        1000000 + IntelAwdlPeerRuntime::kPsfLeaseTtlUs;
    state = table.snapshot(epochs, exactLeaseEnd);
    assert(state.freshPsfPeerCount == 1 && state.latestFreshPsfSlot != 0xff);
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs,
                                exactLeaseEnd, &psf));
    assert(psf.psfFresh && psf.psfAgeUs ==
           IntelAwdlPeerRuntime::kPsfLeaseTtlUs);

    state = table.snapshot(epochs, exactLeaseEnd + 1);
    assert(state.trackedPeerCount == 1 && state.freshPsfPeerCount == 0 &&
           state.latestFreshPsfSlot == 0xff && state.freshMifPeerCount == 0);
    assert(table.getPsfSnapshot(0, epochs, exactLeaseEnd + 1, &psf));
    assert(psf.tracked && psf.hasPsf && !psf.psfFresh &&
           psf.psfAgeUs == IntelAwdlPeerRuntime::kPsfLeaseTtlUs + 1);
}

static void testPsfAndMifSnapshotsAndLeasesStayIndependent()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    auto firstPsf = makeRecord(5, 1000000, 0, 9, 10, 11, true,
                               0x1111u, 0x2222u, 0x3333u, 6, 20, 7,
                               500, 2);
    removeEmbeddedSequenceFromSyncTlv(&firstPsf);
    assert(table.observe(firstPsf, epochs, 1000100) == Result::kCandidate);
    assert(table.observe(makeRecord(5, 1100000, 3, 9, 10, 11, true,
                                    0x4444u, 0x5555u, 0x6666u, 44, 24, 9,
                                    600, 3),
                          epochs, 1100100) == Result::kAdmitted);

    auto state = table.snapshot(epochs, 1100200);
    const uint8_t slot = state.latestFreshMifSlot;
    assert(slot < IntelAwdlPeerRuntime::kPeerCapacity &&
           state.latestFreshPsfSlot == slot && state.freshMifPeerCount == 1 &&
           state.freshPsfPeerCount == 1);
    const auto &mif = state.peers[slot];
    assert(mif.hasMif && mif.mifRxMonotonicUs == 1100000 &&
           mif.mifRxGp2TimestampUs == 0x4444u &&
           mif.phyTxTimestampUs == 0x5555u &&
           mif.targetTxTimestampUs == 0x6666u &&
           mif.syncParameterLength == 57 && mif.txDownCounterTu == 24);
    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(table.getPsfSnapshot(slot, epochs, 1100200, &psf));
    assert(psf.hasPsf && psf.psfRxMonotonicUs == 1000000 &&
           psf.psfRxGp2TimestampUs == 0x1111u &&
           psf.phyTxTimestampUs == 0x2222u &&
           psf.targetTxTimestampUs == 0x3333u &&
           psf.syncParameterLength == 31 && psf.txDownCounterTu == 20);

    // A later PSF refreshes only the PSF lease. The older MIF expires at its
    // own five-second boundary while the peer remains tracked by recent PSF.
    assert(table.observe(makeRecord(5, 5900000, 0, 9, 10, 11, true,
                                    0x7777u, 0x8888u, 0x9999u, 44, 30, 11,
                                    700, 4),
                         epochs, 5900100) == Result::kCandidate);
    state = table.snapshot(epochs, 6100001);
    assert(state.trackedPeerCount == 1 && state.freshPsfPeerCount == 1 &&
           state.freshMifPeerCount == 0);
    assert(state.peers[slot].mifRxMonotonicUs == 1100000 &&
           state.peers[slot].mifRxGp2TimestampUs == 0x4444u &&
           state.peers[slot].phyTxTimestampUs == 0x5555u &&
           !state.peers[slot].mifFresh);
    assert(table.getPsfSnapshot(slot, epochs, 6100001, &psf));
    assert(psf.psfFresh && psf.psfRxMonotonicUs == 5900000 &&
           psf.psfRxGp2TimestampUs == 0x7777u &&
           psf.phyTxTimestampUs == 0x8888u &&
           psf.targetTxTimestampUs == 0x9999u &&
           psf.txDownCounterTu == 30 && psf.masterMetric == 700);

    // A later MIF updates only MIF history. The PSF advertisement then ages
    // past its own lease even though a newer MIF keeps the table entry alive.
    assert(table.observe(makeRecord(5, 6200000, 3, 9, 10, 11, true,
                                    0xaaaaU, 0xbbbbU, 0xccccU, 6, 16, 13,
                                    800, 5),
                         epochs, 6200100) == Result::kUpdated);
    state = table.snapshot(epochs, 11000001);
    assert(state.trackedPeerCount == 1 && state.freshPsfPeerCount == 0 &&
           state.freshMifPeerCount == 1);
    assert(state.peers[slot].mifRxMonotonicUs == 6200000 &&
           state.peers[slot].mifRxGp2TimestampUs == 0xaaaaU &&
           state.peers[slot].phyTxTimestampUs == 0xbbbbU &&
           state.peers[slot].targetTxTimestampUs == 0xccccU &&
           state.peers[slot].txDownCounterTu == 16);
    assert(table.getPsfSnapshot(slot, epochs, 11000001, &psf));
    assert(psf.hasPsf && !psf.psfFresh &&
           psf.psfRxMonotonicUs == 5900000 &&
           psf.psfRxGp2TimestampUs == 0x7777u &&
           psf.phyTxTimestampUs == 0x8888u &&
           psf.txDownCounterTu == 30);

    // The source-tagged ring preserves the mixed arrival order explicitly.
    state = table.snapshot(epochs, 11000001);
    const auto &samples = state.peers[slot];
    assert(samples.timingSampleCount == 3 &&
           samples.timingSamples[0].subtype == 3 &&
           samples.timingSamples[1].subtype == 0 &&
           samples.timingSamples[2].subtype == 3);
}

static void testRejectedPsfPreservesAdvertisementAndMifDiagnostics()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    assert(table.observe(makeRecord(5, 100000, 0), epochs, 100100) ==
           Result::kCandidate);
    auto malformed = makeRecord(5, 110000, 0, 9, 10, 11, true,
                                0xaaaaU, 0xbbbbU, 0xccccU, 44, 20, 9,
                                600, 3);
    corruptPsfSyncCounterButKeepFrameParseable(&malformed);
    assert(table.observe(malformed, epochs, 110100) == Result::kInvalidPsf);

    auto state = table.snapshot(epochs, 110200);
    assert(state.trackedPeerCount == 1 && state.freshPsfPeerCount == 1 &&
           state.acceptedPsfTotal == 1 && state.candidateFrameTotal == 1 &&
           state.rejectedTotal == 1 && state.rejectedPsfTotal == 1 &&
           state.rejectedMifTotal == 0);
    assert(state.lastRejectedResult ==
           static_cast<uint8_t>(Result::kInvalidPsf));
    assert(state.lastPsfDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::InvalidSync));
    assert(state.lastPsfRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kSyncCounterOutOfRange);
    assert(state.lastPsfRejectDiagnostics.txDownCounterTu == 255);
    assert(state.lastMifDecodeStatus == 0xff);

    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs, 110200,
                                &psf));
    assert(psf.hasPsf && psf.psfFresh && psf.psfRxMonotonicUs == 100000 &&
           psf.phyTxTimestampUs == 1000 &&
           psf.targetTxTimestampUs == 1200 &&
           psf.txDownCounterTu == 32);
    const auto &peer = state.peers[state.latestFreshPsfSlot];
    assert(peer.timingSampleCount == 1 &&
           peer.timingSamples[0].subtype == 0 &&
           peer.timingSamples[0].rxMonotonicUs == 100000);

    assert(table.observe(makeRecord(5, 120000, 3, 9, 10, 11, true,
                                    0xddddU, 0xeeeeU, 0xffffU),
                         epochs, 120100) == Result::kAdmitted);
    state = table.snapshot(epochs, 120200);
    assert(state.lastPsfDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::InvalidSync));
    assert(state.lastPsfRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kSyncCounterOutOfRange);
    assert(state.lastMifDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::Ok));
    assert(state.rejectedPsfTotal == 1 && state.rejectedMifTotal == 0);
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs, 120200,
                                &psf));
    assert(psf.psfRxMonotonicUs == 100000 && psf.phyTxTimestampUs == 1000 &&
           psf.targetTxTimestampUs == 1200 && psf.txDownCounterTu == 32);
}

static void testPsfSequenceCopyMismatchIsAcceptedAndObservable()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    auto conflicting = makeRecord(5, 100000, 0, 9, 10, 11, true,
                                  0xaaaaU, 0xbbbbU, 0xccccU);
    corruptExplicitSequenceButKeepFrameParseable(&conflicting);
    assert(table.observe(conflicting, epochs, 100100) == Result::kCandidate);

    const Snapshot state = table.snapshot(epochs, 100200);
    assert(state.trackedPeerCount == 1 && state.freshPsfPeerCount == 1 &&
           state.freshMifPeerCount == 0 && state.acceptedPsfTotal == 1 &&
           state.candidateFrameTotal == 1 && state.rejectedTotal == 0 &&
           state.rejectedPsfTotal == 0 && state.rejectedMifTotal == 0 &&
           state.latestFreshMifSlot == 0xff);
    assert(state.lastPsfDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::Ok));
    assert(state.lastPsfRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(state.lastPsfRejectDiagnostics.embeddedSequenceRecognized &&
           !state.lastPsfRejectDiagnostics.embeddedSequenceVerified &&
           state.lastPsfRejectDiagnostics.embeddedSequenceMismatch &&
           state.lastPsfRejectDiagnostics.embeddedMismatchIndex == 0 &&
           state.lastPsfRejectDiagnostics.embeddedMismatchChannel == 6 &&
           state.lastPsfRejectDiagnostics.canonicalMismatchChannel == 149);
    assert(state.lastMifDecodeStatus == 0xff);

    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs, 100200,
                                &psf));
    assert(psf.psfFresh && psf.embeddedSequenceMismatch &&
           psf.embeddedMismatchIndex == 0 &&
           psf.embeddedMismatchChannel == 6 &&
           psf.canonicalMismatchChannel == 149 && psf.channelSlots[0] == 149);

    // PSF admission alone cannot feed the existing MIF-only election selector.
    LocalState local{};
    setAddress(local.own.bytes, 1);
    local.ownMetric = 60;
    IntelAwdlPeerRuntime::SelectionSummary selection{};
    assert(table.selectMaster(epochs, 100200, local, Ranking::MetricFirst,
                              &selection));
    assert(selection.selectedSlot == 0xff && !selection.followsPeer);
}

static void testRejectsBadEpochTimeParserAndOrdering()
{
    const RuntimeEpochs epochs = activeEpochs();
    Table stale;
    assert(stale.observe(makeRecord(5, 1000, 3, 8), epochs, 1100) ==
           Result::kStaleGeneration);
    Table future;
    assert(future.observe(makeRecord(5, 1100), epochs, 1000) ==
           Result::kInvalidTimestamp);
    Table expired;
    assert(expired.observe(makeRecord(5, 1), epochs,
                         IntelAwdlPeerRuntime::kCandidateTtlUs + 2) ==
           Result::kExpiredFrame);

    Table malformed;
    auto invalid = makeRecord(5, 1000);
    invalid.awdl.phyTx++;
    assert(malformed.observe(invalid, epochs, 1100) ==
           Result::kInvalidFrame);
    invalid = makeRecord(5, 1000);
    invalid.awdl.subtype = 0;
    assert(malformed.observe(invalid, epochs, 1200) ==
           Result::kInvalidFrame);
    Table badAddress;
    invalid = makeRecord(5, 1000);
    invalid.bytes[10] = 0x03; // Multicast Addr2.
    assert(badAddress.observe(invalid, epochs, 1100) ==
           Result::kInvalidSourceAddress);
    Table oversize;
    invalid = makeRecord(5, 1000);
    invalid.length = static_cast<uint16_t>(
        IntelP2PRx::kMaxActionFrameBytes + 1);
    assert(oversize.observe(invalid, epochs, 1100) == Result::kInvalidFrame);

    Table ordering;
    assert(ordering.observe(makeRecord(5, 2000, 3, 9, 10, 11, false, 0, 1000,
                                       1200),
                         epochs, 2100) == Result::kAdmitted);
    assert(ordering.observe(makeRecord(5, 1999, 0), epochs, 2200) ==
           Result::kOutOfOrderFrame);
    const Snapshot state = ordering.snapshot(epochs, 2300);
    assert(state.freshMifPeerCount == 1 && state.trackedPeerCount == 1);
    const auto &peer = state.peers[state.latestFreshMifSlot];
    assert(!peer.mifRxGp2TimestampPresent && peer.mifRxGp2TimestampUs == 0);
    assert(peer.timingSamples[0].rxGp2TimestampPresent == false);
}

static void testRejectedMifPreservesPeerAndValidMifReplacesAtomically()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    assert(table.observe(makeRecord(5, 100000, 3, 9, 10, 11, true,
                                    0x1111u, 0x2222u, 0x3333u),
                         epochs, 100100) == Result::kAdmitted);

    auto malformed = makeRecord(5, 110000, 3, 9, 10, 11, true,
                                0xaaaaU, 0xbbbbU, 0xccccU, 44, 20, 9, 600, 3);
    corruptMifMasterButKeepFrameParseable(&malformed);
    assert(table.observe(malformed, epochs, 110100) == Result::kInvalidMif);
    auto state = table.snapshot(epochs, 110200);
    assert(state.trackedPeerCount == 1 && state.freshMifPeerCount == 1);
    assert(state.rejectedMifTotal == 1 && state.rejectedTotal == 1);
    assert(state.lastRejectedResult == static_cast<uint8_t>(Result::kInvalidMif));
    assert(state.lastRejectedContext == epochs.contextGeneration);
    assert(state.lastMifDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::MasterMismatch));
    assert(state.lastMifRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(state.lastMifRejectDiagnostics.syncParameterLength == 57 &&
           state.lastMifRejectDiagnostics.syncTailLength == 24 &&
           state.lastMifRejectDiagnostics.embeddedSequenceVerified);
    const auto &preserved = state.peers[state.latestFreshMifSlot];
    assert(preserved.mifRxMonotonicUs == 100000 &&
           preserved.mifRxGp2TimestampUs == 0x1111u &&
           preserved.phyTxTimestampUs == 0x2222u &&
           preserved.targetTxTimestampUs == 0x3333u &&
           preserved.txDownCounterTu == 32 &&
           preserved.nextAwSequence == 4 && preserved.nextAwChannel == 6 &&
           preserved.syncParameterLength == 57 &&
           preserved.syncTailLength == 24 &&
           preserved.embeddedSequencePresent &&
           preserved.embeddedSequenceRecognized &&
           preserved.embeddedSequenceVerified &&
           preserved.masterMetric == 500 && preserved.height == 2 &&
           preserved.timingSampleCount == 1);

    // A later valid PSF must not hide the most recent MIF decoder failure.
    assert(table.observe(makeRecord(5, 120000, 0, 9, 10, 11, true,
                                    0xddddU, 0xeeeeU, 0xffffU),
                         epochs, 120100) == Result::kCandidate);
    state = table.snapshot(epochs, 120200);
    assert(state.lastRejectedResult == static_cast<uint8_t>(Result::kInvalidMif));
    assert(state.lastMifDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::MasterMismatch));
    assert(state.lastMifRejectDiagnostics.syncParameterLength == 57 &&
           state.lastMifRejectDiagnostics.embeddedSequenceVerified);
    assert(state.rejectedMifTotal == 1);
    const auto &afterPsf = state.peers[state.latestFreshMifSlot];
    assert(afterPsf.mifRxMonotonicUs == 100000 &&
           afterPsf.mifRxGp2TimestampUs == 0x1111u &&
           afterPsf.phyTxTimestampUs == 0x2222u &&
           afterPsf.targetTxTimestampUs == 0x3333u &&
           afterPsf.syncParameterLength == 57 &&
           afterPsf.syncTailLength == 24 &&
           afterPsf.embeddedSequenceVerified &&
           afterPsf.timingSampleCount == 2);

    // A subsequent valid MIF atomically replaces the whole MIF tuple and
    // schedule. It clears the last decode status to Ok, but does not erase the
    // previous rejection history.
    assert(table.observe(makeRecord(5, 130000, 3, 9, 10, 11, true,
                                    0x4444u, 0x5555u, 0x6666u, 44, 20, 9,
                                    600, 3),
                         epochs, 130100) == Result::kUpdated);
    state = table.snapshot(epochs, 130200);
    assert(state.updatedTotal == 1 && state.rejectedMifTotal == 1);
    assert(state.lastRejectedResult == static_cast<uint8_t>(Result::kInvalidMif));
    assert(state.lastRejectedContext == epochs.contextGeneration);
    assert(state.lastMifDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::Ok));
    assert(state.lastMifRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(state.lastMifRejectDiagnostics.syncParameterLength == 57 &&
           state.lastMifRejectDiagnostics.syncTailLength == 24 &&
           state.lastMifRejectDiagnostics.embeddedSequenceVerified);
    const auto &replaced = state.peers[state.latestFreshMifSlot];
    assert(replaced.mifRxMonotonicUs == 130000 &&
           replaced.mifRxGp2TimestampUs == 0x4444u &&
           replaced.phyTxTimestampUs == 0x5555u &&
           replaced.targetTxTimestampUs == 0x6666u &&
           replaced.txDownCounterTu == 20 &&
           replaced.nextAwSequence == 9 && replaced.nextAwChannel == 44 &&
           replaced.syncParameterLength == 57 &&
           replaced.syncTailLength == 24 &&
           replaced.embeddedSequencePresent &&
           replaced.embeddedSequenceRecognized &&
           replaced.embeddedSequenceVerified &&
           replaced.masterMetric == 600 && replaced.height == 3);
    const uint8_t expectedSlots[16] = {44, 44, 44, 44, 149, 149, 149, 149,
                                       6, 6, 6, 6, 0, 0, 0, 0};
    assert(memcmp(replaced.channelSlots, expectedSlots,
                  sizeof(expectedSlots)) == 0);

    auto conflicting = makeRecord(5, 140000, 3, 9, 10, 11, true,
                                  0x7777u, 0x8888u, 0x9999u, 44, 20, 9,
                                  600, 3);
    corruptExplicitSequenceButKeepFrameParseable(&conflicting);
    assert(table.observe(conflicting, epochs, 140100) == Result::kUpdated);
    state = table.snapshot(epochs, 140200);
    assert(state.lastMifDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::Ok));
    assert(state.lastMifRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(state.lastMifRejectDiagnostics.embeddedSequenceRecognized &&
           !state.lastMifRejectDiagnostics.embeddedSequenceVerified &&
           state.lastMifRejectDiagnostics.embeddedSequenceMismatch &&
           state.lastMifRejectDiagnostics.embeddedMismatchIndex == 0 &&
           state.lastMifRejectDiagnostics.embeddedMismatchChannel == 44 &&
           state.lastMifRejectDiagnostics.canonicalMismatchChannel == 149);
    assert(state.lastMifRejectDiagnostics.syncParameterLength == 57 &&
           state.lastMifRejectDiagnostics.syncTailLength == 24);
    assert(state.updatedTotal == 2 && state.rejectedMifTotal == 1 &&
           state.rejectedTotal == 1);
    const auto &updatedFromCanonicalType18 = state.peers[state.latestFreshMifSlot];
    assert(updatedFromCanonicalType18.syncParameterLength == 57 &&
           updatedFromCanonicalType18.syncTailLength == 24 &&
           updatedFromCanonicalType18.embeddedSequenceMismatch &&
           updatedFromCanonicalType18.embeddedMismatchIndex == 0 &&
           updatedFromCanonicalType18.embeddedMismatchChannel == 44 &&
           updatedFromCanonicalType18.canonicalMismatchChannel == 149 &&
           updatedFromCanonicalType18.channelSlots[0] == 149);
    // A later PSF leaves the MIF mismatch diagnostic intact.
    assert(table.observe(makeRecord(5, 150000, 0, 9, 10, 11), epochs,
                         150100) == Result::kCandidate);
    state = table.snapshot(epochs, 150200);
    assert(state.lastMifDecodeStatus == static_cast<uint8_t>(
        IntelAwdlElection::DecodeStatus::Ok));
    assert(state.lastMifRejectDiagnostics.rejectStage ==
           IntelAwdlElection::MifDecodeRejectStage::kNone);
    assert(state.lastMifRejectDiagnostics.embeddedSequenceMismatch &&
           state.lastMifRejectDiagnostics.embeddedMismatchIndex == 0 &&
           state.lastMifRejectDiagnostics.embeddedMismatchChannel == 44 &&
           state.lastMifRejectDiagnostics.canonicalMismatchChannel == 149);
}

static void testCapacityExpiryEpochAndClockRegression()
{
    Table table;
    RuntimeEpochs epochs = activeEpochs();
    uint64_t timestamp = 5000000;
    for (size_t i = 0; i < IntelAwdlPeerRuntime::kPeerCapacity; ++i) {
        assert(table.observe(makeRecord(static_cast<uint8_t>(i + 1),
                                        timestamp),
                             epochs, timestamp + 10) == Result::kAdmitted);
        timestamp += 100;
    }
    assert(table.snapshot(epochs, timestamp).trackedPeerCount ==
           IntelAwdlPeerRuntime::kPeerCapacity);
    assert(table.snapshot(epochs, timestamp).freshMifPeerCount ==
           IntelAwdlPeerRuntime::kPeerCapacity);

    // The fixed table replaces its least recently seen peer when full.
    assert(table.observe(makeRecord(99, timestamp), epochs, timestamp + 10) ==
           Result::kAdmitted);
    Snapshot state = table.snapshot(epochs, timestamp + 20);
    assert(state.trackedPeerCount == IntelAwdlPeerRuntime::kPeerCapacity);

    // Epoch changes clear live peer state but preserve lifetime numeric totals.
    const uint32_t lifetimeMifs = state.mifFrameTotal;
    epochs.powerGeneration++;
    state = table.snapshot(epochs, timestamp + 30);
    assert(state.trackedPeerCount == 0 && state.freshMifPeerCount == 0);
    assert(state.mifFrameTotal == lifetimeMifs);
    assert(table.observe(makeRecord(99, timestamp + 40, 3, 9, 11, 11),
                         epochs, timestamp + 50) == Result::kAdmitted);

    // PSF frames retain numeric history only until the candidate TTL; they do
    // not renew the MIF lease, which expires sooner (tested above).
    const uint64_t frameTime = timestamp + 40;
    state = table.snapshot(epochs, frameTime +
                           IntelAwdlPeerRuntime::kCandidateTtlUs + 1);
    assert(state.trackedPeerCount == 0 && state.freshMifPeerCount == 0);

    // Clock regression clears the state rather than mixing monotonic epochs.
    Table regressed;
    const uint64_t clockNow = timestamp +
        IntelAwdlPeerRuntime::kCandidateTtlUs + 10;
    assert(regressed.observe(makeRecord(7, clockNow, 3, 9, 11, 11), epochs,
                             clockNow + 10) == Result::kAdmitted);
    assert(regressed.observe(makeRecord(7, clockNow + 20, 0, 9, 11, 11), epochs,
                             clockNow + 5) == Result::kClockRegression);
    assert(regressed.snapshot(epochs, clockNow + 6).trackedPeerCount == 0);
}

static void testMifLeaseBoundaryAndLatestMifSlot()
{
    Table table;
    const RuntimeEpochs epochs = activeEpochs();
    assert(table.observe(makeRecord(5, 10000000, 3), epochs, 10000100) ==
           Result::kAdmitted);
    assert(table.observe(makeRecord(6, 10500000, 3), epochs, 10500100) ==
           Result::kAdmitted);
    const uint64_t boundaryNow = 10500000 +
        IntelAwdlPeerRuntime::kMifLeaseTtlUs - 500000;
    auto state = table.snapshot(epochs, boundaryNow);
    assert(state.freshMifPeerCount == 2);
    assert(state.latestFreshMifSlot < IntelAwdlPeerRuntime::kPeerCapacity);
    assert(state.peers[state.latestFreshMifSlot].mifRxMonotonicUs == 10500000);

    state = table.snapshot(epochs, boundaryNow + 1);
    assert(state.freshMifPeerCount == 1);
    assert(state.peers[state.latestFreshMifSlot].mifRxMonotonicUs == 10500000);
}


using NativeAwdlDiscoveryBinding::Decision;
using NativeAwdlDiscoveryBinding::Mode;
using NativeAwdlDiscoveryBinding::OneShot;
using NativeAwdlDiscoveryBinding::QueueHead;
using BindingSnapshot = NativeAwdlDiscoveryBinding::Snapshot;
using NativeAwdlDiscoveryBinding::Window;

static ActionFrameRecord makeRecordAtChannel(uint8_t peerId, uint64_t rxUs,
                                              uint8_t subtype)
{
    auto record = makeRecord(peerId, rxUs, subtype);
    record.channel = 6; // Synthetic RX index chosen to map to IEEE channel 6.
    return record;
}

static BindingSnapshot bindingFromRuntimePsf(
    const IntelAwdlPeerRuntime::PsfPeerSnapshot &source,
    uint64_t nowUs, bool psfOnChannel6 = true, bool mifOnChannel6 = true)
{
    BindingSnapshot out{};
    out.mode = Mode::kPsfNextSlot;
    out.psfHistorySameEntryPresent = source.tracked && source.hasPsf;
    out.historyCompatible = source.historyCompatible;
    out.peerIncarnation = source.peerIncarnation;
    out.psfRevision = source.psfRevision;
    out.mifRevision = source.mifRevision;
    out.mifRxMonotonicUs = source.mifRxMonotonicUs;
    out.mifAgeUs = source.mifAgeUs;
    out.psfAgeUs = source.psfAgeUs;
    out.hasMif = source.hasMif;
    out.mifFresh = source.mifFresh;
    out.mifSyncConsistent = source.mifSyncConsistent;
    out.mifRxChannel6 = mifOnChannel6;
    out.mif.peerIncarnation = source.mif.peerIncarnation;
    out.mif.mifRevision = source.mif.mifRevision;
    out.mif.rxMonotonicUs = source.mif.rxMonotonicUs;
    out.mif.rxAgeUs = source.mif.rxAgeUs;
    out.mif.epochs = {source.mif.contextGeneration,
                      source.mif.powerGeneration,
                      source.mif.stationGeneration,
                      source.contextGeneration};
    out.mif.rxGp2Us = source.mif.rxGp2Us;
    out.mif.phyTxTimestampUs = source.mif.phyTxTimestampUs;
    out.mif.targetTxTimestampUs = source.mif.targetTxTimestampUs;
    out.mif.awCounter = source.mif.awCounter;
    out.mif.txDownCounterTu = source.mif.txDownCounterTu;
    out.mif.awPeriodTu = source.mif.awPeriodTu;
    out.mif.presenceMode = source.mif.presenceMode;
    out.mif.rxChannel = source.mif.rxChannel;
    memcpy(out.mif.canonicalSlots, source.mif.canonicalSlots,
           sizeof(out.mif.canonicalSlots));
    out.mif.present = source.mif.present;
    out.mif.complete = source.mif.complete;
    out.mif.syncConsistent = source.mif.syncConsistent;
    out.mif.fresh = source.mif.fresh;
    out.mif.rxGp2Present = source.mif.rxGp2Present;
    out.mif.presenceModePresent = source.mif.presenceModePresent;
    out.mif.awCounterSemanticVerified =
        source.mif.awCounterSemanticVerified;
    out.mif.type18Present = source.mif.type18Present;
    out.mif.type18Valid = source.mif.type18Valid;
    out.mif.peerMifRxChannel6Confirmed = mifOnChannel6;
    auto &psf = out.psf;
    psf.peerToken = source.peerIncarnation;
    psf.scheduleRevision = source.psfRevision;
    psf.epochs = {source.contextGeneration, source.powerGeneration,
                  source.stationGeneration, source.contextGeneration};
    psf.rxHostUs = source.psfRxMonotonicUs;
    psf.rxGp2 = source.psfRxGp2TimestampUs;
    psf.phyTxTimestampUs = source.phyTxTimestampUs;
    psf.targetTxTimestampUs = source.targetTxTimestampUs;
    psf.awCounter = source.nextAwSequence;
    psf.txDownTu = source.txDownCounterTu;
    psf.awPeriodTu = source.awPeriodTu;
    psf.presenceMode = 4; // decodePsf only publishes presence mode 4 entries.
    psf.rxChannel = psfOnChannel6 ? 6 : 44;
    memcpy(psf.canonicalChannels, source.channelSlots,
           sizeof(psf.canonicalChannels));
    psf.complete = source.tracked && source.hasPsf && source.psfFresh &&
                   source.syncConsistent &&
                   source.contextGeneration != 0 &&
                   source.powerGeneration != 0 &&
                   source.stationGeneration != 0;
    (void)nowUs;
    return out;
}

static BindingSnapshot validBindingSnapshot(uint64_t nowUs = 2000000)
{
    BindingSnapshot out{};
    out.mode = Mode::kPsfNextSlot;
    out.psfHistorySameEntryPresent = true;
    out.historyCompatible = true;
    out.peerIncarnation = 42;
    out.psfRevision = 3;
    out.mifRevision = 2;
    out.mifRxMonotonicUs = nowUs - 10000;
    out.mifAgeUs = 10000;
    out.psfAgeUs = 5000;
    out.hasMif = true;
    out.mifFresh = true;
    out.mifSyncConsistent = true;
    out.mifRxChannel6 = true;
    auto &psf = out.psf;
    psf.peerToken = out.peerIncarnation;
    psf.scheduleRevision = out.psfRevision;
    psf.epochs = {9, 10, 11, 9};
    psf.rxHostUs = nowUs - out.psfAgeUs;
    psf.rxGp2 = 0x12345678u;
    psf.phyTxTimestampUs = 0x12346000u;
    psf.targetTxTimestampUs = 0x12345f00u;
    psf.awCounter = 28; // Synthetic next canonical slot 8.
    psf.txDownTu = 32;
    psf.awPeriodTu = 16;
    psf.presenceMode = 4;
    psf.rxChannel = 6;
    for (uint8_t i = 0; i < 16; ++i)
        psf.canonicalChannels[i] = 44;
    psf.canonicalChannels[8] = 6;
    psf.complete = true;
    auto &mif = out.mif;
    mif.peerIncarnation = out.peerIncarnation;
    mif.mifRevision = out.mifRevision;
    mif.rxMonotonicUs = out.mifRxMonotonicUs;
    mif.epochs = {psf.epochs.context, psf.epochs.power,
                  psf.epochs.station, psf.epochs.roc};
    mif.rxGp2Us = 0x12345679u;
    mif.phyTxTimestampUs = 0x12346000u;
    mif.targetTxTimestampUs = 0x12345f00u;
    mif.awCounter = 20320; // Synthetic current slot 8.
    mif.txDownCounterTu = 32;
    mif.awPeriodTu = 16;
    mif.presenceMode = 4;
    mif.rxChannel = 6;
    for (uint8_t i = 0; i < 16; ++i)
        mif.canonicalSlots[i] = 44;
    mif.canonicalSlots[8] = 6;
    mif.present = true;
    mif.complete = true;
    mif.syncConsistent = true;
    mif.fresh = true;
    mif.rxGp2Present = true;
    mif.presenceModePresent = true;
    mif.awCounterSemanticVerified = true;
    mif.type18Present = true;
    mif.type18Valid = true;
    mif.peerMifRxChannel6Confirmed = true;
    return out;
}

static Window validWindowFor(const BindingSnapshot &snapshot, uint64_t nowUs,
                             bool requireRuntimeMifBinding = true)
{
    Window window{};
    window.mode = snapshot.mode;
    window.epochs = {snapshot.psf.epochs.context,
                     snapshot.psf.epochs.power,
                     snapshot.psf.epochs.station,
                     snapshot.psf.epochs.roc};
    window.nowUs = nowUs;
    window.leaseStartUs = nowUs - 1000;
    window.leaseEndUs = nowUs + 100000;
    window.phaseEarliestUs = nowUs - 100;
    window.phaseLatestUs = nowUs + 10000;
    window.requireRuntimeMifBinding = requireRuntimeMifBinding;
    window.phaseCandidateValid = true; // Supplied only after existing estimator.
    window.rocActive = true;
    window.windowOpen = true;
    return window;
}

static QueueHead validQmHead(const Window &window)
{
    QueueHead head{};
    head.token = 70;
    head.bornUs = window.nowUs - 100;
    head.generation = static_cast<uint32_t>(window.epochs.power);
    head.queryClass = static_cast<uint8_t>(
        NativeAwdlData::MdnsQueryClass::QmMulticast);
    head.eligible = true;
    return head;
}

static void testRuntimeSnapshotBindsSameSourceMifAndPsf()
{
    Table table;
    const auto epochs = activeEpochs();
    assert(table.observe(makeRecordAtChannel(5, 1000000, 0), epochs,
                         1000010) == Result::kCandidate);
    assert(table.observe(makeRecordAtChannel(5, 1010000, 3), epochs,
                         1010010) == Result::kAdmitted);
    assert(table.observe(makeRecordAtChannel(5, 1020000, 0), epochs,
                         1020010) == Result::kCandidate);
    auto state = table.snapshot(epochs, 1020100);
    assert(state.latestFreshPsfSlot < IntelAwdlPeerRuntime::kPeerCapacity);
    IntelAwdlPeerRuntime::PsfPeerSnapshot raw{};
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs, 1020100,
                                &raw));
    assert(raw.peerIncarnation != 0 && raw.psfRevision == 2 &&
           raw.mifRevision == 1 && raw.hasMif && raw.mifFresh &&
           raw.mifSyncConsistent && raw.psfFresh);
    assert(raw.mif.present && raw.mif.complete && raw.mif.syncConsistent &&
           raw.mif.fresh && raw.mif.rxGp2Present &&
           raw.mif.presenceModePresent && raw.mif.awCounterSemanticVerified &&
           raw.mif.type18Present && raw.mif.type18Valid &&
           raw.mif.peerIncarnation == raw.peerIncarnation &&
           raw.mif.mifRevision == raw.mifRevision &&
           raw.mif.contextGeneration == epochs.contextGeneration &&
           raw.mif.powerGeneration == epochs.powerGeneration &&
           raw.mif.stationGeneration == epochs.stationGeneration &&
           raw.mif.rxMonotonicUs == 1010000 && raw.mif.rxChannel == 6 &&
           raw.mif.presenceMode == 4 && raw.mif.awCounter == 4 &&
           raw.mif.awCounter == raw.mif.nextAwSequence);
    auto snapshot = bindingFromRuntimePsf(raw, 1020100);
    auto window = validWindowFor(snapshot, 1020100);
    auto head = validQmHead(window);
    OneShot oneShot;
    assert(oneShot.lock(snapshot, head, window) == Decision::kReady);
    assert(oneShot.authorizeTake(snapshot, head, window) == Decision::kReady);
    assert(oneShot.attempted());
}


static void testObserverAggregateCannotAuthorizeForeignRuntimePsf()
{
    Table table;
    IntelAwdlPeer::Observer formalObserver;
    const auto epochs = activeEpochs();
    const auto verifiedMif = makeRecordAtChannel(5, 1000000, 3);
    assert(formalObserver.observe(verifiedMif, epochs, 1000010) ==
           IntelAwdlPeer::ObserveResult::kAdmittedPeer);
    assert(table.observe(verifiedMif, epochs, 1000010) == Result::kAdmitted);
    assert(table.observe(makeRecordAtChannel(6, 1010000, 0), epochs,
                         1010010) == Result::kCandidate);
    const auto observerSummary = formalObserver.snapshot(epochs, 1010100);
    assert(observerSummary.validPeerCount == 1);

    const auto runtimeSummary = table.snapshot(epochs, 1010100);
    IntelAwdlPeerRuntime::PsfPeerSnapshot candidate{};
    assert(table.getPsfSnapshot(runtimeSummary.latestFreshPsfSlot, epochs,
                                1010100, &candidate));
    assert(candidate.hasPsf && !candidate.hasMif);
    const auto snapshot = bindingFromRuntimePsf(candidate, 1010100);
    auto window = validWindowFor(snapshot, 1010100, true);
    auto head = validQmHead(window);
    OneShot oneShot;
    // The unrelated observer count requests same-entry runtime binding; it is
    // never used to authenticate this other PSF table slot.
    assert(oneShot.lock(snapshot, head, window) ==
           Decision::kMissingMifBinding);
    assert(!oneShot.attempted());
}

static void testIncarnationNeverReusedAcrossTableReset()
{
    Table table;
    const auto epochs = activeEpochs();
    assert(table.observe(makeRecordAtChannel(5, 1000000, 0), epochs,
                         1000010) == Result::kCandidate);
    auto summary = table.snapshot(epochs, 1000100);
    IntelAwdlPeerRuntime::PsfPeerSnapshot first{};
    assert(table.getPsfSnapshot(summary.latestFreshPsfSlot, epochs, 1000100,
                                &first));
    table.reset();
    assert(table.observe(makeRecordAtChannel(5, 2000000, 0), epochs,
                         2000010) == Result::kCandidate);
    summary = table.snapshot(epochs, 2000100);
    IntelAwdlPeerRuntime::PsfPeerSnapshot second{};
    assert(table.getPsfSnapshot(summary.latestFreshPsfSlot, epochs, 2000100,
                                &second));
    assert(first.peerIncarnation != 0 && second.peerIncarnation >
           first.peerIncarnation);
    auto changedEpochs = epochs;
    changedEpochs.powerGeneration++;
    (void)table.snapshot(changedEpochs, 2000200);
    auto afterEpochRecord = makeRecordAtChannel(5, 2000300, 0);
    afterEpochRecord.powerGeneration = changedEpochs.powerGeneration;
    assert(table.observe(afterEpochRecord, changedEpochs, 2000310) ==
           Result::kCandidate);
    summary = table.snapshot(changedEpochs, 2000400);
    IntelAwdlPeerRuntime::PsfPeerSnapshot afterEpoch{};
    assert(table.getPsfSnapshot(summary.latestFreshPsfSlot, changedEpochs,
                                2000400, &afterEpoch));
    assert(afterEpoch.peerIncarnation > second.peerIncarnation);
}

static void testRuntimeSnapshotRejectsCrossSourceMifAndPsf()
{
    Table table;
    const auto epochs = activeEpochs();
    assert(table.observe(makeRecordAtChannel(5, 1000000, 3), epochs,
                         1000010) == Result::kAdmitted);
    assert(table.observe(makeRecordAtChannel(6, 1010000, 0), epochs,
                         1010010) == Result::kCandidate);
    const auto state = table.snapshot(epochs, 1010100);
    IntelAwdlPeerRuntime::PsfPeerSnapshot raw{};
    assert(table.getPsfSnapshot(state.latestFreshPsfSlot, epochs, 1010100,
                                &raw));
    assert(raw.hasPsf && raw.psfFresh && !raw.hasMif &&
           raw.peerIncarnation != 0);
    const auto snapshot = bindingFromRuntimePsf(raw, 1010100);
    const auto window = validWindowFor(snapshot, 1010100, true);
    auto head = validQmHead(window);
    OneShot oneShot;
    assert(oneShot.lock(snapshot, head, window) ==
           Decision::kMissingMifBinding);
    assert(!oneShot.attempted());
}

static void testSlotReuseInvalidatesLockedPeerIncarnation()
{
    Table table;
    const auto epochs = activeEpochs();
    assert(table.observe(makeRecordAtChannel(1, 1000000, 3), epochs,
                         1000010) == Result::kAdmitted);
    assert(table.observe(makeRecordAtChannel(1, 1000100, 0), epochs,
                         1000110) == Result::kCandidate);
    uint64_t timestamp = 1010000;
    for (uint8_t peer = 2; peer <= IntelAwdlPeerRuntime::kPeerCapacity;
         ++peer) {
        assert(table.observe(makeRecordAtChannel(peer, timestamp, 3), epochs,
                             timestamp + 10) == Result::kAdmitted);
        timestamp += 1000;
    }
    auto state = table.snapshot(epochs, timestamp);
    const uint8_t oldSlot = state.latestFreshPsfSlot;
    assert(oldSlot < IntelAwdlPeerRuntime::kPeerCapacity);
    IntelAwdlPeerRuntime::PsfPeerSnapshot oldRaw{};
    assert(table.getPsfSnapshot(oldSlot, epochs, timestamp, &oldRaw));
    const auto oldSnapshot = bindingFromRuntimePsf(oldRaw, timestamp);
    auto window = validWindowFor(oldSnapshot, timestamp);
    auto head = validQmHead(window);
    OneShot oneShot;
    assert(oneShot.lock(oldSnapshot, head, window) == Decision::kReady);

    assert(table.observe(makeRecordAtChannel(99, timestamp + 1000, 3), epochs,
                         timestamp + 1010) == Result::kAdmitted);
    assert(table.observe(makeRecordAtChannel(99, timestamp + 1100, 0), epochs,
                         timestamp + 1110) == Result::kCandidate);
    const uint64_t currentNow = timestamp + 1200;
    IntelAwdlPeerRuntime::PsfPeerSnapshot currentRaw{};
    assert(table.getPsfSnapshot(oldSlot, epochs, currentNow, &currentRaw));
    const auto currentSnapshot = bindingFromRuntimePsf(currentRaw, currentNow);
    assert(currentSnapshot.peerIncarnation != oldSnapshot.peerIncarnation);
    window.nowUs = currentNow;
    assert(oneShot.authorizeTake(currentSnapshot, head, window) ==
           Decision::kPeerIncarnationChanged);
    assert(!oneShot.attempted());
}

static void testSnapshotRevisionsFreshnessEpochChannelLeaseAndClose()
{
    const uint64_t nowUs = 2000000;
    const auto base = validBindingSnapshot(nowUs);
    auto window = validWindowFor(base, nowUs);
    auto head = validQmHead(window);
    OneShot oneShot;
    assert(oneShot.lock(base, head, window) == Decision::kReady);

    auto changedPsf = base;
    ++changedPsf.psfRevision;
    changedPsf.psf.scheduleRevision = changedPsf.psfRevision;
    assert(oneShot.authorizeTake(changedPsf, head, window) ==
           Decision::kPsfRevisionChanged);

    OneShot psfWitnessGuard;
    window = validWindowFor(base, nowUs);
    head = validQmHead(window);
    assert(psfWitnessGuard.lock(base, head, window) == Decision::kReady);
    auto changedPsfField = base;
    changedPsfField.psf.canonicalChannels[0] = 149;
    assert(psfWitnessGuard.authorizeTake(changedPsfField, head, window) ==
           Decision::kPsfWitnessChanged);
    assert(!psfWitnessGuard.attempted());

    OneShot mifRevisionGuard;
    assert(mifRevisionGuard.lock(base, head, window) == Decision::kReady);
    auto changedMif = base;
    ++changedMif.mifRevision;
    changedMif.mifRxMonotonicUs++;
    changedMif.mifAgeUs--;
    assert(mifRevisionGuard.authorizeTake(changedMif, head, window) ==
           Decision::kMifRevisionChanged);

    auto stalePsf = base;
    window.nowUs = stalePsf.psf.rxHostUs +
                   NativeAwdlDiscoveryBinding::kPsfLeaseUs + 1;
    window.leaseStartUs = window.nowUs - 1000;
    window.leaseEndUs = window.nowUs + 100000;
    window.phaseEarliestUs = window.nowUs - 100;
    window.phaseLatestUs = window.nowUs + 10000;
    assert(NativeAwdlDiscoveryBinding::validate(
               stalePsf, head, window) == Decision::kStalePsf);

    auto staleMif = base;
    window.nowUs = staleMif.mifRxMonotonicUs +
                   NativeAwdlDiscoveryBinding::kMifLeaseUs + 1;
    staleMif.mifAgeUs = NativeAwdlDiscoveryBinding::kMifLeaseUs + 1;
    staleMif.psf.rxHostUs = window.nowUs - 100;
    staleMif.psfAgeUs = 100;
    window.leaseStartUs = window.nowUs - 1000;
    window.leaseEndUs = window.nowUs + 100000;
    window.phaseEarliestUs = window.nowUs - 100;
    window.phaseLatestUs = window.nowUs + 10000;
    assert(NativeAwdlDiscoveryBinding::validate(
               staleMif, head, window) == Decision::kStaleMif);

    window = validWindowFor(base, nowUs);
    window.epochs.context++;
    assert(NativeAwdlDiscoveryBinding::validate(
               base, head, window) == Decision::kEpochMismatch);
    window = validWindowFor(base, nowUs);
    window.epochs.power++;
    assert(NativeAwdlDiscoveryBinding::validate(
               base, head, window) == Decision::kEpochMismatch);
    window = validWindowFor(base, nowUs);
    window.epochs.station++;
    assert(NativeAwdlDiscoveryBinding::validate(
               base, head, window) == Decision::kEpochMismatch);
    window = validWindowFor(base, nowUs);
    window.epochs.roc++;
    assert(NativeAwdlDiscoveryBinding::validate(
               base, head, window) == Decision::kEpochMismatch);
    window = validWindowFor(base, nowUs);
    auto wrongChannel = base;
    wrongChannel.mifRxChannel6 = false;
    assert(NativeAwdlDiscoveryBinding::validate(
               wrongChannel, head, window) == Decision::kChannelMismatch);
    window.nowUs = nowUs;
    window.leaseEndUs = nowUs;
    assert(NativeAwdlDiscoveryBinding::validate(
               base, head, window) == Decision::kLeaseOutside);
    window = validWindowFor(base, nowUs);
    window.phaseLatestUs = nowUs;
    assert(NativeAwdlDiscoveryBinding::validate(
               base, head, window) == Decision::kPhaseExpired);
    window = validWindowFor(base, nowUs);
    window.closing = true;
    assert(NativeAwdlDiscoveryBinding::validate(
               base, head, window) == Decision::kWindowClosed);
    OneShot closingGuard;
    window = validWindowFor(base, nowUs);
    assert(closingGuard.lock(base, head, window) == Decision::kReady);
    window.closing = true;
    assert(closingGuard.authorizeTake(base, head, window) ==
           Decision::kWindowClosed);
    assert(!closingGuard.attempted());
    assert(closingGuard.authorizeTake(base, head, validWindowFor(base, nowUs)) ==
           Decision::kWindowClosed);
    window = validWindowFor(base, nowUs);
    window.rocActive = false;
    assert(NativeAwdlDiscoveryBinding::validate(
               base, head, window) == Decision::kRocInactive);
    window = validWindowFor(base, nowUs);
    head.queryClass = static_cast<uint8_t>(
        NativeAwdlData::MdnsQueryClass::QuUnicastPreferred);
    assert(NativeAwdlDiscoveryBinding::validate(
               base, head, window) == Decision::kQueueHeadInvalid);
}

static void testPeerIdentityAndRevisionOverflowFailClosed()
{
    NativeAwdlPeerIdentity::TokenSequence sequence(UINT64_MAX - 1);
    uint64_t first = 0;
    uint64_t oldEntryToken = 77;
    assert(sequence.allocate(&first) && first == UINT64_MAX);
    assert(!sequence.allocate(&oldEntryToken));
    assert(oldEntryToken == 77); // Failed allocation leaves old entry intact.
    uint64_t revision = UINT64_MAX;
    assert(!NativeAwdlPeerIdentity::advanceRevision(&revision));
    assert(revision == UINT64_MAX);
    revision = 0;
    assert(NativeAwdlPeerIdentity::advanceRevision(&revision) && revision == 1);
}

struct MockExactHeadQueue {
    QueueHead current;
    uint32_t dequeueCalls;
    uint32_t consumed;

    MockExactHeadQueue(const QueueHead &head)
        : current(head), dequeueCalls(0), consumed(0) {}

    bool nextDiscoveryTx(const QueueHead &expected)
    {
        ++dequeueCalls;
        if (!NativeAwdlDiscoveryBinding::sameQueueHead(current, expected))
            return false;
        ++consumed;
        return true;
    }
};

static void testOneShotStrictQmTakeHasNoFallback()
{
    const uint64_t nowUs = 3000000;
    const auto snapshot = validBindingSnapshot(nowUs);
    auto window = validWindowFor(snapshot, nowUs);
    auto head = validQmHead(window);
    OneShot waiting;
    window.phaseEarliestUs = nowUs + 10;
    assert(waiting.lock(snapshot, head, window) == Decision::kReady);
    assert(waiting.authorizeTake(snapshot, head, window) ==
           Decision::kPhaseNotYetOpen);
    assert(!waiting.attempted());
    window.nowUs += 20;
    auto freshSnapshot = snapshot;
    freshSnapshot.psfAgeUs += 20;
    freshSnapshot.mifAgeUs += 20;
    freshSnapshot.mif.rxAgeUs += 20;
    assert(waiting.authorizeTake(freshSnapshot, head, window) ==
           Decision::kReady);

    window = validWindowFor(snapshot, nowUs);
    head = validQmHead(window);
    OneShot oneShot;
    assert(oneShot.lock(snapshot, head, window) == Decision::kReady);
    MockExactHeadQueue queue(head);
    assert(oneShot.authorizeTake(snapshot, head, window) == Decision::kReady);
    assert(queue.nextDiscoveryTx(head));
    assert(queue.dequeueCalls == 1 && queue.consumed == 1);
    assert(oneShot.authorizeTake(snapshot, head, window) ==
           Decision::kAlreadyAttempted);
    assert(queue.dequeueCalls == 1 && queue.consumed == 1);
    uint32_t ordinaryFallbackCalls = 0;
    assert(ordinaryFallbackCalls == 0);

    OneShot changedHead;
    assert(changedHead.lock(snapshot, head, window) == Decision::kReady);
    auto changed = head;
    ++changed.token;
    assert(changedHead.authorizeTake(snapshot, changed, window) ==
           Decision::kQueueHeadChanged);
    assert(!changedHead.attempted());
}

static void testReplayCanonicalSlotsWithoutChannel6RemainClosed()
{
    const uint64_t nowUs = 4000000;
    const uint16_t counters[] = {20324, 20330, 20337};
    const uint8_t expectedSlots[] = {10, 11, 13};
    const uint8_t expectedChannels[] = {149, 0, 149};
    for (size_t i = 0; i < sizeof(counters) / sizeof(counters[0]); ++i) {
        auto snapshot = validBindingSnapshot(nowUs);
        for (uint8_t slot = 0; slot < 16; ++slot)
            snapshot.psf.canonicalChannels[slot] = 0;
        snapshot.psf.canonicalChannels[8] = 6;
        snapshot.psf.canonicalChannels[10] = 149;
        snapshot.psf.canonicalChannels[11] = 0;
        snapshot.psf.canonicalChannels[13] = 149;
        snapshot.psf.awCounter = counters[i];
        const uint8_t nextSlot = static_cast<uint8_t>(
            ((snapshot.psf.awCounter / 4u) + 1u) % 16u);
        assert(nextSlot == expectedSlots[i]);
        assert(snapshot.psf.canonicalChannels[nextSlot] == expectedChannels[i]);
        auto window = validWindowFor(snapshot, nowUs, true);
        auto head = validQmHead(window);
        OneShot oneShot;
        assert(oneShot.lock(snapshot, head, window) ==
               Decision::kNoChannel6NextSlot);
        assert(!oneShot.attempted());
        MockExactHeadQueue queue(head);
        assert(queue.dequeueCalls == 0 && queue.consumed == 0);
    }
}

static void testMifCurrentSlotAllowsOldPsfHistoryButTakesOneQmOnly()
{
    const uint64_t nowUs = 560619407;
    auto snapshot = validBindingSnapshot(nowUs);
    snapshot.mode = Mode::kMifCurrentSlot;
    snapshot.psfHistorySameEntryPresent = true;
    snapshot.historyCompatible = true;
    snapshot.psfAgeUs = 287000; // Identity history only in this mode.
    snapshot.psf.rxHostUs = nowUs - snapshot.psfAgeUs;
    snapshot.psf.rxChannel = 149;
    snapshot.psf.awCounter = 20324; // Old PSF's next slot 10 is not channel 6.
    for (uint8_t slot = 0; slot < 16; ++slot)
        snapshot.psf.canonicalChannels[slot] = 0;
    snapshot.psf.canonicalChannels[8] = 6;
    snapshot.psf.canonicalChannels[10] = 149;

    snapshot.mif.peerIncarnation = snapshot.peerIncarnation;
    snapshot.mif.mifRevision = snapshot.mifRevision;
    snapshot.mif.rxMonotonicUs = nowUs - 4000;
    snapshot.mif.rxAgeUs = 4000;
    snapshot.mif.epochs = {snapshot.psf.epochs.context,
                           snapshot.psf.epochs.power,
                           snapshot.psf.epochs.station,
                           snapshot.psf.epochs.roc};
    snapshot.mif.rxGp2Us = 0x13572468u;
    snapshot.mif.phyTxTimestampUs = 0x13572500u;
    snapshot.mif.targetTxTimestampUs = 0x13572400u;
    snapshot.mif.awCounter = 20320; // Current MIF slot 8 is channel 6.
    snapshot.mif.txDownCounterTu = 32;
    snapshot.mif.awPeriodTu = 16;
    snapshot.mif.presenceMode = 4;
    snapshot.mif.rxChannel = 6; // Raw index is mapped by this fixture.
    for (uint8_t slot = 0; slot < 16; ++slot)
        snapshot.mif.canonicalSlots[slot] = 44;
    snapshot.mif.canonicalSlots[8] = 6;
    snapshot.mif.present = true;
    snapshot.mif.complete = true;
    snapshot.mif.syncConsistent = true;
    snapshot.mif.fresh = true;
    snapshot.mif.rxGp2Present = true;
    snapshot.mif.presenceModePresent = true;
    snapshot.mif.awCounterSemanticVerified = true;
    snapshot.mif.type18Present = true;
    snapshot.mif.type18Valid = true;
    snapshot.mif.peerMifRxChannel6Confirmed = true;
    memcpy(snapshot.mif.canonicalSlots, snapshot.psf.canonicalChannels,
           sizeof(snapshot.mif.canonicalSlots));
    snapshot.mifAgeUs = 4000;
    snapshot.mifRxMonotonicUs = snapshot.mif.rxMonotonicUs;
    snapshot.mifRxMonotonicUs = snapshot.mif.rxMonotonicUs;
    snapshot.hasMif = true;
    snapshot.mifFresh = true;
    snapshot.mifSyncConsistent = true;

    auto window = validWindowFor(snapshot, nowUs, true);
    window.mode = Mode::kMifCurrentSlot;
    window.phaseCandidateValid = true; // Only a successful MIF timing helper result.
    auto head = validQmHead(window);
    OneShot oneShot;
    assert(oneShot.lock(snapshot, head, window) == Decision::kReady);
    assert(oneShot.authorizeTake(snapshot, head, window) == Decision::kReady);
    MockExactHeadQueue queue(head);
    assert(queue.nextDiscoveryTx(head));
    assert(queue.dequeueCalls == 1 && queue.consumed == 1);
    assert(oneShot.authorizeTake(snapshot, head, window) ==
           Decision::kAlreadyAttempted);
    assert(queue.dequeueCalls == 1 && queue.consumed == 1);

    OneShot wrongMode;
    auto psfWindow = window;
    psfWindow.mode = Mode::kPsfNextSlot;
    assert(wrongMode.lock(snapshot, head, psfWindow) ==
           Decision::kModeMismatch);

    OneShot changedMif;
    assert(changedMif.lock(snapshot, head, window) == Decision::kReady);
    auto changed = snapshot;
    changed.mif.canonicalSlots[8] = 149;
    assert(changedMif.authorizeTake(changed, head, window) ==
           Decision::kMifWitnessMismatch);

    OneShot changedHistory;
    assert(changedHistory.lock(snapshot, head, window) == Decision::kReady);
    auto incompatible = snapshot;
    incompatible.historyCompatible = false;
    assert(!NativeAwdlDiscoveryBinding::sameLockedSnapshot(
        snapshot, incompatible, Mode::kMifCurrentSlot, true));
    assert(changedHistory.authorizeTake(incompatible, head, window) ==
           Decision::kHistoryIncompatible);
    MockExactHeadQueue untouched(head);
    assert(untouched.dequeueCalls == 0 && untouched.consumed == 0);
}

static void testSameAddr2HistoryMustMatchMapMasterAndSync()
{
    const RuntimeEpochs epochs = activeEpochs();
    for (uint8_t mismatchKind = 0; mismatchKind < 3; ++mismatchKind) {
        Table table;
        const NativeAwdl::PsfInput mifAdvertisement = validPsf(5);
        auto mif = makeRecordForPsf(mifAdvertisement, 1000000, 3);
        mif.channel = 6;
        assert(table.observe(mif, epochs, 1000010) == Result::kAdmitted);

        NativeAwdl::PsfInput psfAdvertisement = mifAdvertisement;
        if (mismatchKind == 0) {
            // Preserve a valid social schedule while changing one canonical
            // type-18 slot; the PSF and MIF still share the same Addr2.
            psfAdvertisement.channelSlots[0] = 44;
        } else if (mismatchKind == 1) {
            setAddress(psfAdvertisement.masterAddress, 31);
        } else {
            setAddress(psfAdvertisement.syncAddress, 25);
        }
        auto psf = makeRecordForPsf(psfAdvertisement, 1000100, 0);
        psf.channel = 6;
        assert(table.observe(psf, epochs, 1000110) == Result::kCandidate);

        const auto summary = table.snapshot(epochs, 1000200);
        IntelAwdlPeerRuntime::PsfPeerSnapshot raw{};
        assert(table.getPsfSnapshot(summary.latestFreshPsfSlot, epochs,
                                    1000200, &raw));
        assert(raw.hasPsf && raw.hasMif && raw.peerIncarnation != 0);
        assert(!raw.historyCompatible);
        assert(!summary.peers[summary.latestFreshPsfSlot].historyCompatible);

        auto snapshot = bindingFromRuntimePsf(raw, 1000200);
        snapshot.mode = Mode::kMifCurrentSlot;
        auto window = validWindowFor(snapshot, 1000200, true);
        auto head = validQmHead(window);
        OneShot oneShot;
        assert(oneShot.lock(snapshot, head, window) ==
               Decision::kHistoryIncompatible);
        MockExactHeadQueue untouched(head);
        assert(untouched.dequeueCalls == 0 && untouched.consumed == 0);
    }
}

static void testMifCurrentSlotRejectsAbsentOrLateMifCandidate()
{
    const uint64_t nowUs = 560619407;
    Table table;
    const auto epochs = activeEpochs();
    // Actual-source-derived no-early-MIF shape: PSF history exists, but no
    // same-entry accepted MIF can drive the MIF-current phase helper.
    assert(table.observe(makeRecordAtChannel(5, nowUs - 300000, 0), epochs,
                         nowUs - 299990) == Result::kCandidate);
    const auto summary = table.snapshot(epochs, nowUs - 299900);
    IntelAwdlPeerRuntime::PsfPeerSnapshot raw{};
    assert(table.getPsfSnapshot(summary.latestFreshPsfSlot, epochs,
                                nowUs - 299900, &raw));
    auto missing = bindingFromRuntimePsf(raw, nowUs - 299900);
    missing.mode = Mode::kMifCurrentSlot;
    auto missingWindow = validWindowFor(missing, nowUs - 299900, true);
    missingWindow.mode = Mode::kMifCurrentSlot;
    auto missingHead = validQmHead(missingWindow);
    OneShot noMif;
    assert(noMif.lock(missing, missingHead, missingWindow) ==
           Decision::kMissingMifBinding);
    MockExactHeadQueue untouched(missingHead);
    assert(untouched.dequeueCalls == 0 && untouched.consumed == 0);

    // Captured Test065-derived timing interval was already expired at the
    // consumer's actual time. Even a complete fresh MIF cannot reopen it.
    auto late = validBindingSnapshot(nowUs);
    late.mode = Mode::kMifCurrentSlot;
    late.psfHistorySameEntryPresent = true;
    late.psfAgeUs = 287000;
    late.psf.rxHostUs = nowUs - late.psfAgeUs;
    auto lateWindow = validWindowFor(late, nowUs, true);
    lateWindow.mode = Mode::kMifCurrentSlot;
    lateWindow.phaseEarliestUs = 560570845;
    lateWindow.phaseLatestUs = 560576088;
    lateWindow.phaseCandidateValid = false; // timing helper says expired
    auto lateHead = validQmHead(lateWindow);
    OneShot expired;
    assert(expired.lock(late, lateHead, lateWindow) ==
           Decision::kInvalidPhaseCandidate);
    MockExactHeadQueue lateUntouched(lateHead);
    assert(lateUntouched.dequeueCalls == 0 && lateUntouched.consumed == 0);
}

int main()
{
    testPsfAndMifPairsPlusFullSchedule();
    testPsfDoesNotRefreshMifLeaseAndHistoryIsMarkedStale();
    testPsfOnlySnapshotAndIndependentLeaseBoundary();
    testPsfAndMifSnapshotsAndLeasesStayIndependent();
    testRejectedPsfPreservesAdvertisementAndMifDiagnostics();
    testPsfSequenceCopyMismatchIsAcceptedAndObservable();
    testMifWithoutEmbeddedCopyCarriesUnverifiedPeerShape();
    testMifOnlySnapshotCarriesExactPresenceBinding();
    testRejectsBadEpochTimeParserAndOrdering();
    testRejectedMifPreservesPeerAndValidMifReplacesAtomically();
    testCapacityExpiryEpochAndClockRegression();
    testMifLeaseBoundaryAndLatestMifSlot();
    testRuntimeSnapshotBindsSameSourceMifAndPsf();
    testObserverAggregateCannotAuthorizeForeignRuntimePsf();
    testIncarnationNeverReusedAcrossTableReset();
    testRuntimeSnapshotRejectsCrossSourceMifAndPsf();
    testSlotReuseInvalidatesLockedPeerIncarnation();
    testSnapshotRevisionsFreshnessEpochChannelLeaseAndClose();
    testPeerIdentityAndRevisionOverflowFailClosed();
    testOneShotStrictQmTakeHasNoFallback();
    testReplayCanonicalSlotsWithoutChannel6RemainClosed();
    testMifCurrentSlotAllowsOldPsfHistoryButTakesOneQmOnly();
    testSameAddr2HistoryMustMatchMapMasterAndSync();
    testMifCurrentSlotRejectsAbsentOrLateMifCandidate();
    return 0;
}
