// SPDX-License-Identifier: GPL-2.0-only
#include "ItlIwx.hpp"

#ifdef AIRPORT_TAHOE
#include <kern/clock.h>

namespace {
uint64_t peerStateMonotonicUs()
{
    uint64_t absolute = 0, nanoseconds = 0;
    clock_get_uptime(&absolute);
    absolutetime_to_nanoseconds(absolute, &nanoseconds);
    return nanoseconds / 1000;
}

uint64_t packSlots(const uint8_t *slots)
{
    uint64_t packed = 0;
    for (unsigned i = 0; i < 8; ++i)
        packed |= uint64_t(slots[i]) << (8 * i);
    return packed;
}
} // namespace

void ItlIwx::tahoeP2pPublishPeerRuntime()
{
    auto *loop = getMainWorkLoop();
    auto *controller = getController();
    if (!loop || !loop->inGate() || !controller)
        return;
    const IntelAwdlPeer::RuntimeEpochs epochs {
        nativeP2pProbeGeneration_, uint64_t(uint32_t(com.sc_generation)),
        __atomic_load_n(&com.sc_tx_rate_generation, __ATOMIC_ACQUIRE),
        nativeP2pProbeGeneration_ != 0 && com.sc_ic.ic_state == IEEE80211_S_RUN &&
            (com.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR)) == 0
    };
    const uint64_t nowUs = peerStateMonotonicUs();
    const auto state = tahoe_awdl_peer_runtime_.snapshot(epochs, nowUs);
    // Prefer the freshest MIF. After its five-second lease, retain its
    // numeric history explicitly marked not fresh. With no MIF, expose the
    // newest candidate's raw tuples. Never elect or grant radio permission.
    uint8_t slot = state.latestFreshMifSlot;
    if (slot >= IntelAwdlPeerRuntime::kPeerCapacity) {
        for (uint8_t i = 0; i < IntelAwdlPeerRuntime::kPeerCapacity; ++i) {
            const auto &candidate = state.peers[i];
            if (!candidate.tracked)
                continue;
            if (slot >= IntelAwdlPeerRuntime::kPeerCapacity ||
                (candidate.hasMif && !state.peers[slot].hasMif) ||
                (candidate.hasMif == state.peers[slot].hasMif &&
                 (candidate.hasMif ? candidate.mifAgeUs < state.peers[slot].mifAgeUs :
                    candidate.frameAgeUs < state.peers[slot].frameAgeUs)))
                slot = i;
        }
    }
    static const IntelAwdlPeerRuntime::PeerSnapshot empty{};
    const auto &peer = slot < IntelAwdlPeerRuntime::kPeerCapacity ?
        state.peers[slot] : empty;
    // PSF advertisement is a separate view with its own slot and lease.
    // A historical MIF must not hide a current PSF from another peer.
    IntelAwdlPeerRuntime::PsfPeerSnapshot psf{};
    uint8_t psfSlot = state.latestFreshPsfSlot;
    if (psfSlot < IntelAwdlPeerRuntime::kPeerCapacity) {
        if (!tahoe_awdl_peer_runtime_.getPsfSnapshot(psfSlot, epochs, nowUs, &psf) ||
            !psf.hasPsf)
            psfSlot = 0xff;
    }
    if (psfSlot >= IntelAwdlPeerRuntime::kPeerCapacity) {
        for (uint8_t i = 0; i < IntelAwdlPeerRuntime::kPeerCapacity; ++i) {
            IntelAwdlPeerRuntime::PsfPeerSnapshot candidate{};
            if (tahoe_awdl_peer_runtime_.getPsfSnapshot(i, epochs, nowUs, &candidate) &&
                candidate.hasPsf && (psfSlot >= IntelAwdlPeerRuntime::kPeerCapacity ||
                 candidate.psfAgeUs < psf.psfAgeUs)) {
                psf = candidate;
                psfSlot = i;
            }
        }
    }
    const auto &psfDiag = state.lastPsfRejectDiagnostics;
    const auto &diag = state.lastMifRejectDiagnostics;
    const auto &a = peer.timingSamples[0];
    const auto &b = peer.timingSamples[1];
    const auto &c = peer.timingSamples[2];
    // Addresses, names, packet bytes and election identities remain private.
    // All fields below are scalar metadata from one representative table slot.
    // Publish scalars directly: keeping a second 145-entry metrics array
    // beside the bounded snapshot consumed over 6 KiB of kernel stack.
    constexpr size_t count = 161;
    constexpr size_t capacity = sizeof(tahoe_awdl_runtime_published_) /
                                sizeof(tahoe_awdl_runtime_published_[0]);
    static_assert(count <= capacity, "peer publication cache too small");
    size_t metricIndex = 0;
    const auto publish = [&](const char *name, uint64_t value) {
        if (metricIndex >= capacity)
            return;
        if (!tahoe_awdl_runtime_published_once_ ||
            tahoe_awdl_runtime_published_[metricIndex] != value) {
            controller->setProperty(name, value, 64);
            tahoe_awdl_runtime_published_[metricIndex] = value;
        }
        ++metricIndex;
    };
    publish("NativeP2PPeerStateTrackedCount", state.trackedPeerCount);
    publish("NativeP2PPeerStateFreshMifCount", state.freshMifPeerCount);
    publish("NativeP2PPeerStateAdmittedTotal", state.admittedTotal);
    publish("NativeP2PPeerStateUpdatedTotal", state.updatedTotal);
    publish("NativeP2PPeerStatePsfTotal", state.candidateFrameTotal);
    publish("NativeP2PPeerStateMifTotal", state.mifFrameTotal);
    publish("NativeP2PPeerStateRejectedTotal", state.rejectedTotal);
    publish("NativeP2PPeerStateRejectedMifTotal", state.rejectedMifTotal);
    publish("NativeP2PPeerStateLastRejectedResult", state.lastRejectedResult);
    publish("NativeP2PPeerStateLastMifDecodeStatus", state.lastMifDecodeStatus);
    publish("NativeP2PPeerStateLastRejectedContext", state.lastRejectedContext);
    publish("NativeP2PPeerStateLastResult", tahoe_awdl_runtime_last_result_);
    publish("NativeP2PPeerStateLastAdmittedContext", state.lastAdmittedContextGeneration);
    publish("NativeP2PPeerStateSlot", slot);
    publish("NativeP2PPeerStateContext", peer.contextGeneration);
    publish("NativeP2PPeerStatePowerGeneration", peer.powerGeneration);
    publish("NativeP2PPeerStateStationGeneration", peer.stationGeneration);
    publish("NativeP2PPeerStateHasMif", peer.hasMif);
    publish("NativeP2PPeerStateMifFresh", peer.mifFresh);
    publish("NativeP2PPeerStateMifAgeUs", peer.mifAgeUs);
    publish("NativeP2PPeerStateSyncConsistent", peer.syncConsistent);
    publish("NativeP2PPeerStateMifRxHostUs", peer.mifRxMonotonicUs);
    publish("NativeP2PPeerStateMifRxGp2Us", peer.mifRxGp2TimestampUs);
    publish("NativeP2PPeerStateMifRxGp2Present", peer.mifRxGp2TimestampPresent);
    publish("NativeP2PPeerStateMifPhyTxUs", peer.phyTxTimestampUs);
    publish("NativeP2PPeerStateMifTargetTxUs", peer.targetTxTimestampUs);
    publish("NativeP2PPeerStateMasterMetric", peer.masterMetric);
    publish("NativeP2PPeerStateMasterCounter", peer.masterCounter);
    publish("NativeP2PPeerStateOwnMetric", peer.ownMetric);
    publish("NativeP2PPeerStateOwnCounter", peer.ownCounter);
    publish("NativeP2PPeerStateHeight", peer.height);
    publish("NativeP2PPeerStateTxDownCounterTu", peer.txDownCounterTu);
    publish("NativeP2PPeerStateAwPeriodTu", peer.awPeriodTu);
    publish("NativeP2PPeerStateActionPeriodTu", peer.actionFramePeriodTu);
    publish("NativeP2PPeerStateNextAwSequence", peer.nextAwSequence);
    publish("NativeP2PPeerStateNextAwChannel", peer.nextAwChannel);
    publish("NativeP2PPeerStateChannelsLo", packSlots(peer.channelSlots));
    publish("NativeP2PPeerStateChannelsHi", packSlots(peer.channelSlots + 8));
    publish("NativeP2PPeerStateVersion", peer.version);
    publish("NativeP2PPeerStateDeviceClass", peer.deviceClass);
    publish("NativeP2PPeerStateElectionV2", peer.electionV2);
    publish("NativeP2PPeerStateSyncLength", peer.syncParameterLength);
    publish("NativeP2PPeerStateSyncTailLength", peer.syncTailLength);
    publish("NativeP2PPeerStateEmbeddedPresent", peer.embeddedSequencePresent);
    publish("NativeP2PPeerStateEmbeddedRecognized", peer.embeddedSequenceRecognized);
    publish("NativeP2PPeerStateEmbeddedVerified", peer.embeddedSequenceVerified);
    publish("NativeP2PPeerStateEmbeddedMismatch", uint64_t(peer.embeddedSequenceMismatch));
    publish("NativeP2PPeerStateEmbeddedMismatchIndex", uint64_t(peer.embeddedMismatchIndex));
    publish("NativeP2PPeerStateEmbeddedMismatchChannel", uint64_t(peer.embeddedMismatchChannel));
    publish("NativeP2PPeerStateCanonicalMismatchChannel", uint64_t(peer.canonicalMismatchChannel));
    publish("NativeP2PPeerStateTimingCount", peer.timingSampleCount);
    publish("NativeP2PPeerStateSample0RxHostUs", a.rxMonotonicUs);
    publish("NativeP2PPeerStateSample0RxGp2Us", a.rxGp2TimestampUs);
    publish("NativeP2PPeerStateSample0PhyTxUs", a.peerPhyTxTimestampUs);
    publish("NativeP2PPeerStateSample0Present", a.rxGp2TimestampPresent);
    publish("NativeP2PPeerStateSample1RxHostUs", b.rxMonotonicUs);
    publish("NativeP2PPeerStateSample1RxGp2Us", b.rxGp2TimestampUs);
    publish("NativeP2PPeerStateSample1PhyTxUs", b.peerPhyTxTimestampUs);
    publish("NativeP2PPeerStateSample1Present", b.rxGp2TimestampPresent);
    publish("NativeP2PPeerStateSample2RxHostUs", c.rxMonotonicUs);
    publish("NativeP2PPeerStateSample2RxGp2Us", c.rxGp2TimestampUs);
    publish("NativeP2PPeerStateSample2PhyTxUs", c.peerPhyTxTimestampUs);
    publish("NativeP2PPeerStateSample2Present", c.rxGp2TimestampPresent);
    publish("NativeP2PPeerStateMifDecodeRejectStage", uint64_t(diag.rejectStage));
    publish("NativeP2PPeerStateMifDecodeTlvType", uint64_t(diag.offendingTlvType));
    publish("NativeP2PPeerStateMifDecodeRelatedTlvType", uint64_t(diag.relatedTlvType));
    publish("NativeP2PPeerStateMifDecodeTlvOffset", uint64_t(diag.tlvOffset));
    publish("NativeP2PPeerStateMifDecodeDeclaredLength", uint64_t(diag.declaredLength));
    publish("NativeP2PPeerStateMifDecodeAvailableLength", uint64_t(diag.availableLength));
    publish("NativeP2PPeerStateMifDecodeRelatedTlvOffset", uint64_t(diag.relatedTlvOffset));
    publish("NativeP2PPeerStateMifDecodeRelatedDeclaredLength", uint64_t(diag.relatedDeclaredLength));
    publish("NativeP2PPeerStateMifDecodeNextAwChannel", uint64_t(diag.nextAwChannel));
    publish("NativeP2PPeerStateMifDecodeMasterChannel", uint64_t(diag.masterChannel));
    publish("NativeP2PPeerStateMifDecodeTxDownCounterTu", uint64_t(diag.txDownCounterTu));
    publish("NativeP2PPeerStateMifDecodeAwPeriodTu", uint64_t(diag.awPeriodTu));
    publish("NativeP2PPeerStateMifDecodeActionPeriodTu", uint64_t(diag.actionFramePeriodTu));
    publish("NativeP2PPeerStateMifDecodePresenceMode", uint64_t(diag.presenceMode));
    publish("NativeP2PPeerStateMifDecodeNextAwSequence", uint64_t(diag.nextAwSequence));
    publish("NativeP2PPeerStateMifDecodeApAlignment", uint64_t(diag.apAlignment));
    publish("NativeP2PPeerStateMifDecodeSyncLength", uint64_t(diag.syncParameterLength));
    publish("NativeP2PPeerStateMifDecodeSyncTailLength", uint64_t(diag.syncTailLength));
    publish("NativeP2PPeerStateMifDecodeEmbeddedPresent", uint64_t(diag.embeddedSequencePresent));
    publish("NativeP2PPeerStateMifDecodeEmbeddedRecognized", uint64_t(diag.embeddedSequenceRecognized));
    publish("NativeP2PPeerStateMifDecodeEmbeddedVerified", uint64_t(diag.embeddedSequenceVerified));
    publish("NativeP2PPeerStateMifDecodeEmbeddedMismatch", uint64_t(diag.embeddedSequenceMismatch));
    publish("NativeP2PPeerStateMifDecodeEmbeddedMismatchIndex", uint64_t(diag.embeddedMismatchIndex));
    publish("NativeP2PPeerStateMifDecodeEmbeddedMismatchChannel", uint64_t(diag.embeddedMismatchChannel));
    publish("NativeP2PPeerStateMifDecodeCanonicalMismatchChannel", uint64_t(diag.canonicalMismatchChannel));
    publish("NativeP2PPeerStateFreshPsfCount", state.freshPsfPeerCount);
    publish("NativeP2PPeerStateAcceptedPsfTotal", state.acceptedPsfTotal);
    publish("NativeP2PPeerStateRejectedPsfTotal", state.rejectedPsfTotal);
    publish("NativeP2PPeerStateLastPsfDecodeStatus", state.lastPsfDecodeStatus);
    publish("NativeP2PPeerStatePsfSlot", psfSlot);
    publish("NativeP2PPeerStatePsfHas", psf.hasPsf);
    publish("NativeP2PPeerStatePsfFresh", psf.psfFresh);
    publish("NativeP2PPeerStatePsfAgeUs", psf.psfAgeUs);
    publish("NativeP2PPeerStatePsfContext", psf.contextGeneration);
    publish("NativeP2PPeerStatePsfPowerGeneration", psf.powerGeneration);
    publish("NativeP2PPeerStatePsfStationGeneration", psf.stationGeneration);
    publish("NativeP2PPeerStatePsfSyncConsistent", psf.syncConsistent);
    publish("NativeP2PPeerStatePsfRxHostUs", psf.psfRxMonotonicUs);
    publish("NativeP2PPeerStatePsfRxGp2Us", psf.psfRxGp2TimestampUs);
    publish("NativeP2PPeerStatePsfRxGp2Present", psf.psfRxGp2TimestampPresent);
    publish("NativeP2PPeerStatePsfPhyTxUs", psf.phyTxTimestampUs);
    publish("NativeP2PPeerStatePsfTargetTxUs", psf.targetTxTimestampUs);
    publish("NativeP2PPeerStatePsfRxChannel", psf.rxChannel);
    publish("NativeP2PPeerStatePsfMasterMetric", psf.masterMetric);
    publish("NativeP2PPeerStatePsfMasterCounter", psf.masterCounter);
    publish("NativeP2PPeerStatePsfOwnMetric", psf.ownMetric);
    publish("NativeP2PPeerStatePsfOwnCounter", psf.ownCounter);
    publish("NativeP2PPeerStatePsfHeight", psf.height);
    publish("NativeP2PPeerStatePsfTxDownCounterTu", psf.txDownCounterTu);
    publish("NativeP2PPeerStatePsfAwPeriodTu", psf.awPeriodTu);
    publish("NativeP2PPeerStatePsfActionPeriodTu", psf.actionFramePeriodTu);
    publish("NativeP2PPeerStatePsfNextAwSequence", psf.nextAwSequence);
    publish("NativeP2PPeerStatePsfNextAwChannel", psf.nextAwChannel);
    publish("NativeP2PPeerStatePsfVersion", psf.version);
    publish("NativeP2PPeerStatePsfDeviceClass", psf.deviceClass);
    publish("NativeP2PPeerStatePsfElectionV2", psf.electionV2);
    publish("NativeP2PPeerStatePsfSyncLength", psf.syncParameterLength);
    publish("NativeP2PPeerStatePsfSyncTailLength", psf.syncTailLength);
    publish("NativeP2PPeerStatePsfEmbeddedPresent", psf.embeddedSequencePresent);
    publish("NativeP2PPeerStatePsfEmbeddedRecognized", psf.embeddedSequenceRecognized);
    publish("NativeP2PPeerStatePsfEmbeddedVerified", psf.embeddedSequenceVerified);
    publish("NativeP2PPeerStatePsfEmbeddedMismatch", uint64_t(psf.embeddedSequenceMismatch));
    publish("NativeP2PPeerStatePsfEmbeddedMismatchIndex", uint64_t(psf.embeddedMismatchIndex));
    publish("NativeP2PPeerStatePsfEmbeddedMismatchChannel", uint64_t(psf.embeddedMismatchChannel));
    publish("NativeP2PPeerStatePsfCanonicalMismatchChannel", uint64_t(psf.canonicalMismatchChannel));
    publish("NativeP2PPeerStatePsfChannelsLo", packSlots(psf.channelSlots));
    publish("NativeP2PPeerStatePsfChannelsHi", packSlots(psf.channelSlots + 8));
    publish("NativeP2PPeerStateSample0Subtype", a.subtype);
    publish("NativeP2PPeerStateSample1Subtype", b.subtype);
    publish("NativeP2PPeerStateSample2Subtype", c.subtype);
    publish("NativeP2PPeerStatePsfDecodeRejectStage", uint64_t(psfDiag.rejectStage));
    publish("NativeP2PPeerStatePsfDecodeTlvType", uint64_t(psfDiag.offendingTlvType));
    publish("NativeP2PPeerStatePsfDecodeRelatedTlvType", uint64_t(psfDiag.relatedTlvType));
    publish("NativeP2PPeerStatePsfDecodeTlvOffset", uint64_t(psfDiag.tlvOffset));
    publish("NativeP2PPeerStatePsfDecodeDeclaredLength", uint64_t(psfDiag.declaredLength));
    publish("NativeP2PPeerStatePsfDecodeAvailableLength", uint64_t(psfDiag.availableLength));
    publish("NativeP2PPeerStatePsfDecodeRelatedTlvOffset", uint64_t(psfDiag.relatedTlvOffset));
    publish("NativeP2PPeerStatePsfDecodeRelatedDeclaredLength", uint64_t(psfDiag.relatedDeclaredLength));
    publish("NativeP2PPeerStatePsfDecodeNextAwChannel", uint64_t(psfDiag.nextAwChannel));
    publish("NativeP2PPeerStatePsfDecodeMasterChannel", uint64_t(psfDiag.masterChannel));
    publish("NativeP2PPeerStatePsfDecodeTxDownCounterTu", uint64_t(psfDiag.txDownCounterTu));
    publish("NativeP2PPeerStatePsfDecodeAwPeriodTu", uint64_t(psfDiag.awPeriodTu));
    publish("NativeP2PPeerStatePsfDecodeActionPeriodTu", uint64_t(psfDiag.actionFramePeriodTu));
    publish("NativeP2PPeerStatePsfDecodePresenceMode", uint64_t(psfDiag.presenceMode));
    publish("NativeP2PPeerStatePsfDecodeNextAwSequence", uint64_t(psfDiag.nextAwSequence));
    publish("NativeP2PPeerStatePsfDecodeApAlignment", uint64_t(psfDiag.apAlignment));
    publish("NativeP2PPeerStatePsfDecodeSyncLength", uint64_t(psfDiag.syncParameterLength));
    publish("NativeP2PPeerStatePsfDecodeSyncTailLength", uint64_t(psfDiag.syncTailLength));
    publish("NativeP2PPeerStatePsfDecodeEmbeddedPresent", uint64_t(psfDiag.embeddedSequencePresent));
    publish("NativeP2PPeerStatePsfDecodeEmbeddedRecognized", uint64_t(psfDiag.embeddedSequenceRecognized));
    publish("NativeP2PPeerStatePsfDecodeEmbeddedVerified", uint64_t(psfDiag.embeddedSequenceVerified));
    publish("NativeP2PPeerStatePsfDecodeEmbeddedMismatch", uint64_t(psfDiag.embeddedSequenceMismatch));
    publish("NativeP2PPeerStatePsfDecodeEmbeddedMismatchIndex", uint64_t(psfDiag.embeddedMismatchIndex));
    publish("NativeP2PPeerStatePsfDecodeEmbeddedMismatchChannel", uint64_t(psfDiag.embeddedMismatchChannel));
    publish("NativeP2PPeerStatePsfDecodeCanonicalMismatchChannel", uint64_t(psfDiag.canonicalMismatchChannel));
    publish("NativeP2PPeerStateMappingProven", 0);
    publish("NativeP2PPeerStateScheduleEnabled", 0);
    publish("NativeP2PPeerStateElectionApplied", 0);
    tahoe_awdl_runtime_published_once_ = true;
}
#endif
