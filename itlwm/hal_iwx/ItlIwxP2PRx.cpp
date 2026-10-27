// SPDX-License-Identifier: GPL-2.0-only
#include "ItlIwx.hpp"

#ifdef AIRPORT_TAHOE
#include <kern/clock.h>
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
#include "../../native/awdl_native_bsd_data_25G332.hpp"
#endif
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332)
#include "../../native/awdl_native_lifecycle_25G332.hpp"
#endif
#if defined(ITL_NATIVE_AWDL_INIT_OBSERVATION_25G332)
#include "../../native/awdl_native_init_probe_25G332.hpp"
#endif
#if defined(ITL_NATIVE_AWDL_INIT_OBSERVATION_25G332) || defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332)
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSBoolean.h>
#endif

namespace {
uint64_t tahoeP2pRxMonotonicUs()
{
    uint64_t absolute = 0, nanoseconds = 0;
    clock_get_uptime(&absolute);
    absolutetime_to_nanoseconds(absolute, &nanoseconds);
    return nanoseconds / 1000;
}

bool samePeerSnapshot(const IntelAwdlPeer::Snapshot &a,
                      const IntelAwdlPeer::Snapshot &b)
{
    return a.validPeerCount == b.validPeerCount &&
        a.hasLatestPeer == b.hasLatestPeer &&
        a.syncFieldsValid == b.syncFieldsValid &&
        a.rxChannelIndex == b.rxChannelIndex &&
        a.nextAwChannel == b.nextAwChannel && a.masterChannel == b.masterChannel &&
        a.nextSlotTu == b.nextSlotTu && a.awPeriodTu == b.awPeriodTu &&
        a.actionFramePeriodTu == b.actionFramePeriodTu &&
        a.presenceMode == b.presenceMode && a.nextAwSequence == b.nextAwSequence &&
        a.latestPeerAgeUs / 1000000 == b.latestPeerAgeUs / 1000000 &&
        a.candidateFramesTotal == b.candidateFramesTotal &&
        a.psfFramesTotal == b.psfFramesTotal &&
        a.mifFramesTotal == b.mifFramesTotal &&
        a.admittedFramesTotal == b.admittedFramesTotal &&
        a.updatedFramesTotal == b.updatedFramesTotal &&
        a.lastAdmittedContextGeneration == b.lastAdmittedContextGeneration &&
        a.activeWindowPeakValidPeerCount == b.activeWindowPeakValidPeerCount &&
        a.activeWindowPeakContextGeneration == b.activeWindowPeakContextGeneration;
}

constexpr const char *kResetReasonProperties[] = {
    "NativeResetTraceReasonCountUnknown",
    "NativeResetTraceReasonCountAdapterDisableQuiesce",
    "NativeResetTraceReasonCountIfFlagsDown",
    "NativeResetTraceReasonCountMediaChange",
    "NativeResetTraceReasonCountIoctlEnetReset",
    "NativeResetTraceReasonCountInitTaskRunningRecovery",
    "NativeResetTraceReasonCountInitHardwareFailureCleanup",
    "NativeResetTraceReasonCountInitialScanFailureCleanup",
    "NativeResetTraceReasonCountInitialScanWaitInterrupted",
    "NativeResetTraceReasonCountInitTaskNotRunningRecovery"
};

constexpr const char *kInitTriggerProperties[] = {
    "NativeResetTraceTriggerCountUnknown",
    "NativeResetTraceTriggerCountNewStateError",
    "NativeResetTraceTriggerCountTxWatchdogTimeout",
    "NativeResetTraceTriggerCountCriticalTemperature",
    "NativeResetTraceTriggerCountLegacyRfKill",
    "NativeResetTraceTriggerCountLegacyFirmwareSwError",
    "NativeResetTraceTriggerCountLegacyHardwareError",
    "NativeResetTraceTriggerCountMsixFirmwareSwError",
    "NativeResetTraceTriggerCountMsixRfKill",
    "NativeResetTraceTriggerCountMsixHardwareError",
    "NativeResetTraceTriggerCountWakeupDeferred",
    "NativeResetTraceTriggerCountLifecycleFenceRetry"
};
} // namespace

void ItlIwx::tahoeP2pTapTimeEvent(struct iwx_softc *sc,
                                const uint8_t *bytes, size_t length)
{
    // RX dispatch and probe publication share this workloop gate. No commands,
    // allocations, native interface calls or ownership changes on this path.
    if (!sc || !getMainWorkLoop() || !getMainWorkLoop()->inGate())
        return;
    auto lease = tahoe_p2p_rx_lease_;
    lease.currentPowerGeneration = uint64_t(uint32_t(sc->sc_generation));
    lease.currentStationGeneration = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    tahoe_p2p_rx_router_.captureTimeEvent(bytes, length, lease);
}

void ItlIwx::tahoeP2pTapAction(struct iwx_softc *sc, const uint8_t *frame,
                             size_t length, bool wasProtected, uint16_t channel,
                             uint32_t gp2TimestampUs, bool gp2TimestampPresent)
{
    if (!sc || !getMainWorkLoop() || !getMainWorkLoop()->inGate())
        return;
    auto lease = tahoe_p2p_rx_lease_;
    if (!lease.active)
        return;
    lease.currentPowerGeneration = uint64_t(uint32_t(sc->sc_generation));
    lease.currentStationGeneration = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    // The RX descriptor's mac_phy_idx has not yet been proven to carry the
    // complete MAC ID/color. Preserve unknown affinity, never infer it from
    // an AWDL vendor body or from the infrastructure BSSID.
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    const auto session=nativeP2pRocEvents_.snapshot();
    const bool current=lease.contextGeneration==lease.currentContextGeneration&&
        lease.powerGeneration==lease.currentPowerGeneration&&
        lease.stationGeneration==lease.currentStationGeneration&&
        session.commandReturned&&session.commandResult==0&&session.startStatus==1&&
        session.startSeen&&!session.endSeen&&!session.outcomeUnknown&&
        channel<nitems(sc->sc_ic.ic_channels)&&
        ieee80211_chan2ieee(&sc->sc_ic,&sc->sc_ic.ic_channels[channel])==6;
    const auto dataCapture=NativeAwdlBSD::capture(
        frame,length,wasProtected,current,uint32_t(sc->sc_generation));
    if(dataCapture==NativeAwdlBSD::CaptureResult::Rejected||
       dataCapture==NativeAwdlBSD::CaptureResult::QueueFull)
        tahoe_awdl_rx_stage_counters_.recordData(
            uint32_t(lease.contextGeneration),
            TahoeAwdlRxStageCounters::kDataTapRejected);
#endif
    tahoe_p2p_rx_router_.tapActionFrame(frame, length, wasProtected,
                                      channel, false, 0, lease,
                                      tahoeP2pRxMonotonicUs(),
                                      gp2TimestampUs, gp2TimestampPresent);
}

IOReturn ItlIwx::tahoeP2pRxDrainAction(OSObject *, void *context,
                                      void *, void *, void *)
{
    auto *owner = static_cast<ItlIwx *>(context);
    if (!owner || !owner->getMainWorkLoop() ||
        !owner->getMainWorkLoop()->inGate())
        return kIOReturnNotReady;
    owner->tahoeP2pRxDrain();
    return kIOReturnSuccess;
}

void ItlIwx::tahoeP2pRxDrain()
{
    // Only the watchdog consumes this SPSC queue. Records remain private and
    // no peer address, host name, payload or UID is published to IORegistry.
    auto *workLoop = getMainWorkLoop();
    if (!workLoop)
        return;
    if (!workLoop->inGate()) {
        // The watchdog has a different workloop. Never block its gate while
        // acquiring the main gate: retry on the next tick if it is busy.
        auto *gate = tahoeP2pCommandGate();
        if (gate)
            (void)gate->attemptAction(tahoeP2pRxDrainAction, this);
        return;
    }
    const auto &rxLease = tahoe_p2p_rx_lease_;
    if (rxLease.active && rxLease.contextGeneration != 0 &&
        rxLease.contextGeneration == rxLease.currentContextGeneration &&
        rxLease.powerGeneration == rxLease.currentPowerGeneration &&
        rxLease.stationGeneration == rxLease.currentStationGeneration) {
        tahoe_awdl_rx_stage_counters_.beginOwner(rxLease.contextGeneration);
    } else {
        const auto rxStages = tahoe_awdl_rx_stage_counters_.snapshot();
        tahoe_awdl_rx_stage_counters_.endOwner(rxStages.ownerGeneration);
    }
    const uint64_t nowUs = tahoeP2pRxMonotonicUs();
    const IntelAwdlPeer::RuntimeEpochs epochs {
        nativeP2pProbeGeneration_, uint64_t(uint32_t(com.sc_generation)),
        __atomic_load_n(&com.sc_tx_rate_generation, __ATOMIC_ACQUIRE),
        nativeP2pProbeGeneration_ != 0 && com.sc_ic.ic_state == IEEE80211_S_RUN &&
            (com.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR)) == 0
    };
    // A matching, completed lease may already be inactive before the watchdog
    // drains it. Preserve bounded observation evidence for the current epochs;
    // inactive radio/changed epochs still clear the observer. This never grants
    // a new radio lease or turns peer evidence into a transmission permission.
    IntelP2PRx::Record record{};
    for (unsigned i = 0; i < IntelP2PRx::kQueueDepth; ++i) {
        if (!tahoe_p2p_rx_router_.popRecord(&record))
            break;
        if (record.kind == IntelP2PRx::RecordKind::kActionFrame) {
            tahoe_awdl_runtime_last_result_ = static_cast<uint32_t>(
                tahoe_awdl_peer_runtime_.observe(
                    record.payload.actionFrame, epochs, nowUs));
            const auto result = tahoe_awdl_peer_observer_.observe(
                record.payload.actionFrame, epochs, nowUs);
            if (result == IntelAwdlPeer::ObserveResult::kAdmittedPeer ||
                result == IntelAwdlPeer::ObserveResult::kUpdatedPeer ||
                result == IntelAwdlPeer::ObserveResult::kCandidateOnly)
                ++tahoe_awdl_peer_accepted_frames_;
            else
                ++tahoe_awdl_peer_rejected_records_;
            tahoe_awdl_peer_last_result_ = static_cast<uint32_t>(result);
            tahoe_awdl_peer_dirty_ = true;
        }
    }
    bzero(&record, sizeof(record));
    tahoeP2pPublishPeerRuntime();
    const auto peer = tahoe_awdl_peer_observer_.snapshot(epochs, nowUs);
    auto controller = getController();
    if (!controller)
        return;
    tahoeP2pPublishRxStageCounters(controller);
    tahoePublishResetTrace(controller);
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    const auto data=NativeAwdlBSD::snapshot();
    controller->setProperty("NativeAwdlResidentCompiled",kOSBooleanTrue);
    const char *names[]={"NativeAwdlDataAttached","NativeAwdlDataClosing","NativeAwdlDataDetached","NativeAwdlDataLinkReady",
        "NativeAwdlDataTxAccepted","NativeAwdlDataTxRejected","NativeAwdlDataTxExpired","NativeAwdlDataTxEncoded",
        "NativeAwdlDataTxSubmitted","NativeAwdlDataTxCompleted","NativeAwdlDataTxSucceeded","NativeAwdlDataTxFailed",
        "NativeAwdlDataTxStaleCompletion","NativeAwdlDataRxCaptured","NativeAwdlDataRxRejected","NativeAwdlDataRxQueueFull",
        "NativeAwdlDataRxDecoded","NativeAwdlDataRxDelivered","NativeAwdlDataRxInputFailed","NativeAwdlDataTxPending","NativeAwdlDataRxPending",
        "NativeAwdlDataGateChecks","NativeAwdlDataGateAllowed","NativeAwdlDataGateLastBlockers","NativeAwdlDataGateReasonsSeen",
        "NativeAwdlDataIpv6ConfigResult","NativeAwdlDataIpv6Configured","NativeAwdlDataOffloadCapabilities",
        "NativeAwdlDataTxObservationCount","NativeAwdlDataTxLastEthernetLength",
        "NativeAwdlDataTxLastIpv6Length","NativeAwdlDataTxLastUdpLength",
        "NativeAwdlDataTxLastIpv6NextHeader","NativeAwdlDataTxLastSourceEui64MatchesOwn",
        "NativeAwdlDataTxLastUdpHasMdnsPort","NativeAwdlDataTxLastIpv6DestinationIsMulticast",
        "NativeAwdlDataTxLastEthernetMulticastMappingMatches",
        "NativeAwdlDataTxLastUdpChecksumStatus","NativeAwdlDataTxLastIpv6PacketWellFormed",
        "NativeAwdlDataTxLastSourceIsLinkLocal","NativeAwdlDataTxChecksumStatusSeenMask",
        "NativeAwdlDataTxSourceEui64MismatchCount","NativeAwdlDataTxMulticastMappingMismatchCount",
        "NativeAwdlDataTxMalformedCount"};
    static_assert(sizeof(names)/sizeof(names[0])==NativeAwdlBSD::Count,"data counters");
    for(unsigned i=0;i<NativeAwdlBSD::Count;++i){
        auto prior=OSDynamicCast(OSNumber,controller->getProperty(names[i]));
        if(!prior||prior->unsigned64BitValue()!=data.value[i])controller->setProperty(names[i],data.value[i],64);
    }
#endif
#if defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332)
    const auto lifecycle=NativeAwdlLifecycle::snapshot();
    if(controller->getProperty("NativeAwdlLifecycleCompiled")!=kOSBooleanTrue)
        controller->setProperty("NativeAwdlLifecycleCompiled",kOSBooleanTrue);
    const uint32_t lifeValues[]={lifecycle.flags,lifecycle.phase,lifecycle.result,lifecycle.startWitness,
        lifecycle.classSize,lifecycle.referencesBeforeRelease,lifecycle.bsdEflags,lifecycle.bsdIndex,lifecycle.failurePhase,lifecycle.failureResult};
    const char *lifeNames[]={"NativeAwdlLifecycleFlags","NativeAwdlLifecyclePhase","NativeAwdlLifecycleResult",
        "NativeAwdlLifecycleStartWitness","NativeAwdlLifecycleClassSize","NativeAwdlLifecycleReferencesBeforeRelease",
        "NativeAwdlLifecycleBsdEflags","NativeAwdlLifecycleBsdIndex","NativeAwdlLifecycleFailurePhase","NativeAwdlLifecycleFailureResult"};
    for(unsigned int i=0;i<10;++i){
        auto prior=OSDynamicCast(OSNumber,controller->getProperty(lifeNames[i]));
        if(!prior||prior->unsigned32BitValue()!=lifeValues[i])controller->setProperty(lifeNames[i],lifeValues[i],32);
    }
#endif
#if defined(ITL_NATIVE_AWDL_INIT_OBSERVATION_25G332)
    // Publish scalar observation state only on the existing main gate tick.
    // Free may complete on an IOPM thread; it never writes IORegistry itself.
    const auto nativeInit = NativeAwdlInit::snapshot();
    if (controller->getProperty("NativeAwdlInitObservationCompiled") != kOSBooleanTrue)
        controller->setProperty("NativeAwdlInitObservationCompiled", kOSBooleanTrue);
    const uint32_t nativeInitValues[] = {nativeInit.flags, nativeInit.deregisterResult,
        nativeInit.referencesBeforeRelease, nativeInit.classSize};
    const char *nativeInitNames[] = {"NativeAwdlInitObservationFlags", "NativeAwdlInitDeregisterResult",
        "NativeAwdlInitReferencesBeforeRelease", "NativeAwdlInitClassSize"};
    for (unsigned int i = 0; i < 4; ++i) {
        auto prior = OSDynamicCast(OSNumber, controller->getProperty(nativeInitNames[i]));
        if (!prior || prior->unsigned32BitValue() != nativeInitValues[i])
            controller->setProperty(nativeInitNames[i], nativeInitValues[i], 32);
    }
#endif
    if (tahoe_awdl_peer_dirty_ ||
        !samePeerSnapshot(peer, tahoe_awdl_peer_published_)) {
        controller->setProperty("NativeP2PPeerCount", peer.validPeerCount, 32);
        controller->setProperty("NativeP2PPeerHasLatest", peer.hasLatestPeer, 32);
        controller->setProperty("NativeP2PPeerSyncFieldsValid", peer.syncFieldsValid, 32);
        controller->setProperty("NativeP2PPeerRxChannelIndex", peer.rxChannelIndex, 32);
        controller->setProperty("NativeP2PPeerNextAwChannel", peer.nextAwChannel, 32);
        controller->setProperty("NativeP2PPeerMasterChannel", peer.masterChannel, 32);
        controller->setProperty("NativeP2PPeerNextSlotTu", peer.nextSlotTu, 32);
        controller->setProperty("NativeP2PPeerAwPeriodTu", peer.awPeriodTu, 32);
        controller->setProperty("NativeP2PPeerActionPeriodTu", peer.actionFramePeriodTu, 32);
        controller->setProperty("NativeP2PPeerPresenceMode", peer.presenceMode, 32);
        controller->setProperty("NativeP2PPeerNextAwSequence", peer.nextAwSequence, 32);
        controller->setProperty("NativeP2PPeerAgeSeconds", peer.latestPeerAgeUs / 1000000, 64);
        controller->setProperty("NativeP2PPeerCandidateFramesTotal",
                                peer.candidateFramesTotal, 32);
        controller->setProperty("NativeP2PPeerPSFFramesTotal", peer.psfFramesTotal, 32);
        controller->setProperty("NativeP2PPeerMIFFramesTotal", peer.mifFramesTotal, 32);
        controller->setProperty("NativeP2PPeerAdmissionCountTotal",
                                peer.admittedFramesTotal, 32);
        controller->setProperty("NativeP2PPeerUpdateCountTotal",
                                peer.updatedFramesTotal, 32);
        controller->setProperty("NativeP2PPeerHistoryLastAdmissionContextGeneration",
                                peer.lastAdmittedContextGeneration, 64);
        controller->setProperty("NativeP2PPeerHistoryActiveWindowPeakValidCount",
                                peer.activeWindowPeakValidPeerCount, 32);
        controller->setProperty("NativeP2PPeerHistoryActiveWindowPeakContextGeneration",
                                peer.activeWindowPeakContextGeneration, 64);
        controller->setProperty("NativeP2PPeerAcceptedFrames", tahoe_awdl_peer_accepted_frames_, 32);
        controller->setProperty("NativeP2PPeerRejectedRecords", tahoe_awdl_peer_rejected_records_, 32);
        controller->setProperty("NativeP2PPeerLastResult", tahoe_awdl_peer_last_result_, 32);
        tahoe_awdl_peer_published_ = peer;
        tahoe_awdl_peer_dirty_ = false;
    }
    IntelP2PRx::Counters counters{};
    tahoe_p2p_rx_router_.readCounters(&counters);
    const auto &old = tahoe_p2p_rx_published_;
    if (tahoe_p2p_rx_published_once_ &&
        counters.timeEventCaptured == old.timeEventCaptured &&
        counters.actionFrameCaptured == old.actionFrameCaptured &&
        counters.actionGp2TimestampPresentCount == old.actionGp2TimestampPresentCount &&
        counters.lastActionGp2TimestampUs == old.lastActionGp2TimestampUs &&
        counters.lastActionGp2TimestampPresent == old.lastActionGp2TimestampPresent &&
        counters.actionEnvelopeSeen == old.actionEnvelopeSeen &&
        counters.actionParseRejected == old.actionParseRejected &&
        counters.lastActionParseStatus == old.lastActionParseStatus &&
        counters.actionRejectReason == old.actionRejectReason &&
        counters.actionSubtype == old.actionSubtype &&
        counters.actionRxChannel == old.actionRxChannel &&
        counters.actionTlvType == old.actionTlvType &&
        counters.actionTlvExpectedType == old.actionTlvExpectedType &&
        counters.actionTlvDeclaredLen == old.actionTlvDeclaredLen &&
        counters.actionTlvAvailableLen == old.actionTlvAvailableLen &&
        counters.actionTlvOffset == old.actionTlvOffset &&
        counters.actionSeenMask == old.actionSeenMask &&
        counters.actionRequiredMask == old.actionRequiredMask &&
        counters.actionTraceCount == old.actionTraceCount &&
        counters.actionTypeTraceLo == old.actionTypeTraceLo &&
        counters.actionTypeTraceHi == old.actionTypeTraceHi &&
        counters.actionDataPathFlags == old.actionDataPathFlags &&
        counters.actionDataPathExtFlags == old.actionDataPathExtFlags &&
        counters.actionDataPathOptionsLength == old.actionDataPathOptionsLength &&
        counters.actionDataPathOffset == old.actionDataPathOffset &&
        counters.actionDataPathFlagsPresent == old.actionDataPathFlagsPresent &&
        counters.actionDataPathExtFlagsPresent == old.actionDataPathExtFlagsPresent &&
        counters.actionDataPathOptionsLengthPresent == old.actionDataPathOptionsLengthPresent &&
        counters.actionDataPathRejectStage == old.actionDataPathRejectStage &&
        counters.provisionalUid == old.provisionalUid &&
        counters.protectedActionRejected == old.protectedActionRejected &&
        counters.malformedOrForeign == old.malformedOrForeign &&
        counters.tooLarge == old.tooLarge && counters.queueFull == old.queueFull)
        return;
    controller->setProperty("NativeP2PRxTimeEvents", counters.timeEventCaptured, 32);
    controller->setProperty("NativeP2PRxActionFrames", counters.actionFrameCaptured, 32);
    controller->setProperty("NativeP2PRxGp2TimestampPresentCount",
                            counters.actionGp2TimestampPresentCount, 32);
    controller->setProperty("NativeP2PRxLastGp2TimestampUs",
                            counters.lastActionGp2TimestampUs, 32);
    controller->setProperty("NativeP2PRxLastGp2TimestampPresent",
                            counters.lastActionGp2TimestampPresent, 32);
    controller->setProperty("NativeP2PRxEnvelopeSeen", counters.actionEnvelopeSeen, 32);
    controller->setProperty("NativeP2PRxParseRejected", counters.actionParseRejected, 32);
    controller->setProperty("NativeP2PRxLastParseStatus", counters.lastActionParseStatus, 32);
    controller->setProperty("NativeP2PRxLastRejectReason", counters.actionRejectReason, 32);
    controller->setProperty("NativeP2PRxLastRejectSubtype", counters.actionSubtype, 32);
    controller->setProperty("NativeP2PRxLastRejectRxChannel", counters.actionRxChannel, 32);
    controller->setProperty("NativeP2PRxLastRejectTlvType", counters.actionTlvType, 32);
    controller->setProperty("NativeP2PRxLastRejectExpectedType", counters.actionTlvExpectedType, 32);
    controller->setProperty("NativeP2PRxLastRejectDeclaredLen", counters.actionTlvDeclaredLen, 32);
    controller->setProperty("NativeP2PRxLastRejectAvailableLen", counters.actionTlvAvailableLen, 32);
    controller->setProperty("NativeP2PRxLastRejectTlvOffset", counters.actionTlvOffset, 32);
    controller->setProperty("NativeP2PRxLastRejectSeenMask", counters.actionSeenMask, 32);
    controller->setProperty("NativeP2PRxLastRejectRequiredMask", counters.actionRequiredMask, 32);
    controller->setProperty("NativeP2PRxLastRejectTraceCount", counters.actionTraceCount, 32);
    controller->setProperty("NativeP2PRxLastRejectTypeTraceLo", counters.actionTypeTraceLo, 64);
    controller->setProperty("NativeP2PRxLastRejectTypeTraceHi", counters.actionTypeTraceHi, 64);
    controller->setProperty("NativeP2PRxLastRejectDataPathFlags", counters.actionDataPathFlags, 32);
    controller->setProperty("NativeP2PRxLastRejectDataPathExtFlags", counters.actionDataPathExtFlags, 32);
    controller->setProperty("NativeP2PRxLastRejectDataPathOptionsLength", counters.actionDataPathOptionsLength, 32);
    controller->setProperty("NativeP2PRxLastRejectDataPathOffset", counters.actionDataPathOffset, 32);
    controller->setProperty("NativeP2PRxLastRejectDataPathFlagsPresent", counters.actionDataPathFlagsPresent, 32);
    controller->setProperty("NativeP2PRxLastRejectDataPathExtFlagsPresent", counters.actionDataPathExtFlagsPresent, 32);
    controller->setProperty("NativeP2PRxLastRejectDataPathOptionsLengthPresent", counters.actionDataPathOptionsLengthPresent, 32);
    controller->setProperty("NativeP2PRxLastRejectDataPathRejectStage", counters.actionDataPathRejectStage, 32);
    controller->setProperty("NativeP2PRxProvisionalUid", counters.provisionalUid, 32);
    controller->setProperty("NativeP2PRxProtectedRejected", counters.protectedActionRejected, 32);
    controller->setProperty("NativeP2PRxMalformedOrForeign", counters.malformedOrForeign, 32);
    controller->setProperty("NativeP2PRxTooLarge", counters.tooLarge, 32);
    controller->setProperty("NativeP2PRxQueueFull", counters.queueFull, 32);
    tahoe_p2p_rx_published_ = counters;
    tahoe_p2p_rx_published_once_ = true;
}

void ItlIwx::tahoeP2pPublishRxStageCounters(IOEthernetController *controller)
{
    if (!controller)
        return;
    const auto current = tahoe_awdl_rx_stage_counters_.snapshot();
    const auto &old = tahoe_awdl_rx_stage_published_;
    bool changed = !tahoe_awdl_rx_stage_published_once_ ||
        current.ownerGeneration != old.ownerGeneration ||
        current.active != old.active;
    for (unsigned stage = 0; stage < TahoeAwdlRxStageCounters::kStageCount;
         ++stage) {
        for (unsigned kind = 0; kind < TahoeAwdlRxStageCounters::kKindCount;
             ++kind) {
            if (current.counts[stage][kind] != old.counts[stage][kind])
                changed = true;
        }
    }
    for (unsigned stage = 0; stage < TahoeAwdlRxStageCounters::kDataStageCount;
         ++stage) {
        if (current.dataCounts[stage] != old.dataCounts[stage])
            changed = true;
    }
    if (!changed)
        return;

    controller->setProperty("NativeP2PRxStageSchema", 2U, 32);
    controller->setProperty("NativeP2PRxStageOwnerGeneration",
                            current.ownerGeneration, 32);
    controller->setProperty("NativeP2PRxStageOwnerActive", current.active, 32);
    const char *names[TahoeAwdlRxStageCounters::kStageCount][2] = {
        {"NativeP2PRxStageEarlyPsf", "NativeP2PRxStageEarlyMif"},
        {"NativeP2PRxStageAfterDecryptPsf", "NativeP2PRxStageAfterDecryptMif"},
        {"NativeP2PRxStageDecryptRejectedPsf", "NativeP2PRxStageDecryptRejectedMif"},
        {"NativeP2PRxStageAfterDuplicatePsf", "NativeP2PRxStageAfterDuplicateMif"},
        {"NativeP2PRxStageDuplicateRejectedPsf", "NativeP2PRxStageDuplicateRejectedMif"},
        {"NativeP2PRxStageAtTapPsf", "NativeP2PRxStageAtTapMif"}
    };
    for (unsigned stage = 0; stage < TahoeAwdlRxStageCounters::kStageCount;
         ++stage) {
        for (unsigned kind = 0; kind < TahoeAwdlRxStageCounters::kKindCount;
             ++kind) {
            controller->setProperty(names[stage][kind],
                                    current.counts[stage][kind], 32);
        }
    }
    const char *dataNames[TahoeAwdlRxStageCounters::kDataStageCount] = {
        "NativeP2PRxDataStageEarlyAwdlBssidCandidate",
        "NativeP2PRxDataStageAfterDecryptAwdlBssidCandidate",
        "NativeP2PRxDataStageDecryptRejectedAwdlBssidCandidate",
        "NativeP2PRxDataStageAfterDuplicateAwdlBssidCandidate",
        "NativeP2PRxDataStageDuplicateRejectedAwdlBssidCandidate",
        "NativeP2PRxDataStageAtTapAwdlBssidCandidate",
        "NativeP2PRxDataStageTapRejectedAwdlBssidCandidate"
    };
    for (unsigned stage = 0; stage < TahoeAwdlRxStageCounters::kDataStageCount;
         ++stage)
        controller->setProperty(dataNames[stage], current.dataCounts[stage], 32);
    tahoe_awdl_rx_stage_published_ = current;
    tahoe_awdl_rx_stage_published_once_ = true;
}

void ItlIwx::tahoePublishResetTrace(IOEthernetController *controller)
{
    if (!controller)
        return;
    IwxResetTrace::Snapshot snapshot{};
    if (!nativeResetTrace_.read(&snapshot))
        return;
    if (nativeResetTracePublishedOnce_ &&
        snapshot.resetSequence == nativeResetTracePublishedSequence_ &&
        snapshot.lastInitTaskTriggerSequence ==
            nativeResetTracePublishedTriggerSequence_ &&
        snapshot.initTaskTriggerRevision ==
            nativeResetTracePublishedTriggerRevision_)
        return;

    // This method is called by the existing main-workloop RX drain, which is
    // also reached from the 1-second watchdog tick. The reset producer only
    // updates atomics; all IORegistry writes stay on this serialized gate.
    uint32_t beginVersion = nativeResetTracePublishVersion_ + 1U;
    if ((beginVersion & 1U) == 0)
        ++beginVersion;
    const uint32_t finishVersion = beginVersion + 1U;
    controller->setProperty("NativeResetTracePublishVersion",
                            beginVersion, 32);
    controller->setProperty("NativeResetTraceSchema", 1U, 32);
    controller->setProperty("NativeResetTraceLastReason",
                            snapshot.lastResetReason, 32);
    controller->setProperty("NativeResetTraceGeneration",
                            snapshot.generation, 32);
    controller->setProperty("NativeResetTraceDriverFlags",
                            snapshot.driverFlags, 32);
    controller->setProperty("NativeResetTraceInterfaceFlags",
                            snapshot.interfaceFlags, 32);
    controller->setProperty("NativeResetTrace80211State",
                            snapshot.ieee80211State, 32);
    controller->setProperty("NativeResetTraceInitStage",
                            snapshot.initStage, 32);
    controller->setProperty("NativeResetTraceInitError",
                            snapshot.initError, 32);
    for (uint32_t i = 0; i < IwxResetTrace::kResetReasonCount; ++i)
        controller->setProperty(kResetReasonProperties[i],
                                snapshot.resetReasonCounts[i], 32);

    controller->setProperty("NativeResetTraceLastInitTaskTriggerSequence",
                            snapshot.lastInitTaskTriggerSequence, 32);
    controller->setProperty("NativeResetTraceLastInitTaskTrigger",
                            snapshot.lastInitTaskTrigger, 32);
    controller->setProperty("NativeResetTraceInitTaskTriggerRevision",
                            snapshot.initTaskTriggerRevision, 32);
    for (uint32_t i = 0; i < IwxResetTrace::kInitTaskTriggerCount; ++i)
        controller->setProperty(kInitTriggerProperties[i],
                                snapshot.initTaskTriggerCounts[i], 32);

    // Write the reset sequence after the rest of the payload, then close the
    // externally readable batch with an even version. Readers must ignore an
    // odd version or retry if the version changes while collecting fields.
    controller->setProperty("NativeResetTraceSequence",
                            snapshot.resetSequence, 32);
    controller->setProperty("NativeResetTracePublishVersion",
                            finishVersion, 32);
    nativeResetTracePublishedSequence_ = snapshot.resetSequence;
    nativeResetTracePublishedTriggerSequence_ =
        snapshot.lastInitTaskTriggerSequence;
    nativeResetTracePublishedTriggerRevision_ =
        snapshot.initTaskTriggerRevision;
    nativeResetTracePublishVersion_ = finishVersion;
    nativeResetTracePublishedOnce_ = true;
}

#endif
