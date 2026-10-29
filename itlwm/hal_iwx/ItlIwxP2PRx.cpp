// SPDX-License-Identifier: GPL-2.0-only
#include "ItlIwx.hpp"

#include "../../native/p2p_rx149_observation.hpp"

#ifdef AIRPORT_TAHOE
#include <kern/clock.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSNumber.h>
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

bool sameRxEntryWitness(const NativeAwdlRxEntry::Witness &a,
                        const NativeAwdlRxEntry::Witness &b)
{
    return a.present == b.present &&
        a.contextGeneration == b.contextGeneration &&
        a.powerGeneration == b.powerGeneration &&
        a.stationGeneration == b.stationGeneration &&
        a.rocGeneration == b.rocGeneration &&
        a.payloadLength == b.payloadLength && a.dmaCapacity == b.dmaCapacity &&
        a.descriptorSize == b.descriptorSize &&
        a.descriptorVersion == b.descriptorVersion &&
        a.mpduLength == b.mpduLength && a.statusPresent == b.statusPresent &&
        a.status == b.status &&
        a.macPhyIndexPresent == b.macPhyIndexPresent &&
        a.macPhyIndex == b.macPhyIndex &&
        a.filterMatchPresent == b.filterMatchPresent &&
        a.filterMatch == b.filterMatch && a.rpaEnabled == b.rpaEnabled &&
        a.channelPresent == b.channelPresent && a.channel == b.channel &&
        a.frameControlPresent == b.frameControlPresent &&
        a.frameControl == b.frameControl && a.frameType == b.frameType &&
        a.frameSubtype == b.frameSubtype && a.toDs == b.toDs &&
        a.fromDs == b.fromDs &&
        a.awdlBssidCandidate == b.awdlBssidCandidate;
}

bool sameRxEntrySnapshot(const NativeAwdlRxEntry::Snapshot &a,
                         const NativeAwdlRxEntry::Snapshot &b)
{
    if (a.schema != b.schema || a.active != b.active ||
        !NativeAwdlRxEntry::sameEpochs(a.epochs, b.epochs) ||
        !sameRxEntryWitness(a.lastDescriptor, b.lastDescriptor) ||
        !sameRxEntryWitness(a.lastAwdlDataCandidate,
                            b.lastAwdlDataCandidate))
        return false;
    for (unsigned i = 0; i < NativeAwdlRxEntry::CounterCount; ++i)
        if (a.counts[i] != b.counts[i])
            return false;
    return true;
}

bool setNativeP2PRxTraceProperty(IOEthernetController *controller,
                                 const char *suffix, uint64_t value,
                                 unsigned int bits)
{
    if (!controller || !suffix)
        return false;
    char name[112] = {};
    const int length = snprintf(name, sizeof(name),
        "NativeP2PRxTrace%s", suffix);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(name))
        return false;
    return controller->setProperty(name, value, bits);
}

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332) && \
    defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332)
bool setNativeAwdlAttachTraceProperty(IOEthernetController *controller,
                                     const char *suffix, uint64_t value,
                                     unsigned int bits)
{
    if (!controller || !suffix)
        return false;
    char name[128] = {};
    const int length = snprintf(name, sizeof(name),
        "NativeAwdlDataAttachTrace%s", suffix);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(name))
        return false;
    return controller->setProperty(name, value, bits);
}

bool stableAttachTraceSnapshot(
    const NativeAwdlBSD::AttachTraceSnapshot &snapshot)
{
    return snapshot.complete == 1 && (snapshot.versionBegin & 1u) == 0 &&
        snapshot.versionBegin == snapshot.versionEnd &&
        snapshot.schemaVersion == 1;
}

bool sameAttachTraceSnapshotFence(
    const NativeAwdlBSD::AttachTraceSnapshot &a,
    const NativeAwdlBSD::AttachTraceSnapshot &b)
{
    return stableAttachTraceSnapshot(a) && stableAttachTraceSnapshot(b) &&
        a.revision == b.revision &&
        a.versionBegin == b.versionBegin && a.versionEnd == b.versionEnd &&
        a.schemaVersion == b.schemaVersion;
}

bool terminalAttachLifecycle(const NativeAwdlLifecycle::Snapshot &snapshot)
{
    // Phase 12 is a completed retirement. Phase 13 with no failure is the
    // live, fully attached resident interface. A failed phase 13 remains
    // pending until its phase-12 retirement has completed.
    return snapshot.phase == 12 ||
        (snapshot.phase == 13 && snapshot.result == 0 &&
         snapshot.failurePhase == 0);
}

bool sameAttachLifecycleFence(const NativeAwdlLifecycle::Snapshot &a,
                              const NativeAwdlLifecycle::Snapshot &b)
{
    return a.phase == b.phase && a.result == b.result &&
        a.failurePhase == b.failurePhase &&
        a.failureResult == b.failureResult;
}
#endif

bool setNativeP2PRxTraceEventProperty(IOEthernetController *controller,
                                      uint32_t index, const char *field,
                                      uint64_t value, unsigned int bits)
{
    if (!controller || !field)
        return false;
    char name[112] = {};
    const int length = snprintf(name, sizeof(name),
        "NativeP2PRxTraceEvent%u%s", index, field);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(name))
        return false;
    return controller->setProperty(name, value, bits);
}

bool setNativeP2PRxTraceNamedProperty(IOEthernetController *controller,
                                      const char *record,
                                      const char *field, uint64_t value,
                                      unsigned int bits)
{
    if (!controller || !record || !field)
        return false;
    char suffix[96] = {};
    const int length = snprintf(suffix, sizeof(suffix), "%s%s", record, field);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(suffix))
        return false;
    return setNativeP2PRxTraceProperty(controller, suffix, value, bits);
}

bool rx149PropertyIsOne(IOEthernetController *controller, const char *name)
{
    if (!controller || !name)
        return false;
    OSNumber *value = OSDynamicCast(OSNumber,
                                    controller->getProperty(name));
    return value && value->unsigned32BitValue() == 1u;
}

bool rx149StationAndPhyOwnerCurrent(const struct iwx_softc *sc)
{
    if (!sc || sc->sc_ic.ic_state != IEEE80211_S_RUN ||
        (sc->sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR |
                         IWX_FLAG_RFKILL)) != 0 ||
        sc->sc_ic.ic_bss == nullptr)
        return false;
    const auto &roc = sc->sc_p2p_roc;
    const uint32_t currentStationEpoch = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    if (roc.fw_generation != static_cast<uint32_t>(sc->sc_generation) ||
        roc.station_epoch != currentStationEpoch ||
        static_cast<void *>(sc->sc_ic.ic_bss) != roc.station_bss ||
        roc.station_phy_id != 0 ||
        roc.station_phy_id >= IWX_NUM_PHY_CTX ||
        roc.station_phy_channel == nullptr || roc.phy_id != 1 ||
        roc.phy_id >= IWX_NUM_PHY_CTX || roc.roc_channel == nullptr)
        return false;
    const auto *station = reinterpret_cast<const struct iwx_node *>(
        sc->sc_ic.ic_bss);
    const auto *stationPhy = &sc->sc_phyctxt[roc.station_phy_id];
    const auto *p2pPhy = &sc->sc_phyctxt[roc.phy_id];
    return station->in_phyctxt == stationPhy &&
        station->in_phyctxt->id == roc.station_phy_id &&
        station->in_phyctxt->color == roc.station_phy_color &&
        station->in_ni.ni_chan == roc.station_phy_channel &&
        stationPhy->id == roc.station_phy_id &&
        stationPhy->color == roc.station_phy_color &&
        stationPhy->channel == roc.station_phy_channel &&
        sc->sc_p2p.initialized &&
        sc->sc_p2p.fw_generation == roc.fw_generation &&
        sc->sc_p2p.mac_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc->sc_p2p.mac_id == 1 && sc->sc_p2p.phy_leased &&
        sc->sc_p2p.phy_id == roc.phy_id &&
        sc->sc_p2p.binding_id == roc.phy_id &&
        sc->sc_p2p.phy_color == roc.phy_color &&
        sc->sc_p2p.binding_color == roc.phy_color &&
        p2pPhy->id == roc.phy_id && p2pPhy->color == roc.phy_color &&
        p2pPhy->channel == roc.roc_channel;
}

NativeP2PRx149Observation::RocEvidence currentRx149ActionEvidence(
    ItlIwx *owner, struct iwx_softc *sc,
    const IntelP2PRx::LeaseSnapshot &lease,
    uint16_t channelIndex, const IntelROCEvent::SessionSnapshot &session,
    const NativeAwdlRxTrace::Snapshot &traceOwner)
{
    NativeP2PRx149Observation::RocEvidence evidence{};
    if (!owner || !sc)
        return evidence;
    auto *controller = owner->tahoeP2pController();
    const uint32_t armMode = __atomic_load_n(
        &owner->nativeP2pManualArmRequested_, __ATOMIC_ACQUIRE);
    const uint32_t generation = __atomic_load_n(
        &owner->nativeP2pRocGeneration_, __ATOMIC_ACQUIRE);
    const uint32_t currentPower = uint32_t(sc->sc_generation);
    const uint32_t currentStation = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    const bool channelInRange =
        channelIndex < nitems(sc->sc_ic.ic_channels);
    const bool channel149 = channelInRange &&
        ieee80211_chan2ieee(&sc->sc_ic,
            &sc->sc_ic.ic_channels[channelIndex]) ==
                NativeP2PRx149Observation::kIeeeChannel;
    const bool rocChannel149 = sc->sc_p2p_roc.roc_channel != nullptr &&
        nitems(sc->sc_ic.ic_channels) >
            NativeP2PRx149Observation::kIeeeChannel &&
        sc->sc_p2p_roc.roc_channel ==
            &sc->sc_ic.ic_channels[
                NativeP2PRx149Observation::kIeeeChannel] &&
        ieee80211_chan2ieee(&sc->sc_ic, sc->sc_p2p_roc.roc_channel) ==
            NativeP2PRx149Observation::kIeeeChannel;
    const bool traceMatches = owner->nativeAwdlRxEventOwnerSerial_ != 0 &&
        traceOwner.ownerPresent && traceOwner.active &&
        !traceOwner.producerClosed &&
        traceOwner.ownerSerial == owner->nativeAwdlRxEventOwnerSerial_ &&
        traceOwner.epochs.contextGeneration == lease.contextGeneration &&
        traceOwner.epochs.powerGeneration == lease.powerGeneration &&
        traceOwner.epochs.stationGeneration == lease.stationGeneration &&
        traceOwner.epochs.rocGeneration == generation;
    evidence.profileSelected =
        armMode == NativeP2PRx149Observation::kRx149ArmMode &&
        controller && controller->getProperty(
            "NativeP2PRx149ObservationOnly") == kOSBooleanTrue &&
        rx149PropertyIsOne(controller, "NativeP2PRx149ProfileEnabled") &&
        rx149PropertyIsOne(controller, "NativeP2PRx149Selected") &&
        rx149PropertyIsOne(controller, "NativeP2PRx149HostTxBlocked");
    evidence.receiveObservationOnly = __atomic_load_n(
        &sc->sc_p2p_roc.receive_observation_only, __ATOMIC_ACQUIRE) != 0;
    evidence.requestedChannel149 = __atomic_load_n(
        &owner->nativeP2pRocChannel_, __ATOMIC_ACQUIRE) ==
            NativeP2PRx149Observation::kIeeeChannel &&
        __atomic_load_n(&owner->nativeP2pRocDurationMs_,
                        __ATOMIC_ACQUIRE) ==
            NativeP2PRx149Observation::kSessionDurationMs;
    evidence.actualRocChannel149 = rocChannel149;
    evidence.rxChannel149 = channel149;
    evidence.leaseActive = lease.active && sc->sc_p2p.initialized &&
        sc->sc_p2p.mac_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc->sc_p2p.phy_leased && sc->sc_p2p.mac_id == 1 &&
        sc->sc_p2p.phy_id == sc->sc_p2p_roc.phy_id &&
        sc->sc_p2p.binding_id == sc->sc_p2p_roc.phy_id;
    evidence.ownerCurrent = owner->nativeP2pBusy() &&
        __atomic_load_n(&owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) !=
            nullptr && owner->nativeP2pProbeGeneration_ ==
                lease.contextGeneration;
    evidence.epochsMatch = lease.contextGeneration != 0 &&
        lease.contextGeneration == lease.currentContextGeneration &&
        lease.contextGeneration == owner->nativeP2pProbeGeneration_ &&
        lease.powerGeneration == lease.currentPowerGeneration &&
        lease.powerGeneration == currentPower &&
        lease.stationGeneration == lease.currentStationGeneration &&
        lease.stationGeneration == currentStation && traceMatches &&
        rx149StationAndPhyOwnerCurrent(sc);
    evidence.tokenMatches = generation != 0 &&
        generation == lease.contextGeneration &&
        session.generation == generation &&
        sc->sc_p2p_roc.token == generation;
    evidence.commandReturned = session.commandReturned;
    evidence.commandSucceeded = session.commandReturned &&
        session.commandResult == 0;
    evidence.deviceDiscoveryConfiguration = session.configuration ==
        IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV;
    evidence.startSeen = session.startSeen;
    evidence.startSucceeded = session.startSeen && session.startStatus == 1;
    evidence.endSeen = session.endSeen;
    evidence.endConfirmed = session.endSeen && session.cleanupAllowed &&
        session.endStatus == 1 && !session.outcomeUnknown;
    evidence.outcomeUnknown = session.outcomeUnknown;
    if (sc->sc_p2p_roc.phase != IWX_P2P_ROC_SESSION_ACKED)
        evidence.leaseActive = false;
    return evidence;
}

uint32_t tahoeP2pReadLe32(const uint8_t *bytes)
{
    return uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) |
        (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);
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

void ItlIwx::tahoeP2pPublishRxEventTimeline(
    IOEthernetController *controller)
{
    if (!controller || !tahoeP2pOnMainGate())
        return;

    NativeAwdlRxTrace::Snapshot snapshot =
        nativeAwdlRxEventTimeline_.snapshot();
    if (snapshot.ownerPresent &&
        (!snapshot.producerClosed || snapshot.active))
        return;
    if (nativeAwdlRxEventPublishedOnce_ &&
        snapshot.revision == nativeAwdlRxEventPublishedRevision_)
        return;
    if (snapshot.eventCount > NativeAwdlRxTrace::kEventCapacity ||
        nativeAwdlRxEventPublishVersion_ > UINT64_MAX - 2)
        return;

    const NativeP2PProbe::Snapshot probe = nativeP2pProbe_.snapshot();
    const uint32_t rocGeneration = __atomic_load_n(
        &nativeP2pRocGeneration_, __ATOMIC_ACQUIRE);

    // The first clean boot snapshot is deliberately published even though its
    // helper revision is zero. Begin failure stops immediately; any body
    // failure leaves End at the prior value, so readers cannot accept a partial
    // update. Revision is independent of this IORegistry publication version.
    const uint64_t version = nativeAwdlRxEventPublishVersion_ + 2;
    const uint64_t writingVersion = version - 1;
    if (!setNativeP2PRxTraceProperty(controller, "SnapshotVersionBegin",
                                     writingVersion, 64))
        return;

    bool complete = true;
    // Publish the independently maintained probe epochs inside the same
    // begin/end transaction. They are required even for owner=0 preflight.
    complete = controller->setProperty("NativeP2PProbeContextGeneration",
                                       probe.contextGeneration, 32) &&
        controller->setProperty("NativeP2PProbePowerGeneration",
                                probe.powerGeneration, 32) &&
        controller->setProperty("NativeP2PProbeStationGeneration",
                                probe.stationGeneration, 32) &&
        controller->setProperty("NativeP2PRocGeneration", rocGeneration, 32);
#define RX_TRACE_SET32(name, value) \
    do { if (complete) complete = setNativeP2PRxTraceProperty( \
        controller, name, static_cast<uint32_t>(value), 32); } while (0)
#define RX_TRACE_SET64(name, value) \
    do { if (complete) complete = setNativeP2PRxTraceProperty( \
        controller, name, static_cast<uint64_t>(value), 64); } while (0)
    RX_TRACE_SET32("SchemaVersion", snapshot.schemaVersion);
    RX_TRACE_SET32("OwnerPresent", snapshot.ownerPresent);
    RX_TRACE_SET64("OwnerSerial", snapshot.ownerSerial);
    RX_TRACE_SET64("Revision", snapshot.revision);
    RX_TRACE_SET32("ContextGeneration", snapshot.epochs.contextGeneration);
    RX_TRACE_SET32("PowerGeneration", snapshot.epochs.powerGeneration);
    RX_TRACE_SET32("StationGeneration", snapshot.epochs.stationGeneration);
    RX_TRACE_SET32("RocGeneration", snapshot.epochs.rocGeneration);
    RX_TRACE_SET32("Active", snapshot.active);
    RX_TRACE_SET32("ProducerClosed", snapshot.producerClosed);
    RX_TRACE_SET32("PendingDrainCount", snapshot.pendingDrainCount);
    RX_TRACE_SET32("UntrackedPendingDrainCount",
                   snapshot.untrackedPendingDrainCount);
    RX_TRACE_SET32("UntrackedPendingIdentityOverflowCount",
                   snapshot.untrackedPendingIdentityOverflowCount);
    RX_TRACE_SET32("EventCount", snapshot.eventCount);
    RX_TRACE_SET32("DroppedEventCount", snapshot.droppedEventCount);
    RX_TRACE_SET32("StaleCompletionCount", snapshot.staleCompletionCount);
    RX_TRACE_SET32("SourceTableFullCount", snapshot.sourceTableFullCount);
    RX_TRACE_SET32("FilteredActionCount", snapshot.filteredActionCount);
    RX_TRACE_SET32("RejectedOwnerCount", snapshot.rejectedOwnerCount);
    RX_TRACE_SET32("StaleNotificationCount", snapshot.staleNotificationCount);
    RX_TRACE_SET32("SessionAnomalyCount", snapshot.sessionAnomalyCount);
    RX_TRACE_SET32("SessionReducerReturnedTrueCount",
                   snapshot.sessionReducerReturnedTrueCount);
    RX_TRACE_SET32("SessionCanonicalTransitionCount",
                   snapshot.sessionCanonicalTransitionCount);
    RX_TRACE_SET32("SessionNotificationAcceptedCount",
                   snapshot.sessionNotificationAcceptedCount);
    RX_TRACE_SET32("SessionNotificationIgnoredCount",
                   snapshot.sessionNotificationIgnoredCount);
    RX_TRACE_SET32("SessionNotificationDuplicateCount",
                   snapshot.sessionNotificationDuplicateCount);
    RX_TRACE_SET32("SessionNotificationConflictingCount",
                   snapshot.sessionNotificationConflictingCount);
    RX_TRACE_SET32("SessionNotificationLateCount",
                   snapshot.sessionNotificationLateCount);
    RX_TRACE_SET32("SessionNotificationMalformedCount",
                   snapshot.sessionNotificationMalformedCount);
    RX_TRACE_SET32("SessionNotificationForeignCount",
                   snapshot.sessionNotificationForeignCount);
    RX_TRACE_SET32("SessionBoundaryOrderInvalid",
                   snapshot.sessionBoundaryOrderInvalid);
    RX_TRACE_SET32("TimeEventNotificationCount",
                   snapshot.timeEventNotificationCount);
    RX_TRACE_SET32("TimeEventNotificationDroppedCount",
                   snapshot.timeEventNotificationDroppedCount);
    RX_TRACE_SET32("ProducerCloseReason", snapshot.producerCloseReason);

    const auto publishBoundary = [&](const char *name,
                                     const NativeAwdlRxTrace::BoundarySlot &b) {
        const auto set32 = [&](const char *field, uint32_t value) {
            if (complete)
                complete = setNativeP2PRxTraceNamedProperty(
                    controller, name, field, value, 32);
        };
        const auto set64 = [&](const char *field, uint64_t value) {
            if (complete)
                complete = setNativeP2PRxTraceNamedProperty(
                    controller, name, field, value, 64);
        };
        set32("Present", b.present);
        set32("Api", static_cast<uint32_t>(b.api));
        set64("NotificationSerial", b.notificationSerial);
        set64("OwnerSerial", b.ownerSerial);
        set64("HostMonotonicUs", b.hostMonotonicUs);
        set32("ContextGeneration", b.epochs.contextGeneration);
        set32("PowerGeneration", b.epochs.powerGeneration);
        set32("StationGeneration", b.epochs.stationGeneration);
        set32("RocGeneration", b.epochs.rocGeneration);
        set32("HostMonotonicPresent", b.hostMonotonicPresent);
        set32("RawLength", b.rawLength);
        set32("OwnerSessionToken", b.ownerSessionToken);
        set32("ExpectedUidKnown", b.expectedUidKnown);
        set32("ExpectedUid", b.expectedUid);
        set32("MacIdAndColor", b.macIdAndColor);
        set32("RawStatus", b.rawStatus);
        set32("RawStartFlag", b.rawStartFlag);
        set32("Configuration", b.configuration);
        set32("ReducerResultPresent", b.reducerResultPresent);
        set32("ReducerReturnedTrue", b.reducerReturnedTrue);
        set32("ReducerResult", b.reducerResult);
        set32("CanonicalTransitionPresent", b.canonicalTransitionPresent);
        set32("CanonicalTransition", b.canonicalTransition);
    };
    publishBoundary("RocStart", snapshot.rocStart);
    publishBoundary("RocEnd", snapshot.rocEnd);

    const auto publishAnomaly = [&](const char *name,
                                    const NativeAwdlRxTrace::IgnoredNotification &a) {
        const auto set32 = [&](const char *field, uint32_t value) {
            if (complete)
                complete = setNativeP2PRxTraceNamedProperty(
                    controller, name, field, value, 32);
        };
        const auto set64 = [&](const char *field, uint64_t value) {
            if (complete)
                complete = setNativeP2PRxTraceNamedProperty(
                    controller, name, field, value, 64);
        };
        set32("Present", a.present);
        set32("Api", static_cast<uint32_t>(a.api));
        set32("Reason", static_cast<uint32_t>(a.reason));
        set64("NotificationSerial", a.notificationSerial);
        set64("OwnerSerial", a.ownerSerial);
        set64("HostMonotonicUs", a.hostMonotonicUs);
        set32("ContextGeneration", a.epochs.contextGeneration);
        set32("PowerGeneration", a.epochs.powerGeneration);
        set32("StationGeneration", a.epochs.stationGeneration);
        set32("RocGeneration", a.epochs.rocGeneration);
        set32("HostMonotonicPresent", a.hostMonotonicPresent);
        set32("RawLength", a.rawLength);
        set32("OwnerSessionToken", a.ownerSessionToken);
        set32("ExpectedUidKnown", a.expectedUidKnown);
        set32("ExpectedUid", a.expectedUid);
        set32("MacIdAndColor", a.macIdAndColor);
        set32("RawStatus", a.rawStatus);
        set32("RawStartFlag", a.rawStartFlag);
        set32("Configuration", a.configuration);
        set32("ReducerResultPresent", a.reducerResultPresent);
        set32("ReducerReturnedTrue", a.reducerReturnedTrue);
        set32("ReducerResult", a.reducerResult);
    };
    publishAnomaly("FirstSessionAnomaly", snapshot.firstSessionAnomaly);
    publishAnomaly("LastSessionAnomaly", snapshot.lastSessionAnomaly);

    for (uint32_t index = 0; complete && index < snapshot.eventCount; ++index) {
        NativeAwdlRxTrace::Event event{};
        if (!nativeAwdlRxEventTimeline_.eventAt(index, &event)) {
            complete = false;
            break;
        }
        const auto set32 = [&](const char *field, uint32_t value) {
            if (complete)
                complete = setNativeP2PRxTraceEventProperty(
                    controller, index, field, value, 32);
        };
        const auto set64 = [&](const char *field, uint64_t value) {
            if (complete)
                complete = setNativeP2PRxTraceEventProperty(
                    controller, index, field, value, 64);
        };
        set64("Serial", event.serial);
        set64("OwnerSerial", event.ownerSerial);
        set64("HostMonotonicUs", event.hostMonotonicUs);
        set64("QueueSerial", event.queueSerial);
        set64("TxTicketSerial", event.txTicketSerial);
        set64("TxDiagnosticGeneration", event.txDiagnosticGeneration);
        set32("ContextGeneration", event.epochs.contextGeneration);
        set32("PowerGeneration", event.epochs.powerGeneration);
        set32("StationGeneration", event.epochs.stationGeneration);
        set32("RocGeneration", event.epochs.rocGeneration);
        set32("Kind", static_cast<uint32_t>(event.kind));
        set32("HostMonotonicPresent", event.hostMonotonicPresent);
        set32("RawLength", event.rawLength);
        set32("SourceOrdinal", event.sourceOrdinal);
        set32("SourceKnown", event.sourceKnown);
        set32("FrameControlPresent", event.frameControlPresent);
        set32("FrameControl", event.frameControl);
        set32("FrameType", event.frameType);
        set32("FrameSubtype", event.frameSubtype);
        set32("SequenceControlPresent", event.sequenceControlPresent);
        set32("SequenceControl", event.sequenceControl);
        set32("AwdlSubtypePresent", event.awdlSubtypePresent);
        set32("AwdlSubtype", event.awdlSubtype);
        set32("WirePhyPresent", event.wirePhyPresent);
        set32("WirePhyTxUs", event.wirePhyTxUs);
        set32("WireTargetPresent", event.wireTargetPresent);
        set32("WireTargetTxUs", event.wireTargetTxUs);
        set32("ChannelIndex", event.channelIndex);
        set32("RxGp2Present", event.rxGp2Present);
        set32("RxGp2Us", event.rxGp2Us);
        set32("RxMacPhyIndexPresent", event.rxMacPhyIndexPresent);
        set32("RxMacPhyIndex", event.rxMacPhyIndex);
        set32("ParseAttempted", event.parseAttempted);
        set32("ParseResultPresent", event.parseResultPresent);
        set32("ParseStatus", event.parseStatus);
        set32("ParseRejectReason", event.parseRejectReason);
        set32("ParseRejectSubtype", event.parseRejectSubtype);
        set32("ParseTlvType", event.parseTlvType);
        set32("ParseExpectedTlvType", event.parseExpectedTlvType);
        set32("ParseTlvOffset", event.parseTlvOffset);
        set32("ParseDeclaredLength", event.parseDeclaredLength);
        set32("ParseAvailableLength", event.parseAvailableLength);
        set32("DecodeAttempted", event.decodeAttempted);
        set32("DecodeResultPresent", event.decodeResultPresent);
        set32("DecodeStatus", event.decodeStatus);
        set32("DecodeRejectStage", event.decodeRejectStage);
        set32("DecodeOffendingTlvType", event.decodeOffendingTlvType);
        set32("DecodeRelatedTlvType", event.decodeRelatedTlvType);
        set32("RouteAttempted", event.routeAttempted);
        set32("RouteResultPresent", event.routeResultPresent);
        set32("RouteStatus", event.routeStatus);
        set32("QueueAccepted", event.queueAccepted);
        set32("TableObserveAttempted", event.tableObserveAttempted);
        set32("TableResultPresent", event.tableResultPresent);
        set32("TableStatus", event.tableStatus);
        set32("PeerObserverAttempted", event.peerObserverAttempted);
        set32("PeerObserverResultPresent", event.peerObserverResultPresent);
        set32("PeerObserverStatus", event.peerObserverStatus);
        set32("CompletionUpdated", event.completionUpdated);
        set32("PendingDrain", event.pendingDrain);
        set32("NotificationApi", static_cast<uint32_t>(event.notificationApi));
        set32("NotificationMatchStatusPresent",
              event.notificationMatchStatusPresent);
        set32("NotificationMatchStatus", event.notificationMatchStatus);
        set32("TimeEventTimestamp", event.timeEventTimestamp);
        set32("TimeEventSessionId", event.timeEventSessionId);
        set32("TimeEventUniqueId", event.timeEventUniqueId);
        set32("TimeEventMacIdAndColor", event.timeEventMacIdAndColor);
        set32("TimeEventRawAction", event.timeEventRawAction);
        set32("TimeEventRawStatus", event.timeEventRawStatus);
        set32("TimeEventExpectedUidKnown", event.timeEventExpectedUidKnown);
        set32("TimeEventExpectedUid", event.timeEventExpectedUid);
        set32("TxSequenceControl", event.txSequenceControl);
        set32("TxWireInfoPresent", event.txWireInfoPresent);
        set32("TxWirePhyTxUs", event.txWirePhyTxUs);
        set32("TxWireTargetTxUs", event.txWireTargetTxUs);
        set32("TxQueueId", event.txQueueId);
        set32("TxDescriptorIndex", event.txDescriptorIndex);
    }

    if (!complete || nativeAwdlRxEventTimeline_.snapshot().revision !=
                         snapshot.revision)
        return;
    if (!setNativeP2PRxTraceProperty(controller, "SnapshotVersionEnd",
                                     version, 64))
        return;
    if (!setNativeP2PRxTraceProperty(controller, "SnapshotVersionBegin",
                                     version, 64))
        return;

    nativeAwdlRxEventPublishVersion_ = version;
    nativeAwdlRxEventPublishedRevision_ = snapshot.revision;
    nativeAwdlRxEventPublishedOnce_ = true;
#undef RX_TRACE_SET32
#undef RX_TRACE_SET64
}

void ItlIwx::tahoeP2pPublishNativeAwdlAttachTrace(
    IOEthernetController *controller)
{
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332) && \
    defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332)
    if (!controller || !tahoeP2pOnMainGate())
        return;

    const auto publicationSafe = [&]() {
        return controller == getController() &&
            __atomic_load_n(&nativeP2pProbeQueued_, __ATOMIC_ACQUIRE) == 0 &&
            __atomic_load_n(&nativeP2pProbeBusy_, __ATOMIC_ACQUIRE) == 0 &&
            __atomic_load_n(&nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) == nullptr &&
            __atomic_load_n(&nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) == 0 &&
            __atomic_load_n(&nativeP2pCancelRequested_, __ATOMIC_ACQUIRE) == 0 &&
            __atomic_load_n(&nativeLifecycleTearingDown_, __ATOMIC_ACQUIRE) == 0;
    };
    if (!publicationSafe())
        return;

    // A new driver instance can inherit old IORegistry properties from an
    // earlier kext instance. Invalidate them once until this instance has a
    // stable terminal trace. An odd Begin makes all old End/body values stale.
    const auto invalidatePublishedView = [&]() {
        if (nativeAwdlAttachTraceInvalidated_ ||
            nativeAwdlAttachTracePublishVersion_ == UINT32_MAX)
            return;
        const uint32_t writingVersion =
            nativeAwdlAttachTracePublishVersion_ + 1u;
        if ((writingVersion & 1u) == 0 ||
            !setNativeAwdlAttachTraceProperty(
                controller, "SnapshotVersionBegin", writingVersion, 32))
            return;
        nativeAwdlAttachTraceInvalidated_ = true;
        (void)setNativeAwdlAttachTraceProperty(
            controller, "SnapshotComplete", 0, 32);
    };

    const NativeAwdlBSD::AttachTraceSnapshot source =
        NativeAwdlBSD::attachSnapshot();
    if (!stableAttachTraceSnapshot(source)) {
        invalidatePublishedView();
        return;
    }
    if (!source.attempted || source.attemptSerial == 0) {
        invalidatePublishedView();
        return;
    }
    // Lookup success anchors the attempt but leaves the producer active until
    // attach returns. Never publish the intermediate lookup-success state.
    if (source.producerActive || !source.done) {
        invalidatePublishedView();
        return;
    }
    if ((source.failed && !source.failurePresent) ||
        (!source.failed && source.failurePresent) ||
        (source.failureResultPresent && !source.failurePresent) ||
        (source.failureResultPresent && source.failureResultDomain == 0) ||
        (source.lookupResultPresent && source.lookupResultDomain == 0)) {
        invalidatePublishedView();
        return;
    }

    const NativeAwdlLifecycle::Snapshot lifecycleBefore =
        NativeAwdlLifecycle::snapshot();
    NativeAwdlLifecycle::Snapshot lifecycleFence{};
    NativeAwdlBSD::Snapshot dataFence{};
    dataFence = NativeAwdlBSD::snapshot();
    if (!terminalAttachLifecycle(lifecycleBefore) ||
        (dataFence.value[NativeAwdlBSD::Closing] != 0 &&
         lifecycleBefore.phase != 12))
        return; // Startup, active retirement, or teardown is still in flight.

    if (nativeAwdlAttachTracePublishedOnce_ &&
        nativeAwdlAttachTracePublishedRevision_ == source.revision &&
        !nativeAwdlAttachTraceInvalidated_)
        return;
    if (nativeAwdlAttachTracePublishVersion_ > UINT32_MAX - 2u)
        return;

    const uint32_t publishedVersion =
        nativeAwdlAttachTracePublishVersion_ + 2u;
    const uint32_t writingVersion = publishedVersion - 1u;
    if (!setNativeAwdlAttachTraceProperty(
            controller, "SnapshotVersionBegin", writingVersion, 32))
        return;
    nativeAwdlAttachTraceInvalidated_ = true;

    bool writesOk = setNativeAwdlAttachTraceProperty(
        controller, "SnapshotComplete", 0, 32);
#define ATTACH_TRACE_SET32(name, value) \
    do { if (writesOk) writesOk = setNativeAwdlAttachTraceProperty( \
        controller, name, static_cast<uint32_t>(value), 32); } while (0)
#define ATTACH_TRACE_SET64(name, value) \
    do { if (writesOk) writesOk = setNativeAwdlAttachTraceProperty( \
        controller, name, static_cast<uint64_t>(value), 64); } while (0)
    ATTACH_TRACE_SET32("SourceVersionBegin", source.versionBegin);
    ATTACH_TRACE_SET32("SourceVersionEnd", source.versionEnd);
    ATTACH_TRACE_SET32("SourceVersionComplete", source.complete);
    ATTACH_TRACE_SET32("SchemaVersion", source.schemaVersion);
    ATTACH_TRACE_SET64("Revision", source.revision);
    ATTACH_TRACE_SET64("AttemptSerial", source.attemptSerial);
    ATTACH_TRACE_SET32("LookupResultPresent", source.lookupResultPresent);
    ATTACH_TRACE_SET32("LookupResultDomain", source.lookupResultDomain);
    ATTACH_TRACE_SET64("LookupResultValue", source.lookupResultValue);
    ATTACH_TRACE_SET32("Attempted", source.attempted);
    ATTACH_TRACE_SET32("BridgeEntered", source.bridgeEntered);
    ATTACH_TRACE_SET32("ProducerActive", source.producerActive);
    ATTACH_TRACE_SET32("Done", source.done);
    ATTACH_TRACE_SET32("Failed", source.failed);
    ATTACH_TRACE_SET32("Stage", source.stage);
    ATTACH_TRACE_SET32("FailurePresent", source.failurePresent);
    ATTACH_TRACE_SET32("FailureStage", source.failureStage);
    ATTACH_TRACE_SET32("FailureResultPresent", source.failureResultPresent);
    ATTACH_TRACE_SET32("FailureResultDomain", source.failureResultDomain);
    ATTACH_TRACE_SET64("FailureResultValue", source.failureResultValue);
    ATTACH_TRACE_SET32("InputGuardPresent", source.inputGuardPresent);
    ATTACH_TRACE_SET32("InputGuardCode", source.inputGuardCode);
    ATTACH_TRACE_SET32("LiveAddressReadResultPresent",
                       source.liveAddressReadResultPresent);
    ATTACH_TRACE_SET32("LiveAddressReadResultDomain",
                       source.liveAddressReadResultDomain);
    ATTACH_TRACE_SET64("LiveAddressReadResultValue",
                       source.liveAddressReadResultValue);
    ATTACH_TRACE_SET32("LiveAddressMatchPresent",
                       source.liveAddressMatchPresent);
    ATTACH_TRACE_SET32("LiveAddressMatch", source.liveAddressMatch);
    ATTACH_TRACE_SET32("ClaimAttempted", source.claimAttempted);
    ATTACH_TRACE_SET32("ClaimSucceeded", source.claimSucceeded);
    ATTACH_TRACE_SET32("LockAllocationPresent", source.lockAllocationPresent);
    ATTACH_TRACE_SET32("LockAllocated", source.lockAllocated);
    ATTACH_TRACE_SET32("IfnetReferenceResultPresent",
                       source.ifnetReferenceResultPresent);
    ATTACH_TRACE_SET32("IfnetReferenceResultDomain",
                       source.ifnetReferenceResultDomain);
    ATTACH_TRACE_SET64("IfnetReferenceResultValue",
                       source.ifnetReferenceResultValue);
    ATTACH_TRACE_SET32("CanAttachResultPresent", source.canAttachResultPresent);
    ATTACH_TRACE_SET32("CanAttachResultDomain", source.canAttachResultDomain);
    ATTACH_TRACE_SET32("CanAttachResultValue", source.canAttachResultValue);
    ATTACH_TRACE_SET32("InterfaceBound", source.interfaceBound);
    ATTACH_TRACE_SET32("IfFilterAttachResultPresent",
                       source.ifFilterAttachResultPresent);
    ATTACH_TRACE_SET32("IfFilterAttachResultDomain",
                       source.ifFilterAttachResultDomain);
    ATTACH_TRACE_SET64("IfFilterAttachResultValue",
                       source.ifFilterAttachResultValue);
    ATTACH_TRACE_SET32("SetOffloadResultPresent",
                       source.setOffloadResultPresent);
    ATTACH_TRACE_SET32("SetOffloadResultDomain",
                       source.setOffloadResultDomain);
    ATTACH_TRACE_SET64("SetOffloadResultValue", source.setOffloadResultValue);
    ATTACH_TRACE_SET32("SetMtuResultPresent", source.setMtuResultPresent);
    ATTACH_TRACE_SET32("SetMtuResultDomain", source.setMtuResultDomain);
    ATTACH_TRACE_SET64("SetMtuResultValue", source.setMtuResultValue);
    ATTACH_TRACE_SET32("SetFlagsResultPresent", source.setFlagsResultPresent);
    ATTACH_TRACE_SET32("SetFlagsResultDomain", source.setFlagsResultDomain);
    ATTACH_TRACE_SET64("SetFlagsResultValue", source.setFlagsResultValue);
    ATTACH_TRACE_SET32("Ipv6ResultPresent", source.ipv6ResultPresent);
    ATTACH_TRACE_SET32("Ipv6ResultDomain", source.ipv6ResultDomain);
    ATTACH_TRACE_SET64("Ipv6ResultValue", source.ipv6ResultValue);
    ATTACH_TRACE_SET32("Ipv6HasLinkLocalPresent",
                       source.ipv6HasLinkLocalPresent);
    ATTACH_TRACE_SET32("Ipv6HasLinkLocal", source.ipv6HasLinkLocal);
    ATTACH_TRACE_SET32("FinalReadyResultPresent",
                       source.finalReadyResultPresent);
    ATTACH_TRACE_SET32("FinalReadyResultDomain",
                       source.finalReadyResultDomain);
    ATTACH_TRACE_SET32("FinalReadyResultValue",
                       source.finalReadyResultValue);

    NativeAwdlBSD::AttachTraceSnapshot sourceFence =
        NativeAwdlBSD::attachSnapshot();
    lifecycleFence = NativeAwdlLifecycle::snapshot();
    dataFence = NativeAwdlBSD::snapshot();
    if (!writesOk || !publicationSafe() ||
        !sameAttachTraceSnapshotFence(source, sourceFence) ||
        sourceFence.revision != source.revision ||
        !terminalAttachLifecycle(lifecycleFence) ||
        !sameAttachLifecycleFence(lifecycleBefore, lifecycleFence) ||
        (dataFence.value[NativeAwdlBSD::Closing] != 0 &&
         lifecycleFence.phase != 12))
        return;

    if (!setNativeAwdlAttachTraceProperty(
            controller, "SnapshotComplete", 1, 32) ||
        !setNativeAwdlAttachTraceProperty(
            controller, "SnapshotVersionEnd", publishedVersion, 32))
        return;

    sourceFence = NativeAwdlBSD::attachSnapshot();
    lifecycleFence = NativeAwdlLifecycle::snapshot();
    dataFence = NativeAwdlBSD::snapshot();
    if (!publicationSafe() ||
        !sameAttachTraceSnapshotFence(source, sourceFence) ||
        sourceFence.revision != source.revision ||
        !terminalAttachLifecycle(lifecycleFence) ||
        !sameAttachLifecycleFence(lifecycleBefore, lifecycleFence) ||
        (dataFence.value[NativeAwdlBSD::Closing] != 0 &&
         lifecycleFence.phase != 12))
        return;
    if (!setNativeAwdlAttachTraceProperty(
            controller, "SnapshotVersionBegin", publishedVersion, 32))
        return;

    sourceFence = NativeAwdlBSD::attachSnapshot();
    lifecycleFence = NativeAwdlLifecycle::snapshot();
    dataFence = NativeAwdlBSD::snapshot();
    if (!publicationSafe() ||
        !sameAttachTraceSnapshotFence(source, sourceFence) ||
        sourceFence.revision != source.revision ||
        !terminalAttachLifecycle(lifecycleFence) ||
        !sameAttachLifecycleFence(lifecycleBefore, lifecycleFence) ||
        (dataFence.value[NativeAwdlBSD::Closing] != 0 &&
         lifecycleFence.phase != 12)) {
        const uint32_t invalidVersion = publishedVersion + 1u;
        (void)setNativeAwdlAttachTraceProperty(
            controller, "SnapshotVersionBegin", invalidVersion, 32);
        (void)setNativeAwdlAttachTraceProperty(
            controller, "SnapshotComplete", 0, 32);
        return;
    }

    nativeAwdlAttachTracePublishedRevision_ = source.revision;
    nativeAwdlAttachTracePublishVersion_ = publishedVersion;
    nativeAwdlAttachTracePublishedOnce_ = true;
    nativeAwdlAttachTraceInvalidated_ = false;
#undef ATTACH_TRACE_SET32
#undef ATTACH_TRACE_SET64
#else
    (void)controller;
#endif
}

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
    const uint64_t hostUs = tahoeP2pRxMonotonicUs();
    const IntelP2PRx::RouteResult route =
        tahoe_p2p_rx_router_.captureTimeEvent(bytes, length, lease);

    // TIME_EVENT_NOTIFICATION is a separate 24-byte ABI. Record it only when
    // the existing dispatcher supplies a complete exact-length payload and
    // the current trace owner is the same lease; no RX-path parser is added.
    const auto traceOwner = nativeAwdlRxEventTimeline_.snapshot();
    const uint32_t rocGeneration = __atomic_load_n(
        &nativeP2pRocGeneration_, __ATOMIC_ACQUIRE);
    const NativeAwdlRxTrace::Epochs traceEpochs {
        static_cast<uint32_t>(lease.contextGeneration),
        static_cast<uint32_t>(lease.powerGeneration),
        static_cast<uint32_t>(lease.stationGeneration), rocGeneration
    };
    if (bytes && length == 24 && nativeAwdlRxEventOwnerSerial_ != 0 &&
        traceOwner.ownerPresent && traceOwner.active &&
        traceOwner.ownerSerial == nativeAwdlRxEventOwnerSerial_ &&
        NativeAwdlRxTrace::sameEpochs(traceOwner.epochs, traceEpochs)) {
        NativeAwdlRxTrace::TimeEvent24 event{};
        event.hostMonotonicUs = hostUs;
        event.hostMonotonicPresent = 1;
        event.rawLength = static_cast<uint32_t>(length);
        event.timestamp = tahoeP2pReadLe32(bytes + 0);
        event.sessionId = tahoeP2pReadLe32(bytes + 4);
        event.uniqueId = tahoeP2pReadLe32(bytes + 8);
        event.macIdAndColor = tahoeP2pReadLe32(bytes + 12);
        event.rawAction = tahoeP2pReadLe32(bytes + 16);
        event.rawStatus = tahoeP2pReadLe32(bytes + 20);
        event.leaseUidKnown = lease.timeEventUidKnown ? 1u : 0u;
        event.leaseExpectedUid = lease.timeEventUid;
        event.matchStatusPresent = 1;
        event.matchStatus = static_cast<uint32_t>(route);
        (void)nativeAwdlRxEventTimeline_.recordTimeEvent(
            event, traceEpochs, nativeAwdlRxEventOwnerSerial_);
    }
}

void ItlIwx::tahoeP2pTapAction(struct iwx_softc *sc, const uint8_t *frame,
                             size_t length, bool wasProtected, uint16_t channel,
                             uint32_t gp2TimestampUs, bool gp2TimestampPresent,
                             uint32_t rxMacPhyIndex,
                             bool rxMacPhyIndexPresent)
{
    if (!sc || !getMainWorkLoop() || !getMainWorkLoop()->inGate())
        return;
    auto lease = tahoe_p2p_rx_lease_;
    if (!lease.active)
        return;
    lease.currentPowerGeneration = uint64_t(uint32_t(sc->sc_generation));
    lease.currentStationGeneration = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);

    NativeAwdlRxTrace::EventToken traceToken{};
    const uint32_t rocGeneration = __atomic_load_n(
        &nativeP2pRocGeneration_, __ATOMIC_ACQUIRE);
    const auto traceOwner = nativeAwdlRxEventTimeline_.snapshot();
    const NativeAwdlRxTrace::Epochs traceEpochs {
        static_cast<uint32_t>(lease.contextGeneration),
        static_cast<uint32_t>(lease.powerGeneration),
        static_cast<uint32_t>(lease.stationGeneration),
        rocGeneration
    };
    const bool traceOwnerMatches = nativeAwdlRxEventOwnerSerial_ != 0 &&
        traceOwner.ownerPresent &&
        traceOwner.ownerSerial == nativeAwdlRxEventOwnerSerial_ &&
        NativeAwdlRxTrace::sameEpochs(traceOwner.epochs, traceEpochs);
    IOEthernetController *controller = getController();
    const uint32_t armMode = __atomic_load_n(
        &nativeP2pManualArmRequested_, __ATOMIC_ACQUIRE);
    const bool receiveObservationOnly = __atomic_load_n(
        &sc->sc_p2p_roc.receive_observation_only, __ATOMIC_ACQUIRE) != 0;
    const bool rx149ProfilePath = armMode ==
            NativeP2PRx149Observation::kRx149ArmMode ||
        (controller && controller->getProperty(
            "NativeP2PRx149ObservationOnly") == kOSBooleanTrue) ||
        receiveObservationOnly;
    if (rx149ProfilePath) {
        const auto session = nativeP2pRocEvents_.snapshot();
        const auto evidence = currentRx149ActionEvidence(
            this, sc, lease, channel, session, traceOwner);
        if (!NativeP2PRx149Observation::mayConsumeManagementAction(evidence))
            return; // Never queue pre-START, stale-owner, or non-149 Actions.
    }
    if (traceOwnerMatches && frame && length >= 2) {
        NativeAwdlRxTrace::ActionTap tap{};
        const uint64_t hostUs = tahoeP2pRxMonotonicUs();
        tap.hostMonotonicUs = hostUs;
        tap.hostMonotonicPresent = 1;
        tap.rawLength = static_cast<uint32_t>(length > UINT32_MAX ?
                                               UINT32_MAX : length);
        uint16_t rawFrameControl = 0;
        memcpy(&rawFrameControl, frame, sizeof(rawFrameControl));
        const uint32_t frameControl = le16toh(rawFrameControl);
        tap.frameControlPresent = 1;
        tap.frameControl = frameControl;
        tap.frameType = (frameControl >> 2) & 0x3;
        tap.frameSubtype = (frameControl >> 4) & 0xf;
        if (length >= 16) {
            tap.sourceAddress = frame + 10;
            tap.sourceAddressLength = 6;
        }
        if (length >= 24) {
            uint16_t rawSequenceControl = 0;
            memcpy(&rawSequenceControl, frame + 22, sizeof(rawSequenceControl));
            tap.sequenceControlPresent = 1;
            tap.sequenceControl = le16toh(rawSequenceControl);
        }
        tap.channelIndex = channel;
        tap.rxGp2Present = gp2TimestampPresent ? 1u : 0u;
        tap.rxGp2Us = gp2TimestampUs;
        tap.rxMacPhyIndexPresent = rxMacPhyIndexPresent ? 1u : 0u;
        tap.rxMacPhyIndex = rxMacPhyIndex;
        traceToken = nativeAwdlRxEventTimeline_.recordActionTap(tap);
    }

    // The RX descriptor's mac_phy_idx has not yet been proven to carry the
    // complete MAC ID/color. Preserve unknown affinity, never infer it from
    // an AWDL vendor body or from the infrastructure BSSID.
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    const auto session=nativeP2pRocEvents_.snapshot();
    const bool current=NativeP2PRx149Observation::nativeDataPathAllowed(
            rx149ProfilePath) &&
        lease.contextGeneration==lease.currentContextGeneration&&
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
    IntelP2PRx::ParseObservation parseObservation{};
    const IntelP2PRx::RouteResult route =
        tahoe_p2p_rx_router_.tapActionFrame(
            frame, length, wasProtected, channel, false, 0, lease,
            tahoeP2pRxMonotonicUs(), gp2TimestampUs, gp2TimestampPresent,
            traceToken.queueSerial ? &traceToken : nullptr,
            traceOwnerMatches ? &parseObservation : nullptr);
    if (traceOwnerMatches && traceToken.rowPresent) {
        if (parseObservation.attempted || parseObservation.resultPresent) {
            NativeAwdlRxTrace::ParseResult parse{};
            parse.attempted = parseObservation.attempted;
            parse.resultPresent = parseObservation.resultPresent;
            parse.status = static_cast<uint32_t>(parseObservation.status);
            parse.rejectReason = static_cast<uint32_t>(
                parseObservation.diagnostics.reason);
            parse.rejectSubtype = parseObservation.diagnostics.subtype;
            parse.tlvType = parseObservation.diagnostics.tlvType;
            parse.expectedTlvType = parseObservation.diagnostics.expectedType;
            parse.tlvOffset = static_cast<uint32_t>(
                parseObservation.diagnostics.tlvOffset);
            parse.declaredLength = static_cast<uint32_t>(
                parseObservation.diagnostics.declaredLen);
            parse.availableLength = static_cast<uint32_t>(
                parseObservation.diagnostics.availableLen);
            (void)nativeAwdlRxEventTimeline_.setParseResult(traceToken, parse);
        }
        (void)nativeAwdlRxEventTimeline_.setParsedAction(
            traceToken, parseObservation.subtypePresent,
            parseObservation.subtype, parseObservation.actionInfoPresent,
            parseObservation.actionInfo.phyTx,
            parseObservation.actionInfo.targetTx);
        const bool queued = route == IntelP2PRx::RouteResult::kCapturedExact ||
            route == IntelP2PRx::RouteResult::kCapturedUnknownContext;
        NativeAwdlRxTrace::RouteResult routeEvidence{};
        routeEvidence.attempted = 1;
        routeEvidence.resultPresent = 1;
        routeEvidence.status = static_cast<uint32_t>(route);
        routeEvidence.queueAccepted = queued ? 1u : 0u;
        (void)nativeAwdlRxEventTimeline_.setRouteResult(traceToken,
                                                        routeEvidence);
        (void)nativeAwdlRxEventTimeline_.markQueued(traceToken, queued);
    } else if (traceOwnerMatches && traceToken.queueSerial &&
               (route == IntelP2PRx::RouteResult::kCapturedExact ||
                route == IntelP2PRx::RouteResult::kCapturedUnknownContext)) {
        (void)nativeAwdlRxEventTimeline_.markQueued(traceToken, true);
    }
}

bool ItlIwx::tahoeP2pCurrentRxDiagnosticEpochs(
    struct iwx_softc *sc, NativeAwdlRxEntry::Epochs *epochs)
{
    if (!sc || !epochs || !tahoeP2pOnMainGate())
        return false;
    const auto &lease = tahoe_p2p_rx_lease_;
    // Most RX traffic has no active manual P2P lease. Reject it before
    // sampling the ROC reducer or host clock.
    if (!lease.active || lease.contextGeneration == 0 ||
        lease.powerGeneration == 0 || lease.stationGeneration == 0 ||
        lease.contextGeneration != lease.currentContextGeneration ||
        lease.contextGeneration != nativeP2pProbeGeneration_ ||
        lease.powerGeneration != lease.currentPowerGeneration ||
        lease.stationGeneration != lease.currentStationGeneration)
        return false;
    const uint32_t currentPower = uint32_t(sc->sc_generation);
    const uint32_t currentStation = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    if (lease.powerGeneration != currentPower ||
        lease.powerGeneration != uint32_t(sc->sc_p2p.fw_generation) ||
        lease.stationGeneration != currentStation)
        return false;
    const uint32_t currentRoc = __atomic_load_n(
        &nativeP2pRocGeneration_, __ATOMIC_ACQUIRE);
    if (currentRoc == 0)
        return false;
    const auto session = nativeP2pRocEvents_.snapshot();
    const uint64_t nowUs = tahoeP2pRxMonotonicUs();
    if (session.generation != lease.contextGeneration ||
        session.generation != currentRoc || !session.commandReturned ||
        session.commandResult != 0 ||
        session.configuration != IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION ||
        !session.startSeen || session.startStatus != 1 ||
        session.endSeen || session.outcomeUnknown ||
        !NativeAwdlRxEntry::withinDiagnosticWindow(
            nowUs, session.startObservedMonotonicUs) ||
        sc->sc_p2p_roc.token != session.generation ||
        sc->sc_p2p_roc.phase != IWX_P2P_ROC_SESSION_ACKED)
        return false;

    epochs->contextGeneration = uint32_t(lease.contextGeneration);
    epochs->powerGeneration = uint32_t(lease.powerGeneration);
    epochs->stationGeneration = uint32_t(lease.stationGeneration);
    epochs->rocGeneration = session.generation;
    return true;
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
    // The watchdog owns publication. A short main-gate consumer is also used
    // by probe paths that need timely RX evidence without nested publishers.
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
    tahoeP2pRxConsume();

    // Publish with a fresh epoch/time sample after consumption. This keeps the
    // publisher's snapshot current even when this drain was deferred by the
    // watchdog's gate attempt.
    const uint64_t nowUs = tahoeP2pRxMonotonicUs();
    const IntelAwdlPeer::RuntimeEpochs epochs {
        nativeP2pProbeGeneration_, uint64_t(uint32_t(com.sc_generation)),
        __atomic_load_n(&com.sc_tx_rate_generation, __ATOMIC_ACQUIRE),
        nativeP2pProbeGeneration_ != 0 && com.sc_ic.ic_state == IEEE80211_S_RUN &&
            (com.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR)) == 0
    };
    tahoeP2pPublishPeerRuntime();
    const auto peer = tahoe_awdl_peer_observer_.snapshot(epochs, nowUs);
    auto controller = getController();
    if (!controller)
        return;
    tahoeP2pPublishRxStageCounters(controller);
    tahoeP2pPublishRxEntryTelemetry(controller);
    tahoePublishResetTrace(controller);
    tahoeP2pPublishRxEventTimeline(controller);
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    const auto data=NativeAwdlBSD::snapshot();
    controller->setProperty("NativeAwdlResidentCompiled",kOSBooleanTrue);
    const char *names[]={
        "NativeAwdlDataAttached",
        "NativeAwdlDataClosing",
        "NativeAwdlDataDetached",
        "NativeAwdlDataLinkReady",
        "NativeAwdlDataTxAccepted",
        "NativeAwdlDataTxRejected",
        "NativeAwdlDataTxExpired",
        "NativeAwdlDataTxEncoded",
        "NativeAwdlDataTxSubmitted",
        "NativeAwdlDataTxCompleted",
        "NativeAwdlDataTxSucceeded",
        "NativeAwdlDataTxFailed",
        "NativeAwdlDataTxStaleCompletion",
        "NativeAwdlDataRxCaptured",
        "NativeAwdlDataRxRejected",
        "NativeAwdlDataRxQueueFull",
        "NativeAwdlDataRxDecoded",
        "NativeAwdlDataRxDelivered",
        "NativeAwdlDataRxInputFailed",
        "NativeAwdlDataTxPending",
        "NativeAwdlDataRxPending",
        "NativeAwdlDataGateChecks",
        "NativeAwdlDataGateAllowed",
        "NativeAwdlDataGateLastBlockers",
        "NativeAwdlDataGateReasonsSeen",
        "NativeAwdlDataIpv6ConfigResult",
        "NativeAwdlDataIpv6Configured",
        "NativeAwdlDataOffloadCapabilities",
        "NativeAwdlDataTxObservationCount",
        "NativeAwdlDataTxLastEthernetLength",
        "NativeAwdlDataTxLastIpv6Length",
        "NativeAwdlDataTxLastUdpLength",
        "NativeAwdlDataTxLastIpv6NextHeader",
        "NativeAwdlDataTxLastSourceEui64MatchesOwn",
        "NativeAwdlDataTxLastUdpHasMdnsPort",
        "NativeAwdlDataTxLastIpv6DestinationIsMulticast",
        "NativeAwdlDataTxLastEthernetMulticastMappingMatches",
        "NativeAwdlDataTxLastUdpChecksumStatus",
        "NativeAwdlDataTxLastIpv6PacketWellFormed",
        "NativeAwdlDataTxLastSourceIsLinkLocal",
        "NativeAwdlDataTxChecksumStatusSeenMask",
        "NativeAwdlDataTxSourceEui64MismatchCount",
        "NativeAwdlDataTxMulticastMappingMismatchCount",
        "NativeAwdlDataTxMalformedCount",
        "NativeAwdlDataTxMdnsLegacyAttempts",
        "NativeAwdlDataTxMdnsQuAttempts",
        "NativeAwdlDataTxMdnsQmAttempts",
        "NativeAwdlDataTxMdnsOtherAttempts",
        "NativeAwdlDataTxMdnsUnknownAttempts",
        "NativeAwdlDataTxMdnsLegacySubmitted",
        "NativeAwdlDataTxMdnsQuSubmitted",
        "NativeAwdlDataTxMdnsQmSubmitted",
        "NativeAwdlDataTxMdnsOtherSubmitted",
        "NativeAwdlDataTxMdnsUnknownSubmitted",
        "NativeAwdlDataTxMdnsLegacyCompleted",
        "NativeAwdlDataTxMdnsQuCompleted",
        "NativeAwdlDataTxMdnsQmCompleted",
        "NativeAwdlDataTxMdnsOtherCompleted",
        "NativeAwdlDataTxMdnsUnknownCompleted",
        "NativeAwdlDataTxMdnsLegacySucceeded",
        "NativeAwdlDataTxMdnsQuSucceeded",
        "NativeAwdlDataTxMdnsQmSucceeded",
        "NativeAwdlDataTxMdnsOtherSucceeded",
        "NativeAwdlDataTxMdnsUnknownSucceeded",
        "NativeAwdlDataTxMdnsSubmitFailed",
        "NativeAwdlDataTxMdnsCompletionFailed",
        "NativeAwdlDataTxMdnsLastClass",
        "NativeAwdlDataTxMdnsLastSourcePortIs5353",
        "NativeAwdlDataTxMdnsLastDestinationPortIs5353",
        "NativeAwdlDataTxMdnsLastDestinationIsFf02Fb",
        "NativeAwdlDataTxMdnsLastDnsHeaderParsed",
        "NativeAwdlDataTxMdnsLastQr",
        "NativeAwdlDataTxMdnsLastTc",
        "NativeAwdlDataTxMdnsLastQuestionCount",
        "NativeAwdlDataTxMdnsLastTargetPtrInQuestionCount",
        "NativeAwdlDataTxMdnsLastQuQuestionMask",
        "NativeAwdlDataTxMdnsLastAttemptToken"};
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
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    // Attach evidence is emitted only from this existing periodic main-gate
    // drain after its producer and any probe owner have reached a safe point.
    tahoeP2pPublishNativeAwdlAttachTrace(controller);
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

void ItlIwx::tahoeP2pRxConsume()
{
    if (!tahoeP2pOnMainGate())
        return;

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
    NativeAwdlRxEntry::Epochs rxEntryEpochs{};
    if (tahoeP2pCurrentRxDiagnosticEpochs(&com, &rxEntryEpochs)) {
        nativeAwdlRxEntryTelemetry_.beginOwner(rxEntryEpochs);
    } else {
        const auto rxEntry = nativeAwdlRxEntryTelemetry_.snapshot();
        nativeAwdlRxEntryTelemetry_.endOwner(rxEntry.epochs);
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
            IntelAwdlPeerRuntime::ObserveEvidence tableEvidence{};
            const auto tableResult = tahoe_awdl_peer_runtime_.observe(
                record.payload.actionFrame, epochs, nowUs, &tableEvidence);
            tahoe_awdl_runtime_last_result_ = static_cast<uint32_t>(
                tableResult);
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

            const auto &traceToken = record.payload.actionFrame.traceToken;
            if (traceToken.queueSerial) {
                NativeAwdlRxTrace::TableResult tableTrace{};
                tableTrace.attempted = 1;
                tableTrace.resultPresent = 1;
                tableTrace.status = static_cast<uint32_t>(tableResult);
                NativeAwdlRxTrace::ObserverResult observerTrace{};
                observerTrace.attempted = 1;
                observerTrace.resultPresent = 1;
                observerTrace.status = static_cast<uint32_t>(result);
                NativeAwdlRxTrace::DecodeResult decodeTrace{};
                decodeTrace.attempted = tableEvidence.decodeAttempted;
                decodeTrace.resultPresent = tableEvidence.decodeResultPresent;
                decodeTrace.status = tableEvidence.decodeStatus;
                decodeTrace.rejectStage = static_cast<uint32_t>(
                    tableEvidence.decodeDiagnostics.rejectStage);
                decodeTrace.offendingTlvType =
                    tableEvidence.decodeDiagnostics.offendingTlvType;
                decodeTrace.relatedTlvType =
                    tableEvidence.decodeDiagnostics.relatedTlvType;
                (void)nativeAwdlRxEventTimeline_.completeRx(
                    traceToken, tableTrace, observerTrace, decodeTrace);
            }
        }
    }
    bzero(&record, sizeof(record));
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

void ItlIwx::tahoeP2pPublishRxEntryTelemetry(IOEthernetController *controller)
{
    if (!controller || !tahoeP2pOnMainGate())
        return;
    const auto current = nativeAwdlRxEntryTelemetry_.snapshot();
    // Publish only a completed window. RX can drain from the hot ROC loop;
    // allocating dozens of IORegistry numbers per packet would perturb it.
    if (current.active)
        return;
    if (nativeAwdlRxEntryPublishedOnce_ &&
        sameRxEntrySnapshot(current, nativeAwdlRxEntryPublished_))
        return;

    auto write = [controller](const char *name, uint32_t value) {
        return controller->setProperty(name, value, 32);
    };
    NativeAwdlRxEntryPublisher::publish(
        nativeAwdlRxEntryAttemptVersion_, nativeAwdlRxEntryPublishVersion_,
        nativeAwdlRxEntryPublishedOnce_, nativeAwdlRxEntryPublished_, current,
        write, [&]() -> bool {
            if (!write("NativeP2PRxEntrySchema", current.schema)) return false;
            if (!write("NativeP2PRxEntryActive", current.active)) return false;
            if (!write("NativeP2PRxEntryContextGeneration",
                       current.epochs.contextGeneration)) return false;
            if (!write("NativeP2PRxEntryPowerGeneration",
                       current.epochs.powerGeneration)) return false;
            if (!write("NativeP2PRxEntryStationGeneration",
                       current.epochs.stationGeneration)) return false;
            if (!write("NativeP2PRxEntryRocGeneration",
                       current.epochs.rocGeneration)) return false;

            const char *counterNames[NativeAwdlRxEntry::CounterCount] = {
                "NativeP2PRxEntryCountOwnerGateEntries",
                "NativeP2PRxEntryCountStatusTruncated",
                "NativeP2PRxEntryCountCrcRejected",
                "NativeP2PRxEntryCountOverrunRejected",
                "NativeP2PRxEntryCountMpduLengthShort",
                "NativeP2PRxEntryCountDescriptorTruncated",
                "NativeP2PRxEntryCountPayloadTruncated",
                "NativeP2PRxEntryCountCapacityOverflow",
                "NativeP2PRxEntryCountFullDescriptor",
                "NativeP2PRxEntryCountFrameControlValid",
                "NativeP2PRxEntryCountManagementFrame",
                "NativeP2PRxEntryCountControlFrame",
                "NativeP2PRxEntryCountDataFrame",
                "NativeP2PRxEntryCountReservedFrame",
                "NativeP2PRxEntryCountQosDataFrame",
                "NativeP2PRxEntryCountAwdlBssidCandidate",
                "NativeP2PRxEntryCountFilterMatchAvailable",
                "NativeP2PRxEntryCountFilterMatchUnavailable"
            };
            for (unsigned i = 0; i < NativeAwdlRxEntry::CounterCount; ++i)
                if (!write(counterNames[i], current.counts[i])) return false;

            const char *lastDescriptorNames[] = {
                "NativeP2PRxEntryLastDescriptorPresent",
                "NativeP2PRxEntryLastDescriptorContextGeneration",
                "NativeP2PRxEntryLastDescriptorPowerGeneration",
                "NativeP2PRxEntryLastDescriptorStationGeneration",
                "NativeP2PRxEntryLastDescriptorRocGeneration",
                "NativeP2PRxEntryLastDescriptorPayloadLength",
                "NativeP2PRxEntryLastDescriptorDmaCapacity",
                "NativeP2PRxEntryLastDescriptorDescriptorSize",
                "NativeP2PRxEntryLastDescriptorVersion",
                "NativeP2PRxEntryLastDescriptorMpduLength",
                "NativeP2PRxEntryLastDescriptorStatusPresent",
                "NativeP2PRxEntryLastDescriptorStatus",
                "NativeP2PRxEntryLastDescriptorMacPhyIndexPresent",
                "NativeP2PRxEntryLastDescriptorMacPhyIndex",
                "NativeP2PRxEntryLastDescriptorFilterMatchPresent",
                "NativeP2PRxEntryLastDescriptorFilterMatch",
                "NativeP2PRxEntryLastDescriptorRpaEnabled",
                "NativeP2PRxEntryLastDescriptorChannelPresent",
                "NativeP2PRxEntryLastDescriptorChannel",
                "NativeP2PRxEntryLastDescriptorFrameControlPresent",
                "NativeP2PRxEntryLastDescriptorFrameControl",
                "NativeP2PRxEntryLastDescriptorFrameType",
                "NativeP2PRxEntryLastDescriptorFrameSubtype",
                "NativeP2PRxEntryLastDescriptorToDs",
                "NativeP2PRxEntryLastDescriptorFromDs",
                "NativeP2PRxEntryLastDescriptorAwdlBssidCandidate"
            };
            const auto &descriptor = current.lastDescriptor;
            const uint32_t descriptorValues[] = {
                descriptor.present, descriptor.contextGeneration,
                descriptor.powerGeneration, descriptor.stationGeneration,
                descriptor.rocGeneration, descriptor.payloadLength,
                descriptor.dmaCapacity, descriptor.descriptorSize,
                descriptor.descriptorVersion, descriptor.mpduLength,
                descriptor.statusPresent, descriptor.status,
                descriptor.macPhyIndexPresent, descriptor.macPhyIndex,
                descriptor.filterMatchPresent, descriptor.filterMatch,
                descriptor.rpaEnabled, descriptor.channelPresent, descriptor.channel,
                descriptor.frameControlPresent, descriptor.frameControl,
                descriptor.frameType, descriptor.frameSubtype, descriptor.toDs,
                descriptor.fromDs, descriptor.awdlBssidCandidate
            };
            for (unsigned i = 0; i < sizeof(descriptorValues) / sizeof(descriptorValues[0]);
                 ++i)
                if (!write(lastDescriptorNames[i], descriptorValues[i])) return false;

            const char *lastCandidateNames[] = {
                "NativeP2PRxEntryLastAwdlDataCandidatePresent",
                "NativeP2PRxEntryLastAwdlDataCandidateContextGeneration",
                "NativeP2PRxEntryLastAwdlDataCandidatePowerGeneration",
                "NativeP2PRxEntryLastAwdlDataCandidateStationGeneration",
                "NativeP2PRxEntryLastAwdlDataCandidateRocGeneration",
                "NativeP2PRxEntryLastAwdlDataCandidatePayloadLength",
                "NativeP2PRxEntryLastAwdlDataCandidateDmaCapacity",
                "NativeP2PRxEntryLastAwdlDataCandidateDescriptorSize",
                "NativeP2PRxEntryLastAwdlDataCandidateVersion",
                "NativeP2PRxEntryLastAwdlDataCandidateMpduLength",
                "NativeP2PRxEntryLastAwdlDataCandidateStatusPresent",
                "NativeP2PRxEntryLastAwdlDataCandidateStatus",
                "NativeP2PRxEntryLastAwdlDataCandidateMacPhyIndexPresent",
                "NativeP2PRxEntryLastAwdlDataCandidateMacPhyIndex",
                "NativeP2PRxEntryLastAwdlDataCandidateFilterMatchPresent",
                "NativeP2PRxEntryLastAwdlDataCandidateFilterMatch",
                "NativeP2PRxEntryLastAwdlDataCandidateRpaEnabled",
                "NativeP2PRxEntryLastAwdlDataCandidateChannelPresent",
                "NativeP2PRxEntryLastAwdlDataCandidateChannel",
                "NativeP2PRxEntryLastAwdlDataCandidateFrameControlPresent",
                "NativeP2PRxEntryLastAwdlDataCandidateFrameControl",
                "NativeP2PRxEntryLastAwdlDataCandidateFrameType",
                "NativeP2PRxEntryLastAwdlDataCandidateFrameSubtype",
                "NativeP2PRxEntryLastAwdlDataCandidateToDs",
                "NativeP2PRxEntryLastAwdlDataCandidateFromDs",
                "NativeP2PRxEntryLastAwdlDataCandidateAwdlBssidCandidate"
            };
            const auto &candidate = current.lastAwdlDataCandidate;
            const uint32_t candidateValues[] = {
                candidate.present, candidate.contextGeneration,
                candidate.powerGeneration, candidate.stationGeneration,
                candidate.rocGeneration, candidate.payloadLength,
                candidate.dmaCapacity, candidate.descriptorSize,
                candidate.descriptorVersion, candidate.mpduLength,
                candidate.statusPresent, candidate.status,
                candidate.macPhyIndexPresent, candidate.macPhyIndex,
                candidate.filterMatchPresent, candidate.filterMatch,
                candidate.rpaEnabled, candidate.channelPresent, candidate.channel,
                candidate.frameControlPresent, candidate.frameControl,
                candidate.frameType, candidate.frameSubtype, candidate.toDs,
                candidate.fromDs, candidate.awdlBssidCandidate
            };
            for (unsigned i = 0; i < sizeof(candidateValues) / sizeof(candidateValues[0]);
                 ++i)
                if (!write(lastCandidateNames[i], candidateValues[i])) return false;
            return true;
        });
}

void ItlIwx::tahoePublishResetTrace(IOEthernetController *controller)
{
    if (!controller)
        return;
    IwxResetTrace::Snapshot snapshot{};
    if (!nativeResetTrace_.read(&snapshot))
        return;
    const auto publishedWatchdog = OSDynamicCast(OSNumber,
        controller->getProperty("NativeResetTraceTxWatchdogSequence"));
    const bool watchdogUnchanged = publishedWatchdog &&
        publishedWatchdog->unsigned32BitValue() == snapshot.txWatchdogSequence;
    const auto publishedReset = OSDynamicCast(OSNumber,
        controller->getProperty("NativeResetTraceSequence"));
    const bool resetUnchanged = publishedReset &&
        publishedReset->unsigned32BitValue() == snapshot.resetSequence;
    const bool txProgressNeedsPublish =
        com.sc_tx_progress_pending_present &&
        com.sc_tx_progress_pending_watchdog_sequence !=
            nativeResetTracePublishedTxProgressWatchdogSequence_;
    if (nativeResetTracePublishedOnce_ && watchdogUnchanged &&
        snapshot.resetSequence == nativeResetTracePublishedSequence_ &&
        snapshot.lastInitTaskTriggerSequence ==
            nativeResetTracePublishedTriggerSequence_ &&
        snapshot.initTaskTriggerRevision ==
            nativeResetTracePublishedTriggerRevision_ &&
        !txProgressNeedsPublish)
        return;

    // This method is called by the existing main-workloop RX drain, which is
    // also reached from the 1-second watchdog tick. The reset producer only
    // updates atomics; all IORegistry writes stay on this serialized gate.
    uint32_t beginVersion = nativeResetTracePublishVersion_ + 1U;
    if ((beginVersion & 1U) == 0)
        ++beginVersion;
    const uint32_t finishVersion = beginVersion + 1U;
    const uint64_t publishAtMonotonicNs = tahoeP2pRxMonotonicUs() * 1000;
    uint64_t resetPublishAtMonotonicNs = publishAtMonotonicNs;
    if (resetUnchanged) {
        const auto priorResetPublishAt = OSDynamicCast(OSNumber,
            controller->getProperty("NativeResetTraceResetPublishAtMonotonicNs"));
        if (priorResetPublishAt)
            resetPublishAtMonotonicNs = priorResetPublishAt->unsigned64BitValue();
    }
    uint64_t watchdogExpiryPublishAtMonotonicNs = publishAtMonotonicNs;
    if (watchdogUnchanged) {
        const auto priorWatchdogPublishAt = OSDynamicCast(OSNumber,
            controller->getProperty(
                "NativeResetTraceTxWatchdogExpiryPublishAtMonotonicNs"));
        if (priorWatchdogPublishAt)
            watchdogExpiryPublishAtMonotonicNs =
                priorWatchdogPublishAt->unsigned64BitValue();
    }
    controller->setProperty("NativeResetTracePublishVersion",
                            beginVersion, 32);
    controller->setProperty("NativeResetTraceSchema", 3U, 32);
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
    controller->setProperty("NativeResetTraceResetMonotonicNs",
                            snapshot.resetMonotonicNs, 64);
    controller->setProperty("NativeResetTraceResetPublishAtMonotonicNs",
                            resetPublishAtMonotonicNs, 64);
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

    // The watchdog decision is serialized, but STA queue/node writers are
    // not all covered by this gate. Availability=0 is unknown, never empty.
    controller->setProperty("NativeResetTraceTxWatchdogGeneration",
                            snapshot.txWatchdogGeneration, 32);
    controller->setProperty("NativeResetTraceTxWatchdogCountdownAtExpiry",
                            snapshot.txWatchdogCountdownAtExpiry, 32);
    controller->setProperty("NativeResetTraceTxWatchdogArmOutputEpoch",
                            snapshot.txWatchdogArmOutputEpoch, 32);
    controller->setProperty("NativeResetTraceTxWatchdogArmSequence",
                            snapshot.txWatchdogArmSequence, 32);
    controller->setProperty("NativeResetTraceTxWatchdogArmMonotonicNs",
                            snapshot.txWatchdogArmMonotonicNs, 64);
    controller->setProperty("NativeResetTraceTxWatchdogClearOutputEpoch",
                            snapshot.txWatchdogClearOutputEpoch, 32);
    controller->setProperty("NativeResetTraceTxWatchdogClearSequence",
                            snapshot.txWatchdogClearSequence, 32);
    controller->setProperty("NativeResetTraceTxWatchdogClearReason",
                            snapshot.txWatchdogClearReason, 32);
    controller->setProperty("NativeResetTraceTxWatchdogClearMonotonicNs",
                            snapshot.txWatchdogClearMonotonicNs, 64);
    controller->setProperty("NativeResetTraceTxWatchdogExpiryMonotonicNs",
                            snapshot.txWatchdogExpiryMonotonicNs, 64);
    controller->setProperty("NativeResetTraceTxWatchdogProducerSnapshotAvailable",
                            snapshot.txWatchdogProducerSnapshotAvailable, 32);
    controller->setProperty("NativeResetTraceTxWatchdogExpiryPublishAtMonotonicNs",
                            watchdogExpiryPublishAtMonotonicNs, 64);
    controller->setProperty("NativeResetTraceTxWatchdogQueueSnapshotAvailable",
                            snapshot.txWatchdogQueueSnapshotAvailable, 32);
    controller->setProperty("NativeResetTraceTxWatchdogSequence",
                            snapshot.txWatchdogSequence, 32);

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
    // TX progress is a larger batch. Publish it only after the watchdog's
    // recovery enqueue has returned, on this existing periodic main-gate
    // drain. If its seqlock begin/body fails, the owner sequence is not marked
    // published and the next drain retries it.
    tahoePublishTxProgressSnapshot(controller, &com);
}

#endif
