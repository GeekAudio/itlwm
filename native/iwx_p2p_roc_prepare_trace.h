/*
 * Fixed-width, privacy-safe trace for the Tahoe P2P ROC Prepare path.
 * All concurrently accessed storage is atomic. A reader must use the
 * snapshot helper and reject EAGAIN; it must never memcpy the live trace.
 */
#ifndef IWX_P2P_ROC_PREPARE_TRACE_H
#define IWX_P2P_ROC_PREPARE_TRACE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/errno.h>

#define IWX_P2P_ROC_PREPARE_TRACE_FIELDS(X) \
    X(valid) \
    X(serial) \
    X(step) \
    X(reason) \
    X(prepareErrno) \
    X(cleanupErrno) \
    X(configuration) \
    X(token) \
    X(receiveObservation149) \
    X(featureCompiled) \
    X(requestedChannelPresent) \
    X(channelIndex) \
    X(ieeeChannelNumber) \
    X(channelFrequency) \
    X(channelFlags) \
    X(channelIs2GHz) \
    X(channelIs5GHz) \
    X(channelIsDFS) \
    X(channelIsPassive) \
    X(originalChannelFrequency) \
    X(restoredChannelFrequency) \
    X(scGenerationEntry) \
    X(scGenerationExit) \
    X(p2pFirmwareGenerationEntry) \
    X(p2pFirmwareGenerationExit) \
    X(p2pInitializedEntry) \
    X(p2pInitializedExit) \
    X(p2pMacStateEntry) \
    X(p2pMacStateExit) \
    X(p2pMacIdEntry) \
    X(p2pMacIdExit) \
    X(p2pMacColorEntry) \
    X(p2pMacColorExit) \
    X(p2pBindingIdEntry) \
    X(p2pBindingIdExit) \
    X(p2pBindingColorEntry) \
    X(p2pBindingColorExit) \
    X(stationEpochEntry) \
    X(stationEpochExit) \
    X(stationPresentEntry) \
    X(stationPresentExit) \
    X(stationDetailsCapturedEntry) \
    X(stationDetailsCapturedExit) \
    X(stationChannelDetailsCapturedEntry) \
    X(stationChannelDetailsCapturedExit) \
    X(stationIdEntry) \
    X(stationIdExit) \
    X(stationColorEntry) \
    X(stationColorExit) \
    X(stationPhyIdEntry) \
    X(stationPhyIdExit) \
    X(stationPhyColorEntry) \
    X(stationPhyColorExit) \
    X(stationChannelFrequencyEntry) \
    X(stationChannelFrequencyExit) \
    X(channelRegulatoryFlags) \
    X(firmwareCapabilitiesCaptured) \
    X(originalChannelDetailsCaptured) \
    X(restoredChannelDetailsCaptured) \
    X(sessionCapabilityPresent) \
    X(phyContextCommandVersion) \
    X(bindingContextCommandVersion) \
    X(bindingContextNotificationVersion) \
    X(sessionProtectionCommandVersion) \
    X(sessionProtectionNotificationVersion) \
    X(phyLeaseAttempted) \
    X(phyLeaseReturned) \
    X(phyLeaseResult) \
    X(phyLeaseId) \
    X(phyRemoveAttempted) \
    X(phyRemoveReturned) \
    X(phyRemoveResult) \
    X(phyAddAttempted) \
    X(phyAddReturned) \
    X(phyAddResult) \
    X(bindingAddAttempted) \
    X(bindingAddReturned) \
    X(bindingAddResult) \
    X(bindingRawStatus) \
    X(bindingStatusValid) \
    X(bindingRejected) \
    X(restoreRemoveAttempted) \
    X(restoreRemoveReturned) \
    X(restoreRemoveResult) \
    X(restoreAddAttempted) \
    X(restoreAddReturned) \
    X(restoreAddResult) \
    X(phyReleaseAttempted) \
    X(phyReleaseReturned) \
    X(phyReleaseResult) \
    X(prePhase) \
    X(postPhase) \
    X(preBindingState) \
    X(postBindingState) \
    X(prePhyLeased) \
    X(postPhyLeased) \
    X(prePhyId) \
    X(postPhyId) \
    X(prePhyColor) \
    X(postPhyColor) \
    X(sessionSubmitAttempted) \
    X(ownerScGenerationUnchanged) \
    X(ownerP2pFirmwareGenerationUnchanged) \
    X(ownerP2pMacContextUnchanged) \
    X(ownerStationEpochUnchanged) \
    X(ownerBssIdentityUnchanged) \
    X(ownerStationIdUnchanged) \
    X(ownerStationPhyIdentityUnchanged) \
    X(ownerStationPhyIdUnchanged) \
    X(ownerStationPhyColorUnchanged) \
    X(ownerStationPhyChannelUnchanged) \
    X(ownerStationChannelIdentityUnchanged) \
    X(ownerEpochsUnchanged) \
    X(bindingKnownAbsent) \
    X(phyKnownUnleased) \
    X(phaseKnownIdle) \
    X(knownNotSubmittedSafeToAbort) \
    X(fullyRestored)

enum iwx_p2p_roc_prepare_trace_field {
#define IWX_P2P_TRACE_ENUM(name) IWX_P2P_TRACE_##name,
    IWX_P2P_ROC_PREPARE_TRACE_FIELDS(IWX_P2P_TRACE_ENUM)
#undef IWX_P2P_TRACE_ENUM
    IWX_P2P_TRACE_FIELD_COUNT
};

enum iwx_p2p_roc_prepare_step {
    IWX_P2P_PREPARE_STEP_NONE = 0,
    IWX_P2P_PREPARE_STEP_ARGUMENT,
    IWX_P2P_PREPARE_STEP_CHANNEL_INDEX,
    IWX_P2P_PREPARE_STEP_CONFIGURATION,
    IWX_P2P_PREPARE_STEP_RX149_POLICY,
    IWX_P2P_PREPARE_STEP_COMMAND_GATE,
    IWX_P2P_PREPARE_STEP_ROC_IDLE,
    IWX_P2P_PREPARE_STEP_P2P_OWNER,
    IWX_P2P_PREPARE_STEP_ACTIVE_FLAGS,
    IWX_P2P_PREPARE_STEP_STA_RUN,
    IWX_P2P_PREPARE_STEP_STA_PHY,
    IWX_P2P_PREPARE_STEP_CHANNEL_POLICY,
    IWX_P2P_PREPARE_STEP_FIRMWARE_CAPABILITY,
    IWX_P2P_PREPARE_STEP_PHY_LEASE,
    IWX_P2P_PREPARE_STEP_PHY_ID,
    IWX_P2P_PREPARE_STEP_PHY_REMOVE,
    IWX_P2P_PREPARE_STEP_PHY_ADD,
    IWX_P2P_PREPARE_STEP_BINDING_ADD,
    IWX_P2P_PREPARE_STEP_OWNER_RECHECK,
    IWX_P2P_PREPARE_STEP_RESTORE_PHY_REMOVE,
    IWX_P2P_PREPARE_STEP_RESTORE_PHY_ADD,
    IWX_P2P_PREPARE_STEP_PHY_RELEASE,
    IWX_P2P_PREPARE_STEP_COMPLETE
};

enum iwx_p2p_roc_prepare_reason {
    IWX_P2P_PREPARE_REASON_NONE = 0,
    IWX_P2P_PREPARE_REASON_NULL_SOFTC,
    IWX_P2P_PREPARE_REASON_WRONG_SOFTC,
    IWX_P2P_PREPARE_REASON_NULL_CHANNEL,
    IWX_P2P_PREPARE_REASON_ZERO_TOKEN,
    IWX_P2P_PREPARE_REASON_CHANNEL_NOT_IN_TABLE,
    IWX_P2P_PREPARE_REASON_UNSUPPORTED_CONFIGURATION,
    IWX_P2P_PREPARE_REASON_RX149_CHANNEL_NOT_ALLOWED,
    IWX_P2P_PREPARE_REASON_COMMAND_GATE_BUSY,
    IWX_P2P_PREPARE_REASON_ROC_NOT_IDLE,
    IWX_P2P_PREPARE_REASON_P2P_NOT_INITIALIZED,
    IWX_P2P_PREPARE_REASON_FW_GENERATION_MISMATCH,
    IWX_P2P_PREPARE_REASON_MAC_NOT_ACTIVE,
    IWX_P2P_PREPARE_REASON_BINDING_NOT_ABSENT,
    IWX_P2P_PREPARE_REASON_WRONG_MAC_ID,
    IWX_P2P_PREPARE_REASON_ACTIVE_FLAGS_MISSING,
    IWX_P2P_PREPARE_REASON_STA_NOT_RUNNING,
    IWX_P2P_PREPARE_REASON_STA_BSS_MISSING,
    IWX_P2P_PREPARE_REASON_STA_PHY_POINTER_MISMATCH,
    IWX_P2P_PREPARE_REASON_STA_PHY_ID_MISMATCH,
    IWX_P2P_PREPARE_REASON_STA_ID_CONFLICT,
    IWX_P2P_PREPARE_REASON_STA_CHANNEL_MISSING,
    IWX_P2P_PREPARE_REASON_STA_CONTEXT_CHANNEL_MISMATCH,
    IWX_P2P_PREPARE_REASON_CHANNEL6_POLICY,
    IWX_P2P_PREPARE_REASON_OFFCHANNEL_POLICY,
    IWX_P2P_PREPARE_REASON_SESSION_CAPABILITY_MISSING,
    IWX_P2P_PREPARE_REASON_PHY_COMMAND_VERSION,
    IWX_P2P_PREPARE_REASON_BINDING_COMMAND_VERSION,
    IWX_P2P_PREPARE_REASON_BINDING_NOTIFICATION_VERSION,
    IWX_P2P_PREPARE_REASON_SESSION_COMMAND_VERSION,
    IWX_P2P_PREPARE_REASON_SESSION_NOTIFICATION_VERSION,
    IWX_P2P_PREPARE_REASON_PHY_LEASE_FAILED,
    IWX_P2P_PREPARE_REASON_UNEXPECTED_PHY_ID,
    IWX_P2P_PREPARE_REASON_PHY_ID_OUT_OF_RANGE,
    IWX_P2P_PREPARE_REASON_PHY_CHANNEL_MISSING,
    IWX_P2P_PREPARE_REASON_PHY_REMOVE_FAILED,
    IWX_P2P_PREPARE_REASON_PHY_ADD_FAILED,
    IWX_P2P_PREPARE_REASON_BINDING_ADD_DECODED_REJECT,
    IWX_P2P_PREPARE_REASON_BINDING_ADD_NOT_SUBMITTED,
    IWX_P2P_PREPARE_REASON_BINDING_ADD_UNKNOWN,
    IWX_P2P_PREPARE_REASON_OWNER_CHANGED,
    IWX_P2P_PREPARE_REASON_RESTORE_REMOVE_FAILED,
    IWX_P2P_PREPARE_REASON_RESTORE_ADD_FAILED,
    IWX_P2P_PREPARE_REASON_PHY_RELEASE_FAILED,
    IWX_P2P_PREPARE_REASON_PREPARE_SUCCEEDED
};

struct iwx_p2p_roc_prepare_trace {
    volatile uint32_t revision;
    volatile uint32_t values[IWX_P2P_TRACE_FIELD_COUNT];
};

struct iwx_p2p_roc_prepare_trace_snapshot {
#define IWX_P2P_TRACE_MEMBER(name) uint32_t name;
    IWX_P2P_ROC_PREPARE_TRACE_FIELDS(IWX_P2P_TRACE_MEMBER)
#undef IWX_P2P_TRACE_MEMBER
};

static inline uint32_t
iwx_p2p_roc_prepare_trace_load(const struct iwx_p2p_roc_prepare_trace *trace,
                               enum iwx_p2p_roc_prepare_trace_field field)
{
    return __atomic_load_n(&trace->values[field], __ATOMIC_ACQUIRE);
}

static inline void
iwx_p2p_roc_prepare_trace_store(struct iwx_p2p_roc_prepare_trace *trace,
                                enum iwx_p2p_roc_prepare_trace_field field,
                                uint32_t value)
{
    __atomic_store_n(&trace->values[field], value, __ATOMIC_RELEASE);
}

static inline uint32_t
iwx_p2p_roc_prepare_trace_begin(struct iwx_p2p_roc_prepare_trace *trace)
{
    uint32_t expected = __atomic_load_n(&trace->revision, __ATOMIC_ACQUIRE);
    if ((expected & 1U) != 0U)
        return 0U;
    const uint32_t serial =
        iwx_p2p_roc_prepare_trace_load(trace, IWX_P2P_TRACE_serial) + 1U;
    if (!__atomic_compare_exchange_n(&trace->revision, &expected,
                                     expected + 1U, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return 0U;
    for (uint32_t field = 0;
         field < (uint32_t)IWX_P2P_TRACE_FIELD_COUNT; ++field)
        __atomic_store_n(&trace->values[field], 0U, __ATOMIC_RELAXED);
    iwx_p2p_roc_prepare_trace_store(trace, IWX_P2P_TRACE_serial, serial);
    return serial;
}

static inline void
iwx_p2p_roc_prepare_trace_finish(struct iwx_p2p_roc_prepare_trace *trace)
{
    iwx_p2p_roc_prepare_trace_store(trace, IWX_P2P_TRACE_valid, 1U);
    __atomic_add_fetch(&trace->revision, 1U, __ATOMIC_RELEASE);
}

static inline int
iwx_p2p_roc_prepare_trace_read_snapshot(
    const struct iwx_p2p_roc_prepare_trace *trace,
    struct iwx_p2p_roc_prepare_trace_snapshot *snapshot)
{
    if (trace == 0 || snapshot == 0)
        return EINVAL;
    const uint32_t before = __atomic_load_n(&trace->revision, __ATOMIC_ACQUIRE);
    if ((before & 1U) != 0U)
        return EAGAIN;
    const uint32_t serial =
        iwx_p2p_roc_prepare_trace_load(trace, IWX_P2P_TRACE_serial);
    const uint32_t valid =
        iwx_p2p_roc_prepare_trace_load(trace, IWX_P2P_TRACE_valid);
#define IWX_P2P_TRACE_READ(name) \
    snapshot->name = iwx_p2p_roc_prepare_trace_load( \
        trace, IWX_P2P_TRACE_##name);
    IWX_P2P_ROC_PREPARE_TRACE_FIELDS(IWX_P2P_TRACE_READ)
#undef IWX_P2P_TRACE_READ
    const uint32_t after = __atomic_load_n(&trace->revision, __ATOMIC_ACQUIRE);
    if (before != after || (after & 1U) != 0U)
        return EAGAIN;
    /* A pristine zeroed trace is a valid baseline (valid=0, serial=0). */
    if (snapshot->serial != serial || snapshot->valid != valid)
        return EAGAIN;
    return 0;
}

#endif /* IWX_P2P_ROC_PREPARE_TRACE_H */
