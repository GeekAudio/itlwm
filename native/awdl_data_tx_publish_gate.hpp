// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_DATA_TX_PUBLISH_GATE_HPP
#define NATIVE_AWDL_DATA_TX_PUBLISH_GATE_HPP

#include <stdint.h>

namespace NativeAwdlDataTxPublication {

// These values are sampled on the main command gate. The RX event timeline is
// only one diagnostic witness; it cannot by itself establish that firmware's
// ROC session has ended or that the device is off the AWDL channel.
struct LifecycleSnapshot {
    bool timelineOwnerPresent;
    bool timelineActive;
    bool timelineProducerClosed;
    bool timelineDrainsPending;
    bool timelineEpochsMatchSession;

    bool probeBusy;
    bool rxLeaseActive;
    bool txSubmissionBusy;
    bool txResourcesUnsettled;

    // This one-shot controller owns the P2P MAC/RF command path. A clean
    // preflight is valid only before an attempt; a completed run is valid
    // only after the controller reports kComplete with its resource lease
    // released. Neither case reads the unsynchronized firmware ROC struct.
    bool probeCleanPreflight;
    bool probeCompletedAndReleased;

    bool sessionSubmitted;
    bool sessionCommandReturned;
    bool sessionCommandSucceeded;
    bool sessionStartSeen;
    bool sessionEndSeen;
    bool sessionCleanupAllowed;
    bool sessionOutcomeUnknown;
    uint32_t sessionGeneration;

};

constexpr bool shouldDeferBulkProperties(const LifecycleSnapshot &state)
{
    if (state.probeBusy || state.rxLeaseActive || state.txSubmissionBusy ||
        state.txResourcesUnsettled ||
        state.sessionOutcomeUnknown)
        return true;

    if (state.timelineOwnerPresent &&
        (state.timelineActive || !state.timelineProducerClosed ||
         state.timelineDrainsPending ||
         !state.timelineEpochsMatchSession))
        return true;

    const bool sessionEvidencePresent = state.sessionSubmitted ||
        state.sessionCommandReturned || state.sessionStartSeen ||
        state.sessionEndSeen || state.sessionGeneration != 0;

    // A clean boot/preflight can publish an owner=0 trace only when the
    // one-shot probe has never attempted a command and the canonical session
    // reducer shows no prior session.
    if (!sessionEvidencePresent)
        return !state.probeCleanPreflight ||
            state.timelineOwnerPresent;

    // After a session, require the reducer's successful command return and
    // canonical END, plus the one-shot command owner's release result for the
    // matching session epoch. This avoids unsynchronized ROC-struct reads.
    const bool canonicalSessionEnd = state.sessionSubmitted &&
        state.sessionCommandReturned && state.sessionCommandSucceeded &&
        state.sessionEndSeen && state.sessionCleanupAllowed &&
        !state.sessionOutcomeUnknown &&
        state.sessionGeneration != 0;
    return !canonicalSessionEnd || !state.probeCompletedAndReleased ||
        !state.timelineOwnerPresent || !state.timelineProducerClosed ||
        state.timelineActive || !state.timelineEpochsMatchSession;
}

} // namespace NativeAwdlDataTxPublication

#endif // NATIVE_AWDL_DATA_TX_PUBLISH_GATE_HPP
