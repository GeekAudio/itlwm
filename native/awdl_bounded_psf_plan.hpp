// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_BOUNDED_PSF_PLAN_HPP
#define NATIVE_AWDL_BOUNDED_PSF_PLAN_HPP

#include "awdl_action_encode.hpp"

#include <stdint.h>

namespace NativeAwdlProbe {

// MAC supplied by the isolated Intel P2P role. It is treated as a native
// awdl0 identity only when Request::nativeAddressVerified carries the HAL's
// same-generation identity check.
struct ExperimentalP2pMac {
    uint8_t bytes[6];
};

// A bounded ROC lease. The time interval is half-open [start, deadline).
// startConfirmed/activeAtSampleConfirmed must come from the matching ROC
// lifecycle notifications; deadlineUs is the accepted hard lease deadline.
struct RocWitness {
    uint8_t channel;
    uint64_t startUs;
    uint64_t deadlineUs;
    bool startConfirmed;
    bool activeAtSampleConfirmed;
};

struct HtCapabilityWitness {
    uint16_t capabilityInfo;
    uint8_t ampduParameters;
    uint8_t rxMcsMask[4];
    uint8_t rxMcsLength;
    bool confirmed;
};

struct Request {
    ExperimentalP2pMac p2pMac;
    uint64_t monotonicSampleUs;
    uint16_t ieee80211SequenceNumber;
    HtCapabilityWitness ht;

    // Set only after the HAL validates the same-generation native AWDL BSD
    // identity and confirms it equals p2pMac. Zero preserves the legacy frame.
    bool nativeAddressVerified;
};

enum class PlanStatus : uint8_t {
    ObservationOnly,
    InvalidArgument,
    InvalidP2pAddress,
    InvalidRocEvidence,
    InvalidRocChannel,
    InvalidRocInterval,
    SampleOutsideRoc,
    RocTooShortForCompleteSlot,
    RocExceedsOneSequence,
    InvalidHtCapabilities,
    InvalidSequenceNumber,
    InvalidHostPhase
};

struct Summary {
    uint8_t fullyCoveredSlots;
    uint64_t rocRemainingUs;
    uint64_t channelAdvertisedUs;
    uint64_t partialTailNotAdvertisedUs;
    uint64_t sequenceDurationUs;
    uint64_t experimentPhaseOriginUs;
    uint16_t dataPathFlags;
    bool p2pAddressIsNativeAwdlIdentity;
    bool dataPathFlagsZero;
    bool addressFieldPresent;
    bool addressMatchesSource;
    bool dataPathReady; // always false; advertising the address is not readiness
};

// Makes one *experimental* PSF input at a single host-monotonic sample.
// The local phase origin is that sample. Only complete 4-AW slots wholly
// contained in the remaining confirmed ROC lease are advertised; a partial
// tail is left unavailable. This model does not prove AWDL clock alignment,
// native awdl0 identity, periodic service, peer discovery, or data path.
// Failure leaves both output objects untouched.
PlanStatus buildObservationOnlyPsfInput(const Request *request,
                                        const RocWitness *roc,
                                        NativeAwdl::PsfInput *output,
                                        Summary *summary);

} // namespace NativeAwdlProbe

#endif
