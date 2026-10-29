// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_MIF_DISCOVERY_HOLD_TEST068_HPP
#define NATIVE_AWDL_MIF_DISCOVERY_HOLD_TEST068_HPP

#include <stdint.h>

// Pure scheduling policy for Test068. This can pause the existing bounded MIF
// repeat evaluator only while a successfully bound MIF-current discovery
// reservation remains inside its already-estimated half-open target window.
// It neither admits data nor changes any existing MIF/data transmission gate.
namespace NativeAwdlMifDiscoveryHoldTest068 {

struct Input {
    bool modeSelected;
    bool mifCurrentMode;
    bool firstOwnMifCompleted;
    bool candidateLocked;
    bool runtimeMifBindingRequired;
    bool runtimeMifBound;
    bool oneShotLocked;
    bool targetCandidate;
    bool consumed;
    bool windowClosed;
    bool canceled;
    bool rocActive;
    bool epochsMatch;
    uint64_t nowUs;
    uint64_t leaseStartUs;
    uint64_t earliestSubmitUs;
    uint64_t latestSubmitUs;
    uint64_t usableLeaseEndUs;
};

inline bool shouldHoldMifRepeat(const Input &in)
{
    if (!in.modeSelected || !in.mifCurrentMode ||
        !in.firstOwnMifCompleted || !in.candidateLocked ||
        !in.runtimeMifBindingRequired || !in.runtimeMifBound ||
        !in.oneShotLocked || !in.targetCandidate || in.consumed ||
        in.windowClosed || in.canceled || !in.rocActive ||
        !in.epochsMatch || !in.nowUs || !in.leaseStartUs ||
        !in.earliestSubmitUs || in.earliestSubmitUs >= in.latestSubmitUs ||
        in.earliestSubmitUs < in.leaseStartUs ||
        in.latestSubmitUs > in.usableLeaseEndUs)
        return false;

    // latestSubmitUs is exclusive. The reservation covers only the estimated
    // query window (including its pre-open wait), never the remainder of ROC.
    return in.nowUs >= in.leaseStartUs && in.nowUs < in.latestSubmitUs;
}

} // namespace NativeAwdlMifDiscoveryHoldTest068

#endif // NATIVE_AWDL_MIF_DISCOVERY_HOLD_TEST068_HPP
