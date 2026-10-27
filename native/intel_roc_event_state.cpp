// SPDX-License-Identifier: GPL-2.0-only
#include "intel_roc_event_state.hpp"

namespace IntelROCEvent {
namespace {
bool isSupportedSessionConfiguration(uint32_t configuration)
{
    return configuration == 2 || configuration == 3;
}

uint32_t le32(const uint8_t *p)
{
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 |
           uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
}

Tracker::Tracker() {}

bool Tracker::begin(uint32_t generation, uint32_t mac, uint32_t type)
{
    // One invocation per whole-boot probe; a timeout cannot be rearmed.
    if (!generation || state_.submitted)
        return false;
    state_ = {};
    state_.generation = generation;
    state_.submitted = true;
    macIdAndColor_ = mac;
    eventType_ = type;
    return true;
}

void Tracker::apply(const Event &e)
{
    if (e.uid != state_.uniqueId) {
        ++state_.ignoredForeign;
        return;
    }
    if (e.action == 1) {
        // An END before START cannot prove that the host observed a complete
        // dwell. Keep the drain evidence but never repair its ordering.
        if (!state_.startSeen && !state_.endSeen) {
            state_.startSeen = true;
            state_.startStatus = e.status;
            state_.startScheduled = e.status != 0;
        } else if (state_.startSeen && state_.startStatus != e.status) {
            malformed_ = true;
        }
    } else if (e.action == 2) {
        if (!state_.endSeen) {
            state_.endSeen = true;
            state_.endStatus = e.status;
            state_.endScheduled = e.status != 0;
        } else if (state_.endStatus != e.status) {
            malformed_ = true;
        }
    } else {
        // Neither combined nor fragment actions were requested by this probe.
        malformed_ = true;
    }
}

bool Tracker::noteResponse(uint32_t generation, int transportResult,
                          const uint8_t *bytes, size_t length)
{
    if (!state_.submitted || generation != state_.generation ||
        state_.responseDecoded)
        return false;
    if (transportResult || !bytes || length != 16) {
        malformed_ = true;
        return false;
    }
    if (le32(bytes + 4) != eventType_ || le32(bytes + 12) != macIdAndColor_) {
        malformed_ = true;
        return false;
    }
    state_.responseStatus = le32(bytes);
    // FW API documentation says bit0=success and other bits=errors. The old
    // STA caller tests zero instead. Preserve that disagreement explicitly;
    // this probe needs actual scheduled START/END as its stronger evidence.
    state_.responseContractSuccess = state_.responseStatus == 1;
    state_.uniqueId = le32(bytes + 8); // UID zero is a valid identity.
    state_.responseDecoded = true;
    for (unsigned i = 0; i < earlyCount_; ++i)
        apply(early_[i]);
    earlyCount_ = 0;
    return true;
}

bool Tracker::noteNotification(uint32_t generation, const uint8_t *bytes,
                              size_t length)
{
    if (!state_.submitted || generation != state_.generation)
        return false;
    if (!bytes || length != 24) {
        malformed_ = true;
        return false;
    }
    if (le32(bytes + 12) != macIdAndColor_) {
        ++state_.ignoredForeign;
        return false;
    }
    const Event event{le32(bytes + 8), le32(bytes + 16), le32(bytes + 20)};
    if (state_.responseDecoded) {
        apply(event);
        return event.uid == state_.uniqueId;
    }
    for (unsigned i = 0; i < earlyCount_; ++i) {
        if (early_[i].uid == event.uid && early_[i].action == event.action &&
            early_[i].status == event.status)
            return true;
    }
    if (earlyCount_ == sizeof(early_) / sizeof(early_[0])) {
        malformed_ = true;
        return false;
    }
    early_[earlyCount_++] = event;
    return true;
}

void Tracker::expire(uint32_t generation)
{
    if (state_.submitted && generation == state_.generation)
        expired_ = true;
}

Snapshot Tracker::snapshot() const
{
    Snapshot s = state_;
    // A validated matching END is the only drain evidence. Errors, an ADD
    // response, elapsed duration, or a failed START alone cannot release PHY.
    s.cleanupAllowed = s.responseDecoded && s.endSeen && !malformed_;
    s.observedScheduledPair = s.cleanupAllowed && s.startSeen &&
        s.startScheduled && s.endScheduled && !expired_;
    s.outcomeUnknown = state_.submitted &&
        (malformed_ || (expired_ && !s.cleanupAllowed));
    return s;
}

SessionTracker::SessionTracker() {}

bool SessionTracker::begin(uint32_t generation, uint32_t mac, uint32_t configuration)
{
    if (!generation || state_.submitted || mac != 1 ||
        !isSupportedSessionConfiguration(configuration))
        return false;
    state_ = {};
    state_.generation = generation;
    state_.configuration = configuration;
    state_.submitted = true;
    state_.commandResult = -1;
    macId_ = mac;
    configuration_ = configuration;
    return true;
}

bool SessionTracker::noteCommandResult(uint32_t generation, int result)
{
    if (!state_.submitted || generation != state_.generation || state_.commandReturned)
        return false;
    state_.commandResult = result;
    state_.commandReturned = true;
    return true;
}

bool SessionTracker::noteNotification(uint32_t generation, const uint8_t *raw,
                                      size_t length,
                                      uint64_t receiveMonotonicUs)
{
    if (!state_.submitted || generation != state_.generation)
        return false;
    if (!raw || length != 16) {
        malformed_ = true;
        return false;
    }
    if (le32(raw) != macId_ || le32(raw + 12) != configuration_) {
        ++state_.ignoredForeign;
        return false;
    }
    const uint32_t status = le32(raw + 4);
    const uint32_t start = le32(raw + 8);
    if (status > 1 || start > 1) {
        malformed_ = true;
        return false;
    }
    if (start) {
        if (state_.endSeen) {
            malformed_ = true;
        } else if (!state_.startSeen) {
            state_.startSeen = true;
            state_.startStatus = status;
            state_.startObservedMonotonicUs = receiveMonotonicUs;
        } else if (state_.startSeen && state_.startStatus != status) {
            malformed_ = true;
        }
    } else {
        if (!state_.endSeen) {
            state_.endSeen = true;
            state_.endStatus = status;
            state_.endObservedMonotonicUs = receiveMonotonicUs;
        } else if (state_.endStatus != status) {
            malformed_ = true;
        }
    }
    return true;
}

void SessionTracker::expire(uint32_t generation)
{
    if (state_.submitted && state_.generation == generation)
        expired_ = true;
}

SessionSnapshot SessionTracker::snapshot() const
{
    auto value = state_;
    value.cleanupAllowed = value.commandReturned && value.endSeen && !malformed_;
    value.observedScheduledPair = value.cleanupAllowed && value.startSeen &&
        value.startStatus == 1 && value.endStatus == 1 &&
        value.commandResult == 0 && !expired_;
    value.outcomeUnknown = value.submitted && (malformed_ ||
        ((expired_ || (value.commandReturned && value.commandResult != 0)) &&
         !value.cleanupAllowed));
    return value;
}

bool isStationSessionNotification(const uint8_t *raw, size_t length,
                                  uint32_t stationMacId)
{
    return raw && length == 16 && le32(raw) == stationMacId &&
        le32(raw + 12) == 0 && le32(raw + 4) <= 1 && le32(raw + 8) <= 1;
}
} // namespace IntelROCEvent
