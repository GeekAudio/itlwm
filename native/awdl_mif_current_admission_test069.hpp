// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_MIF_CURRENT_ADMISSION_TEST069_HPP
#define NATIVE_AWDL_MIF_CURRENT_ADMISSION_TEST069_HPP

#include <stdint.h>

// Test069 keeps a numeric, scalar-only explanation of why an unlocked
// MIF-current candidate is waiting or has been rejected. Only own-MIF
// completion, a drained action ring, and a stable strict QM head are waitable.
// All peer, epoch, ROC, closing, and schedule failures stay terminal.
namespace Test069MifCurrentAdmission {

enum Blocker : uint32_t {
    kNoSelectedSlot = 1u << 0,
    kPeerIncarnationMismatch = 1u << 1,
    kPsfRevisionMismatch = 1u << 2,
    kMifRevisionMismatch = 1u << 3,
    kMifWitnessMismatch = 1u << 4,
    kOwnMifIncomplete = 1u << 5,
    kActionRingBusy = 1u << 6,
    kStrictQmHeadUnstable = 1u << 7,
    kRocInactive = 1u << 8,
    kClosing = 1u << 9,
    kEpochMismatch = 1u << 10,
    kPeerMifChannelMismatch = 1u << 11,
    kScheduleRejected = 1u << 12,
    kOwnMifMissedWindow = 1u << 13,
    kTimingRejected = 1u << 14
};

constexpr uint32_t kWaitableMask = kOwnMifIncomplete |
    kActionRingBusy | kStrictQmHeadUnstable;

constexpr bool hasOnlyWaitableBlockers(uint32_t blockers)
{
    return (blockers & kWaitableMask) != 0 &&
        (blockers & ~kWaitableMask) == 0;
}

// The production ring snapshot still requires a completed ticket. The action
// ticket deliberately retains armed=true after completion as a tombstone for
// late firmware responses, so armed alone does not mean in-flight ownership.
// A never-completed/empty ticket remains blocked.
constexpr bool completedTicketHasNoInflight(bool ticketArmed,
                                             bool ticketCompleted)
{
    return ticketCompleted && (!ticketArmed || ticketCompleted);
}

} // namespace Test069MifCurrentAdmission

#endif // NATIVE_AWDL_MIF_CURRENT_ADMISSION_TEST069_HPP
