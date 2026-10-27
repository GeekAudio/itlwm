// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#ifdef AIRPORT_TAHOE

#include <stdint.h>
#include <IOKit/IOLocks.h>
#include "../../native/p2p_tx_resources.hpp"

class ItlIwx;
struct iwx_softc;
struct iwx_tx_ring;

enum class TahoeP2PResourceState : uint8_t {
    kAbsent,
    kPending,
    kActive,
    kRemoving,
    kReleasing,
    kUnknown
};

struct TahoeP2PStationLease {
    uint8_t stationId;
    uint32_t generation;
    TahoeP2PResourceState state;
};

struct TahoeP2PTxQueueLease {
    uint8_t stationId;
    uint16_t queueId;
    uint32_t generation;
    TahoeP2PResourceState state;
    IOSimpleLock *stateLock;
    bool submissionBusy;
    uint16_t submissionDescriptorIndex;
    // Monotonic for the lifetime of one allocation. Action sets this through
    // mark_doorbell immediately before the hardware MMIO write; no ring-empty
    // or generation inference may clear/replace this proof.
    bool everDoorbelled;
    // Kept allocated and DMA-mapped after an unknown firmware result.
    struct iwx_tx_ring *pendingRing;
    // One displaced dynamic host ring may be parked when a current-generation
    // firmware flush proves the new P2P station/TID binding. It is not reset
    // or freed until a caller supplies both hardware-stop proofs.
    struct iwx_tx_ring *retainedRing;
    uint32_t retainedRingGeneration;
    uint16_t retainedRingQueueId;
    uint16_t firmwareWritePointer;
    bool unsubmittedAbortInProgress;
    bool idleAbortAfterEndInProgress;
    // Portable lifecycle model is also used by the native tests. Do not copy
    // or memset this lease after construction.
    IntelP2PTx::QueueLease lifecycle;
};

// Historical method names retain the earlier probe API. This HAL currently
// accepts only the fw68 LONG_GROUP/SCD_QUEUE_CFG v2 queue path and fails
// closed when DATA_PATH/SCD_QUEUE_CONFIG is advertised.

// These are called only from the active native P2P command owner. A returned
// `resourceMayExist` means the caller must retain the station/queue lease.
int iwx_tahoe_p2p_add_broadcast_station(ItlIwx *owner, struct iwx_softc *sc,
                                        TahoeP2PStationLease *lease,
                                        uint8_t stationId,
                                        bool *resourceMayExist);
int iwx_tahoe_p2p_remove_broadcast_station(ItlIwx *owner,
                                           struct iwx_softc *sc,
                                           TahoeP2PStationLease *lease,
                                           TahoeP2PTxQueueLease *queueLease,
                                           bool *resourceMayExist);
int iwx_tahoe_p2p_tvqm_allocate(ItlIwx *owner, struct iwx_softc *sc,
                                TahoeP2PTxQueueLease *lease,
                                const TahoeP2PStationLease *stationLease,
                                uint32_t size,
                                uint16_t *queueId,
                                bool *resourceMayExist);
int iwx_tahoe_p2p_tvqm_remove(ItlIwx *owner, struct iwx_softc *sc,
                              TahoeP2PStationLease *stationLease,
                              TahoeP2PTxQueueLease *queueLease,
                              bool *resourceMayExist);
// Abort a queue allocation that was acknowledged by firmware but never
// installed or submitted. The pending ring is released only after a valid
// TXPATH_FLUSH and REMOVE_STA acknowledgement for this station.
int iwx_tahoe_p2p_tvqm_abort_unsubmitted(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    bool *resourceMayExist);
// Abort an installed queue after a confirmed ROC END only when the caller
// independently proves that no completion ticket was armed. A successful
// exact TXPATH_FLUSH + REMOVE_STA ACK releases only the current P2P ring; a
// displaced retained host ring is never touched by this path.
int iwx_tahoe_p2p_tvqm_abort_idle_after_end(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    bool rocEndConfirmed, bool noTicketArmed,
    bool *resourceMayExist);
// Retained displaced rings remain allocated across normal queue/STA cleanup.
// Both booleans must be sourced from the actual MASTER_DISABLED + SW_RESET
// stop path before this helper is allowed to free the retained DMA backing.
int iwx_tahoe_p2p_tvqm_release_retained_after_master_disabled(
    ItlIwx *owner, struct iwx_softc *sc,
    bool masterDisabledObserved, bool swResetIssued);

// The submit helper reserves one descriptor under the queue lock, increments
// outstanding accounting, and returns its ring/index. Call finish after the
// doorbell; cancel if local preparation fails before submission.
int iwx_tahoe_p2p_tvqm_begin_tx(struct iwx_softc *sc,
                                TahoeP2PTxQueueLease *lease,
                                struct iwx_tx_ring **ring,
                                uint16_t *descriptorIndex);
// Call from the Action submitter immediately before the MMIO doorbell. This
// irreversibly marks the allocation as having possibly reached firmware.
int iwx_tahoe_p2p_tvqm_mark_doorbell(
    struct iwx_softc *sc, TahoeP2PTxQueueLease *lease,
    struct iwx_tx_ring *ring, uint16_t descriptorIndex);
int iwx_tahoe_p2p_tvqm_finish_tx_submit(
    TahoeP2PTxQueueLease *lease);
int iwx_tahoe_p2p_tvqm_cancel_tx_submit(
    TahoeP2PTxQueueLease *lease);

// Used by the legacy STA queue allocator before replacing sc->txq[qid].
// Unknown, pending-with-known-ID, removing, and releasing leases all reserve
// the slot. If the lease lock cannot be acquired, fail closed.
bool iwx_tahoe_p2p_tvqm_queue_owned(
    TahoeP2PTxQueueLease *lease, uint16_t queueId);
// Blocks new legacy STA TVQM allocations while a P2P queue allocation,
// installed queue, removal, or unresolved command outcome exists.
bool iwx_tahoe_p2p_tvqm_may_exist(TahoeP2PTxQueueLease *lease);

// The response hook acquires this short spinlock before touching the shared
// ring and keeps it until descriptor ownership/tail/outstanding state is
// updated. Never hold it across synchronous firmware commands or mbuf frees.
bool iwx_tahoe_p2p_tvqm_lock_completion(
    struct iwx_softc *sc, TahoeP2PTxQueueLease *lease, uint16_t queueId,
    struct iwx_tx_ring **ring, IOInterruptState *interruptState);
int iwx_tahoe_p2p_tvqm_tx_completed_locked(
    struct iwx_softc *sc, TahoeP2PTxQueueLease *lease);
void iwx_tahoe_p2p_tvqm_unlock(TahoeP2PTxQueueLease *lease,
                               IOInterruptState interruptState);

// Call only after a TX response has been validated and all descriptors have
// been retired. Queue REMOVE ACK by itself never releases DMA resources.
int iwx_tahoe_p2p_tvqm_confirm_drained(ItlIwx *owner, struct iwx_softc *sc,
                                       TahoeP2PTxQueueLease *lease,
                                       bool *resourceMayExist);

#endif // AIRPORT_TAHOE

