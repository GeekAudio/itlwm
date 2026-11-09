// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#ifndef ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
#define ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332 0
#endif

#if defined(AIRPORT_TAHOE) && ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332

#include <stdint.h>
#include <sys/mbuf.h>
#include "../../native/p2p_action_tx.hpp"
#include "../../native/awdl_directed_origin_tx.hpp"
#include "../../native/iwx_mcc_refresh_policy.hpp"
#include "ItlIwxP2PDataTxWitness.hpp"

static constexpr uint8_t kTahoeP2PDirectedDataMaxPackets = 2;

class ItlIwx;
struct iwx_softc;
struct iwx_rx_packet;
struct iwx_rx_data;
struct TahoeP2PStationLease;
struct TahoeP2PTxQueueLease;

using TahoeP2PDirectedDataEpochs = NativeAwdlDirectedOriginTx::Epochs;

// One explicitly armed, fixed-payload native BSD data diagnostic.
struct TahoeP2PDirectedDataArm {
    uint8_t peerMac[6];
    uint8_t localIpv6[16];
    uint8_t nonce[8];
    char runToken[33];
    // Zero/one preserves the original one-packet arm shape. Two opts into
    // the bounded Test130 exchange and requires two distinct packetNonces
    // plus a link-local peer IPv6 address.
    uint8_t packetCount;
    uint8_t peerIPv6[16];
    uint8_t packetNonces[kTahoeP2PDirectedDataMaxPackets][8];
};

struct TahoeP2PDirectedDataBinding {
    uint64_t ownerSerial;
    uint64_t runSerial;
    TahoeP2PDirectedDataEpochs epochs;
    uint32_t generation;
    uint32_t p2pFirmwareGeneration;
    uint64_t rocToken;   // zero until the matching START is observed
    uint64_t rocStartUs; // zero until bind_origin_window
    uint64_t deadlineUs; // immutable, in clock_get_uptime microseconds
    IwxMccRefreshPolicy::DirectedDataWitness mcc;
};

// Copy of the actual BSD origin ticket returned after ROC START. The packet
// token comes only from popDirectedOriginTx(); it is not a reply/request ID.
using TahoeP2PDirectedDataOriginTicket =
    NativeAwdlDirectedOriginTx::Ticket;

struct TahoeP2PDirectedDataOriginPacket {
    TahoeP2PDirectedDataOriginTicket ticket;
    uint64_t packetToken;
    uint64_t identityTicketSerial;
    uint8_t slot;
    uint8_t nonce[8];
    uint16_t wifiSequence;
    uint16_t awdlSequence;
};

// Fixed per-packet evidence. Slot records are immutable once a later packet
// is admitted; the active CompletionTracker is reused only after the current
// slot is terminally completed. The nonce is private to the HAL and never
// copied into diagnostic snapshots.
struct TahoeP2PDirectedDataPacketRecord {
    uint64_t packetToken;
    uint64_t doorbellUs;
    uint64_t txResponseUs;
    uint64_t exactReplyCaptureUs;
    uint64_t exactReplyInputUs;
    uint16_t wifiSequence;
    uint16_t awdlSequence;
    uint16_t descriptorIndex;
    uint16_t expectedNextSsn;
    uint16_t sequenceControl;
    uint16_t frameControl;
    uint16_t responseFrameControl;
    uint16_t byteCount;
    uint16_t firmwareStatus;
    uint8_t nonce[8];
    uint8_t slot;
    bool identityBound;
    bool sequenceReserved;
    bool permitIssued;
    bool doorbellIssued;
    bool completionObserved;
    bool frameAttemptSucceeded;
    bool exactReplyCaptured;
    bool exactReplyDelivered;
    bool originDoorbellRecorded;
    bool originCompletionRecorded;
    bool resourcesAbsent;
};

struct TahoeP2PDirectedDataPacketSnapshot {
    uint64_t packetToken;
    uint64_t doorbellUs;
    uint64_t txResponseUs;
    uint64_t exactReplyCaptureUs;
    uint64_t exactReplyInputUs;
    uint16_t wifiSequence;
    uint16_t awdlSequence;
    uint16_t descriptorIndex;
    uint16_t expectedNextSsn;
    uint16_t sequenceControl;
    uint16_t frameControl;
    uint16_t responseFrameControl;
    uint16_t byteCount;
    uint16_t firmwareStatus;
    uint8_t slot;
    bool identityBound;
    bool sequenceReserved;
    bool permitIssued;
    bool doorbellIssued;
    bool completionObserved;
    bool frameAttemptSucceeded;
    bool exactReplyCaptured;
    bool exactReplyDelivered;
    bool originDoorbellRecorded;
    bool originCompletionRecorded;
    bool resourcesAbsent;
};

enum class TahoeP2PDirectedDataState : uint8_t {
    kIdle,
    kArmed,
    kTicketBound,
    kPermitIssued,
    kInFlight,
    kCompleted,
    kQuarantined,
    kClosed
};

enum class TahoeP2PDirectedDataReason : uint8_t {
    kNone,
    kInvalidArgument,
    kWrongOwnerOrGate,
    kStaleEpoch,
    kWrongRoleOrTid,
    kWrongOriginTicket,
    kWrongPacketShape,
    kWrongNonceOrAddress,
    kExpired,
    kPermitMismatch,
    kQueueUnavailable,
    kRingMismatch,
    kMappingFailure,
    kTicketFailure,
    kDoorbellUnknown,
    kResponseMalformed,
    kResponseForeign,
    kResponseDuplicate,
    kResponseMismatch,
    kCompletionFailure,
    kStopProofMissing,
    kDrainMismatch,
    kOwnerClosed
};

struct TahoeP2PDirectedDataPermit {
    uint64_t permitSerial;
    uint64_t armSerial;
    uint64_t ticketSerial;
    uint64_t packetToken;
    uint64_t ownerSerial;
    uint64_t runSerial;
    uint64_t interfaceIncarnation;
    uint64_t stationAllocationSerial;
    uint64_t queueAllocationSerial;
    uint32_t ifindex;
    TahoeP2PDirectedDataEpochs epochs;
    uint32_t generation;
    uint32_t p2pFirmwareGeneration;
    uint64_t rocToken;
    uint64_t deadlineUs;
    uint16_t queueId;
    uint16_t wifiSequence;
    uint16_t awdlSequence;
    uint16_t descriptorIndex;
    uint8_t stationId;
    uint8_t packetSlot;
    bool valid;
};

struct TahoeP2PDirectedDataSnapshot {
    // BSD Spent tickets remain as immutable replay/audit history. ticketSerial
    // is not a live mbuf, DMA, station, or queue ownership signal; use the
    // explicit originClosed/state and hardware lease snapshots for those.
    TahoeP2PDirectedDataState state;
    TahoeP2PDirectedDataReason reason;
    uint64_t armSerial;
    uint64_t ticketSerial;
    uint64_t packetToken;
    uint64_t ownerSerial;
    uint64_t runSerial;
    uint64_t interfaceIncarnation;
    uint64_t stationAllocationSerial;
    uint64_t queueAllocationSerial;
    uint64_t rocToken;
    uint64_t deadlineUs;
    uint32_t generation;
    uint32_t p2pFirmwareGeneration;
    IwxMccRefreshPolicy::DirectedDataWitness mcc;
    uint32_t ifindex;
    uint16_t queueId;
    uint16_t stationId;
    uint16_t descriptorIndex;
    uint16_t ringSize;
    uint16_t sequenceControl;
    uint16_t frameControl;
    uint16_t byteCount;
    uint16_t expectedNextSsn;
    uint16_t reservedWifiSequence;
    uint16_t reservedAwdlSequence;
    uint16_t firmwareStatus;
    uint32_t stopProofMask;
    bool originWindowBound;
    // Live BSD-origin ticket ownership: true only while the exact ticket has
    // not been committed closed. The context retains the historical ticket.
    bool originTicketBound;
    bool originClosed;
    bool completionArmed;
    bool sequenceReservationValid;
    bool permitIssued;
    bool doorbellIssued;
    bool completionObserved;
    bool frameAttemptSucceeded;
    bool mbufHeldByRing;
    bool hardStopDrained;
    uint8_t packetCount;
    uint8_t currentSlot;
    TahoeP2PDirectedDataPacketSnapshot packets[
        kTahoeP2PDirectedDataMaxPackets];
};

enum class TahoeP2PDirectedDataStopProof : uint8_t {
    kMasterDisabledObserved,
    kSwResetIssued,
    kOwnedTxRingResetAfterStop
};
constexpr uint32_t kTahoeP2PDirectedDataStopMasterDisabled = 1u << 0;
constexpr uint32_t kTahoeP2PDirectedDataStopSwReset = 1u << 1;
constexpr uint32_t kTahoeP2PDirectedDataStopOwnedRingReset = 1u << 2;
constexpr uint32_t kTahoeP2PDirectedDataRequiredStopProofs =
    kTahoeP2PDirectedDataStopMasterDisabled |
    kTahoeP2PDirectedDataStopSwReset |
    kTahoeP2PDirectedDataStopOwnedRingReset;

struct TahoeP2PDirectedDataContext {
    IntelP2PActionTx::CompletionTracker completion;
    TahoeP2PDirectedDataTxWitness::Snapshot txWitness{};
    TahoeP2PDirectedDataTxWitness::Snapshot packetWitness[
        kTahoeP2PDirectedDataMaxPackets]{};
    TahoeP2PDirectedDataPacketRecord packets[
        kTahoeP2PDirectedDataMaxPackets]{};
    TahoeP2PDirectedDataArm arm;
    TahoeP2PDirectedDataBinding binding;
    // The main-gate validator compares this exact worker token with the live
    // probe owner. It is not permission to submit commands from the gate.
    void *workerThread;
    TahoeP2PDirectedDataOriginTicket originTicket;
    TahoeP2PDirectedDataPermit permit;
    TahoeP2PDirectedDataState state;
    TahoeP2PDirectedDataReason reason;
    // Atomic gate-independent summary for lifecycle guards. Zero means this
    // context has never entered a resource-owning state (or has a verified
    // safe retirement); one means an owner may still exist or be uncertain.
    // All accesses after construction must use __atomic_load/store builtins.
    uint32_t mayOwnResource;
    uint64_t armSerialHighWater;
    uint64_t permitSerialHighWater;
    uint64_t allocationSerialHighWater;
    uint16_t wifiSequenceHighWater;
    uint16_t awdlSequenceHighWater;
    uint16_t reservedWifiSequence;
    uint16_t reservedAwdlSequence;
    bool sequenceReservationValid;
    uint64_t stationAllocationSerial;
    uint64_t queueAllocationSerial;
    uint64_t packetToken;
    uint64_t interfaceIncarnation;
    uint32_t ifindex;
    uint16_t queueId;
    uint16_t stationId;
    uint16_t descriptorIndex;
    uint16_t ringSize;
    uint16_t sequenceControl;
    uint16_t frameControl;
    uint16_t byteCount;
    uint16_t expectedNextSsn;
    uint16_t firmwareStatus;
    uint32_t stopProofMask;
    // Historical exact-run ticket association. Keep this and originTicket
    // after close for replay/audit identity; snapshots derive live ownership
    // from ticketBound && !originClosed.
    bool ticketBound;
    bool originWindowBound;
    bool originClosed;
    bool permitIssued;
    bool doorbellIssued;
    bool completionObserved;
    bool frameAttemptSucceeded;
    bool mbufHeldByRing;
    bool hardStopDrained;
    uint8_t packetCount;
    uint8_t currentSlot;

    TahoeP2PDirectedDataContext()
        : completion(), packetWitness{}, packets{}, arm{}, binding{}, workerThread(nullptr),
          originTicket{}, permit{},
          state(TahoeP2PDirectedDataState::kIdle),
          reason(TahoeP2PDirectedDataReason::kNone), mayOwnResource(0),
          armSerialHighWater(0),
          permitSerialHighWater(0), allocationSerialHighWater(0),
          wifiSequenceHighWater(0), awdlSequenceHighWater(0),
          reservedWifiSequence(0), reservedAwdlSequence(0),
          sequenceReservationValid(false),
          stationAllocationSerial(0), queueAllocationSerial(0),
          packetToken(0), interfaceIncarnation(0), ifindex(0), queueId(0xffff),
          stationId(0xffff), descriptorIndex(0xffff), ringSize(0),
          sequenceControl(0), frameControl(0), byteCount(0),
          expectedNextSsn(0xffff), firmwareStatus(0xffff),
          stopProofMask(0), ticketBound(false),
          originWindowBound(false), originClosed(false),
          permitIssued(false), doorbellIssued(false), completionObserved(false),
          frameAttemptSucceeded(false), mbufHeldByRing(false),
          hardStopDrained(false), packetCount(1), currentSlot(0) {}
};

// Allocate globally unique per-owner resource identities. Zero is failure;
// callers must leave a lease unissued rather than wrap the persistent high-water.
uint64_t iwx_tahoe_p2p_directed_data_next_allocation_serial(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context);

// Arm after the LINK/TID0 leases are active and before ROC START. `ownerSerial`
// is the current START-owner serial; HAL assigns `runSerial` from its persistent
// 64-bit arm high-water and returns the exact binding for the BSD OpenRequest.
int iwx_tahoe_p2p_directed_data_arm(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataArm *arm,
    uint64_t ownerSerial, const TahoeP2PDirectedDataEpochs *epochs,
    uint32_t generation,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PDirectedDataBinding *bindingOut);
int iwx_tahoe_p2p_directed_data_bind_origin_window(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context, uint64_t rocToken,
    uint64_t rocStartUs, uint64_t deadlineUs);
bool iwx_tahoe_p2p_directed_data_reserve_sequences(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    uint16_t *wifiSequence,
    uint16_t *awdlSequence);
int iwx_tahoe_p2p_directed_data_bind_origin_ticket(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginTicket *ticket);
// Records a verified, kernel-delivered exact echo receipt for the current
// packet slot. Call outside the BSD lock; the main gate validates the full
// ticket/packet identity and the immutable ROC deadline before latching it.
bool iwx_tahoe_p2p_directed_data_note_exact_reply(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginPacket *origin);
bool iwx_tahoe_p2p_directed_data_record_origin_doorbell(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginPacket *origin);
bool iwx_tahoe_p2p_directed_data_record_origin_completion(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginPacket *origin);
// The mbuf is borrowed here. This verifies the BSD pop identity and exact 96B
// MPDU, then returns a one-use permit; submit revalidates all bytes.
int iwx_tahoe_p2p_directed_data_make_permit(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataOriginPacket *origin,
    mbuf_t encodedMpdu, TahoeP2PDirectedDataPermit *permit);
// A non-null encodedMpdu is consumed on every path. Pre-doorbell errors free it;
// after a possible doorbell, uncertainty retains it in the ring/quarantine.
// The caller must never free or retry a packet after calling this function.
int iwx_tahoe_p2p_directed_data_tx_submit(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataPermit *permit, mbuf_t encodedMpdu);
// Like the Action hook, consume every response for the owned qid, including
// malformed/foreign/duplicate responses which must quarantine rather than
// fall through to generic STA reclaim.
bool iwx_tahoe_p2p_directed_data_tx_response(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PDirectedDataContext *context,
    struct iwx_rx_packet *packet, struct iwx_rx_data *rxData,
    TahoeP2PDirectedDataTxWitness::TxPassThrough *passThroughReason);
bool iwx_tahoe_p2p_directed_data_reject_ba(
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PDirectedDataContext *context, uint16_t queueId);
void iwx_tahoe_p2p_directed_data_quarantine(
    TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataReason reason);
// Idempotently closes the exact BSD origin ticket when present. It does not
// remove the queue; callers use the TX lease cleanup API after ROC END. A
// possible doorbell stays quarantined and returns busy.
bool iwx_tahoe_p2p_directed_data_seal_tx_witness(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    const TahoeP2PDirectedDataBinding &binding,
    TahoeP2PDirectedDataTxWitness::Snapshot *out);
TahoeP2PDirectedDataTxWitness::Snapshot *
iwx_tahoe_p2p_directed_data_tx_witness_for_descriptor(
    TahoeP2PDirectedDataContext *context, uint16_t queueId,
    uint16_t descriptorIndex);

int iwx_tahoe_p2p_directed_data_close(
    ItlIwx *owner, TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataReason reason);
bool iwx_tahoe_p2p_directed_data_never_armed(
    ItlIwx *owner, const TahoeP2PDirectedDataContext *context);
bool iwx_tahoe_p2p_directed_data_defer_tx_ring_reset(
    ItlIwx *owner, const TahoeP2PDirectedDataContext *context,
    const TahoeP2PTxQueueLease *queueLease, uint16_t queueId);
// Stop code records each proof only at its real source line. Reclaim requires
// MASTER_DISABLED, SW_RESET issued, and the P2P ring reset after both proofs.
void iwx_tahoe_p2p_directed_data_record_stop_proof(
    TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataStopProof proof);
int iwx_tahoe_p2p_directed_data_drain_after_hardstop(
    ItlIwx *owner, struct iwx_softc *sc,
    TahoeP2PStationLease *stationLease,
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PDirectedDataContext *context);
bool iwx_tahoe_p2p_directed_data_snapshot(
    ItlIwx *owner, const TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataSnapshot *snapshot, bool tryOnly = false,
    int *gateResultOut = nullptr);

#endif // AIRPORT_TAHOE && ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
