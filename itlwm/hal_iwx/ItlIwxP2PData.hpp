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
};

// Copy of the actual BSD origin ticket returned after ROC START. The packet
// token comes only from popDirectedOriginTx(); it is not a reply/request ID.
using TahoeP2PDirectedDataOriginTicket =
    NativeAwdlDirectedOriginTx::Ticket;

struct TahoeP2PDirectedDataOriginPacket {
    TahoeP2PDirectedDataOriginTicket ticket;
    uint64_t packetToken;
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
    uint8_t stationId;
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
    TahoeP2PDirectedDataArm arm;
    TahoeP2PDirectedDataBinding binding;
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
    bool ticketBound;
    bool originWindowBound;
    bool originClosed;
    bool permitIssued;
    bool doorbellIssued;
    bool completionObserved;
    bool frameAttemptSucceeded;
    bool mbufHeldByRing;
    bool hardStopDrained;

    TahoeP2PDirectedDataContext()
        : completion(), arm{}, binding{}, originTicket{}, permit{},
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
          hardStopDrained(false) {}
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
    struct iwx_rx_packet *packet, struct iwx_rx_data *rxData);
bool iwx_tahoe_p2p_directed_data_reject_ba(
    TahoeP2PTxQueueLease *queueLease,
    TahoeP2PDirectedDataContext *context, uint16_t queueId);
void iwx_tahoe_p2p_directed_data_quarantine(
    TahoeP2PDirectedDataContext *context,
    TahoeP2PDirectedDataReason reason);
// Idempotently closes the exact BSD origin ticket when present. It does not
// remove the queue; callers use the TX lease cleanup API after ROC END. A
// possible doorbell stays quarantined and returns busy.
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
