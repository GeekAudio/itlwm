// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/mbuf.h>
#include <net/kpi_interface.h>
#include "awdl_bsd_attach_trace.hpp"
#include "p2p_rx149_data_input.hpp"
namespace NativeAwdlBSD {
enum Counter : unsigned {
    Attached, Closing, Detached, LinkReady, TxAccepted, TxRejected,
    TxExpired, TxEncoded, TxSubmitted, TxCompleted, TxSucceeded, TxFailed,
    TxStaleCompletion, RxCaptured, RxRejected, RxQueueFull, RxDecoded,
    RxDelivered, RxInputFailed, TxPending, RxPending,
    GateChecks, GateAllowed, GateLastBlockers, GateReasonsSeen,
    Ipv6ConfigResult, Ipv6Configured, OffloadCapabilities,
    TxObservationCount, TxLastEthernetLength, TxLastIpv6Length,
    TxLastUdpLength, TxLastIpv6NextHeader, TxLastSourceEui64MatchesOwn,
    TxLastUdpHasMdnsPort, TxLastIpv6DestinationIsMulticast,
    TxLastEthernetMulticastMappingMatches, TxLastUdpChecksumStatus,
    TxLastIpv6PacketWellFormed, TxLastSourceIsLinkLocal,
    TxChecksumStatusSeenMask, TxSourceEui64MismatchCount,
    TxMulticastMappingMismatchCount, TxMalformedCount,
    TxMdnsLegacyAttempts, TxMdnsQuAttempts, TxMdnsQmAttempts,
    TxMdnsOtherAttempts, TxMdnsUnknownAttempts,
    TxMdnsLegacySubmitted, TxMdnsQuSubmitted, TxMdnsQmSubmitted,
    TxMdnsOtherSubmitted, TxMdnsUnknownSubmitted,
    TxMdnsLegacyCompleted, TxMdnsQuCompleted, TxMdnsQmCompleted,
    TxMdnsOtherCompleted, TxMdnsUnknownCompleted,
    TxMdnsLegacySucceeded, TxMdnsQuSucceeded, TxMdnsQmSucceeded,
    TxMdnsOtherSucceeded, TxMdnsUnknownSucceeded,
    TxMdnsSubmitFailed, TxMdnsCompletionFailed,
    TxMdnsLastClass, TxMdnsLastSourcePortIs5353,
    TxMdnsLastDestinationPortIs5353, TxMdnsLastDestinationIsFf02Fb,
    TxMdnsLastDnsHeaderParsed, TxMdnsLastQr, TxMdnsLastTc,
    TxMdnsLastQuestionCount, TxMdnsLastTargetPtrInQuestionCount,
    TxMdnsLastQuQuestionMask, TxMdnsLastAttemptToken, Count
};
enum Rx149InputDisposition : uint32_t {
    Rx149ReceiptNone=0,
    Rx149ReceiptCaptured=1,
    Rx149ReceiptStaleOrInvalid=2,
    Rx149ReceiptDecodeRejected=3,
    Rx149ReceiptAddressRejected=4,
    Rx149ReceiptMbufAllocationFailed=5,
    Rx149ReceiptIfnetInputSucceeded=6,
    Rx149ReceiptIfnetInputFailed=7,
    Rx149ReceiptQueueFull=8
};
// One bounded, payload-free receipt for the latest Test086 MPDU. This proves
// local queue/decode/DLIL attempts only; it is not proof of RF peer receipt.
struct Rx149InputReceipt {
    uint32_t schemaVersion=2;
    uint32_t disposition=Rx149ReceiptNone;
    uint64_t sequence=0;
    uint64_t contentRevision=0;
    uint64_t ownerSerial=0;
    uint64_t interfaceIncarnation=0;
    uint32_t contextGeneration=0;
    uint32_t powerGeneration=0;
    uint32_t stationGeneration=0;
    uint32_t rocGeneration=0;
    uint64_t captureUs=0;
    uint64_t inputUs=0; // lock-linearized DLIL admission ticket time
    uint64_t deadlineUs=0;
    uint32_t ieeeChannel=0;
    uint32_t macIndexPresent=0;
    uint32_t macIndex=0;
    uint32_t macPhyDecodeMode=0;
    uint32_t originalRxStatus=0;
    uint32_t mpduLength=0;
    uint32_t decodedIpv6Count=0;
    uint32_t ifnetInputResultPresent=0;
    int32_t ifnetInputResult=0;
};
struct Rx149RecoveryAuthority {
    // Captured before a complete HAL initialization begins. Recovery is valid
    // only when this exact blocked-fault serial is still current afterward.
    uint32_t faultSerial=0;
    // Generation produced by that successful full initialization.
    uint32_t powerGeneration=0;
    bool fullInitializationSucceeded=false;
    bool faultSourceClear=false;
};
enum class Rx149RecoveryResult : uint32_t {
    Recovered=0,
    NotBlocked=1,
    InvalidAuthority=2,
    StaleFaultSerial=3,
    BridgeUnavailable=4,
    WrongPowerGeneration=5,
    CurrentOwnerActive=6,
    VersionExhausted=7,
    WorkerActive=8,
    InputTicketActive=9,
    PermitQueueNotDrained=10,
    FaultRaced=11
};
struct Snapshot {
    uint64_t value[Count];
    Rx149InputReceipt rx149Input;
};
// Numeric-only capability for the exact selected eligible QM packet. This snapshot
// exposes no mbuf, address, or payload and is revalidated before dequeue.
struct DiscoveryTxSnapshot {
    uint64_t token;
    uint64_t bornUs;
    uint32_t generation;
    uint8_t queryClass;
    bool eligible;
};
enum class CaptureResult : uint8_t {
    NotAwdlDataCandidate,
    Captured,
    Rejected,
    QueueFull
};
bool attach(ifnet_t,const uint8_t address[6]);
AttachTraceSnapshot attachSnapshot();
void noteResidentLookupResult(int result);
// Short, nonblocking publication point. It may run in the main radio gate;
// it performs no KPI, detach, wait, or release operation.
void publishClosing();
bool close(); // outside radio gate; waits only for outstanding filter/input calls
// Returns the live ifnet link address only for the current attached owner and
// radio generation. The KPI call runs without IOSimpleLock held.
bool address(uint32_t expectedPowerGeneration, uint8_t out[6]);
void poll(bool radioReady,uint32_t powerGeneration);
// Scoped Test086 worker drain. Unlike the legacy two-argument poll, this
// overload consumes only channel-149 packets carrying a fresh RX permit. The
// caller supplies a freshly sampled main-gate lease; nullptr is fail-closed.
void poll(bool radioReady,uint32_t powerGeneration,
          const NativeP2PRx149DataInput::Lease *rx149Lease);
CaptureResult capture(const uint8_t *,size_t,bool protectedFrame,bool leaseCurrent,uint32_t powerGeneration);
CaptureResult captureRx149Data(const uint8_t *,size_t,bool protectedFrame,
          const NativeP2PRx149DataInput::Lease &,
          const NativeP2PRx149DataInput::Permit &,uint32_t powerGeneration);
// Only the main-gate lease publisher may activate/refresh a lease. Worker
// drains validate this authority and can never reopen it from a copied guard.
void publishRx149DataInputLease(
          const NativeP2PRx149DataInput::Lease &lease);
// Revoke only if the numeric owner tuple still names the active permit. The
// unconditional overload is for terminal cancellation/reset paths.
void revokeRx149DataInput();
void revokeRx149DataInput(uint64_t ownerSerial,
          const NativeP2PRx149DataInput::Epochs &epochs);
// Latched, lock-free RX149 fail-closed fence for HW_ERR/RFKILL interrupt
// paths. It performs no clock read, queue walk, KPI, wait, or allocation.
void invalidateRx149DataInputFast();
bool rx149DataInputBlocked();
// Sample at HAL initialization entry, then attach the same serial and the
// new generation only after full init/READY completes with the source fault
// clear. The bridge never clears its fence from a plain Wi-Fi-ready or
// preflight result; this pre-ARM transition does not require a future ROC.
uint32_t rx149DataInputFaultSerial();
Rx149RecoveryResult recoverRx149DataInput(
          const Rx149RecoveryAuthority &authority);
#if defined(ITL_NATIVE_AWDL_RX149_TEST_HOOKS)
enum class Rx149TestHookPoint : uint8_t {
    LeaseAuthorization,
    CaptureAuthorization,
    InputTicketAuthorization,
    BeforeInputTicketReservation,
    AfterInputTicket
};
using Rx149TestHook = void (*)(Rx149TestHookPoint);
void setRx149TestHookForTests(Rx149TestHook hook);
#endif
mbuf_t nextTx(uint16_t wifiSequence,uint64_t *token);
// Reads bounded immutable queue metadata and returns the earliest current
// strict-QM item, which may be behind unrelated FIFO entries. A successful
// peek grants no ownership; nextDiscoveryTx must match this exact token,
// generation, born time, and class before removing only that item. Skipped
// entries retain their relative order.
bool peekDiscoveryTx(uint32_t expectedPowerGeneration,
                     DiscoveryTxSnapshot *out);
// nullptr + consumed=false leaves the queue untouched. nullptr + consumed=true
// means the matching packet was consumed but failed fresh validation/encoding.
// A non-null returned mbuf is the encoded MPDU and consumed is true.
mbuf_t nextDiscoveryTx(uint16_t wifiSequence,
                       const DiscoveryTxSnapshot &expected,
                       uint64_t *token,bool *consumed);
void submitted(uint64_t token,int result);
void completed(uint64_t token,bool success);
void cancelQueued();
Snapshot snapshot();
void gateObservation(uint32_t blockers);
}
