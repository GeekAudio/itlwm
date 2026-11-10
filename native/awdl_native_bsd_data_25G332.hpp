// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/mbuf.h>
#include <net/kpi_interface.h>
#include "awdl_bsd_attach_trace.hpp"
#include "p2p_rx149_data_input.hpp"
#include "p2p_directed_data_rx_input.hpp"
#include "awdl_directed_data_rx_receipt.hpp"
#include "rx149_capture_diagnostics.hpp"
#include "awdl_reply_shadow.hpp"
#ifndef ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
#define ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332 0
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332) && \
    (!defined(ITL_NATIVE_AWDL_RESIDENT_25G332) || \
     !ITL_NATIVE_AWDL_RESIDENT_25G332 || \
     defined(ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332) || \
     ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332)
#error "Discovery RX input requires the resident-only non-RX149/non-directed profile"
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
#include "awdl_discovery_rx_input.hpp"
#endif
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
#include "awdl_directed_origin_tx.hpp"
#endif
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
    TxMdnsLastQuQuestionMask, TxMdnsLastAttemptToken,
    DirectedRxCaptured, DirectedRxRejected, DirectedRxQueueFull,
    DirectedRxDecoded, DirectedRxDelivered, DirectedRxInputFailed,
    DirectedRxPending,
    DiscoveryInputCalls, DiscoveryInputResult, DiscoveryInputSuccess,
    DiscoverySameWindowCommitted, Count
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
    DirectedDataRxInputReceipt directedDataRxInput;
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
// Payload-free witness that an ordinary system-origin IPv6 packet is at the
// head of the resident TX FIFO. This is demand evidence only: it grants no
// firmware ownership and does not dequeue or authorize a transmission.
struct SystemDataTxDemandSnapshot {
    uint64_t token;
    uint64_t queuedUs;
    uint32_t powerGeneration;
};
enum class CaptureResult : uint8_t {
    NotAwdlDataCandidate,
    Captured,
    Rejected,
    QueueFull,
    Duplicate
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
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
// Separate mode-4/channel-6 bridge owner. This never consumes RX149 permits.
void poll(bool radioReady,uint32_t powerGeneration,
          const NativeP2PDirectedDataRxInput::Lease *directedDataRxLease);
CaptureResult captureDirectedDataRx(const uint8_t *,size_t,bool protectedFrame,
          const NativeP2PDirectedDataRxInput::Lease &,
          const NativeP2PDirectedDataRxInput::Permit &,uint32_t powerGeneration);
bool publishDirectedDataRxInputLease(
          const NativeP2PDirectedDataRxInput::Lease &lease);
// IRQ/main-gate safe fence for canonical ROC END. This exact owner/epoch
// marker is lock-free and never blocks on the BSD bridge lock.
bool markDirectedDataEndFast(uint64_t ownerSerial,
          const NativeP2PDirectedDataRxInput::Epochs &epochs);
void revokeDirectedDataRxInput();
void revokeDirectedDataRxInput(uint64_t ownerSerial,
          const NativeP2PDirectedDataRxInput::Epochs &epochs);
#endif
CaptureResult capture(const uint8_t *,size_t,bool protectedFrame,bool leaseCurrent,uint32_t powerGeneration);
CaptureResult captureRx149Data(const uint8_t *,size_t,bool protectedFrame,
          const NativeP2PRx149DataInput::Lease &,
          const NativeP2PRx149DataInput::Permit &,uint32_t powerGeneration);
// Immutable first-eight-attempt numeric diagnostics. This does not return
// permission, alter a lease/gate, or claim packet/input completion.
void captureRx149Diagnostics(Rx149CaptureDiagnostics::Wire *out);
#if defined(ITL_NATIVE_AWDL_RX149_TEST_HOOKS)
// Host-only seam changes incarnation without clearing slots to test identity.
void advanceRx149InterfaceIncarnationForTests();
#endif
// Only the main-gate lease publisher may activate/refresh a lease. Worker
// drains validate this authority and can never reopen it from a copied guard.
// True means activation/refresh succeeded at the locked authorization point;
// it does not reserve an input ticket or prevent subsequent revocation.
// A strictly qualified first-START wait returns false without tombstoning a
// fresh owner only while the bridge has no active lease and remains ready.
bool publishRx149DataInputLease(
          const NativeP2PRx149DataInput::Lease &lease);
#if defined(ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332)
struct DiscoveryRxIfnetIdentity {
    uint32_t ifindex=0;
    uint64_t ifnetIncarnation=0;
    uint8_t localMac[6]{};
};
// Call outside the radio main gate; the bridge pins the ifnet, samples its
// live index/address, and confirms the same attachment generation afterward.
bool readDiscoveryRxIfnetIdentity(DiscoveryRxIfnetIdentity *out);
bool publishDiscoveryRxInputLease(
          const NativeAwdlDiscoveryRxInput::Lease &lease,
          const NativeAwdlDiscoveryRxInput::MainGate &gate);
CaptureResult captureDiscoveryRxData(const uint8_t *,size_t,bool protectedFrame,
          const NativeAwdlDiscoveryRxInput::Lease &,
          const NativeAwdlDiscoveryRxInput::MainGate &,
          const NativeAwdlDiscoveryRxInput::Permit &,uint32_t powerGeneration);
using DiscoveryRxAdmissionAction=bool (*)(void *ticketContext,
          const NativeAwdlDiscoveryRxInput::Lease &,
          const NativeAwdlDiscoveryRxInput::MainGate &);
using DiscoveryRxGateRunner=bool (*)(void *ownerContext,
          const NativeAwdlDiscoveryRxInput::Identity &,
          DiscoveryRxAdmissionAction,void *ticketContext);
void pollDiscoveryRx(bool radioReady,uint32_t powerGeneration,
          const NativeAwdlDiscoveryRxInput::Lease *lease,
          const NativeAwdlDiscoveryRxInput::MainGate *gate,
          DiscoveryRxGateRunner gateRunner=nullptr,
          void *ownerContext=nullptr);
// IRQ/main-gate safe exact-identity END fence. It reserves no input ticket and
// never waits for the BSD bridge lock.
bool markDiscoveryRxEndFast(
          const NativeAwdlDiscoveryRxInput::Identity &identity);
void revokeDiscoveryRxInput(
          const NativeAwdlDiscoveryRxInput::Identity &identity);
void revokeDiscoveryRxInput();
// True after END/revoke only when the dedicated queue, worker, and DLIL ticket
// have all drained. The resident ifnet may remain attached.
bool discoveryRxQuiescent();
#endif
// Shadow-only configuration from the authoritative main-gate caller. This
// never activates/refreshes a copied lease and never permits firmware TX.
// One immutable configuration per bridge lifetime, default disabled.
bool configureReplyShadow(const NativeAwdlReplyShadow::Config &,
                          const NativeP2PRx149DataInput::Lease &);
void disableReplyShadow();
NativeAwdlReplyShadow::Snapshot replyShadowSnapshot();
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
// Observe only the current FIFO head. Receive-only and directed-origin
// profiles return false because they do not use the ordinary system TX queue.
bool peekSystemDataTxDemand(uint32_t expectedPowerGeneration,
                            SystemDataTxDemandSnapshot *out);
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
                       uint64_t *token,bool *consumed,
                       bool omitKnownAnswer=false);
void submitted(uint64_t token,int result);
void completed(uint64_t token,bool success);
void cancelQueued();
Snapshot snapshot();
void gateObservation(uint32_t blockers);
#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332
// Bounded one/two-packet active UDP origin. openDirectedOriginTx binds the
// caller's START/owner tuple to this live BSD interface; ifindex, interface
// incarnation, and source MAC are captured here and never accepted from the
// caller. Call these APIs outside IOSimpleLock/main-gate critical sections.
bool openDirectedOriginTx(
    const NativeAwdlDirectedOriginTx::OpenRequest &request,
    NativeAwdlDirectedOriginTx::Ticket *out);
bool closeDirectedOriginTx(
    const NativeAwdlDirectedOriginTx::Ticket &ticket);
void revokeDirectedOriginTx();
// The returned mbuf contains exactly one 96-byte 802.11 MPDU (no FCS), and
// ownership transfers to the caller. The original BSD output mbuf is freed by
// this call on both encode success and failure. PacketIdentity::packetSerial
// is independent from ticketSerial and Wi-Fi/AWDL sequence numbers.
mbuf_t popDirectedOriginTx(
    const NativeAwdlDirectedOriginTx::Ticket &ticket,
    uint16_t wifiSequence,uint16_t awdlSequence,
    NativeAwdlDirectedOriginTx::PacketIdentity *identity);
// Legacy single-packet ABI. The token is the independent packetSerial.
mbuf_t popDirectedOriginTx(
    const NativeAwdlDirectedOriginTx::Ticket &ticket,
    uint16_t wifiSequence,uint16_t awdlSequence,uint64_t *packetToken);
// Called after the actual HBUS write, outside the main-gate/BSD-lock nesting.
bool recordDirectedTxDoorbell(
    const NativeAwdlDirectedOriginTx::Ticket &ticket,
    const NativeAwdlDirectedOriginTx::PacketIdentity &identity,
    uint64_t submitUs);
// Records only the HAL's exact, successful per-packet TX_RSP result.
bool recordDirectedTxCompletion(
    const NativeAwdlDirectedOriginTx::Ticket &ticket,
    const NativeAwdlDirectedOriginTx::PacketIdentity &identity,
    bool frameAttemptSucceeded,uint64_t txResponseUs);
bool snapshotDirectedExactReply(
    const NativeAwdlDirectedOriginTx::Ticket &ticket,uint64_t packetSerial,
    NativeAwdlDirectedOriginTx::ExactReplyReceipt *out);
void snapshotDirectedOriginTx(
    NativeAwdlDirectedOriginTx::Snapshot *out);
#endif
}
