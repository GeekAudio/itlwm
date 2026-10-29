// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/mbuf.h>
#include <net/kpi_interface.h>
#include "awdl_bsd_attach_trace.hpp"
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
struct Snapshot {uint64_t value[Count];};
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
CaptureResult capture(const uint8_t *,size_t,bool protectedFrame,bool leaseCurrent,uint32_t powerGeneration);
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
