// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/mbuf.h>
#include <net/kpi_interface.h>
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
    TxMulticastMappingMismatchCount, TxMalformedCount, Count
};
struct Snapshot {uint64_t value[Count];};
enum class CaptureResult : uint8_t {
    NotAwdlDataCandidate,
    Captured,
    Rejected,
    QueueFull
};
bool attach(ifnet_t,const uint8_t address[6]);
bool close(); // outside radio gate; waits only for outstanding filter/input calls
bool address(uint8_t out[6]);
void poll(bool radioReady,uint32_t powerGeneration);
CaptureResult capture(const uint8_t *,size_t,bool protectedFrame,bool leaseCurrent,uint32_t powerGeneration);
mbuf_t nextTx(uint16_t wifiSequence,uint64_t *token);
void submitted(uint64_t token,int result);
void completed(uint64_t token,bool success);
void cancelQueued();
Snapshot snapshot();
void gateObservation(uint32_t blockers);
}
