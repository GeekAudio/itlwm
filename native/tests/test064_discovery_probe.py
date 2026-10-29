#!/usr/bin/env python3
"""Compile and exercise extracted Test064 production discovery helpers.

This compiles the actual discoveryExperimentEnabled/discoveryNumber/
discoveryAnchor/discoveryPsf/takeDiscoveryPacket bodies from
ItlIwxP2PProbe.cpp with small host-side IOKit/peer-table/BSD queue stubs. It
does not copy their control flow into a mock implementation.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"


def function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise RuntimeError(f"missing production function: {signature}")
    opening = source.find("{", start + len(signature))
    if opening < 0:
        raise RuntimeError(f"missing body: {signature}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise RuntimeError(f"unterminated function body: {signature}")


def caller_gate_audit(source: str) -> None:
    # Keep these checks tied to the production call site and exact ordering.
    # They protect the outer successful-own-PSF/MIF gate and the post-encode
    # time sample that is too large to host-compile with the full kernel loop.
    trigger = source.find("packet = takeDiscoveryPacket(run, epochs,")
    if trigger < 0:
        raise RuntimeError("production caller no longer invokes takeDiscoveryPacket")
    gate_start = source.rfind("if(successfulStart", 0, trigger)
    if gate_start < 0:
        raise RuntimeError("cannot find successful-start native data gate")
    surrounding = source[gate_start:trigger]
    compact = re.sub(r"\s+", "", surrounding)
    for required in (
        "probe->mifResultCaptured&&probe->mifTxSucceeded",
        "run->nativeDataAttempts==0",
        "!run->discoveryConsumed",
    ):
        if required not in compact:
            raise RuntimeError(f"caller gate missing: {required}")

    take_body = function_body(source, "static mbuf_t takeDiscoveryPacket(P2PProbeRun *run,")
    next_tx = take_body.find("NativeAwdlBSD::nextDiscoveryTx(")
    submit_start = source.find("const uint64_t gateUs = p2pProbeMonotonicNanoseconds() / 1000ULL;", trigger)
    submit = source.find("iwx_tahoe_p2p_action_tx_submit(", trigger)
    if next_tx < 0 or submit_start < trigger or submit < submit_start:
        raise RuntimeError("post-encode now check must follow queue encoding and precede submit")
    if "gateUs < run->discoveryTarget.earliestSubmitUs" not in source[submit_start:submit]:
        raise RuntimeError("post-encode lower time bound check missing")
    if "gateUs >= run->discoveryTarget.latestSubmitUs" not in source[submit_start:submit]:
        raise RuntimeError("post-encode upper time bound check missing")
    if "&& !probe->discoveryConsumed" not in source[gate_start:trigger]:
        raise RuntimeError("consumed discovery packet must stop later native data sends")
    if source.count("NativeAwdlBSD::nextTx(") != 1:
        raise RuntimeError("native BSD data dequeue has an unexpected additional TX path")
    action_call_start = source.find("const int result=iwx_tahoe_p2p_action_tx_submit(", trigger)
    action_call_end = source.find(");", action_call_start)
    if action_call_start < 0 or action_call_end < 0:
        raise RuntimeError("native action submit call is missing")
    action_call = re.sub(r"\s+", "", source[action_call_start:action_call_end])
    for required in (
        "discoveryPacket?run->discoveryTarget.earliestSubmitUs:0",
        "discoveryPacket?run->discoveryTarget.latestSubmitUs:0",
        "discoveryPacket?run->stationGeneration:0",
    ):
        if required not in action_call:
            raise RuntimeError(f"deadline submit provenance missing: {required}")
    if "#errorThediscoveryexperimentrequiresthesignedTX-evidencebuildprofile." not in re.sub(
        r"\s+", "", source
    ):
        raise RuntimeError("discovery build must require the signed TX-evidence profile")
    build_script = (ROOT / "scripts/build_tahoe.py").read_text()
    if "args.native_awdl_resident_data and args.native_awdl_tx_evidence" not in build_script or \
       "args.p2p_gp2_observation and args.p2p_manual_trigger" not in build_script:
        raise RuntimeError("build script must require resident, GP2, manual and TX-evidence profile")

    mif_prepare = function_body(
        source,
        "static bool prepareMifCandidateAfterPsfCompletion("
    )
    compact_prepare = re.sub(r"\s+", "", mif_prepare)
    for required in ("!probe->psfResultCaptured", "!probe->psfTxSucceeded"):
        if required not in compact_prepare:
            raise RuntimeError(f"own MIF path is no longer gated on successful own PSF: {required}")
    if "set(\"ClockMappingVerified\", 0);" not in source or \
       "set(\"AirtimeVerified\", 0);" not in source or \
       "set(\"FormalPeerPolicyChanged\", 0);" not in source or \
       "set(\"ExperimentalOnly\", 1);" not in source:
        raise RuntimeError("discovery publication proof flags changed unexpectedly")

    call = source.find("const bool discoveryProfile = discoveryExperimentEnabled(self);", gate_start)
    fallback = source.find("if (!packet)\n                    packet = NativeAwdlBSD::nextTx(", call)
    profile_branch = source.find("if (discoveryProfile && !discoveryPacket) {", call)
    branch_end = source.find("if (peerBlockers && !discoveryPacket)", profile_branch)
    if min(call, fallback, profile_branch, branch_end) < 0 or not (
        call < profile_branch < branch_end < fallback
    ):
        raise RuntimeError("discovery-profile failure must return before normal BSD nextTx fallback")
    profile_failure = source[profile_branch:branch_end]
    compact_profile_failure = re.sub(r"\s+", "", profile_failure)
    for required in (
        "if(peer.validPeerCount&&!run->discoveryWindowClosed)",
        "run->discoveryStatus=16;",
        "run->discoveryWindowClosed=true;",
        "returnkIOReturnNotReady;",
    ):
        if required not in compact_profile_failure:
            raise RuntimeError(f"admitted-MIF early skip gate missing: {required}")


HARNESS = r'''#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <string>
#include "native/awdl_discovery_phase_experiment.hpp"
#include "native/awdl_host_phase.hpp"

class OSObject { public: virtual ~OSObject() {} };
class OSNumber : public OSObject {
public:
    explicit OSNumber(uint64_t value = 0) : value(value) {}
    uint64_t unsigned64BitValue() const { return value; }
    uint64_t value;
};
class OSBoolean : public OSObject {};
static OSBoolean gTrue;
static OSObject *kOSBooleanTrue = &gTrue;
#define OSDynamicCast(type, value) dynamic_cast<type *>(value)

class IOEthernetController : public OSObject {
public:
    OSObject *getProperty(const char *key) {
        ++propertyReads;
        const auto it = properties.find(key);
        return it == properties.end() ? nullptr : it->second;
    }
    void put(const char *key, OSObject *value) { properties[key] = value; }
    void putNumber(const char *key, uint64_t value) {
        numbers[key] = OSNumber(value);
        put(key, &numbers[key]);
    }
    std::map<std::string, OSObject *> properties;
    std::map<std::string, OSNumber> numbers;
    unsigned propertyReads = 0;
};

namespace IntelAwdlPeer {
struct RuntimeEpochs {
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    bool valid;
};
}
namespace IntelAwdlPeerRuntime {
constexpr uint8_t kPeerCapacity = 4;
struct PsfPeerSnapshot {
    uint64_t psfAgeUs;
    uint64_t contextGeneration, powerGeneration, stationGeneration;
    uint64_t psfRxMonotonicUs;
    uint32_t psfRxGp2TimestampUs, phyTxTimestampUs, targetTxTimestampUs;
    uint16_t txDownCounterTu, awPeriodTu, nextAwSequence;
    uint8_t rxChannel, channelSlots[16];
    bool tracked, hasPsf, psfFresh, syncConsistent;
    bool psfRxGp2TimestampPresent;
    bool hasMif;
};
}

struct Ieee80211Channel { uint8_t ieee; };
struct Ieee80211Com { Ieee80211Channel ic_channels[4]; };
struct Softc { Ieee80211Com sc_ic; };
static uint8_t ieee80211_chan2ieee(Ieee80211Com *, Ieee80211Channel *channel) {
    return channel->ieee;
}

struct PeerRuntime {
    IntelAwdlPeerRuntime::PsfPeerSnapshot selected{};
    IntelAwdlPeerRuntime::PsfPeerSnapshot changedAtRecheck{};
    unsigned reads = 0;
    bool present = true;
    bool changeAtRecheck = false;
    bool getPsfSnapshot(uint8_t slot, const IntelAwdlPeer::RuntimeEpochs &,
                       uint64_t, IntelAwdlPeerRuntime::PsfPeerSnapshot *out) {
        ++reads;
        if (!out || slot != 0 || !present)
            return false;
        *out = (changeAtRecheck && reads > 1) ? changedAtRecheck : selected;
        return true;
    }
};

struct ItlIwx {
    IOEthernetController *controller = nullptr;
    bool onMainGate = true;
    PeerRuntime tahoe_awdl_peer_runtime_;
    Softc com{};
    IOEthernetController *tahoeP2pController() { return controller; }
    bool tahoeP2pOnMainGate() const { return onMainGate; }
};
struct PsfInputLite { uint8_t channelSlots[16]; };
struct RocCandidate {
    uint64_t startObservedUs, hardDeadlineUs, sampleUs;
    PsfInputLite input;
};
namespace NativeAwdlBSD {
struct DiscoveryTxSnapshot {
    uint64_t token, bornUs;
    uint32_t generation;
    uint8_t queryClass;
    bool eligible;
};
}
struct P2PProbeRun {
    ItlIwx *owner;
    bool discoveryConsumed;
    bool discoveryCandidateLocked;
    bool discoveryWindowClosed;
    uint8_t discoveryPeerSlot;
    uint16_t discoveryRxChannelIndex;
    uint32_t nativeDataAttempts;
    uint32_t contextGeneration, powerGeneration, stationGeneration;
    uint32_t discoveryStatus, discoveryPhaseStatus, discoveryChecks;
    uint32_t discoveryPublishVersion, discoveryLastPublishedStatus;
    uint64_t discoveryPacketToken, discoveryPsfObservedUs;
    uint64_t discoverySubmitCallStartUs, discoverySubmitCallEndUs;
    uint64_t discoveryCompletedBaseline, discoverySucceededBaseline;
    int discoverySubmitResult;
    NativeAwdlDiscoveryPhase::EstimatedTarget discoveryTarget;
    NativeAwdlDiscoveryPhase::PsfWitness discoveryPsfWitness;
    NativeAwdlBSD::DiscoveryTxSnapshot discoveryHead;
    RocCandidate psfCandidate;
    uint64_t mifPacingWindowEndUs;
};

using mbuf_t = struct FakeMbuf *;
struct FakeMbuf {};
namespace NativeAwdlBSD {
enum Counter { TxCompleted = 0, TxSucceeded = 1 };
struct Snapshot { uint64_t value[2]; };
static Snapshot gCounters{{5, 4}};
static DiscoveryTxSnapshot gHead{91, 741000000, 12, 3, true};
static FakeMbuf gPacket;
static unsigned peeks = 0, consumes = 0;
static bool headEligible = true, returnPacket = true, consumeHead = true;
inline Snapshot snapshot() { return gCounters; }
inline bool peekDiscoveryTx(uint32_t power, DiscoveryTxSnapshot *out) {
    ++peeks;
    if (!headEligible || !out || power != gHead.generation)
        return false;
    *out = gHead;
    return true;
}
inline mbuf_t nextDiscoveryTx(uint16_t, const DiscoveryTxSnapshot &head,
                              uint64_t *token, bool *consumed) {
    ++consumes;
    if (consumed) *consumed = false;
    if (!token || !consumed || !consumeHead || head.token != gHead.token)
        return nullptr;
    *token = gHead.token;
    *consumed = true;
    return returnPacket ? &gPacket : nullptr;
}
}

static uint64_t gTimesUs[4] = {741050000, 741050100, 741050200, 741050300};
static unsigned gTimeIndex = 0;
static uint64_t p2pProbeMonotonicNanoseconds() {
    const unsigned index = gTimeIndex < 4 ? gTimeIndex++ : 3;
    return gTimesUs[index] * 1000ULL;
}
static unsigned gPublishCalls = 0;
static void publishDiscoveryExperiment(P2PProbeRun *, bool = false) {
    ++gPublishCalls;
}

// PRODUCTION_FUNCTIONS_INSERTION_POINT

static void putBool(IOEthernetController &controller, const char *key) {
    controller.put(key, kOSBooleanTrue);
}
static void putAnchor(IOEthernetController &controller, uint64_t context,
                      uint64_t power, uint64_t station) {
    controller.putNumber("NativeP2PGp2PreStatus", 1);
    controller.putNumber("NativeP2PGp2PreGeneration", context);
    controller.putNumber("NativeP2PGp2PowerGeneration", power);
    controller.putNumber("NativeP2PGp2StationGeneration", station);
    controller.putNumber("NativeP2PGp2PreValue", 675917609U);
    controller.putNumber("NativeP2PGp2PreHostBeforeUs", 740711353ULL);
    controller.putNumber("NativeP2PGp2PreHostAfterUs", 740711356ULL);
}
static void putProfile(IOEthernetController &controller) {
    const char *keys[] = {"NativeAwdlDiscoveryExperimentEnabled",
        "NativeAwdlResidentEnabled", "NativeP2PGp2Observation",
        "NativeP2PManualTrigger"};
    for (const char *key : keys) putBool(controller, key);
}
static void setup(P2PProbeRun &run, ItlIwx &owner,
                  IOEthernetController &controller) {
    controller = IOEthernetController{};
    owner = ItlIwx{};
    owner.controller = &controller;
    owner.com.sc_ic.ic_channels[0].ieee = 6;
    owner.com.sc_ic.ic_channels[1].ieee = 11;
    owner.tahoe_awdl_peer_runtime_.selected = {};
    auto &psf = owner.tahoe_awdl_peer_runtime_.selected;
    psf.contextGeneration = 11;
    psf.powerGeneration = 12;
    psf.stationGeneration = 13;
    psf.psfRxMonotonicUs = 741024377ULL;
    psf.psfRxGp2TimestampUs = 676227262U;
    psf.phyTxTimestampUs = 1328926346U;
    psf.targetTxTimestampUs = 1328926240U;
    psf.nextAwSequence = 20190;
    psf.txDownCounterTu = 21;
    psf.awPeriodTu = 16;
    psf.rxChannel = 0;
    const uint8_t channels[16] = {
        36, 36, 149, 0, 0, 0, 0, 36, 6, 36, 149, 36, 0, 0, 0, 36
    };
    memcpy(psf.channelSlots, channels, sizeof(channels));
    psf.tracked = psf.hasPsf = psf.psfFresh = psf.syncConsistent = true;
    psf.psfRxGp2TimestampPresent = true;
    psf.hasMif = false; // A PSF-only observation is not a formal MIF peer.
    owner.tahoe_awdl_peer_runtime_.reads = 0;
    owner.tahoe_awdl_peer_runtime_.present = true;
    owner.tahoe_awdl_peer_runtime_.changeAtRecheck = false;

    run = {};
    run.owner = &owner;
    run.contextGeneration = 11;
    run.powerGeneration = 12;
    run.stationGeneration = 13;
    run.psfCandidate.startObservedUs = 741000000ULL;
    run.psfCandidate.hardDeadlineUs = 741120000ULL;
    run.psfCandidate.sampleUs = 741009156ULL;
    run.psfCandidate.input.channelSlots[0] = 6; // One announced local slot.
    assert(configureMifPacingWindow(&run));
    assert(run.mifPacingWindowEndUs == 741074692ULL);
    putProfile(controller);
    putAnchor(controller, 11, 12, 13);
    NativeAwdlBSD::gHead = {91, 741000000, 12, 3, true};
    NativeAwdlBSD::headEligible = true;
    NativeAwdlBSD::returnPacket = true;
    NativeAwdlBSD::consumeHead = true;
    NativeAwdlBSD::peeks = NativeAwdlBSD::consumes = 0;
    gTimesUs[0] = 741050000;
    gTimesUs[1] = 741050100;
    gTimeIndex = 0;
    gPublishCalls = 0;
}

static IntelAwdlPeer::RuntimeEpochs runtimeEpochs() {
    return {11, 12, 13, true};
}
static IntelAwdlPeer::RuntimeEpochs runtimeEpochs(uint64_t context,
                                                  uint64_t power,
                                                  uint64_t station) {
    return {context, power, station, true};
}

static void testActualExtractedTakeAndNoMifAdmission()
{
    P2PProbeRun run{}; ItlIwx owner{}; IOEthernetController controller;
    setup(run, owner, controller);
    uint64_t token = 0;
    mbuf_t packet = takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token);
    assert(packet != nullptr && token == 91);
    assert(run.discoveryConsumed && run.discoveryPacketToken == 91);
    assert(run.nativeDataAttempts == 0); // claim precedes the caller's submit
    assert(run.discoveryPhaseStatus == static_cast<uint32_t>(
        NativeAwdlDiscoveryPhase::Status::kEstimatedCandidate));
    assert(run.discoveryTarget.earliestSubmitUs == 741046503ULL);
    assert(run.discoveryTarget.latestSubmitUs == 741054692ULL);
    assert(!run.discoveryTarget.clockMappingVerified &&
           !run.discoveryTarget.airtimeVerified &&
           run.discoveryTarget.experimentalOnly);
    assert(NativeAwdlBSD::peeks == 1 && NativeAwdlBSD::consumes == 1);
    // 4 experiment booleans plus exactly seven immutable pre-ROC scalar reads.
    assert(controller.propertyReads == 11);
    assert(owner.tahoe_awdl_peer_runtime_.reads ==
           IntelAwdlPeerRuntime::kPeerCapacity + 1); // scan then recheck
    assert(!owner.tahoe_awdl_peer_runtime_.selected.hasMif);
}

static void testConsumedOrAttemptedRunCannotTakeHeadAgain()
{
    P2PProbeRun run{}; ItlIwx owner{}; IOEthernetController controller;
    setup(run, owner, controller);
    run.discoveryConsumed = true;
    uint64_t token = 0;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(NativeAwdlBSD::peeks == 0 && NativeAwdlBSD::consumes == 0);

    setup(run, owner, controller);
    run.nativeDataAttempts = 1;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(NativeAwdlBSD::peeks == 0 && NativeAwdlBSD::consumes == 0);

    setup(run, owner, controller);
    NativeAwdlBSD::returnPacket = false; // The FIFO token is consumed, encoding fails.
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryConsumed && run.discoveryStatus == 11);
    assert(NativeAwdlBSD::consumes == 1);
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(NativeAwdlBSD::peeks == 1 && NativeAwdlBSD::consumes == 1);
}

static void testStrictQmHeadAndPreAnchorStatus()
{
    P2PProbeRun run{}; ItlIwx owner{}; IOEthernetController controller;
    setup(run, owner, controller);
    NativeAwdlBSD::headEligible = false;
    uint64_t token = 0;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryStatus == 3 && NativeAwdlBSD::consumes == 0);

    setup(run, owner, controller);
    controller.putNumber("NativeP2PGp2PreStatus", 2);
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryStatus == 4 && NativeAwdlBSD::consumes == 0);
}

static void testExactSnapshotAndChannelRecheck()
{
    P2PProbeRun run{}; ItlIwx owner{}; IOEthernetController controller;
    setup(run, owner, controller);
    owner.tahoe_awdl_peer_runtime_.changeAtRecheck = true;
    owner.tahoe_awdl_peer_runtime_.changedAtRecheck =
        owner.tahoe_awdl_peer_runtime_.selected;
    owner.tahoe_awdl_peer_runtime_.changedAtRecheck.targetTxTimestampUs++;
    uint64_t token = 0;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryStatus == 9 && NativeAwdlBSD::consumes == 0);
    assert(run.discoveryPhaseStatus == static_cast<uint32_t>(
        NativeAwdlDiscoveryPhase::Status::kCurrentSnapshotMismatch));
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(NativeAwdlBSD::peeks == 1 && NativeAwdlBSD::consumes == 0);

    setup(run, owner, controller);
    owner.tahoe_awdl_peer_runtime_.changeAtRecheck = true;
    owner.tahoe_awdl_peer_runtime_.changedAtRecheck =
        owner.tahoe_awdl_peer_runtime_.selected;
    owner.tahoe_awdl_peer_runtime_.changedAtRecheck.rxChannel = 1;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryStatus == 9 && NativeAwdlBSD::consumes == 0);
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(NativeAwdlBSD::peeks == 1 && NativeAwdlBSD::consumes == 0);
}

static void testCandidateTimeAndLeaseReserve()
{
    P2PProbeRun run{}; ItlIwx owner{}; IOEthernetController controller;
    setup(run, owner, controller);
    gTimesUs[0] = 741030000; // Before estimated window.
    gTimesUs[1] = 741030100;
    uint64_t token = 0;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryStatus == 7 && NativeAwdlBSD::consumes == 0);

    setup(run, owner, controller);
    run.mifPacingWindowEndUs--; // Breaks the full-window + 20 ms reserve.
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryStatus == 9 && run.discoveryWindowClosed &&
           NativeAwdlBSD::consumes == 0);

    setup(run, owner, controller);
    gTimesUs[1] = 741054692; // At the exclusive upper bound on recheck.
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryStatus == 8 && run.discoveryWindowClosed &&
           NativeAwdlBSD::consumes == 0);
    owner.tahoe_awdl_peer_runtime_.selected.psfRxMonotonicUs += 1000;
    gTimeIndex = 0;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(NativeAwdlBSD::peeks == 1 && NativeAwdlBSD::consumes == 0);
}

static void testZeroEpochCannotBecomeDiscoveryCandidate()
{
    P2PProbeRun run{}; ItlIwx owner{}; IOEthernetController controller;
    setup(run, owner, controller);
    run.contextGeneration = 0;
    owner.tahoe_awdl_peer_runtime_.selected.contextGeneration = 0;
    putAnchor(controller, 0, 12, 13);
    uint64_t token = 0;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(0, 12, 13), 4, &token) == nullptr);
    assert(run.discoveryWindowClosed && NativeAwdlBSD::consumes == 0);
    assert(run.discoveryPhaseStatus == static_cast<uint32_t>(
        NativeAwdlDiscoveryPhase::Status::kZeroEpoch));
}

static void testEarlyCandidateLocksAndRetriesSameHead()
{
    P2PProbeRun run{}; ItlIwx owner{}; IOEthernetController controller;
    setup(run, owner, controller);
    gTimesUs[0] = 741030000;
    gTimesUs[1] = 741030100;
    uint64_t token = 0;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryStatus == 7 && run.discoveryCandidateLocked &&
           !run.discoveryWindowClosed && NativeAwdlBSD::consumes == 0);

    gTimesUs[0] = 741050000;
    gTimesUs[1] = 741050100;
    gTimeIndex = 0;
    const mbuf_t packet = takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token);
    assert(packet != nullptr && token == 91 && run.discoveryConsumed);
    assert(owner.tahoe_awdl_peer_runtime_.reads ==
           IntelAwdlPeerRuntime::kPeerCapacity + 2); // first scan, then two rechecks
}

static void testChangedHeadClosesLockedCandidate()
{
    P2PProbeRun run{}; ItlIwx owner{}; IOEthernetController controller;
    setup(run, owner, controller);
    gTimesUs[0] = 741030000;
    gTimesUs[1] = 741030100;
    uint64_t token = 0;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryCandidateLocked && !run.discoveryWindowClosed);
    NativeAwdlBSD::gHead.token++;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryWindowClosed && run.discoveryStatus == 9 &&
           NativeAwdlBSD::consumes == 0);
}

static void testMissingHeadClosesLockedCandidate()
{
    P2PProbeRun run{}; ItlIwx owner{}; IOEthernetController controller;
    setup(run, owner, controller);
    gTimesUs[0] = 741030000;
    gTimesUs[1] = 741030100;
    uint64_t token = 0;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryCandidateLocked && !run.discoveryWindowClosed);
    NativeAwdlBSD::headEligible = false;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryWindowClosed && run.discoveryStatus == 3 &&
           NativeAwdlBSD::consumes == 0);
}

static void testChangedPsfCannotRetargetLockedCandidate()
{
    P2PProbeRun run{}; ItlIwx owner{}; IOEthernetController controller;
    setup(run, owner, controller);
    gTimesUs[0] = 741030000;
    gTimesUs[1] = 741030100;
    uint64_t token = 0;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryCandidateLocked && !run.discoveryWindowClosed);
    const uint64_t lockedRevision = run.discoveryPsfWitness.scheduleRevision;
    owner.tahoe_awdl_peer_runtime_.selected.targetTxTimestampUs++;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(run.discoveryWindowClosed && run.discoveryStatus == 9 &&
           run.discoveryPsfWitness.scheduleRevision == lockedRevision &&
           NativeAwdlBSD::consumes == 0);
    assert(run.discoveryPhaseStatus == static_cast<uint32_t>(
        NativeAwdlDiscoveryPhase::Status::kCurrentSnapshotMismatch));
    const unsigned peeksAfterMismatch = NativeAwdlBSD::peeks;
    owner.tahoe_awdl_peer_runtime_.selected.psfRxMonotonicUs += 1000;
    assert(takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token) == nullptr);
    assert(NativeAwdlBSD::peeks == peeksAfterMismatch &&
           NativeAwdlBSD::consumes == 0);
}

static void testLocalAnnouncedPrefixIsContiguousAndBounded()
{
    P2PProbeRun run{}; ItlIwx owner{}; IOEthernetController controller;
    setup(run, owner, controller);
    run.psfCandidate.input.channelSlots[1] = 6;
    assert(!configureMifPacingWindow(&run)); // Nonzero slot after an empty one.

    setup(run, owner, controller);
    run.psfCandidate.hardDeadlineUs = 741060000ULL;
    assert(!configureMifPacingWindow(&run)); // Announced prefix outlives ROC.
}

static void testWideValidPhyCorrection()
{
    P2PProbeRun run{}; ItlIwx owner{}; IOEthernetController controller;
    setup(run, owner, controller);
    auto &psf = owner.tahoe_awdl_peer_runtime_.selected;
    psf.txDownCounterTu = 64;
    psf.phyTxTimestampUs = psf.targetTxTimestampUs + 65535U;
    gTimesUs[0] = 741025200ULL;
    gTimesUs[1] = 741025300ULL;
    gTimeIndex = 0;
    uint64_t token = 0;
    const mbuf_t packet = takeDiscoveryPacket(&run, runtimeEpochs(), 4, &token);
    assert(packet != nullptr && token == 91);
    assert(run.discoveryTarget.targetGp2Raw == 676235455U);
    assert(run.discoveryPhaseStatus == static_cast<uint32_t>(
        NativeAwdlDiscoveryPhase::Status::kEstimatedCandidate));
}

int main() {
    testActualExtractedTakeAndNoMifAdmission();
    testConsumedOrAttemptedRunCannotTakeHeadAgain();
    testStrictQmHeadAndPreAnchorStatus();
    testExactSnapshotAndChannelRecheck();
    testCandidateTimeAndLeaseReserve();
    testZeroEpochCannotBecomeDiscoveryCandidate();
    testEarlyCandidateLocksAndRetriesSameHead();
    testChangedHeadClosesLockedCandidate();
    testMissingHeadClosesLockedCandidate();
    testChangedPsfCannotRetargetLockedCandidate();
    testLocalAnnouncedPrefixIsContiguousAndBounded();
    testWideValidPhyCorrection();
    puts("PASS: extracted production Test064 discovery helper and capture gates");
    return 0;
}
'''

ACTION_CALL_HARNESS = r'''#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "native/awdl_discovery_phase_experiment.hpp"
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332) && \
    !defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
#error discovery profile requires TX evidence
#endif
struct FakeMbuf {};
using mbuf_t = FakeMbuf *;
struct ItlIwx { int com, nativeP2pTxQueue_, nativeP2pActionTx_; };
struct P2PProbeRun {
    uint32_t contextGeneration, stationGeneration;
    NativeAwdlDiscoveryPhase::EstimatedTarget discoveryTarget;
};
static uint64_t gEarliest, gDeadline;
static uint32_t gStationGeneration;
static const void *gEvidence;
int iwx_tahoe_p2p_action_tx_submit(ItlIwx *, int *, int *, int *, uint32_t,
                                   bool, bool, mbuf_t, uint64_t
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
                                   , const void *evidenceMetadata = nullptr
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
                                   , uint64_t estimatedNotBeforeUs = 0,
                                   uint64_t estimatedDeadlineUs = 0,
                                   uint32_t experimentalStationGeneration = 0
#endif
                                   ) {
#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)
    gEvidence = evidenceMetadata;
#endif
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    gEarliest = estimatedNotBeforeUs;
    gDeadline = estimatedDeadlineUs;
    gStationGeneration = experimentalStationGeneration;
#endif
    return 47;
}
static int executeActualCall(ItlIwx *self, P2PProbeRun *run, mbuf_t packet,
                             uint64_t token, bool discoveryPacket) {
    (void)discoveryPacket;
    const int result = ACTUAL_CALL_EXPRESSION;
    return result;
}
int main() {
    ItlIwx owner{};
    P2PProbeRun run{};
    run.contextGeneration = 101;
    run.stationGeneration = 202;
    run.discoveryTarget.earliestSubmitUs = 303;
    run.discoveryTarget.latestSubmitUs = 404;
    FakeMbuf storage;
    assert(executeActualCall(&owner, &run, &storage, 505, false) == 47);
#if defined(ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332)
    assert(gEarliest == 0 && gDeadline == 0 && gStationGeneration == 0);
    assert(executeActualCall(&owner, &run, &storage, 505, true) == 47);
    assert(gEarliest == 303 && gDeadline == 404 && gStationGeneration == 202);
#else
    assert(gEarliest == 0 && gDeadline == 0 && gStationGeneration == 0);
#endif
    puts("PASS: exact production action-submit call across TX-evidence/discovery macro profiles");
    return 0;
}
'''


def main() -> int:
    source = SOURCE.read_text()
    caller_gate_audit(source)
    trigger = source.find("packet = takeDiscoveryPacket(run, epochs,")
    if trigger < 0:
        raise RuntimeError("cannot locate production discovery capture trigger")
    signatures = (
        "static bool discoveryExperimentEnabled(ItlIwx *owner)",
        "static bool discoveryNumber(IOEthernetController *controller,",
        "static bool discoveryAnchor(P2PProbeRun *run,",
        "static NativeAwdlDiscoveryPhase::PsfWitness discoveryPsf(",
        "static bool configureMifPacingWindow(P2PProbeRun *probe)",
        "static mbuf_t takeDiscoveryPacket(P2PProbeRun *run,",
    )
    extracted = "\n\n".join(function_body(source, signature) for signature in signatures)
    # The GP2 anchor read path must consume only published scalar properties.
    anchor_body = function_body(source, signatures[2])
    for forbidden in ("iwx_read_prph", "readBracketedGp2", "acquireClockNic",
                      "IOSimpleLock", "readGp2"):
        if forbidden in anchor_body:
            raise RuntimeError(f"discovery anchor performs a direct hardware read: {forbidden}")
    for required in ("NativeP2PGp2PreStatus", "NativeP2PGp2PreValue",
                     "NativeP2PGp2PreHostBeforeUs", "NativeP2PGp2PreHostAfterUs",
                     "NativeP2PGp2PreGeneration", "NativeP2PGp2PowerGeneration",
                     "NativeP2PGp2StationGeneration"):
        if required not in anchor_body:
            raise RuntimeError(f"immutable pre-ROC witness key missing: {required}")
    if "NativeP2PGp2Post" in anchor_body or "NativeP2PGp2Post" in function_body(source, signatures[4]):
        raise RuntimeError("the discovery path must not read post/active-ROC GP2 values")

    # Strict QM/multicast classification belongs to the actual BSD queue. Make
    # sure the probe consumes that one eligible FIFO head and never drains it.
    queue = (ROOT / "native/awdl_native_bsd_data_25G332.cpp").read_text()
    peek_body = function_body(queue, "bool peekDiscoveryTx(uint32_t expectedPowerGeneration,")
    dequeue_body = function_body(queue, "mbuf_t nextDiscoveryTx(uint16_t sequence,")
    impl_body = function_body(queue, "mbuf_t nextTxImpl(uint16_t sequence,uint64_t *token,")
    if "MdnsQueryClass::QmMulticast" not in peek_body or "nextTxImpl(sequence,token,&expected,consumed)" not in dequeue_body or "snapshotMatches" not in impl_body:
        raise RuntimeError("queue head must be strict AirDrop QM and revalidated before dequeue")
    if "tx.head" not in impl_body or "snapshotMatches(head,*expected)" not in impl_body:
        raise RuntimeError("discovery path must consume a single exact FIFO head")

    body_marker = "// PRODUCTION_FUNCTIONS_INSERTION_POINT\n"
    if body_marker not in HARNESS:
        raise RuntimeError("internal harness marker missing")
    harness = HARNESS.replace(body_marker, extracted + "\n\n", 1)
    compiler = os.environ.get("CXX", "clang++")
    with tempfile.TemporaryDirectory(prefix="test064-discovery-probe-") as temp:
        temp_dir = pathlib.Path(temp)
        cpp = temp_dir / "test064_discovery_probe_harness.cpp"
        binary = temp_dir / "test064_discovery_probe_harness"
        cpp.write_text(harness)
        subprocess.run([
            compiler, "-std=c++14", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "-I", str(ROOT), str(cpp), "-o", str(binary),
        ], check=True)
        run = subprocess.run([str(binary)], check=False, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(run.stdout, end="")
        if run.returncode:
            raise RuntimeError(f"extracted Test064 harness failed: {run.returncode}")

        # Compile the exact action-submit expression as it appears in the
        # production caller with the two valid macro combinations. The build
        # profile intentionally rejects discovery without TX evidence.
        call_start = source.find("const int result=iwx_tahoe_p2p_action_tx_submit(", trigger)
        paren_start = source.find("(", call_start)
        depth = 0
        paren_end = -1
        for index in range(paren_start, len(source)):
            if source[index] == "(":
                depth += 1
            elif source[index] == ")":
                depth -= 1
                if depth == 0:
                    paren_end = index
                    break
        if call_start < 0 or paren_end < 0:
            raise RuntimeError("cannot extract actual P2P action-submit expression")
        call_expression = source[call_start + len("const int result="):paren_end + 1]
        macro_cpp = temp_dir / "test064_discovery_probe_submit_call.cpp"
        macro_cpp.write_text(ACTION_CALL_HARNESS.replace(
            "ACTUAL_CALL_EXPRESSION", call_expression))
        macro_configs = [
            ("evidence_only", ["-DITL_NATIVE_AWDL_TX_EVIDENCE_25G332=1"]),
            ("evidence_and_discovery", [
                "-DITL_NATIVE_AWDL_TX_EVIDENCE_25G332=1",
                "-DITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332=1",
            ]),
        ]
        for name, defines in macro_configs:
            macro_binary = temp_dir / f"submit_{name}"
            subprocess.run([
                compiler, "-std=c++14", "-Wall", "-Wextra", "-Werror",
                "-I", str(ROOT), *defines, str(macro_cpp), "-o", str(macro_binary),
            ], check=True)
            subprocess.run([str(macro_binary)], check=True)
    print("PASS: production call-site gates, post-encode time check, strict QM head, and pre-ROC-only anchor audit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
