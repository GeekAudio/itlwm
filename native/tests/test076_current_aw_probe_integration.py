#!/usr/bin/env python3
"""Compile extracted Test076 Probe planner and publisher code in a host harness."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
FIXTURE = ROOT / "native/tests/awdl_mif_current_aw_fallback_test.cpp"


def braced_source(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start : end + 1]
    raise AssertionError(f"unterminated block: {marker}")


def check_actual_call_chain(source: str) -> None:
    mif = braced_source(source, "static mbuf_t takeDiscoveryPacketMifCurrent(")
    initial = mif.index(
        "planDiscoveryMifCurrentTarget(\n        timingInput, run->currentAwTrace.fallbackEnabled, target,"
    )
    record_initial_attempt = mif.index(
        "recordDiscoveryCurrentAwAttempt(run, false, timingInput, target,"
    )
    final = mif.index(
        "planDiscoveryMifCurrentTarget(\n        finalTimingInput, run->currentAwTrace.fallbackEnabled, finalTarget,"
    )
    record_final_attempt = mif.index(
        "recordDiscoveryCurrentAwAttempt(run, true, finalTimingInput, finalTarget,"
    )
    exact_compare = mif.index("sameDiscoveryMifCandidate(target, finalTarget)")
    authorization = mif.index("run->discoveryBinding.authorizeTake(")
    dequeue = mif.index("NativeAwdlBSD::nextDiscoveryTx(", authorization)
    assert (initial < record_initial_attempt < final < record_final_attempt <
            exact_compare < authorization < dequeue)
    assert "run->discoveryMifTarget = target;" in mif
    assert "record.input.timing = input;" in source
    assert "record.candidate = candidate;" in source
    assert "a.targetAwStartGp2Us == b.targetAwStartGp2Us" in source
    assert "a.targetAwCounter == b.targetAwCounter" in source
    assert "left.targetAwRelation == right.targetAwRelation" in source
    assert "left.targetAwStartOffsetUs == right.targetAwStartOffsetUs" in source
    assert "left.beforeRxUs == right.beforeRxUs" in source
    publisher = braced_source(source, "static void publishDiscoveryCurrentAwTrace(")
    quiet_false = braced_source(publisher, "if (!quiet)")
    assert "describeDiscoveryCurrentAwPlan" not in quiet_false
    assert publisher.index("if (!quiet)") < publisher.index(
        "describeDiscoveryCurrentAwPlan"
    )
    attempt_publisher = braced_source(
        source, "static bool publishDiscoveryCurrentAwAttempt("
    )
    assert attempt_publisher.count("controller->setProperty(") == 1
    assert "OSData::withBytes(&snapshot, sizeof(snapshot))" in attempt_publisher
    assert '"NativeP2PCurrentAwAttemptOnly"' in attempt_publisher
    assert "snapshot.evidenceClass = 1" in attempt_publisher
    assert "snapshot.peerReceiptProven = 0" in attempt_publisher
    assert "snapshot.radioTransmitProven = 0" in attempt_publisher

    finish = braced_source(source, "IOReturn ItlIwx::tahoeP2pFinishAction(")
    assert finish.index("publishDiscoveryCurrentAwAttempt(run);") < finish.index(
        "nativeAwdlRxEventTimeline_.closeProducer"
    )

    publish_state = braced_source(source, "void ItlIwx::tahoeP2pPublishProbeState()")
    busy_guard = publish_state.index("if (nativeP2PPublicationBusy(this))")
    qm_request = publish_state.index(
        "requestNativeP2PQmWireSnapshotPublish(this);"
    )
    roc_publish = publish_state.index("tahoeP2pPublishRocState();")
    assert busy_guard < qm_request < roc_publish
    qm_action = braced_source(
        source, "static IOReturn publishPendingQmWireSnapshotAction("
    )
    assert qm_action.index("nativeP2PPublicationBusy(owner)") < qm_action.index(
        "iwx_tahoe_p2p_action_publish_pending_qm_wire_snapshot(owner);"
    )
    qm_request_function = braced_source(
        source, "static void requestNativeP2PQmWireSnapshotPublish("
    )
    assert "gate->attemptAction(publishPendingQmWireSnapshotAction, owner)" in qm_request_function


def build_harness(source: str, fixture: str) -> str:
    blocks = [
        braced_source(source, "struct CurrentAwPlanRecord"),
        braced_source(source, "struct CurrentAwTraceRecord"),
        braced_source(source, "struct CurrentAwAttemptPlan"),
        braced_source(source, "struct CurrentAwAttemptObservation"),
        braced_source(source, "struct __attribute__((packed)) CurrentAwAttemptOnlyPayload"),
        braced_source(source, "enum CurrentAwQuietBlocker : uint32_t"),
        braced_source(source, "struct CurrentAwPublishedPlan"),
        braced_source(source, "static Test066MifCurrentPhase::Status planDiscoveryMifCurrentTarget("),
        braced_source(source, "static bool sameDiscoveryMifCandidate("),
        braced_source(source, "static void recordDiscoveryCurrentAwPlan("),
        braced_source(source, "static void recordDiscoveryCurrentAwAttempt("),
        braced_source(source, "static uint64_t discoveryCurrentAwOffsetMagnitude("),
        braced_source(source, "static CurrentAwPublishedPlan describeDiscoveryCurrentAwPlan("),
        braced_source(source, "static bool publishDiscoveryCurrentAwPlan("),
        braced_source(source, "static void invalidateDiscoveryCurrentAwTrace("),
        braced_source(source, "static void invalidateDiscoveryCurrentAwAttempt("),
        braced_source(source, "static bool publishDiscoveryCurrentAwAttempt("),
        braced_source(source, "static void publishDiscoveryCurrentAwTrace("),
        braced_source(fixture, "Input exactRxGeometry("),
    ]
    return r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <map>
#include <string>
#include <string.h>
#include <utility>
#include <vector>
#include "native/awdl_mif_current_aw_fallback.hpp"

using namespace NativeAwdlMifCurrentAw;

namespace NativeAwdlDiscoveryBinding {
enum class Mode : uint8_t { kPsfNextSlot, kMifCurrentSlot };
}

struct OSSymbol {
    const char *name;
    static const OSSymbol *existingSymbolForCString(const char *value) {
        static const OSSymbol symbols[] = {
            {"NativeP2PCurrentAwTraceComplete"},
            {"NativeP2PCurrentAwTraceSnapshotVersionBegin"},
            {"NativeP2PCurrentAwTraceSnapshotVersionEnd"},
            {"NativeP2PCurrentAwTraceQuiet"},
            {"NativeP2PCurrentAwTraceQuietBlockerMask"},
            {"NativeP2PCurrentAwAttemptOnly"},
        };
        for (const OSSymbol &symbol : symbols) {
            if (strcmp(symbol.name, value) == 0)
                return &symbol;
        }
        return nullptr;
    }
    void release() const {}
};

struct OSData {
    std::vector<uint8_t> bytes;
    static OSData *withBytes(const void *source, size_t length) {
        if (!source)
            return nullptr;
        auto *data = new OSData;
        const auto *begin = static_cast<const uint8_t *>(source);
        data->bytes.assign(begin, begin + length);
        return data;
    }
    void release() { delete this; }
};

struct IOEthernetController {
    std::map<std::string, uint64_t> values;
    std::map<std::string, std::vector<uint8_t>> dataValues;
    std::map<std::string, unsigned> writes;
    std::map<std::string, unsigned> dataWrites;
    std::vector<std::pair<std::string, uint64_t>> history;
    unsigned failAtWrite = 0;
    unsigned callCount = 0;
    std::string failKey;
    bool failAll = false;
    bool failDataSet = false;
    bool failed = false;
    bool setProperty(const char *key, uint64_t value, unsigned bits) {
        assert(key && bits == 64);
        ++writes[key];
        ++callCount;
        if (failAll || callCount == failAtWrite ||
            (!failKey.empty() && failKey == key)) {
            failed = true;
            return false;
        }
        values[key] = value;
        history.emplace_back(key, value);
        return true;
    }
    bool setProperty(const char *key, OSData *value) {
        assert(key && value);
        ++dataWrites[key];
        if (failDataSet) {
            failed = true;
            return false;
        }
        dataValues[key] = value->bytes;
        return true;
    }
    void removeProperty(const OSSymbol *key) {
        assert(key && key->name);
        values.erase(std::string(key->name));
        dataValues.erase(std::string(key->name));
    }
    bool has(const std::string &key) const {
        return values.find(key) != values.end();
    }
    uint64_t get(const std::string &key) const {
        const auto it = values.find(key);
        assert(it != values.end());
        return it->second;
    }
    bool collectorAccepts() const {
        const char *required[] = {
            "NativeP2PCurrentAwTraceSchema",
            "NativeP2PCurrentAwTraceComplete",
            "NativeP2PCurrentAwTraceSnapshotVersionBegin",
            "NativeP2PCurrentAwTraceSnapshotVersionEnd",
            "NativeP2PCurrentAwTraceContextGeneration",
            "NativeP2PCurrentAwTraceIdentityValid",
            "NativeP2PCurrentAwTraceInputValid",
            "NativeP2PCurrentAwTraceInitialRecordedStatus",
            "NativeP2PCurrentAwTraceFinalRecordedStatus",
        };
        for (const char *key : required) {
            if (!has(key))
                return false;
        }
        const uint64_t begin = get(
            "NativeP2PCurrentAwTraceSnapshotVersionBegin");
        const uint64_t end = get(
            "NativeP2PCurrentAwTraceSnapshotVersionEnd");
        return get("NativeP2PCurrentAwTraceComplete") == 1 &&
            get("NativeP2PCurrentAwTraceSchema") == 1 &&
            begin != 0 && (begin & 1U) == 0 && begin == end &&
            get("NativeP2PCurrentAwTraceContextGeneration") != 0;
    }
};

struct ItlIwx {
    IOEthernetController *controller;
    bool tahoeP2pOnMainGate() const { return true; }
    IOEthernetController *tahoeP2pController() const { return controller; }
};

__EXTRACTED_STRUCTS__

struct P2PProbeRun {
    ItlIwx *owner;
    bool discoveryModeSelected;
    bool discoveryCandidateLocked;
    bool discoveryConsumed;
    NativeAwdlDiscoveryBinding::Mode discoveryMode;
    CurrentAwTraceRecord currentAwTrace;
    CurrentAwAttemptObservation currentAwAttempt;
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
};

__EXTRACTED_FUNCTIONS__

static uint64_t property(const IOEthernetController &controller,
                         const char *group, const char *key) {
    return controller.get(std::string("NativeP2PCurrentAwTrace") + group + key);
}

int main() {
    const Input original = exactRxGeometry();
    auto base = original;
    NativeAwdlMifCurrentAw::Candidate initial{};
    NativeAwdlMifCurrentAw::Candidate final{};
    NativeAwdlMifCurrentAw::RejectReason initialReason{};
    NativeAwdlMifCurrentAw::RejectReason finalReason{};
    const auto initialStatus = planDiscoveryMifCurrentTarget(
        original.timing, true, initial, initialReason);
    auto finalInput = original;
    finalInput.timing.nowUs = 348934000ULL;
    const auto finalStatus = planDiscoveryMifCurrentTarget(
        finalInput.timing, true, final, finalReason);
    assert(initialStatus == Test066MifCurrentPhase::Status::kCandidate);
    assert(finalStatus == Test066MifCurrentPhase::Status::kCandidate);
    assert(initial.fallbackUsed && final.fallbackUsed);
    assert(sameDiscoveryMifCandidate(initial, final));
    assert(initial.earliestSubmitUs == 348933054ULL);
    assert(initial.latestSubmitUs == 348941243ULL);
    assert(final.earliestSubmitUs == initial.earliestSubmitUs);
    assert(final.latestSubmitUs == initial.latestSubmitUs);
    assert(initialReason == NativeAwdlMifCurrentAw::RejectReason::kNotAttempted);

    auto changed = final;
    ++changed.targetAwStartGp2Us;
    assert(!sameDiscoveryMifCandidate(initial, changed));
    changed = final;
    changed.targetAwRelation = NativeAwdlMifCurrentAw::TargetAwRelation::kFutureFromMifRx;
    assert(!sameDiscoveryMifCandidate(initial, changed));
    changed = final;
    ++changed.beforeRxUs;
    assert(!sameDiscoveryMifCandidate(initial, changed));

    IOEthernetController controller{};
    ItlIwx owner{&controller};
    P2PProbeRun run{};
    run.owner = &owner;
    run.discoveryModeSelected = true;
    run.discoveryMode = NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot;
    run.contextGeneration = 11;
    run.powerGeneration = 12;
    run.stationGeneration = 13;
    run.currentAwTrace.fallbackEnabled = true;
    run.currentAwTrace.inputValid = true;
    run.currentAwTrace.identityValid = true;
    run.currentAwTrace.rocGeneration = 14;
    run.currentAwTrace.peerIncarnation = base.timing.mif.peerIncarnation;
    run.currentAwTrace.psfRevision = 30;
    run.currentAwTrace.mifRevision = base.timing.mif.mifRevision;
    run.currentAwTrace.qmToken = 42;
    run.currentAwTrace.qmGeneration = 12;
    run.currentAwTrace.finalCompareValid = true;
    run.currentAwTrace.finalCompareMatch = true;
    run.currentAwTrace.rxProducerClosed = true;
    run.currentAwTrace.rxDrainComplete = true;
    recordDiscoveryCurrentAwPlan(&run, false, original.timing, initial,
                                 initialStatus, initialReason);
    run.discoveryCandidateLocked = true;
    recordDiscoveryCurrentAwPlan(&run, true, finalInput.timing, final,
                                 finalStatus, finalReason);
    recordDiscoveryCurrentAwAttempt(&run, false, original.timing, initial,
                                    initialStatus, 42, 12);
    recordDiscoveryCurrentAwAttempt(&run, true, finalInput.timing, final,
                                    finalStatus, 42, 12);
    base.timing.mif.rxGp2Us ^= 0x100U;

    assert(publishDiscoveryCurrentAwAttempt(&run));
    const std::string attemptKey = "NativeP2PCurrentAwAttemptOnly";
    assert(controller.dataWrites[attemptKey] == 1);
    assert(controller.dataValues[attemptKey].size() ==
        sizeof(CurrentAwAttemptOnlyPayload));
    CurrentAwAttemptOnlyPayload attemptPayload{};
    memcpy(&attemptPayload, controller.dataValues[attemptKey].data(),
           sizeof(attemptPayload));
    assert(attemptPayload.magic == 0x41574143u);
    assert(attemptPayload.schema == 1 && attemptPayload.complete == 1);
    assert(attemptPayload.evidenceClass == 1);
    assert(attemptPayload.peerReceiptProven == 0);
    assert(attemptPayload.radioTransmitProven == 0);
    assert(attemptPayload.qmToken == 42 && attemptPayload.qmGeneration == 12);
    assert(attemptPayload.contextGeneration == 11);
    assert(attemptPayload.powerGeneration == 12);
    assert(attemptPayload.stationGeneration == 13);
    assert(attemptPayload.initialPresent == 1 && attemptPayload.finalPresent == 1);
    assert(attemptPayload.fallbackEnabled == 1);
    assert(attemptPayload.initialCandidateValid == 1 &&
           attemptPayload.finalCandidateValid == 1);
    assert(attemptPayload.initialFallbackUsed == 1 &&
           attemptPayload.finalFallbackUsed == 1);
    assert(attemptPayload.consistencyFlags == 3);
    assert(attemptPayload.rocGeneration == original.timing.currentEpochs.roc);
    assert(attemptPayload.initialPlannerNowUs == original.timing.nowUs);
    assert(attemptPayload.finalPlannerNowUs == finalInput.timing.nowUs);
    assert(attemptPayload.initialStatus ==
           static_cast<uint32_t>(initialStatus));
    assert(attemptPayload.finalStatus ==
           static_cast<uint32_t>(finalStatus));
    assert(attemptPayload.initialEarliestSubmitUs == initial.earliestSubmitUs);
    assert(attemptPayload.initialLatestSubmitUs == initial.latestSubmitUs);
    assert(attemptPayload.finalEarliestSubmitUs == final.earliestSubmitUs);
    assert(attemptPayload.finalLatestSubmitUs == final.latestSubmitUs);

    IOEthernetController changedIdentityController{};
    owner.controller = &changedIdentityController;
    P2PProbeRun changedIdentityRun = run;
    changedIdentityRun.owner = &owner;
    changedIdentityRun.currentAwAttempt = {};
    recordDiscoveryCurrentAwAttempt(&changedIdentityRun, false,
        original.timing, initial, initialStatus, 42, 12);
    auto changedEpochInput = finalInput;
    changedEpochInput.timing.currentEpochs.roc += 1;
    recordDiscoveryCurrentAwAttempt(&changedIdentityRun, true,
        changedEpochInput.timing, final, finalStatus, 43, 12);
    assert(publishDiscoveryCurrentAwAttempt(&changedIdentityRun));
    CurrentAwAttemptOnlyPayload changedIdentityPayload{};
    const auto &changedIdentityBytes =
        changedIdentityController.dataValues[attemptKey];
    assert(changedIdentityBytes.size() == sizeof(changedIdentityPayload));
    memcpy(&changedIdentityPayload, changedIdentityBytes.data(),
           sizeof(changedIdentityPayload));
    assert(changedIdentityPayload.initialPresent == 1 &&
           changedIdentityPayload.finalPresent == 1);
    assert(changedIdentityPayload.initialPlannerNowUs == original.timing.nowUs);
    assert(changedIdentityPayload.finalPlannerNowUs == finalInput.timing.nowUs);
    assert(changedIdentityPayload.qmToken == 42 &&
           changedIdentityPayload.qmGeneration == 12);
    assert(changedIdentityPayload.consistencyFlags == 0);

    IOEthernetController attemptWriteFailed{};
    attemptWriteFailed.dataValues[attemptKey] =
        std::vector<uint8_t>(sizeof(CurrentAwAttemptOnlyPayload), 0xff);
    attemptWriteFailed.failDataSet = true;
    owner.controller = &attemptWriteFailed;
    P2PProbeRun failedAttemptRun = run;
    failedAttemptRun.owner = &owner;
    failedAttemptRun.currentAwAttempt.published = false;
    assert(!publishDiscoveryCurrentAwAttempt(&failedAttemptRun));
    assert(attemptWriteFailed.dataWrites[attemptKey] == 1);
    assert(attemptWriteFailed.dataValues.count(attemptKey) == 0);
    owner.controller = &controller;

    publishDiscoveryCurrentAwTrace(&run, true);
    assert(run.currentAwTrace.published);
    assert(property(controller, "", "Complete") == 1);
    assert(property(controller, "", "Quiet") == 1);
    assert(property(controller, "", "SnapshotVersionBegin") == 22);
    assert(property(controller, "", "SnapshotVersionEnd") == 22);
    assert(property(controller, "", "FinalCompareMatch") == 1);
    assert(property(controller, "", "MifRxGp2Us") == 300636427ULL);
    assert(property(controller, "Initial", "LegacyStatus26") == 1);
    assert(property(controller, "Initial", "ReconstructedGeometryEquivalent") == 1);
    assert(property(controller, "Final", "ReconstructedGeometryEquivalent") == 1);
    assert(property(controller, "Initial", "EarliestSubmitUs") == 348933054ULL);
    assert(property(controller, "Initial", "LatestSubmitUs") == 348941243ULL);
    assert(property(controller, "Final", "EarliestSubmitUs") == 348933054ULL);
    assert(property(controller, "Final", "LatestSubmitUs") == 348941243ULL);
    assert(property(controller, "Initial", "Relation") ==
        static_cast<uint32_t>(TargetAwRelation::kCurrentAwStartedBeforeMifRx));
    assert(property(controller, "Initial", "ForwardDeltaValid") == 0);
    assert(property(controller, "Initial", "OffsetMagnitudeUs") == 1635);
    assert(property(controller, "Initial", "BeforeRxUs") == 1635);
    assert(controller.collectorAccepts());
    for (const auto &entry : controller.writes) {
        const unsigned expected =
            entry.first == "NativeP2PCurrentAwTraceSnapshotVersionBegin" ||
            entry.first == "NativeP2PCurrentAwTraceComplete" ? 2U : 1U;
        if (entry.second != expected)
            fprintf(stderr, "unexpected write count %s: %u (wanted %u)\n",
                    entry.first.c_str(), entry.second, expected);
        assert(entry.second == expected);
    }
    assert(controller.writes["NativeP2PCurrentAwTraceInputValid"] == 1);

    const auto beginOdd = controller.history.front();
    assert(beginOdd.first == "NativeP2PCurrentAwTraceSnapshotVersionBegin");
    assert(beginOdd.second == 21);
    unsigned completeWrites = 0;
    std::vector<uint64_t> completeValues;
    for (const auto &entry : controller.history) {
        if (entry.first == "NativeP2PCurrentAwTraceComplete") {
            ++completeWrites;
            completeValues.push_back(entry.second);
        }
    }
    assert(completeWrites == 2 && completeValues[0] == 0 && completeValues[1] == 1);

    const size_t successfulWriteCount = controller.history.size();
    assert(successfulWriteCount > 10);
    const std::string completeKey =
        "NativeP2PCurrentAwTraceComplete";
    const std::string beginKey =
        "NativeP2PCurrentAwTraceSnapshotVersionBegin";
    const std::string endKey =
        "NativeP2PCurrentAwTraceSnapshotVersionEnd";
    const std::string quietKey =
        "NativeP2PCurrentAwTraceQuiet";
    const std::string quietBlockerMaskKey =
        "NativeP2PCurrentAwTraceQuietBlockerMask";
    for (unsigned failure = 1; failure <= successfulWriteCount; ++failure) {
        IOEthernetController failedController{};
        failedController.values[completeKey] = 1;
        failedController.values[beginKey] = 22;
        failedController.values[endKey] = 22;
        failedController.values[quietKey] = 1;
        failedController.values[quietBlockerMaskKey] = 127;
        failedController.failAtWrite = failure;
        owner.controller = &failedController;
        P2PProbeRun failedRun = run;
        failedRun.owner = &owner;
        failedRun.currentAwTrace.published = false;
        publishDiscoveryCurrentAwTrace(&failedRun, true);
        assert(failedController.failed);
        assert(!failedRun.currentAwTrace.published);
        assert(!failedController.has(completeKey));
        assert(!failedController.has(quietKey));
        assert(!failedController.has(quietBlockerMaskKey));
        assert(!failedController.collectorAccepts());
    }

    const char *permanentFailureKeys[] = {
        "NativeP2PCurrentAwTraceSnapshotVersionBegin",
        "NativeP2PCurrentAwTraceComplete",
        "NativeP2PCurrentAwTraceSchema",
        "NativeP2PCurrentAwTraceSnapshotVersionEnd",
        "NativeP2PCurrentAwTraceQuiet",
        "NativeP2PCurrentAwTraceQuietBlockerMask",
    };
    for (const char *failedKey : permanentFailureKeys) {
        IOEthernetController failedController{};
        failedController.values[completeKey] = 1;
        failedController.values[beginKey] = 22;
        failedController.values[endKey] = 22;
        failedController.values[quietKey] = 1;
        failedController.values[quietBlockerMaskKey] = 127;
        failedController.failKey = failedKey;
        owner.controller = &failedController;
        P2PProbeRun failedRun = run;
        failedRun.owner = &owner;
        failedRun.currentAwTrace.published = false;
        publishDiscoveryCurrentAwTrace(&failedRun, true);
        assert(failedController.failed);
        assert(!failedRun.currentAwTrace.published);
        assert(!failedController.has(completeKey));
        assert(!failedController.has(quietKey));
        assert(!failedController.has(quietBlockerMaskKey));
        assert(!failedController.collectorAccepts());
    }

    IOEthernetController allWritesFail{};
    allWritesFail.values[completeKey] = 1;
    allWritesFail.values[beginKey] = 22;
    allWritesFail.values[endKey] = 22;
    allWritesFail.failAll = true;
    owner.controller = &allWritesFail;
    P2PProbeRun allWritesFailRun = run;
    allWritesFailRun.owner = &owner;
    allWritesFailRun.currentAwTrace.published = false;
    publishDiscoveryCurrentAwTrace(&allWritesFailRun, true);
    assert(allWritesFail.failed);
    assert(!allWritesFailRun.currentAwTrace.published);
    assert(!allWritesFail.has(completeKey));
    assert(!allWritesFail.has(beginKey));
    assert(!allWritesFail.has(endKey));
    assert(!allWritesFail.collectorAccepts());

    IOEthernetController unknownController{};
    unknownController.values[completeKey] = 1;
    unknownController.values[beginKey] = 22;
    unknownController.values[endKey] = 22;
    unknownController.values[quietKey] = 1;
    unknownController.values[quietBlockerMaskKey] = 127;
    owner.controller = &unknownController;
    P2PProbeRun unknownRun = run;
    unknownRun.owner = &owner;
    unknownRun.currentAwTrace.published = false;
    unknownRun.currentAwTrace.quietBlockerMask =
        kCurrentAwQuietBlockerRxDrainIncomplete |
        kCurrentAwQuietBlockerProbeBusy;
    publishDiscoveryCurrentAwTrace(&unknownRun, false);
    assert(!unknownRun.currentAwTrace.published);
    assert(property(unknownController, "", "Complete") == 0);
    assert(property(unknownController, "", "SnapshotVersionBegin") == 21);
    assert(property(unknownController, "", "SnapshotVersionEnd") == 22);
    assert(unknownController.history.size() == 4);
    assert(unknownController.writes.size() == 4);
    assert(unknownController.writes[beginKey] == 1);
    assert(unknownController.writes[completeKey] == 1);
    assert(property(unknownController, "", "Quiet") == 0);
    assert(property(unknownController, "", "QuietBlockerMask") ==
        (kCurrentAwQuietBlockerRxDrainIncomplete |
         kCurrentAwQuietBlockerProbeBusy));
    assert(unknownController.get(quietKey) == 0);
    assert(unknownController.get(quietBlockerMaskKey) ==
        (kCurrentAwQuietBlockerRxDrainIncomplete |
         kCurrentAwQuietBlockerProbeBusy));
    assert(unknownController.values.count(
        "NativeP2PCurrentAwTraceInitialDescriptionValid") == 0);
    assert(!unknownController.collectorAccepts());

    IOEthernetController quietWritesFail{};
    quietWritesFail.values[completeKey] = 1;
    quietWritesFail.values[beginKey] = 22;
    quietWritesFail.values[endKey] = 22;
    quietWritesFail.failAll = true;
    owner.controller = &quietWritesFail;
    P2PProbeRun quietWritesFailRun = run;
    quietWritesFailRun.owner = &owner;
    quietWritesFailRun.currentAwTrace.published = false;
    publishDiscoveryCurrentAwTrace(&quietWritesFailRun, false);
    assert(quietWritesFail.failed);
    assert(!quietWritesFailRun.currentAwTrace.published);
    assert(quietWritesFail.history.empty());
    assert(quietWritesFail.writes.size() == 1);
    assert(!quietWritesFail.has(completeKey));
    assert(!quietWritesFail.collectorAccepts());
    assert(discoveryCurrentAwOffsetMagnitude(INT32_MIN) == 2147483648ULL);
    return 0;
}
        """.replace("__EXTRACTED_STRUCTS__", "\n\n".join(
        block + ";" for block in blocks[:7]
        )).replace(
        "__EXTRACTED_FUNCTIONS__", "\n\n".join(blocks[7:])
    )


def main() -> int:
    source = PROBE.read_text(encoding="utf-8")
    fixture = FIXTURE.read_text(encoding="utf-8")
    check_actual_call_chain(source)
    compiler = shutil.which("clang++") or shutil.which("clang")
    if not compiler:
        raise RuntimeError("clang++ or clang is required for the host harness")
    harness = build_harness(source, fixture)
    with tempfile.TemporaryDirectory(prefix="test076-probe-integration-") as temp:
        source_path = Path(temp) / "probe-integration.cpp"
        binary = Path(temp) / "probe-integration"
        source_path.write_text(harness)
        subprocess.run(
            [compiler, "-std=c++14", "-Wall", "-Wextra", "-Werror",
             f"-I{ROOT}", str(source_path), "-o", str(binary)],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
