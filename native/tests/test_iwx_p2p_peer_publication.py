#!/usr/bin/env python3
"""Execute the production AWDL peer publisher against a deterministic mock.

This extracts only ItlIwxP2PPeer.cpp's publish method and packSlots helper.
The mock table supplies bounded snapshots; no kernel, radio, TX, or EFI code
is linked or run. RX-drain gate placement is checked from its production source.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PUBLISH_SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PPeer.cpp"
RX_SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PRx.cpp"


def extract_function(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise RuntimeError(f"unterminated function: {signature}")


def check_rx_drain_source() -> None:
    source = RX_SOURCE.read_text()
    action = extract_function(source, "IOReturn ItlIwx::tahoeP2pRxDrainAction(")
    drain = extract_function(source, "void ItlIwx::tahoeP2pRxDrain()")

    assert "!owner->getMainWorkLoop()->inGate()" in action
    assert "owner->tahoeP2pRxDrain();" in action
    assert action.index("inGate()") < action.index("tahoeP2pRxDrain();")

    off_gate = drain.index("if (!workLoop->inGate())")
    attempt = drain.index("gate->attemptAction(tahoeP2pRxDrainAction, this)")
    early_return = drain.index("return;", attempt)
    queue_pop = drain.index("tahoe_p2p_rx_router_.popRecord(&record)")
    assert off_gate < attempt < early_return < queue_pop
    assert "tahoeP2pPublishPeerRuntime();" in drain
    assert drain.index("tahoe_awdl_peer_runtime_.observe(") < drain.index(
        "tahoeP2pPublishPeerRuntime();"
    )
    assert not re.search(
        r"\b(?:tahoeP2p(?:Arm|Exercise|Publish).*Tx|nativeP2pActionTx|"
        r"tahoe_awdl_peer_runtime_\.selectMaster)\s*\(",
        drain,
    )


def main() -> int:
    source = PUBLISH_SOURCE.read_text()
    header = (ROOT / "itlwm/hal_iwx/ItlIwx.hpp").read_text()
    cache_capacity = re.search(r"tahoe_awdl_runtime_published_\[(\d+)\]", header).group(1)
    publish = extract_function(
        source, "void ItlIwx::tahoeP2pPublishPeerRuntime()"
    )
    pack_slots = extract_function(source, "uint64_t packSlots(const uint8_t *slots)")

    metric_names = re.findall(
        r'(?m)^\s*publish\("(NativeP2PPeerState[^"]+)",', publish
    )
    publish_count = int(
        re.search(r"constexpr size_t count = (\d+);", publish).group(1)
    )
    assert metric_names
    assert publish_count == 161
    assert len(metric_names) == publish_count
    assert len(set(metric_names)) == publish_count
    assert len(metric_names) <= int(cache_capacity)
    assert all(name.startswith("NativeP2PPeerState") for name in metric_names)
    assert all(
        not any(token in name.lower() for token in ("address", "mac", "name", "uid", "bytes"))
        for name in metric_names
    )
    assert "sourceAddress" not in publish
    assert "selectMaster(" not in publish
    assert not re.search(
        r"\b(?:tahoeP2p(?:Arm|Exercise|Publish).*Tx|nativeP2pActionTx|"
        r"submitCommand|sendCommand)\s*\(",
        publish,
    )
    assert "!loop->inGate()" in publish
    assert "!controller" in publish
    assert f"constexpr size_t count = {publish_count};" in publish
    assert "static_assert(count <= capacity" in publish
    assert "if (metricIndex >= capacity)" in publish
    assert "tahoe_awdl_runtime_published_[metricIndex] != value" in publish
    assert "++metricIndex;" in publish
    assert not re.search(r"\b(?:PeerMetric|metrics\s*\[)", publish)

    check_rx_drain_source()

    fixture = r'''
#include "awdl_peer_runtime_table.hpp"

#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <map>
#include <string>

#define IEEE80211_S_RUN 4
#define IWX_FLAG_SHUTDOWN 0x00000001u
#define IWX_FLAG_HW_ERR 0x00000002u

static uint64_t gNowUs = 10000000;
static uint64_t peerStateMonotonicUs() { return gNowUs; }

namespace {
''' + pack_slots + r'''
} // namespace

struct MainWorkLoop {
    bool gated = true;
    bool inGate() const { return gated; }
};

struct MockController {
    std::map<std::string, uint64_t> values;
    unsigned writes = 0;
    void setProperty(const char *name, uint64_t value, unsigned width) {
        assert(name && width == 64);
        values[name] = value;
        ++writes;
    }
    uint64_t get(const char *name) const {
        const auto it = values.find(name);
        assert(it != values.end());
        return it->second;
    }
};

static bool sameEpochs(const IntelAwdlPeer::RuntimeEpochs &a,
                       const IntelAwdlPeer::RuntimeEpochs &b) {
    return a.contextGeneration == b.contextGeneration &&
           a.powerGeneration == b.powerGeneration &&
           a.stationGeneration == b.stationGeneration && a.active == b.active;
}

// Mirrors the real Table::snapshot epoch behavior: new epochs clear current
// entries but preserve cumulative numeric counters and last-admission history.
struct MockRuntimeTable {
    IntelAwdlPeerRuntime::Snapshot state{};
    IntelAwdlPeerRuntime::PsfPeerSnapshot psfPeers[
        IntelAwdlPeerRuntime::kPeerCapacity]{};
    IntelAwdlPeer::RuntimeEpochs epochs{};
    bool haveEpoch = false;
    unsigned calls = 0;
    unsigned psfCalls = 0;
    uint64_t lastNowUs = 0;

    MockRuntimeTable() {
        state.latestFreshMifSlot = 0xff;
        state.latestFreshPsfSlot = 0xff;
        state.lastRejectedResult = 0xff;
        state.lastMifDecodeStatus = 0xff;
        state.lastPsfDecodeStatus = 0xff;
    }

    IntelAwdlPeerRuntime::Snapshot snapshot(
        const IntelAwdlPeer::RuntimeEpochs &current, uint64_t nowUs) {
        ++calls;
        lastNowUs = nowUs;
        if (!haveEpoch) {
            epochs = current;
            haveEpoch = true;
        } else if (!sameEpochs(epochs, current)) {
            IntelAwdlPeerRuntime::Snapshot empty{};
            empty.latestFreshMifSlot = 0xff;
            empty.admittedTotal = state.admittedTotal;
            empty.updatedTotal = state.updatedTotal;
            empty.candidateFrameTotal = state.candidateFrameTotal;
            empty.mifFrameTotal = state.mifFrameTotal;
            empty.rejectedTotal = state.rejectedTotal;
            empty.rejectedMifTotal = state.rejectedMifTotal;
            empty.acceptedPsfTotal = state.acceptedPsfTotal;
            empty.rejectedPsfTotal = state.rejectedPsfTotal;
            empty.lastAdmittedContextGeneration =
                state.lastAdmittedContextGeneration;
            empty.lastRejectedContext = state.lastRejectedContext;
            empty.lastRejectedResult = state.lastRejectedResult;
            empty.lastMifDecodeStatus = state.lastMifDecodeStatus;
            empty.lastPsfDecodeStatus = state.lastPsfDecodeStatus;
            empty.lastMifRejectDiagnostics = state.lastMifRejectDiagnostics;
            empty.lastPsfRejectDiagnostics = state.lastPsfRejectDiagnostics;
            state = empty;
            memset(psfPeers, 0, sizeof(psfPeers));
            epochs = current;
        }
        if (!current.active) {
            const uint32_t admitted = state.admittedTotal;
            const uint32_t updated = state.updatedTotal;
            const uint32_t candidate = state.candidateFrameTotal;
            const uint32_t mif = state.mifFrameTotal;
            const uint32_t rejected = state.rejectedTotal;
            const uint32_t rejectedMif = state.rejectedMifTotal;
            const uint32_t acceptedPsf = state.acceptedPsfTotal;
            const uint32_t rejectedPsf = state.rejectedPsfTotal;
            const uint64_t lastAdmission = state.lastAdmittedContextGeneration;
            const uint64_t lastRejectedContext = state.lastRejectedContext;
            const uint8_t lastRejectedResult = state.lastRejectedResult;
            const uint8_t lastMifDecodeStatus = state.lastMifDecodeStatus;
            const uint8_t lastPsfDecodeStatus = state.lastPsfDecodeStatus;
            const auto lastMifDiag = state.lastMifRejectDiagnostics;
            const auto lastPsfDiag = state.lastPsfRejectDiagnostics;
            state = IntelAwdlPeerRuntime::Snapshot{};
            state.latestFreshMifSlot = 0xff;
            state.latestFreshPsfSlot = 0xff;
            state.rejectedMifTotal = rejectedMif;
            state.acceptedPsfTotal = acceptedPsf;
            state.rejectedPsfTotal = rejectedPsf;
            state.lastRejectedContext = lastRejectedContext;
            state.lastRejectedResult = lastRejectedResult;
            state.lastMifDecodeStatus = lastMifDecodeStatus;
            state.lastPsfDecodeStatus = lastPsfDecodeStatus;
            state.lastMifRejectDiagnostics = lastMifDiag;
            state.lastPsfRejectDiagnostics = lastPsfDiag;
            state.admittedTotal = admitted;
            state.updatedTotal = updated;
            state.candidateFrameTotal = candidate;
            state.mifFrameTotal = mif;
            state.rejectedTotal = rejected;
            state.lastAdmittedContextGeneration = lastAdmission;
            memset(psfPeers, 0, sizeof(psfPeers));
        }
        return state;
    }

    bool getPsfSnapshot(uint8_t slot,
                        const IntelAwdlPeer::RuntimeEpochs &current,
                        uint64_t nowUs,
                        IntelAwdlPeerRuntime::PsfPeerSnapshot *output) {
        ++psfCalls;
        if (!output)
            return false;
        *output = IntelAwdlPeerRuntime::PsfPeerSnapshot{};
        if (!haveEpoch || !current.active ||
            slot >= IntelAwdlPeerRuntime::kPeerCapacity ||
            !sameEpochs(epochs, current))
            return false;
        const auto &candidate = psfPeers[slot];
        if (!candidate.tracked ||
            candidate.contextGeneration != current.contextGeneration ||
            candidate.powerGeneration != current.powerGeneration ||
            candidate.stationGeneration != current.stationGeneration ||
            nowUs < candidate.psfRxMonotonicUs)
            return false;
        if (!candidate.hasPsf)
            return false;
        *output = candidate;
        output->psfAgeUs = nowUs - candidate.psfRxMonotonicUs;
        output->psfFresh = output->psfAgeUs <= 5000000 &&
                           candidate.syncConsistent;
        return true;
    }
};

struct MockCom {
    int sc_generation = 9;
    uint32_t sc_tx_rate_generation = 11;
    struct { int ic_state = IEEE80211_S_RUN; } sc_ic;
    uint32_t sc_flags = 0;
};

struct ItlIwx {
    MainWorkLoop loop;
    MockController sink;
    MockController *controller = &sink;
    MockCom com;
    uint32_t nativeP2pProbeGeneration_ = 7;
    MockRuntimeTable tahoe_awdl_peer_runtime_;
    uint64_t tahoe_awdl_runtime_published_[__CACHE_CAPACITY__] {};
    uint32_t tahoe_awdl_runtime_last_result_ = 77;
    bool tahoe_awdl_runtime_published_once_ = false;

    MainWorkLoop *getMainWorkLoop() { return &loop; }
    MockController *getController() { return controller; }
    void tahoeP2pPublishPeerRuntime();
};

''' + publish + r'''

static void fillPeer(IntelAwdlPeerRuntime::PeerSnapshot *peer,
                     uint32_t marker, bool hasMif, bool fresh) {
    *peer = IntelAwdlPeerRuntime::PeerSnapshot{};
    peer->tracked = true;
    peer->frameAgeUs = marker;
    peer->contextGeneration = marker + 100;
    peer->powerGeneration = marker + 200;
    peer->stationGeneration = marker + 300;
    peer->timingSampleCount = 3;
    for (size_t i = 0; i < IntelAwdlPeerRuntime::kTimingSampleCapacity; ++i) {
        auto &sample = peer->timingSamples[i];
        sample.rxMonotonicUs = uint64_t(marker) * 1000000 + 100 + i;
        sample.rxGp2TimestampUs = marker * 100 + 10 + i;
        sample.peerPhyTxTimestampUs = marker * 1000000 + 300 + i;
        sample.subtype = i == 1 ? 3 : 0;
        sample.rxGp2TimestampPresent = (i & 1) == 0;
    }
    if (!hasMif)
        return;

    peer->hasMif = true;
    peer->mifFresh = fresh;
    peer->mifAgeUs = marker * 10;
    peer->syncConsistent = true;
    peer->mifRxMonotonicUs = uint64_t(marker) * 1000000 + 500;
    peer->mifRxGp2TimestampUs = marker * 100 + 20;
    peer->mifRxGp2TimestampPresent = true;
    peer->phyTxTimestampUs = marker * 100 + 21;
    peer->targetTxTimestampUs = marker * 100 + 22;
    peer->masterMetric = marker * 1000 + 23;
    peer->masterCounter = marker * 1000 + 24;
    peer->ownMetric = marker * 1000 + 25;
    peer->ownCounter = marker * 1000 + 26;
    peer->height = marker * 1000 + 27;
    peer->txDownCounterTu = marker + 28;
    peer->awPeriodTu = marker + 29;
    peer->actionFramePeriodTu = marker + 30;
    peer->nextAwSequence = marker + 31;
    peer->nextAwChannel = static_cast<uint8_t>(marker + 32);
    peer->version = static_cast<uint8_t>(marker + 33);
    peer->deviceClass = static_cast<uint8_t>(marker + 34);
    peer->electionV2 = true;
    peer->syncParameterLength = marker + 35;
    peer->syncTailLength = marker + 36;
    peer->embeddedSequencePresent = true;
    peer->embeddedSequenceRecognized = true;
    peer->embeddedSequenceVerified = false;
    peer->embeddedSequenceMismatch = true;
    peer->embeddedMismatchIndex = static_cast<uint8_t>(marker % 16);
    peer->embeddedMismatchChannel = 6;
    peer->canonicalMismatchChannel = 44;
    for (size_t i = 0; i < 16; ++i)
        peer->channelSlots[i] = static_cast<uint8_t>(marker + i);
}

static void fillPsf(IntelAwdlPeerRuntime::PsfPeerSnapshot *peer,
                    uint32_t marker, uint64_t ageUs,
                    const IntelAwdlPeer::RuntimeEpochs &epochs,
                    bool hasPsf = true, bool consistent = true) {
    *peer = IntelAwdlPeerRuntime::PsfPeerSnapshot{};
    peer->tracked = true;
    peer->hasPsf = hasPsf;
    peer->contextGeneration = epochs.contextGeneration;
    peer->powerGeneration = epochs.powerGeneration;
    peer->stationGeneration = epochs.stationGeneration;
    peer->psfRxMonotonicUs = gNowUs - ageUs;
    peer->psfAgeUs = ageUs;
    peer->psfRxGp2TimestampUs = marker * 100 + 101;
    peer->psfRxGp2TimestampPresent = true;
    peer->phyTxTimestampUs = marker * 100 + 102;
    peer->targetTxTimestampUs = marker * 100 + 103;
    peer->height = marker * 1000 + 104;
    peer->masterMetric = marker * 1000 + 105;
    peer->masterCounter = marker * 1000 + 106;
    peer->ownMetric = marker * 1000 + 107;
    peer->ownCounter = marker * 1000 + 108;
    peer->rxChannel = static_cast<uint16_t>(marker + 109);
    peer->txDownCounterTu = static_cast<uint16_t>(marker + 110);
    peer->awPeriodTu = static_cast<uint16_t>(marker + 111);
    peer->actionFramePeriodTu = static_cast<uint16_t>(marker + 112);
    peer->nextAwSequence = static_cast<uint16_t>(marker + 113);
    peer->syncParameterLength = static_cast<uint16_t>(marker + 114);
    peer->syncTailLength = static_cast<uint16_t>(marker + 115);
    peer->nextAwChannel = static_cast<uint8_t>(marker + 116);
    peer->version = static_cast<uint8_t>(marker + 117);
    peer->deviceClass = static_cast<uint8_t>(marker + 118);
    peer->syncConsistent = consistent;
    peer->psfFresh = ageUs <= 5000000 && consistent;
    peer->electionV2 = true;
    peer->embeddedSequencePresent = true;
    peer->embeddedSequenceRecognized = true;
    peer->embeddedSequenceVerified = false;
    peer->embeddedSequenceMismatch = true;
    peer->embeddedMismatchIndex = static_cast<uint8_t>(marker % 16);
    peer->embeddedMismatchChannel = 6;
    peer->canonicalMismatchChannel = 44;
    for (size_t i = 0; i < 16; ++i)
        peer->channelSlots[i] = static_cast<uint8_t>(marker + 20 + i);
}

static IntelAwdlPeer::RuntimeEpochs epochsFor(const ItlIwx &driver) {
    return {driver.nativeP2pProbeGeneration_,
            uint64_t(uint32_t(driver.com.sc_generation)),
            __atomic_load_n(&driver.com.sc_tx_rate_generation, __ATOMIC_ACQUIRE),
            driver.com.sc_ic.ic_state == IEEE80211_S_RUN &&
                (driver.com.sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR)) == 0};
}

static void assertNoPrivatePropertyNames(const MockController &sink) {
    for (const auto &item : sink.values) {
        assert(item.first.find("NativeP2PPeerState") == 0);
        const std::string lower = item.first;
        assert(lower.find("Address") == std::string::npos);
        assert(lower.find("Mac") == std::string::npos);
        assert(lower.find("Name") == std::string::npos);
        assert(lower.find("Uid") == std::string::npos);
        assert(lower.find("Bytes") == std::string::npos);
    }
}

static void testMainGateIsRequired() {
    ItlIwx driver;
    driver.tahoe_awdl_peer_runtime_.state.trackedPeerCount = 1;
    driver.loop.gated = false;
    driver.tahoeP2pPublishPeerRuntime();
    assert(driver.tahoe_awdl_peer_runtime_.calls == 0);
    assert(driver.sink.writes == 0);
    assert(!driver.tahoe_awdl_runtime_published_once_);

    driver.loop.gated = true;
    driver.controller = nullptr;
    driver.tahoeP2pPublishPeerRuntime();
    assert(driver.tahoe_awdl_peer_runtime_.calls == 0);
    assert(driver.sink.writes == 0);
}

static void testFreshSlotMappingAndChangedOnlyNumericPublication() {
    ItlIwx driver;
    auto &state = driver.tahoe_awdl_peer_runtime_.state;
    state = IntelAwdlPeerRuntime::Snapshot{};
    state.latestFreshMifSlot = 1;
    state.trackedPeerCount = 2;
    state.freshMifPeerCount = 1;
    state.admittedTotal = 5;
    state.updatedTotal = 3;
    state.candidateFrameTotal = 9;
    state.mifFrameTotal = 7;
    state.rejectedTotal = 2;
    state.rejectedMifTotal = 6;
    state.lastAdmittedContextGeneration = 701;
    state.lastRejectedContext = 702;
    state.lastRejectedResult = 8;
    state.lastMifDecodeStatus = 0; // Latest MIF decode succeeded with a copy mismatch.
    state.lastMifRejectDiagnostics.rejectStage =
        IntelAwdlElection::MifDecodeRejectStage::kNone;
    state.lastMifRejectDiagnostics.syncParameterLength = 59;
    state.lastMifRejectDiagnostics.embeddedSequenceRecognized = 1;
    state.lastMifRejectDiagnostics.embeddedSequenceMismatch = 1;
    state.lastMifRejectDiagnostics.embeddedMismatchIndex = 5;
    state.lastMifRejectDiagnostics.embeddedMismatchChannel = 149;
    state.lastMifRejectDiagnostics.canonicalMismatchChannel = 6;
    state.latestFreshPsfSlot = 0;
    state.freshPsfPeerCount = 1;
    state.acceptedPsfTotal = 13;
    state.rejectedPsfTotal = 4;
    state.lastPsfDecodeStatus = 0; // Independent successful PSF mismatch decode.
    state.lastPsfRejectDiagnostics.rejectStage =
        IntelAwdlElection::MifDecodeRejectStage::kNone;
    state.lastPsfRejectDiagnostics.syncParameterLength = 75;
    state.lastPsfRejectDiagnostics.embeddedSequenceRecognized = 1;
    state.lastPsfRejectDiagnostics.embeddedSequenceMismatch = 1;
    state.lastPsfRejectDiagnostics.embeddedMismatchIndex = 8;
    state.lastPsfRejectDiagnostics.embeddedMismatchChannel = 149;
    state.lastPsfRejectDiagnostics.canonicalMismatchChannel = 6;
    fillPeer(&state.peers[0], 41, true, false);
    fillPeer(&state.peers[1], 1, true, true);
    state.peers[1].embeddedMismatchIndex = 2;
    state.peers[1].embeddedMismatchChannel = 44;
    state.peers[1].canonicalMismatchChannel = 149;
    fillPsf(&driver.tahoe_awdl_peer_runtime_.psfPeers[0], 41, 100,
            epochsFor(driver));

    driver.tahoeP2pPublishPeerRuntime();
    const auto &properties = driver.sink;
    assert(driver.sink.writes == 161);
    assert(properties.get("NativeP2PPeerStateSlot") == 1);
    assert(properties.get("NativeP2PPeerStateFreshMifCount") == 1);
    assert(properties.get("NativeP2PPeerStateHasMif") == 1);
    assert(properties.get("NativeP2PPeerStateMifFresh") == 1);
    assert(properties.get("NativeP2PPeerStateContext") == 101);
    assert(properties.get("NativeP2PPeerStatePowerGeneration") == 201);
    assert(properties.get("NativeP2PPeerStateStationGeneration") == 301);
    assert(properties.get("NativeP2PPeerStateMifRxHostUs") == 1000500);
    assert(properties.get("NativeP2PPeerStateMifRxGp2Us") == 120);
    assert(properties.get("NativeP2PPeerStateMifPhyTxUs") == 121);
    assert(properties.get("NativeP2PPeerStateMifTargetTxUs") == 122);
    assert(properties.get("NativeP2PPeerStateMasterMetric") == 1023);
    assert(properties.get("NativeP2PPeerStateSyncLength") == 36);
    assert(properties.get("NativeP2PPeerStateSyncTailLength") == 37);
    assert(properties.get("NativeP2PPeerStateEmbeddedPresent") == 1);
    assert(properties.get("NativeP2PPeerStateEmbeddedRecognized") == 1);
    assert(properties.get("NativeP2PPeerStateEmbeddedVerified") == 0);
    assert(properties.get("NativeP2PPeerStateEmbeddedMismatch") == 1);
    assert(properties.get("NativeP2PPeerStateEmbeddedMismatchIndex") == 2);
    assert(properties.get("NativeP2PPeerStateEmbeddedMismatchChannel") == 44);
    assert(properties.get("NativeP2PPeerStateCanonicalMismatchChannel") == 149);
    assert(properties.get("NativeP2PPeerStateLastMifDecodeStatus") == 0);
    assert(properties.get("NativeP2PPeerStateMifDecodeRejectStage") ==
           uint64_t(IntelAwdlElection::MifDecodeRejectStage::kNone));
    assert(properties.get("NativeP2PPeerStateMifDecodeDeclaredLength") == 0);
    assert(properties.get("NativeP2PPeerStateMifDecodeSyncLength") == 59);
    assert(properties.get("NativeP2PPeerStateMifDecodeEmbeddedVerified") == 0);
    // The table's latest MIF decode belongs to a different peer than the
    // selected per-peer MIF snapshot above.
    assert(properties.get("NativeP2PPeerStateMifDecodeEmbeddedMismatch") == 1);
    assert(properties.get("NativeP2PPeerStateMifDecodeEmbeddedMismatchIndex") == 5);
    assert(properties.get("NativeP2PPeerStateMifDecodeEmbeddedMismatchChannel") == 149);
    assert(properties.get("NativeP2PPeerStateMifDecodeCanonicalMismatchChannel") == 6);
    assert(properties.get("NativeP2PPeerStatePsfSlot") == 0);
    assert(properties.get("NativeP2PPeerStatePsfHas") == 1);
    assert(properties.get("NativeP2PPeerStatePsfFresh") == 1);
    assert(properties.get("NativeP2PPeerStatePsfAgeUs") == 100);
    assert(properties.get("NativeP2PPeerStatePsfContext") == 7);
    assert(properties.get("NativeP2PPeerStatePsfPowerGeneration") == 9);
    assert(properties.get("NativeP2PPeerStatePsfStationGeneration") == 11);
    assert(properties.get("NativeP2PPeerStatePsfRxHostUs") == 9999900);
    assert(properties.get("NativeP2PPeerStatePsfRxGp2Us") == 4201);
    assert(properties.get("NativeP2PPeerStatePsfPhyTxUs") == 4202);
    assert(properties.get("NativeP2PPeerStatePsfTargetTxUs") == 4203);
    assert(properties.get("NativeP2PPeerStatePsfRxChannel") == 150);
    assert(properties.get("NativeP2PPeerStatePsfMasterMetric") == 41105);
    assert(properties.get("NativeP2PPeerStatePsfTxDownCounterTu") == 151);
    assert(properties.get("NativeP2PPeerStatePsfSyncLength") == 155);
    assert(properties.get("NativeP2PPeerStatePsfSyncTailLength") == 156);
    assert(properties.get("NativeP2PPeerStatePsfEmbeddedPresent") == 1);
    assert(properties.get("NativeP2PPeerStatePsfEmbeddedRecognized") == 1);
    assert(properties.get("NativeP2PPeerStatePsfEmbeddedVerified") == 0);
    assert(properties.get("NativeP2PPeerStatePsfEmbeddedMismatch") == 1);
    assert(properties.get("NativeP2PPeerStatePsfEmbeddedMismatchIndex") == 9);
    assert(properties.get("NativeP2PPeerStatePsfEmbeddedMismatchChannel") == 6);
    assert(properties.get("NativeP2PPeerStatePsfCanonicalMismatchChannel") == 44);
    assert(properties.get("NativeP2PPeerStatePsfChannelsLo") ==
           0x44434241403f3e3dULL);
    assert(properties.get("NativeP2PPeerStatePsfChannelsHi") ==
           0x4c4b4a4948474645ULL);
    // The selected MIF and PSF deliberately belong to different table slots.
    assert(properties.get("NativeP2PPeerStateSlot") == 1);
    assert(properties.get("NativeP2PPeerStateMasterMetric") == 1023);
    assert(properties.get("NativeP2PPeerStateMifRxGp2Us") == 120);
    assert(properties.get("NativeP2PPeerStateLastPsfDecodeStatus") == 0);
    assert(properties.get("NativeP2PPeerStateAcceptedPsfTotal") == 13);
    assert(properties.get("NativeP2PPeerStateRejectedPsfTotal") == 4);
    assert(properties.get("NativeP2PPeerStatePsfDecodeRejectStage") ==
           uint64_t(IntelAwdlElection::MifDecodeRejectStage::kNone));
    assert(properties.get("NativeP2PPeerStatePsfDecodeTlvType") == 0);
    assert(properties.get("NativeP2PPeerStatePsfDecodeDeclaredLength") == 0);
    assert(properties.get("NativeP2PPeerStatePsfDecodeSyncLength") == 75);
    // Likewise, the last PSF decode diagnostic is independent of the selected
    // per-peer PSF snapshot and of the MIF diagnostic tuple.
    assert(properties.get("NativeP2PPeerStatePsfDecodeEmbeddedMismatch") == 1);
    assert(properties.get("NativeP2PPeerStatePsfDecodeEmbeddedMismatchIndex") == 8);
    assert(properties.get("NativeP2PPeerStatePsfDecodeEmbeddedMismatchChannel") == 149);
    assert(properties.get("NativeP2PPeerStatePsfDecodeCanonicalMismatchChannel") == 6);
    assert(properties.get("NativeP2PPeerStateChannelsLo") ==
           0x0807060504030201ULL);
    assert(properties.get("NativeP2PPeerStateChannelsHi") ==
           0x100f0e0d0c0b0a09ULL);

    // All three tuples come from the selected slot and preserve raw clock
    // domains separately. Slot 0 deliberately contains different values.
    assert(properties.get("NativeP2PPeerStateTimingCount") == 3);
    assert(properties.get("NativeP2PPeerStateSample0RxHostUs") == 1000100);
    assert(properties.get("NativeP2PPeerStateSample0RxGp2Us") == 110);
    assert(properties.get("NativeP2PPeerStateSample0PhyTxUs") == 1000300);
    assert(properties.get("NativeP2PPeerStateSample0Present") == 1);
    assert(properties.get("NativeP2PPeerStateSample1RxHostUs") == 1000101);
    assert(properties.get("NativeP2PPeerStateSample1RxGp2Us") == 111);
    assert(properties.get("NativeP2PPeerStateSample1PhyTxUs") == 1000301);
    assert(properties.get("NativeP2PPeerStateSample1Present") == 0);
    assert(properties.get("NativeP2PPeerStateSample2RxHostUs") == 1000102);
    assert(properties.get("NativeP2PPeerStateSample2RxGp2Us") == 112);
    assert(properties.get("NativeP2PPeerStateSample2PhyTxUs") == 1000302);
    assert(properties.get("NativeP2PPeerStateSample2Present") == 1);
    assert(properties.get("NativeP2PPeerStateSample0Subtype") == 0);
    assert(properties.get("NativeP2PPeerStateSample1Subtype") == 3);
    assert(properties.get("NativeP2PPeerStateSample2Subtype") == 0);
    assert(properties.get("NativeP2PPeerStateMappingProven") == 0);
    assert(properties.get("NativeP2PPeerStateScheduleEnabled") == 0);
    assert(properties.get("NativeP2PPeerStateElectionApplied") == 0);
    assertNoPrivatePropertyNames(properties);

    const unsigned writes = driver.sink.writes;
    driver.tahoeP2pPublishPeerRuntime();
    assert(driver.sink.writes == writes);

    // Each runtime generation invalidates the peer slots. Table diagnostics
    // remain cumulative, while all slot-specific numbers are republished zero.
    for (unsigned generation = 0; generation < 4; ++generation) {
        if (generation != 0) {
            state = IntelAwdlPeerRuntime::Snapshot{};
            state.latestFreshMifSlot = 1;
            state.trackedPeerCount = 1;
            state.freshMifPeerCount = 1;
            state.admittedTotal = 5;
            state.updatedTotal = 3;
            state.candidateFrameTotal = 9;
            state.mifFrameTotal = 7;
            state.rejectedTotal = 2;
            state.rejectedMifTotal = 6;
            state.latestFreshPsfSlot = 0;
            state.freshPsfPeerCount = 1;
            state.acceptedPsfTotal = 13;
            state.rejectedPsfTotal = 4;
            state.lastAdmittedContextGeneration = 701;
            state.lastRejectedContext = 702;
            state.lastRejectedResult = 8;
            state.lastMifDecodeStatus = 0;
            state.lastMifRejectDiagnostics.rejectStage =
                IntelAwdlElection::MifDecodeRejectStage::kNone;
            state.lastMifRejectDiagnostics.syncParameterLength = 59;
            state.lastMifRejectDiagnostics.embeddedSequenceRecognized = 1;
            state.lastMifRejectDiagnostics.embeddedSequenceMismatch = 1;
            state.lastMifRejectDiagnostics.embeddedMismatchIndex = 5;
            state.lastMifRejectDiagnostics.embeddedMismatchChannel = 149;
            state.lastMifRejectDiagnostics.canonicalMismatchChannel = 6;
            state.lastPsfDecodeStatus = 0;
            state.lastPsfRejectDiagnostics.rejectStage =
                IntelAwdlElection::MifDecodeRejectStage::kNone;
            state.lastPsfRejectDiagnostics.syncParameterLength = 75;
            state.lastPsfRejectDiagnostics.embeddedSequenceRecognized = 1;
            state.lastPsfRejectDiagnostics.embeddedSequenceMismatch = 1;
            state.lastPsfRejectDiagnostics.embeddedMismatchIndex = 8;
            state.lastPsfRejectDiagnostics.embeddedMismatchChannel = 149;
            state.lastPsfRejectDiagnostics.canonicalMismatchChannel = 6;
            fillPeer(&state.peers[1], 1, true, true);
            fillPsf(&driver.tahoe_awdl_peer_runtime_.psfPeers[0], 41, 100,
                    epochsFor(driver));
            driver.tahoeP2pPublishPeerRuntime();
            assert(driver.sink.get("NativeP2PPeerStateSlot") == 1);
        }

        switch (generation) {
            case 0: ++driver.nativeP2pProbeGeneration_; break;
            case 1: ++driver.com.sc_generation; break;
            case 2: ++driver.com.sc_tx_rate_generation; break;
            case 3: driver.com.sc_ic.ic_state = 0; break;
        }
        driver.tahoeP2pPublishPeerRuntime();
        assert(driver.sink.get("NativeP2PPeerStateTrackedCount") == 0);
        assert(driver.sink.get("NativeP2PPeerStateFreshMifCount") == 0);
        assert(driver.sink.get("NativeP2PPeerStateSlot") == 0xff);
        assert(driver.sink.get("NativeP2PPeerStateContext") == 0);
        assert(driver.sink.get("NativeP2PPeerStateHasMif") == 0);
        assert(driver.sink.get("NativeP2PPeerStateMifFresh") == 0);
        assert(driver.sink.get("NativeP2PPeerStateMifRxHostUs") == 0);
        assert(driver.sink.get("NativeP2PPeerStateTimingCount") == 0);
        assert(driver.sink.get("NativeP2PPeerStateSample2PhyTxUs") == 0);
        assert(driver.sink.get("NativeP2PPeerStateChannelsLo") == 0);
        assert(driver.sink.get("NativeP2PPeerStateChannelsHi") == 0);
        assert(driver.sink.get("NativeP2PPeerStateEmbeddedMismatch") == 0);
        assert(driver.sink.get("NativeP2PPeerStateEmbeddedMismatchIndex") == 0);
        assert(driver.sink.get("NativeP2PPeerStateEmbeddedMismatchChannel") == 0);
        assert(driver.sink.get("NativeP2PPeerStateCanonicalMismatchChannel") == 0);
        assert(driver.sink.get("NativeP2PPeerStateMappingProven") == 0);
        assert(driver.sink.get("NativeP2PPeerStateScheduleEnabled") == 0);
        assert(driver.sink.get("NativeP2PPeerStateElectionApplied") == 0);
        assert(driver.sink.get("NativeP2PPeerStateAdmittedTotal") == 5);
        assert(driver.sink.get("NativeP2PPeerStateUpdatedTotal") == 3);
        assert(driver.sink.get("NativeP2PPeerStateRejectedMifTotal") == 6);
        assert(driver.sink.get("NativeP2PPeerStateLastRejectedResult") == 8);
        assert(driver.sink.get("NativeP2PPeerStateLastMifDecodeStatus") == 0);
        assert(driver.sink.get("NativeP2PPeerStateMifDecodeRejectStage") ==
               uint64_t(IntelAwdlElection::MifDecodeRejectStage::kNone));
        assert(driver.sink.get("NativeP2PPeerStateMifDecodeEmbeddedMismatch") == 1);
        assert(driver.sink.get("NativeP2PPeerStateMifDecodeEmbeddedMismatchIndex") == 5);
        assert(driver.sink.get("NativeP2PPeerStateMifDecodeEmbeddedMismatchChannel") == 149);
        assert(driver.sink.get("NativeP2PPeerStateMifDecodeCanonicalMismatchChannel") == 6);
        assert(driver.sink.get("NativeP2PPeerStateLastRejectedContext") == 702);
        assert(driver.sink.get("NativeP2PPeerStateLastResult") == 77);
        assert(driver.sink.get("NativeP2PPeerStateFreshPsfCount") == 0);
        assert(driver.sink.get("NativeP2PPeerStatePsfSlot") == 0xff);
        assert(driver.sink.get("NativeP2PPeerStatePsfHas") == 0);
        assert(driver.sink.get("NativeP2PPeerStatePsfFresh") == 0);
        assert(driver.sink.get("NativeP2PPeerStatePsfAgeUs") == 0);
        assert(driver.sink.get("NativeP2PPeerStatePsfRxHostUs") == 0);
        assert(driver.sink.get("NativeP2PPeerStatePsfChannelsLo") == 0);
        assert(driver.sink.get("NativeP2PPeerStatePsfEmbeddedMismatch") == 0);
        assert(driver.sink.get("NativeP2PPeerStatePsfEmbeddedMismatchIndex") == 0);
        assert(driver.sink.get("NativeP2PPeerStatePsfEmbeddedMismatchChannel") == 0);
        assert(driver.sink.get("NativeP2PPeerStatePsfCanonicalMismatchChannel") == 0);
        assert(driver.sink.get("NativeP2PPeerStateAcceptedPsfTotal") == 13);
        assert(driver.sink.get("NativeP2PPeerStateRejectedPsfTotal") == 4);
        assert(driver.sink.get("NativeP2PPeerStateLastPsfDecodeStatus") == 0);
        assert(driver.sink.get("NativeP2PPeerStatePsfDecodeRejectStage") ==
               uint64_t(IntelAwdlElection::MifDecodeRejectStage::kNone));
        assert(driver.sink.get("NativeP2PPeerStatePsfDecodeDeclaredLength") == 0);
        assert(driver.sink.get("NativeP2PPeerStatePsfDecodeEmbeddedMismatch") == 1);
        assert(driver.sink.get("NativeP2PPeerStatePsfDecodeEmbeddedMismatchIndex") == 8);
        assert(driver.sink.get("NativeP2PPeerStatePsfDecodeEmbeddedMismatchChannel") == 149);
        assert(driver.sink.get("NativeP2PPeerStatePsfDecodeCanonicalMismatchChannel") == 6);
    }
}

static void testStaleMifHistoryPriorityAndCandidateOnlyFallback() {
    ItlIwx stale;
    auto &staleState = stale.tahoe_awdl_peer_runtime_.state;
    staleState.latestFreshMifSlot = 0xff;
    staleState.trackedPeerCount = 2;
    staleState.freshMifPeerCount = 0;
    fillPeer(&staleState.peers[0], 41, true, false);
    fillPeer(&staleState.peers[1], 2, false, false);
    staleState.peers[0].frameAgeUs = 500;
    staleState.peers[1].frameAgeUs = 1; // newer PSF-only candidate
    stale.tahoeP2pPublishPeerRuntime();
    assert(stale.sink.get("NativeP2PPeerStateSlot") == 0);
    assert(stale.sink.get("NativeP2PPeerStateHasMif") == 1);
    assert(stale.sink.get("NativeP2PPeerStateMifFresh") == 0);
    assert(stale.sink.get("NativeP2PPeerStateMifAgeUs") == 410);
    assert(stale.sink.get("NativeP2PPeerStateMifRxGp2Us") == 4120);
    assert(stale.sink.get("NativeP2PPeerStateSample0RxGp2Us") == 4110);
    assertNoPrivatePropertyNames(stale.sink);

    ItlIwx candidate;
    auto &candidateState = candidate.tahoe_awdl_peer_runtime_.state;
    candidateState.latestFreshMifSlot = 0xff;
    candidateState.trackedPeerCount = 1;
    candidateState.freshMifPeerCount = 0;
    fillPeer(&candidateState.peers[0], 7, false, false);
    candidate.tahoeP2pPublishPeerRuntime();
    assert(candidate.sink.get("NativeP2PPeerStateSlot") == 0);
    assert(candidate.sink.get("NativeP2PPeerStateHasMif") == 0);
    assert(candidate.sink.get("NativeP2PPeerStateMifFresh") == 0);
    assert(candidate.sink.get("NativeP2PPeerStateMifAgeUs") == 0);
    assert(candidate.sink.get("NativeP2PPeerStateMifRxGp2Us") == 0);
    assert(candidate.sink.get("NativeP2PPeerStateTimingCount") == 3);
    assert(candidate.sink.get("NativeP2PPeerStateSample0RxHostUs") == 7000100);
    assert(candidate.sink.get("NativeP2PPeerStateSample0RxGp2Us") == 710);
    assert(candidate.sink.get("NativeP2PPeerStateSample0PhyTxUs") == 7000300);
    assertNoPrivatePropertyNames(candidate.sink);
}

static void testExpiredPsfIsHistoricalAndNeverFresh() {
    ItlIwx driver;
    auto &state = driver.tahoe_awdl_peer_runtime_.state;
    state.latestFreshMifSlot = 0xff;
    state.latestFreshPsfSlot = 0xff;
    state.trackedPeerCount = 1;
    state.freshMifPeerCount = 0;
    state.freshPsfPeerCount = 0;
    fillPsf(&driver.tahoe_awdl_peer_runtime_.psfPeers[3], 9,
            5000001, epochsFor(driver));
    driver.tahoeP2pPublishPeerRuntime();
    assert(driver.sink.get("NativeP2PPeerStatePsfSlot") == 3);
    assert(driver.sink.get("NativeP2PPeerStatePsfHas") == 1);
    assert(driver.sink.get("NativeP2PPeerStatePsfFresh") == 0);
    assert(driver.sink.get("NativeP2PPeerStatePsfAgeUs") == 5000001);
    assert(driver.sink.get("NativeP2PPeerStatePsfRxHostUs") == gNowUs - 5000001);
    assert(driver.sink.get("NativeP2PPeerStatePsfMasterMetric") == 9105);
    assertNoPrivatePropertyNames(driver.sink);
}

int main() {
    testMainGateIsRequired();
    testFreshSlotMappingAndChangedOnlyNumericPublication();
    testStaleMifHistoryPriorityAndCandidateOnlyFallback();
    testExpiredPsfIsHistoricalAndNeverFresh();
}
'''

    fixture = fixture.replace("__CACHE_CAPACITY__", cache_capacity)
    with tempfile.TemporaryDirectory(prefix="iwx-p2p-peer-publication-") as tmp:
        cpp = Path(tmp) / "fixture.cpp"
        binary = Path(tmp) / "fixture"
        cpp.write_text(fixture)
        subprocess.run(
            [
                "xcrun",
                "clang++",
                "-std=c++14",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-O1",
                "-g",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-I",
                str(ROOT / "native"),
                str(cpp),
                "-o",
                str(binary),
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
    print(
        "PASS: extracted peer publication main-gate, fresh/stale/candidate "
        "selection, independent PSF/MIF slot and diagnostics, three subtype "
        "labels, 5-second PSF expiry/history and epoch reset, paired timing "
        f"tuples, 16-slot packing, {publish_count} numeric fields within the "
        f"actual {cache_capacity}-entry cache, changed-only publication; "
        "RX drain returns to main gate. No TX, radio, EFI, or peer discovery "
        "was run."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
