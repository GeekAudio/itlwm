#!/usr/bin/env python3
"""Exercise the production Action HAL's final estimated-window guard."""
import importlib.util
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HAL_TEST = ROOT / "native/tests/test_iwx_p2p_action_hal.py"
spec = importlib.util.spec_from_file_location("p2p_action_hal", HAL_TEST)
hal = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(hal)


def modified_shim():
    shim = hal.SHIM.replace(
        '#include "native/awdl_mif_encode.hpp"',
        '#include "native/awdl_mif_encode.hpp"\n'
        '#include "native/awdl_data_frame.hpp"\n'
        '#include "native/awdl_advertisement_identity.hpp"\n'
        '#include "native/awdl_tx_window_evidence.hpp"',
    )
    shim = shim.replace(
        "static unsigned gDoorbells = 0, gDoorbellMarkCalls = 0;",
        "static uint64_t gDeadlineClockNs = 0;\n"
        "static uint32_t *gRateGenerationToMutate = nullptr;\n"
        "static uint8_t gResidentAddress[6]{};\n"
        "static bool ownerChangeQidAfterTicketArm = false;\n"
        "static int ownerQidAfterTicketArm = -1;\n"
        "static uint64_t gNativeInFlightToken = 0;\n"
        "static unsigned gNativeSubmittedFailures = 0;\n"
        "static unsigned gNativeTxSubmitFailed = 0, gNativeTxStale = 0;\n"
        "static bool gResidentEnabled = false;\n"
        "static unsigned gDoorbells = 0, gDoorbellMarkCalls = 0;\n"
        "static int gQueueCancelResult = 0;",
    )
    shim = shim.replace(
        "struct FakeCursor {\n    int result = 1;",
        "struct FakeCursor {\n    int result = 1;\n"
        "    uint64_t advanceOnMapNs = 0;\n"
        "    bool changeRateGenerationOnMap = false;\n"
        "    uint32_t rateGenerationAfterMap = 0;\n"
        "    uint8_t *rocPhaseToChange = nullptr;\n"
        "    uint8_t rocPhaseAfterMap = 0;",
    )
    shim = shim.replace(
        "if (result <= 0 || !m || maximum < 1) return result;\n"
        "        segments[0] = {0x200000, m->length};",
        "if (advanceOnMapNs) {\n"
        "            gDeadlineClockNs += advanceOnMapNs;\n"
        "            advanceOnMapNs = 0;\n"
        "        }\n"
        "        if (changeRateGenerationOnMap && gRateGenerationToMutate) {\n"
        "            *gRateGenerationToMutate = rateGenerationAfterMap;\n"
        "            changeRateGenerationOnMap = false;\n"
        "            gRateGenerationToMutate = nullptr;\n"
        "        }\n"
        "        if (rocPhaseToChange) { *rocPhaseToChange = rocPhaseAfterMap;\n"
        "            rocPhaseToChange = nullptr; }\n"
        "        if (result <= 0 || !m || maximum < 1) return result;\n"
        "        segments[0] = {0x200000, m->length};",
    )
    shim = shim.replace(
        "    int sc_generation = 7;\n    int sc_dmat = 0;",
        "    int sc_generation = 7;\n"
        "    uint32_t sc_tx_rate_generation = 0;\n    int sc_dmat = 0;",
    )
    shim = shim.replace(
        "    kPreDoorbellCancelFailed = 20, kExistingTicketUnknown = 21\n};",
        "    kPreDoorbellCancelFailed = 20, kExistingTicketUnknown = 21,\n"
        "    kNativeAwdlIdentity = 22, kExperimentalDeadline = 23,\n"
        "    kControlSubmitFence = 24\n};",
    )
    shim = shim.replace(
        "struct TahoeP2PActionTxContext {",
        "#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)\n"
        "struct TahoeP2PActionTxSubmitMetadata {\n"
        "    uint64_t diagnosticGeneration;\n"
        "    NativeAwdlTxWindowEvidence::Epoch epoch;\n"
        "    NativeAwdlTxWindowEvidence::FrameKind frameKind;\n"
        "    uint32_t frameOrdinal;\n};\n"
        "struct TahoeP2PActionTxEvidenceSidecar {\n"
        "    uint64_t ticketToken; uint32_t deviceFamily, txCommandApi, txLayout;\n"
        "    uint32_t statusFlags; bool used;\n"
        "    TahoeP2PActionTxEvidenceSidecar() : ticketToken(0), deviceFamily(0),\n"
        "        txCommandApi(0), txLayout(0), statusFlags(0), used(false) {}\n};\n"
        "enum TahoeP2PActionTxEvidenceStatusFlag : uint32_t {\n"
        "    kP2PTxEvidenceDoorbellMarked = 1u << 0,\n"
        "    kP2PTxEvidenceDoorbellIssued = 1u << 1,\n"
        "    kP2PTxEvidenceSubmitLowerValid = 1u << 2,\n"
        "    kP2PTxEvidenceCompletionUpperValid = 1u << 3,\n"
        "    kP2PTxEvidenceFirmwareSuccess = 1u << 4,\n"
        "    kP2PTxEvidenceUnbound = 1u << 5,\n"
        "    kP2PTxEvidenceFirmwareFailure = 1u << 6,\n"
        "    kP2PTxEvidenceInvalidUnknown = 1u << 7,\n"
        "    kP2PTxEvidencePostDoorbellFinishFailure = 1u << 8\n};\n"
        "struct TahoeP2PActionTxWindowEvidence {\n"
        "    NativeAwdlTxWindowEvidence::Ledger ledger;\n"
        "    NativeAwdlTxWindowEvidence::TicketIdentity pendingIdentity;\n"
        "    NativeAwdlTxWindowEvidence::Epoch epoch;\n"
        "    TahoeP2PActionTxEvidenceSidecar sidecars[NativeAwdlTxWindowEvidence::kTicketCapacity];\n"
        "    uint64_t diagnosticGeneration, nextTicketSerial, snapshotVersion, lastPublishedSnapshotVersion;\n"
        "    uint32_t pendingStatusFlags, droppedTicketCount, pendingSidecarIndex, pendingDeviceFamily, pendingTxCommandApi, pendingTxLayout;\n"
        "    bool initialized, pendingTicketPrepared, pendingIdentityValid;\n"
        "    TahoeP2PActionTxWindowEvidence() : ledger(), pendingIdentity{}, epoch{}, sidecars{},\n"
        "        diagnosticGeneration(0), nextTicketSerial(0), snapshotVersion(0), lastPublishedSnapshotVersion(0),\n"
        "        pendingStatusFlags(0), droppedTicketCount(0), pendingSidecarIndex(0xffffffffu),\n"
        "        pendingDeviceFamily(0), pendingTxCommandApi(0), pendingTxLayout(0), initialized(false),\n"
        "        pendingTicketPrepared(false), pendingIdentityValid(false) {}\n};\n"
        "#endif\n"
        "struct TahoeP2PActionTxContext {",
    )
    shim = shim.replace(
        "struct TahoeP2PActionTxContext {",
        "struct TahoeP2PActionTxControlSubmitFence {\n"
        "    uint64_t phaseOriginUs, peerMifRxUs, effectiveEndUs;\n"
        "    uint64_t preparedFrameUs, preparedFrameMaxAgeUs;\n"
        "    uint64_t contextGeneration, powerGeneration, stationGeneration, rocGeneration;\n"
        "};\n"
        "struct TahoeP2PActionTxContext {",
    )
    shim = shim.replace(
        "struct TahoeP2PActionTxContext {\n    IntelP2PActionTx::CompletionTracker completion;",
        "struct TahoeP2PActionTxContext {\n    IntelP2PActionTx::CompletionTracker completion;\n"
        "#if defined(ITL_NATIVE_AWDL_TX_EVIDENCE_25G332)\n"
        "    TahoeP2PActionTxWindowEvidence windowEvidence;\n#endif\n",
    )
    shim = shim.replace(
        "class ItlIwx {\npublic:\n    iwx_softc com{};",
        "struct OSBoolean {};\n"
        "static OSBoolean gTrueBoolean;\n"
        "static OSBoolean *kOSBooleanTrue = &gTrueBoolean;\n"
        "class IOEthernetController {\npublic:\n"
        "    OSBoolean *getProperty(const char *) {\n"
        "        return gResidentEnabled ? kOSBooleanTrue : nullptr;\n"
        "    }\n"
        "    bool setProperty(const char *, uint64_t, unsigned) { return true; }\n"
        "    bool setProperty(const char *, uint32_t, unsigned) { return true; }\n"
        "};\n"
        "static IOEthernetController gTestController;\n"
        "namespace NativeAwdlBSD {\n"
        "inline bool address(uint32_t generation, uint8_t out[6]) {\n"
        "    if (!generation || !out) return false;\n"
        "    std::memcpy(out, gResidentAddress, 6); return true;\n"
        "}\n"
        "inline void completed(uint64_t, bool) {}\n"
        "inline void submitted(uint64_t token, int result) {\n"
        "    if (!token) return;\n"
        "    if (token != gNativeInFlightToken) { ++gNativeTxStale; return; }\n"
        "    if (result) { ++gNativeSubmittedFailures; ++gNativeTxSubmitFailed;\n"
        "        gNativeInFlightToken = 0; }\n"
        "    else gNativeInFlightToken = 0;\n"
        "}\n"
        "}\n"
        "class ItlIwx {\npublic:\n    iwx_softc com{};\n"
        "    uint32_t nativeP2pProbeGeneration_ = 0;\n"
        "    IOEthernetController *tahoeP2pController() { return &gTestController; }",
    )
    shim = shim.replace(
        "        ring->byteCounts[index] = bytes;",
        "        ring->byteCounts[index] = bytes;\n"
        "        if (ownerChangeQidAfterTicketArm) {\n"
        "            ring->qid = ownerQidAfterTicketArm;\n"
        "            ownerChangeQidAfterTicketArm = false;\n"
        "        }",
    )
    shim = shim.replace(
        "static int iwx_tahoe_p2p_tvqm_cancel_tx_submit(TahoeP2PTxQueueLease *lease) {\n"
        "    if (!lease || !lease->submissionBusy || !lease->outstanding) return EINVAL;",
        "static int iwx_tahoe_p2p_tvqm_cancel_tx_submit(TahoeP2PTxQueueLease *lease) {\n"
        "    if (gQueueCancelResult) return gQueueCancelResult;\n"
        "    if (!lease || !lease->submissionBusy || !lease->outstanding) return EINVAL;",
    )
    assert "kExperimentalDeadline = 23" in shim
    assert "nativeP2pProbeGeneration_ = 0" in shim
    return shim


def native_frame_helper():
    return r"""
static mbuf_t makeDeadlineNativeFrame() {
    uint8_t ipv6[40]{}; ipv6[0] = 0x60;
    NativeAwdlData::EncodeInput input{};
    const uint8_t destination[6] = {0x02, 0x66, 0x55, 0x44, 0x33, 0x22};
    std::memcpy(input.destinationAddress, destination, 6);
    std::memcpy(input.sourceAddress, kSource, 6);
    input.wifiSequenceNumber = 31;
    input.awdlSequenceNumber = 13;
    input.ipv6Packet = ipv6; input.ipv6Length = sizeof(ipv6);
    uint8_t bytes[128]{}; size_t length = 0;
    assert(NativeAwdlData::encodeIpv6DataMpdu(
        &input, bytes, sizeof(bytes), &length) == NativeAwdlData::Status::Ok);
    return new mbuf(bytes, length);
}
static int submitDeadline(Fixture &f, uint64_t notBeforeUs,
                         uint64_t deadlineUs, uint32_t stationGeneration,
                         uint64_t token = 0xabc) {
    gResidentEnabled = true;
    std::memcpy(gResidentAddress, kSource, 6);
    f.owner.nativeP2pProbeGeneration_ = 55;
    f.owner.com.sc_tx_rate_generation = stationGeneration;
    TahoeP2PActionTxSubmitMetadata metadata{};
    metadata.diagnosticGeneration = 42;
    metadata.epoch.contextGeneration = 42;
    metadata.epoch.powerGeneration = 7;
    metadata.epoch.stationGeneration = stationGeneration;
    metadata.epoch.rocGeneration = 55;
    metadata.frameKind = NativeAwdlTxWindowEvidence::FrameKind::Psf;
    metadata.frameOrdinal = 1;
    mbuf_t frame = makeDeadlineNativeFrame();
    gNativeInFlightToken = token;
    const int result = iwx_tahoe_p2p_action_tx_submit(
        &f.owner, &f.owner.com, &f.lease, &f.context, 55, true, false,
        frame, token, &metadata, notBeforeUs, deadlineUs, stationGeneration,
        nullptr);
    // The caller owns NativeAwdlBSD token retirement after the HAL returns.
    NativeAwdlBSD::submitted(token, result);
    return result;
}
"""


def deadline_tests():
    return r"""
    // Bounds are a half-open host-monotonic estimate, sampled after mapping.
    // At the inclusive lower edge is allowed; at the upper edge is rejected.
    {
        Fixture f; gDeadlineClockNs = 5000000ULL;
        assert(submitDeadline(f, 5000, 6000, 9) == 0);
        assert(gDoorbellMarkCalls == 1 && gDoorbells == 1);
        assert(f.ring()->queued == 1 && f.context.nativeDataToken == 0xabc);
        testCleanupAfterProvenDrain(f);
    }
    {
        Fixture f; gDeadlineClockNs = 4999000ULL;
        const unsigned marks = gDoorbellMarkCalls, bells = gDoorbells;
        const unsigned failed = gNativeSubmittedFailures;
        assert(submitDeadline(f, 5000, 6000, 10) == ETIMEDOUT);
        assert(gDoorbellMarkCalls == marks && gDoorbells == bells);
        assert(f.context.state == TahoeP2PActionTxState::kIdle &&
               f.context.nativeDataToken == 0 && f.ring()->cur == 0 &&
               f.ring()->queued == 0 && f.lease.outstanding == 0 &&
               !f.lease.submissionBusy && !f.context.completion.snapshot().armed);
        assert(!f.context.windowEvidence.pendingTicketPrepared &&
               !f.context.windowEvidence.pendingIdentityValid);
        assert(gNativeSubmittedFailures == failed + 1);
    }
    {
        Fixture f; gDeadlineClockNs = 5999000ULL;
        assert(submitDeadline(f, 5000, 6000, 11) == 0);
        assert(gDoorbellMarkCalls == 2 && gDoorbells == 2);
        testCleanupAfterProvenDrain(f);
    }
    // One nanosecond inside the left edge is admitted; ceil at the right edge
    // conservatively rejects a sample that is still 1 ns before the deadline.
    {
        Fixture f; gDeadlineClockNs = 5000001ULL;
        assert(submitDeadline(f, 5000, 6000, 113) == 0);
        assert(gDoorbells == 3);
        testCleanupAfterProvenDrain(f);
    }
    {
        Fixture f; gDeadlineClockNs = 5999999ULL;
        const unsigned marks = gDoorbellMarkCalls, bells = gDoorbells;
        assert(submitDeadline(f, 5000, 6000, 114) == ETIMEDOUT);
        assert(gDoorbellMarkCalls == marks && gDoorbells == bells);
    }
    {
        Fixture f; gDeadlineClockNs = 6000000ULL;
        const unsigned marks = gDoorbellMarkCalls, bells = gDoorbells;
        assert(submitDeadline(f, 5000, 6000, 111) == ETIMEDOUT);
        assert(gDoorbellMarkCalls == marks && gDoorbells == bells);
        assert(f.ring()->cur == 0 && f.ring()->queued == 0 &&
               f.lease.outstanding == 0);
    }
    {
        Fixture f; gDeadlineClockNs = 6001000ULL;
        const unsigned marks = gDoorbellMarkCalls, bells = gDoorbells;
        assert(submitDeadline(f, 5000, 6000, 112) == ETIMEDOUT);
        assert(gDoorbellMarkCalls == marks && gDoorbells == bells);
        assert(f.ring()->cur == 0 && f.ring()->queued == 0 &&
               f.lease.outstanding == 0);
    }
    // Payload mapping can consume the remaining window; the final guard sees it.
    {
        Fixture f; gDeadlineClockNs = 5500000ULL;
        f.cursor.advanceOnMapNs = 500000ULL;
        const unsigned marks = gDoorbellMarkCalls, bells = gDoorbells;
        assert(submitDeadline(f, 5000, 6000, 12) == ETIMEDOUT);
        assert(gDoorbellMarkCalls == marks && gDoorbells == bells);
        assert(f.lease.outstanding == 0 && f.ring()->queued == 0 &&
               f.context.state == TahoeP2PActionTxState::kIdle);
        assert(!f.context.windowEvidence.pendingTicketPrepared);
    }
    // A station-rate epoch change during preparation cancels before MMIO.
    {
        Fixture f; gDeadlineClockNs = 5200000ULL;
        f.cursor.changeRateGenerationOnMap = true;
        f.cursor.rateGenerationAfterMap = 44;
        f.owner.com.sc_tx_rate_generation = 13;
        gRateGenerationToMutate = &f.owner.com.sc_tx_rate_generation;
        const unsigned marks = gDoorbellMarkCalls, bells = gDoorbells;
        const unsigned failed = gNativeSubmittedFailures;
        assert(submitDeadline(f, 5000, 6000, 13) == ESTALE);
        assert(gDoorbellMarkCalls == marks && gDoorbells == bells);
        assert(f.context.state == TahoeP2PActionTxState::kIdle &&
               f.context.nativeDataToken == 0 && f.ring()->cur == 0 &&
               f.ring()->queued == 0 && f.lease.outstanding == 0);
        assert(!f.context.windowEvidence.pendingTicketPrepared);
        assert(gNativeSubmittedFailures == failed + 1);
    }
    // The discovery experiment permits only an observed ACKED ROC phase.
    {
        Fixture f; gDeadlineClockNs = 5200000ULL;
        f.cursor.rocPhaseToChange = &f.owner.com.sc_p2p_roc.phase;
        f.cursor.rocPhaseAfterMap = IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN;
        const unsigned marks = gDoorbellMarkCalls, bells = gDoorbells;
        assert(submitDeadline(f, 5000, 6000, 16) == ESTALE);
        assert(gDoorbellMarkCalls == marks && gDoorbells == bells &&
               f.context.state == TahoeP2PActionTxState::kIdle &&
               f.lease.outstanding == 0 && f.ring()->queued == 0);
    }
    // If exact ticket cancellation loses identity, retain mapped ownership and
    // quarantine instead of freeing a slot whose state can no longer be proven.
    {
        Fixture f; gDeadlineClockNs = 7000000ULL;
        ownerChangeQidAfterTicketArm = true;
        ownerQidAfterTicketArm = 13;
        const unsigned id = gNextMbufId;
        const unsigned marks = gDoorbellMarkCalls, bells = gDoorbells;
        assert(submitDeadline(f, 5000, 6000, 17) == ETIMEDOUT);
        assert(gDoorbellMarkCalls == marks && gDoorbells == bells &&
               f.context.state == TahoeP2PActionTxState::kQuarantined &&
               f.context.nativeDataToken == 0xabc &&
               f.context.completion.snapshot().armed &&
               gFreedById[id] == 0 && f.ring()->data[0].m != nullptr &&
               f.lease.outstanding == 1 && f.lease.submissionBusy);
        // No mark/MMIO happened; host-only teardown can now release the buffer.
        testCleanupAfterProvenDrain(f);
    }
    // Invalid/partial windows fail before queue reservation and ticket arm.
    {
        Fixture f; gDeadlineClockNs = 5200000ULL;
        gResidentEnabled = true; std::memcpy(gResidentAddress, kSource, 6);
        f.owner.nativeP2pProbeGeneration_ = 55;
        const unsigned marks = gDoorbellMarkCalls;
        gNativeInFlightToken = 0xabc;
        mbuf_t frame = makeDeadlineNativeFrame(); const unsigned id = frame->id;
        const int result = iwx_tahoe_p2p_action_tx_submit(&f.owner, &f.owner.com,
            &f.lease, &f.context, 55, true, false, frame, 0xabc, nullptr,
            5000, 0, 13, nullptr);
        NativeAwdlBSD::submitted(0xabc, result);
        assert(result == EINVAL);
        assert(gFreedById[id] == 1 && f.lease.outstanding == 0 &&
               f.ring()->queued == 0 && gDoorbellMarkCalls == marks);
    }
    {
        Fixture f; gDeadlineClockNs = 5200000ULL;
        const unsigned marks = gDoorbellMarkCalls;
        assert(submitDeadline(f, 6000, 5000, 18) == EINVAL);
        assert(f.lease.outstanding == 0 && f.ring()->queued == 0 &&
               gDoorbellMarkCalls == marks &&
               f.context.state == TahoeP2PActionTxState::kIdle);
    }
    {
        Fixture f; gDeadlineClockNs = 5200000ULL;
        const unsigned marks = gDoorbellMarkCalls;
        assert(submitDeadline(f, 5000, 6000, 0) == EINVAL);
        assert(f.lease.outstanding == 0 && f.ring()->queued == 0 &&
               gDoorbellMarkCalls == marks &&
               f.context.state == TahoeP2PActionTxState::kIdle);
    }
    {
        Fixture f; gDeadlineClockNs = 5200000ULL;
        const unsigned marks = gDoorbellMarkCalls;
        assert(submitDeadline(f, 5000, 6000, 19, 0) == EINVAL);
        assert(f.lease.outstanding == 0 && f.ring()->queued == 0 &&
               gDoorbellMarkCalls == marks &&
               f.context.state == TahoeP2PActionTxState::kIdle);
    }
    // Queue-cancel ambiguity is quarantined, and ownership is released once.
    {
        Fixture f; gDeadlineClockNs = 7000000ULL;
        const unsigned frees = gMbufFrees, marks = gDoorbellMarkCalls,
                       bells = gDoorbells;
        gQueueCancelResult = EIO;
        assert(submitDeadline(f, 5000, 6000, 14) == EIO);
        gQueueCancelResult = 0;
        assert(f.context.state == TahoeP2PActionTxState::kQuarantined &&
               gMbufFrees == frees + 1 && gDoorbellMarkCalls == marks &&
               gDoorbells == bells && f.lease.outstanding == 1 &&
               f.lease.submissionBusy);
    }
    // A failed mark remains a no-MMIO cancellation; a valid mark issues once.
    {
        Fixture f; gDeadlineClockNs = 5300000ULL;
        const unsigned bells = gDoorbells;
        gDoorbellMarkResult = EIO;
        assert(submitDeadline(f, 5000, 6000, 15) == EIO);
        gDoorbellMarkResult = 0;
        assert(gDoorbells == bells && f.ring()->cur == 0 &&
               f.ring()->queued == 0 && f.lease.outstanding == 0 &&
               f.context.state == TahoeP2PActionTxState::kIdle);
    }
    // Existing callers with default zero window arguments retain legacy submit.
    {
        Fixture f; mbuf_t frame = makeFrame();
        const unsigned bells = gDoorbells;
        assert(iwx_tahoe_p2p_action_tx_submit(&f.owner, &f.owner.com,
            &f.lease, &f.context, 55, true, false, frame, 0, nullptr,
            0, 0, 0, nullptr) == 0);
        assert(gDoorbells == bells + 1 && f.ring()->queued == 1);
        testCleanupAfterProvenDrain(f);
    }
    assert(gNativeTxStale == 0 &&
           gNativeSubmittedFailures == gNativeTxSubmitFailed);
    gResidentEnabled = false;
"""


def main():
    # Extend only the shared extraction harness; production functions remain
    # source-extracted and are compiled with both experiment feature flags.
    shim = modified_shim()
    body = hal.BODY.replace(
        "&owner, &owner.com, &lease, &context, 55, true, false, frame, 0);",
        "&owner, &owner.com, &lease, &context, 55, true, false, "
        "frame, 0, nullptr, 0, 0, 0, nullptr);",
    )
    body = body.replace(
        "int main() {", "int main() {\n" + deadline_tests(), 1)
    # Helpers belong at file scope; insert immediately before the fixture tests.
    body = body.replace(
        "int main() {", native_frame_helper() + "\nint main() {", 1)
    # The prior insertion landed only the cases in main; leave the helper at
    # file scope as a separate inserted declaration.
    with tempfile.TemporaryDirectory(prefix="test064-tx-deadline-") as temp:
        cpp = Path(temp) / "test064_tx_deadline.cpp"
        binary = Path(temp) / "test064_tx_deadline"
        clocks = r"""
static void clock_get_uptime(uint64_t *uptime) { *uptime = gDeadlineClockNs; }
static void absolutetime_to_nanoseconds(uint64_t uptime, uint64_t *ns) {
    *ns = uptime;
}
"""
        cpp.write_text(
            "#define ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332 1\n"
            "#define ITL_NATIVE_AWDL_RESIDENT_25G332 1\n" +
            "#define ITL_NATIVE_AWDL_TX_EVIDENCE_25G332 1\n" +
            shim + "\n" + clocks + "\n" + hal.production_helpers + "\n" +
            hal.production_generic_helpers + "\n" +
            hal.production_functions + "\n" + body
        )
        subprocess.run([
            "c++", "-std=c++14", "-O1", "-g", "-Wall", "-Wextra",
            "-Werror", "-Wno-unused-function", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", "-I", str(ROOT), str(cpp),
            str(ROOT / "native/p2p_action_tx.cpp"),
            str(ROOT / "native/awdl_action_frame.cpp"),
            str(ROOT / "native/awdl_action_encode.cpp"),
            str(ROOT / "native/awdl_mif_encode.cpp"),
            str(ROOT / "native/awdl_data_frame.cpp"),
            str(ROOT / "native/awdl_tx_window_evidence.cpp"),
            "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)

    artifactRoot = ROOT.parent / "IntelWirelessNative"
    sources = [
        ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.hpp",
        ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp",
        Path(__file__),
        HAL_TEST,
        ROOT / "native/p2p_action_tx.cpp",
        ROOT / "native/awdl_data_frame.cpp",
        ROOT / "native/awdl_tx_window_evidence.hpp",
        ROOT / "native/awdl_tx_window_evidence.cpp",
    ]
    report = {
        "test": "Test064 native Action HAL estimated submit-window verification",
        "checks": [
            "half_open_not_before_inclusive_deadline_exclusive",
            "nanosecond_floor_lower_and_ceil_upper_boundaries",
            "outside_window_cancel_before_doorbell",
            "payload_mapping_time_advance_rechecked",
            "station_generation_epoch_change_cancelled",
            "submit_unknown_roc_phase_rejected",
            "exact_ticket_cancel_identity_unknown_quarantined_and_retained",
            "partial_window_rejected_before_queue_or_ticket_prepare",
            "reversed_bounds_missing_station_and_missing_token_rejected",
            "ambiguous_queue_cancel_quarantined_without_double_free",
            "doorbell_mark_failure_remains_no_mmio",
            "legacy_zero_defaults_preserve_submit_behavior",
            "valid_window_issues_exactly_one_doorbell",
            "caller_retires_bridge_token_once_without_stale_failure",
        ],
        "asan_ubsan": {
            "passed": True,
            "source_extracted_production_action_submit": True,
        },
        "source_sha256": {
            str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
            for path in sources
        },
        "proof_boundary": {
            "host_shim_and_simulated_monotonic_clock": True,
            "discovery_resident_and_tx_evidence_feature_flags_compiled": True,
            "legacy_extraction_harness_explicit_zero_token_fix": True,
            "caller_token_retirement_accounted_once": True,
            "macos_kernel_runtime_tested": False,
            "firmware_or_rf_tested": False,
            "peer_receipt_or_airdrop_tested": False,
            "estimated_submit_window_is_not_airtime_proof": True,
            "preemption_after_final_clock_sample_remains_unbounded": True,
        },
    }
    reportPath = artifactRoot / "research/test064-tx-deadline-verification-private.json"
    reportPath.parent.mkdir(parents=True, exist_ok=True)
    reportPath.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    os.chmod(reportPath, 0o600)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
