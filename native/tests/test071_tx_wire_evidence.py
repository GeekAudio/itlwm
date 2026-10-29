#!/usr/bin/env python3
"""Test final-frame TX wire evidence through submit/cancel/completion paths."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HAL_TEST = ROOT / "native/tests/test_iwx_p2p_action_hal.py"
DEADLINE_TEST = ROOT / "native/tests/test064_tx_deadline.py"
ACTION = ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp"
ARTIFACT = ROOT.parent / "IntelWirelessNative/research/test071-tx-wire-evidence-private.json"


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


hal = load_module(HAL_TEST, "test071_action_hal")
deadline = load_module(DEADLINE_TEST, "test071_tx_deadline")


WIRE_CASES = r"""
    // The caller refreshes the already encoded PSF before submitting it. The
    // HAL must export fields parsed from this final mbuf and retain them over
    // the matching firmware completion.
    {
        Fixture f;
        gDeadlineClockNs = 5200000ULL;
        mbuf_t frame = makePsfFrame();
        put16(frame->bytes.data() + 22, 0x6780); // refreshed sequence control
        put32(frame->bytes.data() + 32, 0);       // zero is present, not absent
        put32(frame->bytes.data() + 36, 0x12345678);
        const uint16_t mpduLength = static_cast<uint16_t>(frame->length);

        TahoeP2PActionTxSubmitMetadata metadata{};
        metadata.diagnosticGeneration = 55;
        metadata.epoch.contextGeneration = 55;
        metadata.epoch.powerGeneration = 7;
        metadata.epoch.stationGeneration = 9;
        metadata.epoch.rocGeneration = 55;
        metadata.frameKind = NativeAwdlTxWindowEvidence::FrameKind::Psf;
        metadata.frameOrdinal = 1;
        assert(iwx_tahoe_p2p_action_tx_submit(&f.owner, &f.owner.com,
            &f.lease, &f.context, 55, true, false, frame, 0, &metadata,
            0, 0, 0, nullptr) == 0);

        NativeAwdlTxWindowEvidence::TicketSnapshot prepared{};
        assert(f.context.windowEvidence.ledger.snapshotTicket(0, &prepared));
        assert(prepared.used && prepared.identity.ticketToken != 0);
        assert(prepared.identity.frameSequenceControl == 0x6780);
        assert(prepared.identity.epoch.contextGeneration == 55 &&
               prepared.identity.epoch.powerGeneration == 7 &&
               prepared.identity.epoch.stationGeneration == 9 &&
               prepared.identity.epoch.rocGeneration == 55);
        assert(prepared.identity.queueId == 12 &&
               prepared.identity.ringSize == 8 &&
               prepared.identity.descriptorIndex == 0);
        assert(prepared.identity.wireInfoPresent == 1 &&
               prepared.identity.wireSubtype == 0 &&
               prepared.identity.wireMpduLength == mpduLength);
        assert(prepared.identity.wirePhyTxPresent == 1 &&
               prepared.identity.wirePhyTxUs == 0);
        assert(prepared.identity.wireTargetTxPresent == 1 &&
               prepared.identity.wireTargetTxUs == 0x12345678);

        iwx_rx_packet response{};
        makeResponse(response, 12, 0x6780, 1, mpduLength, 0x00d0, 1);
        assert(dispatch(f, response));
        NativeAwdlTxWindowEvidence::TicketSnapshot completed{};
        assert(f.context.windowEvidence.ledger.snapshotTicket(0, &completed));
        assert(completed.completed &&
               completed.identity.ticketToken == prepared.identity.ticketToken);
        assert(completed.identity.wireInfoPresent == 1 &&
               completed.identity.wireSubtype == 0 &&
               completed.identity.wireMpduLength == mpduLength &&
               completed.identity.wirePhyTxPresent == 1 &&
               completed.identity.wirePhyTxUs == 0 &&
               completed.identity.wireTargetTxPresent == 1 &&
               completed.identity.wireTargetTxUs == 0x12345678);
    }

    // Cancellation after the TX ticket is armed discards the pending wire
    // annotation with that exact ticket and does not leave a ledger record.
    {
        Fixture f;
        gDeadlineClockNs = 30000000ULL; // outside the valid MIF freshness span
        f.owner.nativeP2pProbeGeneration_ = 55;
        f.owner.com.sc_tx_rate_generation = 9;
        mbuf_t frame = makePsfFrame();
        put32(frame->bytes.data() + 32, 0x87654321);
        put32(frame->bytes.data() + 36, 0);

        TahoeP2PActionTxSubmitMetadata metadata{};
        metadata.diagnosticGeneration = 55;
        metadata.epoch.contextGeneration = 55;
        metadata.epoch.powerGeneration = 7;
        metadata.epoch.stationGeneration = 9;
        metadata.epoch.rocGeneration = 55;
        metadata.frameKind = NativeAwdlTxWindowEvidence::FrameKind::Psf;
        metadata.frameOrdinal = 2;
        TahoeP2PActionTxControlSubmitFence fence{};
        fence.phaseOriginUs = 1000;
        fence.peerMifRxUs = 2000;
        fence.preparedFrameUs = 3000;
        fence.preparedFrameMaxAgeUs = 9000;
        fence.effectiveEndUs = 1000000;
        fence.contextGeneration = 55;
        fence.powerGeneration = 7;
        fence.stationGeneration = 9;
        fence.rocGeneration = 55;
        const unsigned marks = gDoorbellMarkCalls;
        assert(iwx_tahoe_p2p_action_tx_submit(&f.owner, &f.owner.com,
            &f.lease, &f.context, 55, true, false, frame, 0, &metadata,
            0, 0, 0, &fence) == ETIMEDOUT);
        assert(gDoorbellMarkCalls == marks && f.ring()->queued == 0 &&
               f.lease.outstanding == 0 &&
               !f.context.completion.snapshot().armed);
        assert(!f.context.windowEvidence.pendingTicketPrepared &&
               !f.context.windowEvidence.pendingIdentityValid &&
               f.context.windowEvidence.pendingIdentity.ticketToken == 0 &&
               f.context.windowEvidence.pendingIdentity.wireInfoPresent == 0 &&
               f.context.windowEvidence.pendingIdentity.wirePhyTxPresent == 0 &&
               f.context.windowEvidence.pendingIdentity.wireTargetTxPresent == 0);
        NativeAwdlTxWindowEvidence::TicketSnapshot absent{};
        assert(!f.context.windowEvidence.ledger.snapshotTicket(0, &absent));
    }

    // A final MIF remains distinguishable from PSF, including a present-zero
    // target timestamp. The values are still only local wire-header evidence.
    {
        Fixture f;
        gDeadlineClockNs = 6200000ULL;
        mbuf_t frame = makeMifFrame();
        put32(frame->bytes.data() + 32, 0xabcdef01);
        put32(frame->bytes.data() + 36, 0);
        const uint16_t mpduLength = static_cast<uint16_t>(frame->length);
        TahoeP2PActionTxSubmitMetadata metadata{};
        metadata.diagnosticGeneration = 55;
        metadata.epoch.contextGeneration = 55;
        metadata.epoch.powerGeneration = 7;
        metadata.epoch.stationGeneration = 9;
        metadata.epoch.rocGeneration = 55;
        metadata.frameKind = NativeAwdlTxWindowEvidence::FrameKind::Mif;
        metadata.frameOrdinal = 3;
        assert(iwx_tahoe_p2p_action_tx_submit(&f.owner, &f.owner.com,
            &f.lease, &f.context, 55, true, false, frame, 0, &metadata,
            0, 0, 0, nullptr) == 0);
        NativeAwdlTxWindowEvidence::TicketSnapshot mif{};
        assert(f.context.windowEvidence.ledger.snapshotTicket(0, &mif));
        assert(mif.used && mif.identity.frameKind ==
               NativeAwdlTxWindowEvidence::FrameKind::Mif);
        assert(mif.identity.wireInfoPresent == 1 &&
               mif.identity.wireSubtype == 3 &&
               mif.identity.wireMpduLength == mpduLength &&
               mif.identity.wirePhyTxPresent == 1 &&
               mif.identity.wirePhyTxUs == 0xabcdef01 &&
               mif.identity.wireTargetTxPresent == 1 &&
               mif.identity.wireTargetTxUs == 0);
        testCleanupAfterProvenDrain(f);
    }
"""


def main():
    action_source = ACTION.read_text()
    assert action_source.count("NativeAwdl::parseActionFrame(") == 1
    assert "identity.wireInfoPresent = 1;" in action_source
    assert "identity.wirePhyTxPresent = 1;" in action_source
    assert "identity.wireTargetTxPresent = 1;" in action_source

    body = hal.BODY
    body = body.replace(
        "&owner, &owner.com, &lease, &context, 55, true, false, frame, 0);",
        "&owner, &owner.com, &lease, &context, 55, true, false, "
        "frame, 0, nullptr, 0, 0, 0, nullptr);")
    end = body.rfind("\n}")
    assert end >= 0
    body = body[:end] + "\n" + WIRE_CASES + body[end:]
    body = body.replace(
        "int main() {", "int main() {\n" + deadline.deadline_tests(), 1)
    body = body.replace(
        "int main() {", deadline.native_frame_helper() + "\nint main() {", 1)

    with tempfile.TemporaryDirectory(prefix="test071-tx-wire-") as temp:
        source = Path(temp) / "test071_tx_wire.cpp"
        binary = Path(temp) / "test071_tx_wire"
        clocks = r"""
static void clock_get_uptime(uint64_t *uptime) { *uptime = gDeadlineClockNs; }
static void absolutetime_to_nanoseconds(uint64_t uptime, uint64_t *ns) {
    *ns = uptime;
}
"""
        source.write_text(
            "#define ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332 1\n"
            "#define ITL_NATIVE_AWDL_RESIDENT_25G332 1\n"
            "#define ITL_NATIVE_AWDL_TX_EVIDENCE_25G332 1\n" +
            deadline.modified_shim() + "\n" + clocks + "\n" +
            hal.production_helpers + "\n" +
            hal.production_generic_helpers + "\n" +
            hal.production_functions + "\n" + body
        )
        subprocess.run([
            "c++", "-std=c++14", "-O1", "-g", "-Wall", "-Wextra",
            "-Werror", "-Wno-unused-function", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", "-I", str(ROOT), str(source),
            str(ROOT / "native/p2p_action_tx.cpp"),
            str(ROOT / "native/awdl_action_frame.cpp"),
            str(ROOT / "native/awdl_action_encode.cpp"),
            str(ROOT / "native/awdl_mif_encode.cpp"),
            str(ROOT / "native/awdl_data_frame.cpp"),
            str(ROOT / "native/awdl_tx_window_evidence.cpp"),
            "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)

    # Ensure the wire fields remain usable in a freestanding/kernel-style TU.
    with tempfile.TemporaryDirectory(prefix="test071-tx-wire-tu-") as temp:
        source = Path(temp) / "identity.cpp"
        source.write_text(
            '#include "native/awdl_tx_window_evidence.hpp"\n'
            'int main() { NativeAwdlTxWindowEvidence::TicketIdentity id{}; '
            'id.wireInfoPresent = 1; id.wirePhyTxPresent = 1; '
            'return id.wirePhyTxUs == 0 ? 0 : 1; }\n'
        )
        subprocess.run([
            "c++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
            "-fno-exceptions", "-fno-rtti", "-fsyntax-only", "-I",
            str(ROOT), str(source),
        ], check=True)

    # Compile and run the pre-existing action HAL harness without any Test070/071
    # feature defines; this exercises the ordinary macro-off production path.
    subprocess.run([sys.executable, str(HAL_TEST)], check=True)

    files = [ROOT / "native/awdl_tx_window_evidence.hpp",
             ACTION, Path(__file__),
             HAL_TEST, DEADLINE_TEST,
             ROOT / "native/p2p_action_tx.cpp",
             ROOT / "native/awdl_action_frame.cpp",
             ROOT / "native/awdl_tx_window_evidence.cpp"]
    report = {
        "schema": "test071-tx-wire-evidence-v1",
        "scope": "final prepared PSF/MIF metadata and exact ticket lifecycle",
        "freeze": {
            "production_sources": [
                "native/awdl_tx_window_evidence.hpp",
                "itlwm/hal_iwx/ItlIwxP2PAction.cpp",
            ],
            "focused_fixture": "native/tests/test071_tx_wire_evidence.py",
            "probe_publisher": "owned by core agent; outside this source freeze",
            "deployment": False,
        },
        "asan_ubsan_passed": True,
        "kernel_style_macro_off_tu_passed": True,
        "ordinary_action_hal_macro_off_passed": True,
        "source_sha256": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in files
        },
        "cases": [
            "refreshed PSF sequence and zero-present PHY plus target timestamp",
            "wire subtype, MPDU length, epochs, qid, ring and descriptor identity",
            "local matched completion preserves exact immutable wire fields",
            "exact pre-doorbell cancellation clears pending wire metadata and leaves no ticket",
            "refreshed MIF subtype 3 and zero-present target timestamp",
            "source guard confirms one production AWDL parse call; annotation is not an admission condition",
        ],
        "limits": [
            "the TX wire fields do not alter native RX event timeline or queue semantics",
            "host shim only; no driver deployment, RF capture, peer receipt or AirDrop proof",
            "wire timestamps are parsed header fields, not verified airtime",
        ],
    }
    ARTIFACT.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    ARTIFACT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    ARTIFACT.chmod(0o600)
    print("PASS: Test071 TX wire evidence submit/cancel/completion under ASan/UBSan")
    print("PASS: macro-off kernel-style ticket identity syntax compile")
    print(ARTIFACT)


if __name__ == "__main__":
    main()
