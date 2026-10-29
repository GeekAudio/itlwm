#!/usr/bin/env python3
"""Compile the production Action HAL and exercise Test070's last-submit fence."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DEADLINE_TEST = ROOT / "native/tests/test064_tx_deadline.py"
spec = importlib.util.spec_from_file_location("test064_tx_deadline", DEADLINE_TEST)
test064 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(test064)
hal = test064.hal
ACTION_SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp"
PROBE_SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"

CONTROL_SUBMIT_TESTS = r"""
static TahoeP2PActionTxControlSubmitFence makeControlFence(
    uint64_t peerRxUs, uint64_t preparedUs, uint64_t effectiveEndUs) {
    TahoeP2PActionTxControlSubmitFence fence{};
    fence.phaseOriginUs = 900000;
    fence.peerMifRxUs = peerRxUs;
    fence.effectiveEndUs = effectiveEndUs;
    fence.preparedFrameUs = preparedUs;
    fence.preparedFrameMaxAgeUs = 10000;
    fence.contextGeneration = 55;
    fence.powerGeneration = 7;
    fence.stationGeneration = 19;
    fence.rocGeneration = 55;
    return fence;
}
static int submitControlFence(Fixture &f,
    TahoeP2PActionTxControlSubmitFence fence) {
    f.owner.nativeP2pProbeGeneration_ = 55;
    f.owner.com.sc_tx_rate_generation = 19;
    mbuf_t frame = makeMifFrame();
    const unsigned id = frame->id;
    const int result = iwx_tahoe_p2p_action_tx_submit(
        &f.owner, &f.owner.com, &f.lease, &f.context, 55, true, false,
        frame, 0, nullptr, 0, 0, 0, &fence);
    if (result != 0)
        assert(gFreedById[id] == 1);
    return result;
}
static void controlSubmitFenceTests() {
    // The actual MIF path has no BSD data token and keeps a management frame.
    {
        Fixture f;
        const uint64_t rx = 1000000;
        gDeadlineClockNs = (rx + 9000) * 1000ULL;
        auto fence = makeControlFence(rx, rx + 8000, rx + 60000);
        const unsigned bells = gDoorbells;
        assert(submitControlFence(f, fence) == 0);
        assert(gDoorbells == bells + 1 && f.ring()->queued == 1);
        assert(f.context.nativeDataToken == 0 &&
               f.ring()->data[0].type == IEEE80211_FC0_TYPE_MGT);
        testCleanupAfterProvenDrain(f);
        assert(gFreedById[gNextMbufId - 1] == 1);
    }
    // An exact 16-TU upper bound passes; one nanosecond beyond it rounds up
    // and is rejected instead of being truncated to the accepted microsecond.
    {
        Fixture f;
        const uint64_t rx = 1000000;
        const uint64_t now = rx + 16ULL * 1024ULL;
        gDeadlineClockNs = now * 1000ULL;
        auto fence = makeControlFence(rx, now - 5000, now + 60000);
        assert(submitControlFence(f, fence) == 0);
        testCleanupAfterProvenDrain(f);
    }
    {
        Fixture f;
        const uint64_t rx = 1000000;
        const uint64_t now = rx + 16ULL * 1024ULL;
        gDeadlineClockNs = now * 1000ULL + 1;
        auto fence = makeControlFence(rx, now - 5000, now + 60000);
        const unsigned marks = gDoorbellMarkCalls, bells = gDoorbells;
        assert(submitControlFence(f, fence) == ETIMEDOUT);
        assert(gDoorbellMarkCalls == marks && gDoorbells == bells &&
               f.ring()->cur == 0 && f.ring()->queued == 0 &&
               f.lease.outstanding == 0 && !f.lease.submissionBusy &&
               !f.context.completion.snapshot().armed &&
               f.context.state == TahoeP2PActionTxState::kIdle &&
               f.context.nativeDataToken == 0);
    }
    // The lease reserve is strict: exactly 20 ms remaining is cancelled;
    // one extra microsecond remains admissible.
    {
        Fixture f;
        const uint64_t now = 2000000;
        gDeadlineClockNs = now * 1000ULL;
        auto fence = makeControlFence(now - 5000, now - 1000,
                                      now + 20000);
        const unsigned bells = gDoorbells;
        assert(submitControlFence(f, fence) == ETIMEDOUT);
        assert(gDoorbells == bells && f.context.nativeDataToken == 0);
    }
    {
        Fixture f;
        const uint64_t now = 2000000;
        gDeadlineClockNs = now * 1000ULL;
        auto fence = makeControlFence(now - 5000, now - 1000,
                                      now + 20001);
        assert(submitControlFence(f, fence) == 0);
        testCleanupAfterProvenDrain(f);
    }
    // Prepared-frame freshness is also checked after DMA mapping: exact max
    // age passes, while ceil(10,000 us + 1 ns) cancels before queue commit.
    {
        Fixture f;
        const uint64_t now = 3000000;
        gDeadlineClockNs = now * 1000ULL;
        auto fence = makeControlFence(now - 12000, now - 10000,
                                      now + 60000);
        assert(submitControlFence(f, fence) == 0);
        testCleanupAfterProvenDrain(f);
    }
    {
        Fixture f;
        const uint64_t now = 3000000;
        gDeadlineClockNs = now * 1000ULL + 1;
        auto fence = makeControlFence(now - 12000, now - 10000,
                                      now + 60000);
        const unsigned bells = gDoorbells;
        assert(submitControlFence(f, fence) == ETIMEDOUT);
        assert(gDoorbells == bells && f.ring()->cur == 0 &&
               f.ring()->queued == 0 && f.lease.outstanding == 0 &&
               f.context.nativeDataToken == 0);
    }
    // A station or ROC epoch change while the descriptor is being prepared
    // is rejected by the same final fence and uses the exact ticket cancel.
    {
        Fixture f;
        const uint64_t now = 4000000;
        gDeadlineClockNs = now * 1000ULL;
        auto fence = makeControlFence(now - 5000, now - 1000,
                                      now + 60000);
        f.cursor.changeRateGenerationOnMap = true;
        f.cursor.rateGenerationAfterMap = 20;
        gRateGenerationToMutate = &f.owner.com.sc_tx_rate_generation;
        const unsigned marks = gDoorbellMarkCalls, bells = gDoorbells;
        assert(submitControlFence(f, fence) == ESTALE);
        assert(gDoorbellMarkCalls == marks && gDoorbells == bells &&
               f.context.state == TahoeP2PActionTxState::kIdle &&
               f.context.nativeDataToken == 0 && f.ring()->queued == 0 &&
               f.lease.outstanding == 0 &&
               !f.context.completion.snapshot().armed);
    }
    {
        Fixture f;
        const uint64_t now = 4000000;
        gDeadlineClockNs = now * 1000ULL;
        auto fence = makeControlFence(now - 5000, now - 1000,
                                      now + 60000);
        f.cursor.rocPhaseToChange = &f.owner.com.sc_p2p_roc.phase;
        f.cursor.rocPhaseAfterMap = IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN;
        const unsigned marks = gDoorbellMarkCalls, bells = gDoorbells;
        assert(submitControlFence(f, fence) == ESTALE);
        assert(gDoorbellMarkCalls == marks && gDoorbells == bells &&
               f.context.state == TahoeP2PActionTxState::kIdle &&
               f.context.nativeDataToken == 0 && f.ring()->queued == 0 &&
               f.lease.outstanding == 0);
    }
    // Invalid or mismatched caller snapshots are rejected before begin_tx.
    {
        Fixture f;
        const uint64_t now = 5000000;
        gDeadlineClockNs = now * 1000ULL;
        auto fence = makeControlFence(now - 5000, now - 1000,
                                      now + 60000);
        fence.rocGeneration = 56;
        const unsigned marks = gDoorbellMarkCalls;
        assert(submitControlFence(f, fence) == EINVAL);
        assert(gDoorbellMarkCalls == marks && f.lease.outstanding == 0 &&
               f.ring()->queued == 0 && f.context.nativeDataToken == 0);
    }
}
"""


def main():
    action_source = ACTION_SOURCE.read_text(encoding="utf-8")
    probe_source = PROBE_SOURCE.read_text(encoding="utf-8")
    action_submit = hal.extract_function(
        action_source, "int iwx_tahoe_p2p_action_tx_submit(")
    assert "estimatedDeadlineUs > estimatedNotBeforeUs && nativeDataToken != 0" in action_submit
    assert action_submit.index("owner->iwx_tx_update_byte_tbl(") < \
           action_submit.index("if (controlSubmitFence) {") < \
           action_submit.index("ring->cur = (index + 1) % ring->ring_count")
    fence_check = action_submit[action_submit.index("if (controlSubmitFence) {"):
        action_submit.index("ring->cur = (index + 1) % ring->ring_count")]
    assert "context->completion.cancelUnsubmitted(" in fence_check
    assert "cancelBeforeDoorbell(" in fence_check
    assert "kControlSubmitFence" in fence_check
    assert "bootstrapSubmitFence.peerMifRxUs =" in probe_source
    assert "bootstrapSubmitFence.preparedFrameUs = probe->mifCandidate.sampleUs" in probe_source
    assert "bootstrapSubmitFence.contextGeneration =" in probe_source
    assert "bootstrapSubmitFence.powerGeneration =" in probe_source
    assert "bootstrapSubmitFence.stationGeneration =" in probe_source
    assert "bootstrapSubmitFence.rocGeneration =" in probe_source
    assert "0, 0, 0, bootstrapSubmitFencePointer" in probe_source

    shim = test064.modified_shim()
    body = hal.BODY.replace(
        "&owner, &owner.com, &lease, &context, 55, true, false, frame, 0);",
        "&owner, &owner.com, &lease, &context, 55, true, false, "
        "frame, 0, nullptr, 0, 0, 0, nullptr);",
    )
    body = body.replace(
        "int main() {", "int main() {\n" + test064.deadline_tests() +
        "\ncontrolSubmitFenceTests();", 1)
    body = body.replace(
        "int main() {", "\n" + test064.native_frame_helper() +
        "\n" + CONTROL_SUBMIT_TESTS + "\nint main() {", 1)

    with tempfile.TemporaryDirectory(prefix="test070-control-submit-fence-") as temp:
        cpp = Path(temp) / "test070_control_submit_fence.cpp"
        binary = Path(temp) / "test070_control_submit_fence"
        clocks = r"""
static void clock_get_uptime(uint64_t *uptime) { *uptime = gDeadlineClockNs; }
static void absolutetime_to_nanoseconds(uint64_t uptime, uint64_t *ns) {
    *ns = uptime;
}
"""
        cpp.write_text(
            "#define ITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332 1\n"
            "#define ITL_NATIVE_AWDL_RESIDENT_25G332 1\n"
            "#define ITL_NATIVE_AWDL_TX_EVIDENCE_25G332 1\n" +
            shim + "\n" + clocks + "\n" + hal.production_helpers + "\n" +
            hal.production_generic_helpers + "\n" + hal.production_functions +
            "\n" + body
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
    print("PASS: production Action submit fence, 16-TU rounding, prepared-age and lease bounds, epoch recheck, exact cancel, no synthetic BSD token, and legacy deadline regressions under ASan/UBSan")


if __name__ == "__main__":
    main()
