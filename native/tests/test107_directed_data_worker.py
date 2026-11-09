#!/usr/bin/env python3
"""Check Test107 worker failure reporting and retirement contracts.

The policy classifier is compiled from the production source. The remaining
checks bind the worker's fault/retire ordering to the actual HAL and queue APIs;
this is a source-contract test, not a hardware TX simulation.
"""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PROBE_PATH = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
SOURCE = PROBE_PATH.read_text()
ACTION_SOURCE = (ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp").read_text()


def extract(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


stage_enum = extract(SOURCE, "enum DirectedDataStage : uint32_t {")
failure_classifier = extract(
    SOURCE, "struct DirectedDataFailureDisposition {")
failure_function = extract(
    SOURCE, "static DirectedDataFailureDisposition directedDataFailureDisposition(")

fixture = r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
""" + stage_enum + ";\n" + failure_classifier + ";\n" + failure_function + r"""
int main() {
    const auto cleaned = directedDataFailureDisposition(EIO, true);
    assert(cleaned.stage == kDirectedDataFailedCleaned);
    assert(cleaned.dataResult == EIO);
    assert(cleaned.workerResult == 0);
    assert(cleaned.cleanupAck && cleaned.resourcesAbsent);

    const auto timeout = directedDataFailureDisposition(ETIMEDOUT, true);
    assert(timeout.stage == kDirectedDataFailedCleaned);
    assert(timeout.dataResult == ETIMEDOUT);
    assert(timeout.workerResult == 0);

    const auto retained = directedDataFailureDisposition(EIO, false);
    assert(retained.stage == kDirectedDataQuarantined);
    assert(retained.dataResult == EIO);
    assert(retained.workerResult == EIO);
    assert(!retained.cleanupAck && !retained.resourcesAbsent);

    const auto invalid = directedDataFailureDisposition(0, false);
    assert(invalid.stage == kDirectedDataQuarantined);
    assert(invalid.dataResult == EIO && invalid.workerResult == EIO);
}
"""
with tempfile.TemporaryDirectory(prefix="test107-data-worker-") as tmp:
    source = Path(tmp) / "failure_disposition.cpp"
    binary = Path(tmp) / "failure_disposition"
    source.write_text(fixture)
    compiled = subprocess.run(
        ["c++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         str(source), "-o", str(binary)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if compiled.returncode:
        raise SystemExit(compiled.stdout)
    subprocess.run([str(binary)], check=True)


worker = extract(SOURCE, "static int exerciseDirectedDataTx(P2PProbeRun *probe)")
worker_flat = " ".join(worker.split())
roc_action = extract(SOURCE, "IOReturn ItlIwx::tahoeP2pRocEventAction(")
roc_action_flat = " ".join(roc_action.split())
failure_path = extract(
    worker, "auto recordFailure = [&](int error, uint32_t stage) {")
assert "directedDataCheckInnerCleanup(probe)" in failure_path
assert "directedDataFailureDisposition(error, absent)" in failure_path
assert "return disposition.workerResult;" in failure_path
assert "kDirectedDataQuarantined" in SOURCE

# Keep the first local failure (for example malformed BSD MPDU / rejected
# permit) across later END polling and teardown. A safe cleanup is generic
# completion only; DataResult remains the original errno.
assert "auto rememberPreSubmitFailure = [&](int error)" in worker
assert "rememberPreSubmitFailure(failure);" in worker
assert "preSubmitFailure != 0 ? preSubmitFailure : ETIMEDOUT" in worker
assert "probe->directedDataResult = failure;" in worker

# A submitted mbuf transfers ownership exactly once to HAL. This path cannot
# retry, free, or resubmit it after the call.
submit = "iwx_tahoe_p2p_directed_data_tx_submit("
assert worker.count(submit) == 1
after_submit = worker[worker.index(submit):]
assert "mbuf_freem(encodedMpdu)" not in after_submit
assert "iwx_tahoe_p2p_directed_data_tx_submit(" not in after_submit[len(submit):]

# Normal retirement waits for exact firmware station removal and ring drain;
# an unarmed path is eligible only after canonical END and the HAL never-armed
# proof. Unknown doorbell/completion state returns through quarantine.
remove = worker.index("iwx_tahoe_p2p_tvqm_remove(")
drained = worker.index("iwx_tahoe_p2p_tvqm_confirm_drained(", remove)
assert remove < drained
assert "iwx_tahoe_p2p_directed_data_never_armed(" in worker
assert "iwx_tahoe_p2p_tvqm_abort_idle_after_end(" in worker
assert "&owner->nativeP2pTxQueue_, sessionEnded, neverArmed," in worker
assert "if (finalData.doorbellIssued && !finalData.completionObserved)" in worker
assert "if (!endWaitSatisfied)" in worker
assert "if (!data.doorbellIssued || data.completionObserved)" in worker
assert "if (data.state == TahoeP2PDirectedDataState::kQuarantined)" in worker
assert "if (finalData.state == TahoeP2PDirectedDataState::kQuarantined)" in worker

# Stage 8 requires successful local firmware completion and complete cleanup.
# Completion is explicitly not presented as a peer ACK.
assert "!finalData.completionObserved || !finalData.frameAttemptSucceeded" in worker_flat
assert "probe->directedDataInnerCleanupProven =" in worker
assert "if (!probe->directedDataInnerCleanupProven)" in worker
assert "deferDirectedDataTerminal(owner, probe, failure == 0 ?" in worker
finish = extract(SOURCE, "IOReturn ItlIwx::tahoeP2pFinishAction(")
assert "NativeP2PDirectedCompleteCleanup::outerProofComplete(proof)" in finish
assert "directedDataFinalResourcesAbsent(owner, run)" in finish
assert "nativeP2pDirectedDataTx_.completion.snapshot()" not in worker
assert "nativeP2pDirectedDataTx_.state" not in worker
assert "owner, &owner->nativeP2pDirectedDataTx_, &finalData" in worker_flat
assert '"NativeP2PDirectedDataFirmwareAttemptSucceeded"' in SOURCE
assert '"NativeP2PDirectedDataPeerAcknowledged"' not in SOURCE
for field in ("HalState", "HalReason", "QueueId", "StationId",
              "DescriptorIndex", "FrameControl", "SequenceControl",
              "ByteCount", "ExpectedNextSsn"):
    assert f'"NativeP2PDirectedData{field}"' in SOURCE
for field in ("PeerMAC", "LocalIPv6", "Nonce", "RunToken"):
    assert f'"NativeP2PDirectedData{field}"' not in SOURCE

for helper_marker in (
        "static void publishDirectedDataState(",
        "static bool directedDataStationQueueDataAbsent(",
        "static bool directedDataHasNoDoorbell("):
    helper = extract(SOURCE, helper_marker)
    assert "iwx_tahoe_p2p_directed_data_snapshot(" in helper
    assert "nativeP2pDirectedDataTx_.completion.snapshot()" not in helper

# Ready's window witness reads the canonical HAL binding inside the ROC main
# gate. The arm-time probe copy remains useful only for the original identity.
assert "readyOriginWindowCurrent( originWindow)" in roc_action_flat
assert "originWindow.canonicalBinding.rocStartUs=canonical.rocStartUs" in roc_action_flat
assert "originWindow.armBinding.rocStartUs= probe->directedDataBinding.rocStartUs" in roc_action_flat
assert "probe->directedDataBinding.rocStartUs==rxLease.startUs" not in roc_action_flat
assert "originWindow.contextTicket=&halData.originTicket" in roc_action_flat
assert "originWindow.probeTicket=&probe->directedDataOriginTicket" in roc_action_flat
arm_callback = extract(SOURCE, "static bool tahoeP2pArmDirectedDataRoc(")
hal_arm = extract(ACTION_SOURCE, "int iwx_tahoe_p2p_directed_data_arm(")
window_bind = extract(
    ACTION_SOURCE, "static IOReturn directedDataBindOriginWindowAction(")
ticket_bind = extract(
    ACTION_SOURCE, "static IOReturn directedDataBindOriginTicketAction(")
assert "probe->directedDataBinding = run.binding;" in arm_callback
assert "*bindingOut = context->binding;" in hal_arm
assert "rocStartUs" not in hal_arm
assert "context->binding.rocStartUs = action->rocStartUs;" in window_bind
assert "context->binding.deadlineUs = action->deadlineUs;" in window_bind
assert "context->originWindowBound = true;" in window_bind
assert "probe->directedDataBinding" not in window_bind
assert "context->state = TahoeP2PDirectedDataState::kTicketBound;" in ticket_bind
assert "context->ticketBound = true;" in ticket_bind
assert "context->originClosed = false;" in ticket_bind

# A confirmed END with no published Ready must enter the same gated cleanup as
# other started-session failures, not fall through to the pre-session label.
not_ready_end = extract(worker, "if (!started) {")
assert "directedDataSessionEndConfirmed(event.snapshot" in not_ready_end
assert "return failStartedSessionCleanly(failure," in not_ready_end
assert "FailureSite::EndWait" in not_ready_end
assert "sessionEnded = true;" not in not_ready_end
assert worker.index("return failStartedSessionCleanly(failure,") < worker.index(
    "cleanup_before_session:")
started_cleanup = extract(
    worker, "auto failStartedSessionCleanly = [&](\n")
assert "directedDataCleanupCheckAction" in started_cleanup
assert "directedDataHasNoDoorbell(owner,&noDoorbellCheck)" in started_cleanup
assert "iwx_tahoe_p2p_tvqm_abort_idle_after_end(" in started_cleanup
assert "iwx_tahoe_p2p_tvqm_abort_idle_no_session(" not in started_cleanup

assert "iwx_tahoe_p2p_directed_data_never_armed( owner," in worker_flat

# ROC submission runs outside the command gate. HAL arm mutates the shared
# Data Context only on the main gate, so the ROC arm callback must marshal the
# short arm action before returning to the caller that sends the firmware
# command. The firmware command itself must remain outside that gate action.
arm_action = extract(SOURCE, "static IOReturn directedDataArmAction(")
arm_callback = extract(SOURCE, "static bool tahoeP2pArmDirectedDataRoc(")
assert "owner->tahoeP2pOnMainGate()" in arm_action
assert "iwx_tahoe_p2p_directed_data_arm(" in arm_action
assert "gate->runAction(directedDataArmAction, &run)" in arm_callback
assert "iwx_tahoe_p2p_directed_data_arm(" not in arm_callback
assert "tahoeP2pRocSubmit(" not in arm_action

print("Test107 directed data worker failure/retire contract passed")
