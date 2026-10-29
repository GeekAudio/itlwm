#!/usr/bin/env python3
"""Test069 candidate pinning, tracker tombstones, and production contracts."""
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROBE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
PACING = ROOT / "native/awdl_mif_pacing.hpp"
TRACKER = ROOT / "native/p2p_action_tx.cpp"
TRACKER_HEADER = ROOT / "native/p2p_action_tx.hpp"
ADMISSION = ROOT / "native/awdl_mif_current_admission_test069.hpp"
POLICY_TEST = ROOT / "native/tests/awdl_mif_current_admission_test069.cpp"


def function_body(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and following == "/":
                state = "code"
                index += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif ((state == "string" and char == '"') or
                  (state == "char" and char == "'")):
                state = "code"
        elif char == "/" and following == "/":
            state = "line_comment"
            index += 1
        elif char == "/" and following == "*":
            state = "block_comment"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "char"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
        index += 1
    raise AssertionError(f"Unclosed C++ body: {signature}")


source = PROBE.read_text(encoding="utf-8")
pacing_source = PACING.read_text(encoding="utf-8")
tracker = TRACKER.read_text(encoding="utf-8")
tracker_header = TRACKER_HEADER.read_text(encoding="utf-8")
admission = ADMISSION.read_text(encoding="utf-8")
mif = function_body(source, "static mbuf_t takeDiscoveryPacketMifCurrent(")
capture = function_body(source, "static bool captureP2PTxSnapshot(")
peer_failure = function_body(source, "static NativeAwdlDiscoveryBinding::Decision mifCurrentPeerFailure(")
decision_blocker = function_body(source, "static uint32_t mifCurrentDecisionBlocker(")
policy_selector = function_body(source, "static NativeAwdlProbe::MifPacingPolicy mifPacingPolicyForProbe(")
pacing_input_builder = function_body(source, "static NativeAwdlProbe::MifPacingInput makeMifPacingInput(")
cheap_gate = function_body(source, "static bool tryPrepareMifAtPacingPoint(")
refresh_gate = function_body(source, "static NativeAwdlProbe::MifPacingPlan refreshMifPacingAnchorInGate(")
final_gate_policy = function_body(source, "static NativeAwdlProbe::MifPacingPlan finalCheckMifPacingAnchorInGate(")

# Capture uses one native TX lock for lifecycle, completion ticket, and ring
# indices, so the idle predicate does not combine unrelated snapshots.
lock_at = capture.index("IOSimpleLockLockDisableInterrupt")
queue_at = capture.index("lifecycle.snapshot()")
ticket_at = capture.index("completion.snapshot()")
ring_at = capture.index("ring->queued")
unlock_at = capture.index("IOSimpleLockUnlockEnableInterrupt")
assert lock_at < queue_at < ticket_at < ring_at < unlock_at

# Real Tracker completion keeps armed=true as a tombstone; re-arming requires
# the old ticket to be completed. No test-only mirrored state is substituted.
arm = function_body(tracker, "Result CompletionTracker::arm(")
complete = function_body(tracker, "Result CompletionTracker::complete(")
cancel = function_body(tracker, "Result CompletionTracker::cancelUnsubmitted(")
drain = function_body(tracker, "Result CompletionTracker::firmwareDrained(")
assert "ticket_.armed && !ticket_.completed" in arm
assert "ticket_.completed = true;" in complete
assert "ticket_.armed = false" not in complete
assert "memset(&ticket_, 0, sizeof(ticket_));" in cancel
assert "memset(&ticket_, 0, sizeof(ticket_));" in drain
assert "bool armed;" in tracker_header and "bool completed;" in tracker_header

# The MIF-current ring gate keeps all physical-ownership checks and requires a
# completed ticket while accepting its armed completion tombstone.
ring_start = mif.index("const bool ringIdle = txSnapshotValid")
ring_end = mif.index("NativeAwdlBSD::DiscoveryTxSnapshot secondHead", ring_start)
ring_gate = mif[ring_start:ring_end]
for required in (
        "txSnapshot.queueLeaseActive", "txSnapshot.txRingEmpty",
        "txSnapshot.ringIndicesConsistent", "txSnapshot.outstandingTx == 0",
        "TahoeP2PActionTxState::kIdle",
        "completedTicketHasNoInflight(\n            txSnapshot.ticketArmed, txSnapshot.ticketCompleted)"):
    assert required in ring_gate, required
assert "!txSnapshot.ticketArmed" not in ring_gate

final_start = mif.index("const bool finalRingIdle = finalTxValid")
final_end = mif.index("IntelAwdlPeerRuntime::PsfPeerSnapshot finalPeer", final_start)
final_gate = mif[final_start:final_end]
for required in (
        "finalTx.queueLeaseActive", "finalTx.txRingEmpty",
        "finalTx.ringIndicesConsistent", "finalTx.outstandingTx == 0",
        "TahoeP2PActionTxState::kIdle",
        "completedTicketHasNoInflight(\n            finalTx.ticketArmed, finalTx.ticketCompleted)"):
    assert required in final_gate, required
assert "!finalTx.ticketArmed" not in final_gate

# Candidate identity is committed only after the timing helper returns a real
# candidate and the actual production OneShot locks that exact MIF/PSF/head.
plan_at = mif.index("Test066MifCurrentPhase::plan(timingInput")
lock_at = mif.index("run->discoveryBinding.lock(", plan_at)
candidate_commit_at = mif.index("run->discoveryCandidateLocked = true;", lock_at)
assert plan_at < lock_at < candidate_commit_at
assert mif.rfind("timingStatus !=", plan_at, lock_at) != -1
assert "timingStatus != Test066MifCurrentPhase::Status::kCandidate" in mif
assert "run->discoveryBinding.authorizeTake(" in mif
assert "NativeAwdlBSD::nextDiscoveryTx(" in mif
assert "NativeAwdlBSD::nextTx(" not in mif

# Before OneShot lock, peer table updates remain retryable. Once locked, the
# original incarnation, PSF revision, MIF revision, witness, epochs, and exact
# strict QM head are terminally revalidated before the one dequeue.
for required in (
        "kPeerIncarnationMismatch", "kPsfRevisionMismatch",
        "kMifRevisionMismatch", "kMifWitnessMismatch", "kEpochMismatch",
        "kStrictQmHeadUnstable", "kOwnMifIncomplete", "kActionRingBusy",
        "kRocInactive", "kClosing", "kPeerMifChannelMismatch",
        "kScheduleRejected", "kOwnMifMissedWindow"):
    assert required in mif, required
for required in (
        "kNoSelectedSlot", "Decision::kPeerIncarnationChanged",
        "Decision::kPsfRevisionChanged", "Decision::kMifRevisionChanged",
        "Decision::kEpochMismatch", "Decision::kMifWitnessMismatch"):
    assert required in peer_failure, required
for required in (
        "Decision::kPeerIncarnationChanged",
        "Decision::kPsfRevisionChanged", "Decision::kMifRevisionChanged",
        "Decision::kEpochMismatch", "Decision::kChannelMismatch",
        "Decision::kQueueHeadChanged"):
    assert required in decision_blocker, required
assert "// The candidate has not reached a timing plan or OneShot lock." in mif
assert "run->discoveryWindowClosed = true;" in mif
assert "input.gates.ownMifTxSucceeded = run->mifResultCaptured &&\n            run->mifTxCompleted && run->mifTxSucceeded;" in mif
assert "sameDiscoveryHead(head, run->discoveryHead)" in mif
assert "finalTarget.mifRevision != target.mifRevision" in mif

# Only local, bounded prerequisites are waitable. The base gate separately
# rejects stale/missing epochs, inactive/closing ROC, and a peer not received
# on channel 6. Mask telemetry is a single numeric field and republishes on
# mask changes even when the coarse status is unchanged.
assert "constexpr uint32_t kWaitableMask = kOwnMifIncomplete |" in admission
assert "blockers & ~kWaitableMask" in admission
assert "Test069MifCurrentAdmission::hasOnlyWaitableBlockers(blockers)" in mif
assert "if (!rocActive)" in mif and "if (closing)" in mif
assert "if (!peerEpochsMatch)" in mif and "if (!peerMifChannel6)" in mif
assert 'set("PrerequisiteBlockers", run->discoveryPrerequisiteBlockers);' in source
assert "run->discoveryLastPublishedPrerequisiteBlockers ==\n             run->discoveryPrerequisiteBlockers" in source
assert "run->discoveryLastPublishedBindingFailureReason ==\n             run->discoveryBindingFailureReason" in source

# One selector drives all three pacing layers. The fresh-PSF refresh and
# final pre-submit checks both route through the same input builder.
assert "probe->discoveryModeSelected" in policy_selector
assert "NativeAwdlDiscoveryBinding::Mode::kMifCurrentSlot" in policy_selector
assert "MifPacingPolicy::Test069EarlyFirstMif" in policy_selector
assert "MifPacingPolicy::LegacyPsfAfterNotBefore" in policy_selector
assert "input.policy = mifPacingPolicyForProbe(probe);" in pacing_input_builder
assert "mifPacingNotBeforeUs(" in cheap_gate
cheap_call = cheap_gate[cheap_gate.index("mifPacingNotBeforeUs("):]
cheap_call = cheap_call[:cheap_call.index(")) {")]
assert "mifPacingPolicyForProbe(probe)" in cheap_call
assert "makeMifPacingInput(" in refresh_gate
assert "makeMifPacingInput(" in final_gate_policy
assert "MifPacingPolicy::Test069EarlyFirstMif" in pacing_source
assert "frameOrdinal == 0" in pacing_source
assert "input.peerPsfRxUs < input.phaseOriginUs" in pacing_source

# This scalar policy has no access to the owner or live peer table. The
# production caller supplies only its already captured booleans.
helper = admission[admission.index("constexpr bool hasOnlyWaitableBlockers"):
                   admission.index("// The production ring snapshot")]
assert "owner" not in helper and "self" not in helper and "PsfPeerSnapshot" not in helper

with tempfile.TemporaryDirectory(prefix="awdl-test069-") as directory:
    binary = pathlib.Path(directory) / "awdl-mif-current-admission-test069"
    subprocess.run([
        "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        str(POLICY_TEST), str(ROOT / "native/p2p_action_tx.cpp"),
        "-o", str(binary),
    ], cwd=ROOT, check=True)
    subprocess.run([str(binary)], cwd=ROOT, check=True)

print("PASS: real CompletionTracker tombstone/rearm/drain and OneShot revision/head gates under ASan/UBSan")
print("PASS: Test069 candidate pinning, strict wait mask, physical ring gates, and lock/snapshot source contracts")
