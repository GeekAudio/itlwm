#!/usr/bin/env python3
"""Source-level integration guards for the bounded Test077 Qm snapshot."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "itlwm" / "hal_iwx" / "ItlIwxP2PAction.cpp"
HEADER = ROOT / "itlwm" / "hal_iwx" / "ItlIwxP2PAction.hpp"
PROBE = ROOT / "itlwm" / "hal_iwx" / "ItlIwxP2PProbe.cpp"
SOURCE = ACTION.read_text()
action_submit = SOURCE.split("int iwx_tahoe_p2p_action_tx_submit(", 1)[1].split(
    "bool iwx_tahoe_p2p_action_tx_response(", 1)[0]
publisher = SOURCE.split(
    "bool iwx_tahoe_p2p_action_publish_pending_qm_wire_snapshot(", 1
)[1].split("bool iwx_tahoe_p2p_action_reject_ba_queue(", 1)[0]

# DecodedFrame borrows bytes from the stack `raw` buffer. The borrowed pointer
# may be examined only in the decode scope; no later-stage dereference exists.
assert action_submit.count("dataInfo.packets[0].ipv6Packet") == 1
assert "ipv6DestinationIsAirdropMdns =" in action_submit
assert "ipv6Packet + 24" in action_submit
assert "dataInfo.packets[0].ipv6Packet + 24" not in action_submit
candidate_index = action_submit.index("const bool qmWireSnapshotCandidate")
assert "dataInfo." not in action_submit[candidate_index:]

# The submit path records fixed value-only facts and bounded raw bytes after
# queue finish. It has no IORegistry publication and no GP2/MMIO sample.
finish = action_submit.index("iwx_tahoe_p2p_tvqm_finish_tx_submit(queueLease)")
stage = action_submit.index("stageQmWireSnapshot(qmWireSnapshot,")
assert finish < stage
assert "setProperty(" not in action_submit
assert "read_prph" not in action_submit and "IWX_READ_PRPH" not in action_submit
assert "CurrentGp2" not in action_submit
assert re.search(r"else if\s*\(qmWireRawSnapshotCandidate\s*&&\s*"
                 r"qmWireRawSnapshotReady\)\s*\{", action_submit)
assert "const uint32_t txFlags" in action_submit
tx_flags = action_submit.split("const uint32_t txFlags", 1)[1].split(";", 1)[0]
assert "qmWireSnapshotCandidate" in tx_flags
assert "qmWireRawSnapshotCandidate" not in tx_flags
assert "mbuf_copydata(frame, 0," in action_submit
assert "qmWireRawSnapshot.mpduBytes +" in action_submit
assert "deviceCommand->data" in action_submit
raw_capture = action_submit.index("Copy diagnostic bytes before the final submit-time/epoch gate")
assert raw_capture < action_submit.index("const uint64_t submitNanoseconds")
assert raw_capture < action_submit.index("controlSubmitFenceTimeValid(")
assert "qmWireRawSnapshot.doorbellUs = p2pActionMonotonicUs()" in action_submit
assert "qmWireRawSnapshot.finishUs = p2pActionMonotonicUs()" in action_submit

# Legacy facts and private raw bytes are separate immutable blobs. Both carry
# the same token/epoch identity; the final status object is published last.
assert re.search(r"OSData::withBytes\(\s*encodedFacts.bytes,\s*"
                 r"sizeof\(encodedFacts.bytes\)\)", publisher)
assert re.search(r"OSData::withBytes\(\s*encodedRaw.bytes,\s*"
                 r"sizeof\(encodedRaw.bytes\)\)", publisher)
assert re.search(r"OSData::withBytes\(\s*encodedStatus.bytes,\s*"
                 r"sizeof\(encodedStatus.bytes\)\)", publisher)
assert publisher.count("setProperty(") == 4
assert '"NativeP2PQmWireStageRejectCount"' in publisher
assert '"NativeP2PQmWireSnapshot"' in publisher
assert '"NativeP2PQmWireRawSnapshotPrivate"' in publisher
assert '"NativeP2PQmWireRawSnapshotPrivateStatus"' in publisher
assert publisher.index('"NativeP2PQmWireSnapshot"') < publisher.index(
    '"NativeP2PQmWireRawSnapshotPrivate"'
)
assert publisher.index('"NativeP2PQmWireStageRejectCount"') < publisher.index(
    '"NativeP2PQmWireRawSnapshotPrivateStatus"'
)
assert publisher.index('"NativeP2PQmWireRawSnapshotPrivate"') < publisher.index(
    '"NativeP2PQmWireRawSnapshotPrivateStatus"'
)
assert "finalStage == QmWireRawStage::kPublished" in publisher
assert publisher.index("tahoeP2pOnMainGate()") < publisher.index(
    "pendingQmWireSnapshotState, &expected"
)
record_definition = (ROOT / "native" / "awdl_qm_wire_snapshot.hpp").read_text().split(
    "struct Record {", 1
)[1].split("};", 1)[0]
assert "*" not in record_definition
assert "mbuf_t" not in record_definition
raw_header = (ROOT / "native" / "awdl_qm_wire_snapshot.hpp").read_text()
raw_definition = raw_header.split("struct Record {", 2)[2].split("};", 1)[0]
assert "*" not in raw_definition
assert "mbuf_t" not in raw_definition
assert "paddr" not in raw_definition
assert "sameIdentity" in raw_header
assert "claimFirstSlot" in raw_header
stage_function = SOURCE.split("static bool stageQmWireSnapshot(", 1)[1].split(
    "static bool stageQmWireOutcome(", 1
)[0]
assert "claimFirstSlot" in stage_function
assert "sameIdentity" in stage_function
assert stage_function.index("claimFirstSlot") < stage_function.index(
    "pendingQmWirePublication.facts = facts"
)
outcome_stage = SOURCE.split("static bool stageQmWireOutcome(", 1)[1].split(
    "#endif", 1
)[0]
assert "claimFirstSlot" in outcome_stage

assert "bool iwx_tahoe_p2p_action_publish_pending_qm_wire_snapshot(ItlIwx *owner);" in HEADER.read_text()
probe_source = PROBE.read_text()
probe_publisher = probe_source.split(
    "void ItlIwx::tahoeP2pPublishProbeState()", 1
)[1]
busy_guard = probe_publisher.index("if (nativeP2PPublicationBusy(this))")
request_pending = probe_publisher.index(
    "requestNativeP2PQmWireSnapshotPublish(this)"
)
assert busy_guard < request_pending
callback = probe_source.split(
    "static IOReturn publishPendingQmWireSnapshotAction(", 1
)[1].split("static void requestNativeP2PQmWireSnapshotPublish(", 1)[0]
request = probe_source.split(
    "static void requestNativeP2PQmWireSnapshotPublish(", 1
)[1].split("void ItlIwx::tahoeP2pPublishProbeState()", 1)[0]
assert callback.index("tahoeP2pOnMainGate()") < callback.index(
    "nativeP2PPublicationBusy(owner)"
)
assert callback.index("nativeP2PPublicationBusy(owner)") < callback.index(
    "iwx_tahoe_p2p_action_publish_pending_qm_wire_snapshot(owner)"
)
assert "gate->attemptAction(publishPendingQmWireSnapshotAction, owner)" in request
assert "gate->runAction(" not in request
assert "kAddress1MatchesAirdropMdnsMapping" in (ROOT / "native" / "awdl_qm_wire_snapshot.hpp").read_text()

print("Test077 Qm snapshot integration guards passed")
