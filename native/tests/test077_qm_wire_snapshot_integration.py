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

# The submit path records a fixed value-only snapshot after queue finish. It
# has no IORegistry publication and no GP2/MMIO sample.
finish = action_submit.index("iwx_tahoe_p2p_tvqm_finish_tx_submit(queueLease)")
stage = action_submit.index("stageQmWireSnapshot(qmWireSnapshot)")
assert finish < stage
assert "setProperty(" not in action_submit
assert "read_prph" not in action_submit and "IWX_READ_PRPH" not in action_submit
assert "CurrentGp2" not in action_submit
assert re.search(r"else if\s*\(qmWireSnapshotValid\)\s*\{", action_submit)

# One immutable OSData property is the complete publication. If allocation or
# setProperty fails, state is failed and no independent completion marker is
# emitted; this cannot expose a partially updated field set.
assert "OSData::withBytes(encoded.bytes, sizeof(encoded.bytes))" in publisher
assert publisher.count("setProperty(") == 1
assert '"NativeP2PQmWireSnapshot"' in publisher
assert "published ? 4u : 5u" in publisher
assert "NativeP2PQmWireSnapshotComplete" not in SOURCE
assert publisher.index("tahoeP2pOnMainGate()") < publisher.index(
    "pendingQmWireSnapshotState, &expected"
)
record_definition = (ROOT / "native" / "awdl_qm_wire_snapshot.hpp").read_text().split(
    "struct Record {", 1
)[1].split("};", 1)[0]
assert "*" not in record_definition
assert "mbuf_t" not in record_definition

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
