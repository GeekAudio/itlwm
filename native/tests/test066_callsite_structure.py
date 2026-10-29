#!/usr/bin/env python3
"""Structural checks for the private Test066 HAL candidate.

This is not a kernel build, queue concurrency proof, RF test, or AirDrop result.
"""
from pathlib import Path

source = Path(__file__).parents[2] / "itlwm" / "hal_iwx" / "ItlIwxP2PProbe.cpp"
text = source.read_text()

assert "discoveryMifCurrentSlotEnabled(owner) ?" in text
assert "run.discoveryModeSelected = discoveryExperimentEnabled(owner);" in text
assert "run.discoveryMode ==" in text
assert "run.discoveryRequiresRuntimeMifBinding = true;" in text
assert "const bool requireRuntimeMifBinding = peer.validPeerCount != 0;" in text
assert "const bool observerGateClear = mifCurrentMode ||" in text
assert "discoveryProfile && observerGateClear" in text
assert "const bool discoveryProfile = run->discoveryModeSelected;" in text
assert "takeDiscoveryPacket(run, epochs," in text

# Aggregate formal-observer count is published separately and never read by
# the MIF-current implementation to select or authenticate a runtime slot.
mif = text[text.index("static mbuf_t takeDiscoveryPacketMifCurrent"):]
mif = mif[:mif.index("static mbuf_t takeDiscoveryPacket(")]
assert "peer.validPeerCount" not in mif
assert "getPsfSnapshot(" in mif
assert "candidate.mif.peerIncarnation != candidate.peerIncarnation" in mif
assert "candidate.mif.mifRevision != candidate.mifRevision" in mif
assert "selectedSnapshot.mif.rxMonotonicUs !=" in mif
assert "current.mif.peerIncarnation != current.peerIncarnation" in mif
assert "current.mif.mifRevision != current.mifRevision" in mif
assert "discoveryPsfHistory(" in mif
assert "Test066MifCurrentPhase::plan(timingInput," in mif
assert "NativeAwdlDiscoveryPhase::estimateTarget" not in mif
assert "finalTimingInput, finalTarget" in mif
assert "run->discoveryBinding.authorizeTake(" in mif
assert "NativeAwdlBSD::nextDiscoveryTx(" in mif
assert "NativeAwdlBSD::nextTx(" not in mif
assert "run->discoveryMifTimingStatus" in mif
assert "run->discoveryWindowClosed = true;" in mif

# Time-domain evidence is intentionally host-monotonic only. No code marks
# GP2 mapping or airtime as verified.
assert "clock_get_uptime() followed by absolutetime_to_nanoseconds()" in mif
publish = text[text.index("static void publishDiscoveryExperiment"):text.index("static bool discoveryNumber")]
assert 'set("ClockMappingVerified", 0);' in publish
assert 'set("AirtimeVerified", 0);' in publish
assert 'set("FormalPeerPolicyChanged", 0);' in publish
for field in ("MifTimingStatus", "MifFirstCompletionUs", "MifCurrentSlot",
              "MifEarliestSubmitUs", "MifLatestSubmitUs",
              "MifTargetAwStartGp2", "MifTargetAwCounter"):
    assert f'set("{field}"' in publish

# MIF mode relaxes only the aggregate observer blocker; it still requires the
# same-entry runtime MIF witness. The failure path returns before ordinary TX.
profile_block = text[text.index("if (discoveryProfile && !discoveryPacket)"):]
assert "mifCurrentMode ? (1u << 14)" in profile_block
assert "return kIOReturnNotReady;" in profile_block
assert profile_block.index("return kIOReturnNotReady;") < profile_block.index("NativeAwdlBSD::nextTx(")
assert "kAlreadyAttempted" in (Path(__file__).parents[1] / "awdl_discovery_admitted_binding.hpp").read_text()

# The reviewed wire interpretation is gated by a decoded presence-4 type-4
# value and a full valid same-entry type-18 sequence.
runtime = (Path(__file__).parents[1] / "awdl_peer_runtime_table.cpp").read_text()
assert "kReviewedMifWireAwCounterInterpretation" in runtime
assert "mifAd.presenceMode == 4" in runtime
assert "mifAd.type18Present && mifAd.type18Valid" in runtime

print("PASS: Test066 private dual-mode HAL structure and fail-closed gates")
