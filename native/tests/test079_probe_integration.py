#!/usr/bin/env python3
"""Compile real Test079 Probe identity/pair helpers with small type shims."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"


def extract_braced_declaration(source: str, marker: str) -> str:
    start = source.index(marker)
    open_brace = source.index("{", start)
    depth = 0
    for index in range(open_brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise ValueError(f"unclosed declaration: {marker}")


def extract_function(source: str, marker: str) -> str:
    start = source.index(marker)
    while True:
        paren = source.index("(", start)
        depth = 0
        close_paren = -1
        for index in range(paren, len(source)):
            if source[index] == "(":
                depth += 1
            elif source[index] == ")":
                depth -= 1
                if depth == 0:
                    close_paren = index
                    break
        if close_paren < 0:
            raise ValueError(f"unclosed signature: {marker}")
        body = close_paren + 1
        while body < len(source) and source[body].isspace():
            body += 1
        if body < len(source) and source[body] == "{":
            return _extract_from(source, start, body)
        # A forward declaration ends in ';'; keep looking for the definition.
        if body < len(source) and source[body] == ";":
            try:
                start = source.index(marker, start + len(marker))
            except ValueError as error:
                raise ValueError(f"definition not found: {marker}") from error
            continue
        raise ValueError(f"unexpected declaration after signature: {marker}")


def _extract_from(source: str, start: int, open_brace: int) -> str:
    depth = 0
    for index in range(open_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise ValueError("unclosed function body")


def main() -> None:
    probe = PROBE.read_text()
    declarations = [
        extract_braced_declaration(probe, "struct P2PProbeTicketIdentity {") + ";",
        extract_braced_declaration(
            probe, "struct P2PMifCompletionClassification {") + ";",
        extract_braced_declaration(probe, "struct P2PTxDiagnosticSnapshot {") + ";",
        extract_function(probe, "static P2PProbeTicketIdentity ticketIdentityFromSnapshot("),
        extract_function(probe, "static bool ticketIdentityFieldsMatch("),
        extract_function(probe, "static bool ticketIdentityMatches("),
        extract_function(probe, "static P2PMifCompletionClassification classifyMifCompletion("),
        extract_function(probe, "static bool mifBootstrapPairSnapshotMatches("),
    ]
    cpp = r"""
#include <assert.h>
#include <stdint.h>

enum class TahoeP2PActionTxState : uint32_t { kIdle = 0, kInFlight = 1 };

namespace Test070MifBootstrap {
struct Binding { uint64_t rocGeneration; };
}

struct MifPacingPeerView {
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t peerIncarnation;
    uint64_t psfRevision;
    uint64_t mifRevision;
    uint64_t rxMonotonicUs;
    uint64_t mifRxMonotonicUs;
    uint64_t rocGeneration;
    uint16_t slot;
    bool ownerCurrent;
    bool rocActive;
    bool rocChannel6Confirmed;
    bool rxChannel6Confirmed;
    bool mifRxChannel6Confirmed;
};

struct P2PProbeRun {
    bool mifBootstrapPairClaimed;
    uint8_t mifBootstrapPairSlot;
    uint64_t mifBootstrapPairPeerIncarnation;
    uint64_t mifBootstrapPairPsfRevision;
    uint64_t mifBootstrapPairMifRevision;
    uint64_t mifBootstrapPairPsfRxUs;
    uint64_t mifBootstrapPairMifRxUs;
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    Test070MifBootstrap::Binding mifBootstrapBinding;
};

__DECLARATIONS__

P2PTxDiagnosticSnapshot validSnapshot()
{
    P2PTxDiagnosticSnapshot snapshot{};
    snapshot.queueGeneration = 101;
    snapshot.actionGeneration = 202;
    snapshot.queueId = 9;
    snapshot.actionQueueId = 9;
    snapshot.actionDescriptorIndex = 4;
    snapshot.actionRocToken = 303;
    snapshot.actionSequenceControl = 0x1230;
    snapshot.actionFrameControl = 0x00d0;
    snapshot.actionByteCount = 92;
    snapshot.nextSequenceNumber = 0x124;
    snapshot.ticketStatus = 1;
    snapshot.ticketSequenceControl = 0x1230;
    snapshot.ticketFrameControl = 0x00d0;
    snapshot.ticketByteCount = 92;
    snapshot.ticketCompleted = true;
    snapshot.ticketArmed = true;
    snapshot.actionState = static_cast<uint32_t>(TahoeP2PActionTxState::kIdle);
    snapshot.frameAttemptSucceeded = true;
    // The completion tracker deliberately does not promote a TX response
    // status to peer receipt; identity matching gates local ticket completion.
    snapshot.peerAcknowledged = false;
    return snapshot;
}

MifPacingPeerView pairView()
{
    MifPacingPeerView peer{};
    peer.slot = 2;
    peer.peerIncarnation = 77;
    peer.psfRevision = 15;
    peer.mifRevision = 22;
    peer.rxMonotonicUs = 1001000;
    peer.mifRxMonotonicUs = 1000000;
    peer.contextGeneration = 11;
    peer.powerGeneration = 12;
    peer.stationGeneration = 13;
    peer.rocGeneration = 11;
    peer.ownerCurrent = true;
    peer.rocActive = true;
    peer.rocChannel6Confirmed = true;
    peer.rxChannel6Confirmed = true;
    peer.mifRxChannel6Confirmed = true;
    return peer;
}

int main()
{
    const P2PTxDiagnosticSnapshot bootstrap = validSnapshot();
    const P2PProbeTicketIdentity bootstrapIdentity =
        ticketIdentityFromSnapshot(bootstrap);
    assert(bootstrapIdentity.valid);
    assert(ticketIdentityFieldsMatch(bootstrapIdentity, bootstrap));
    assert(ticketIdentityMatches(bootstrapIdentity, bootstrap));
    assert(!bootstrap.peerAcknowledged);

    const auto ordinaryCompletion = classifyMifCompletion(
        false, false, P2PProbeTicketIdentity{}, P2PProbeTicketIdentity{},
        bootstrap);
    assert(ordinaryCompletion.txSucceeded);
    assert(ordinaryCompletion.grantsOwnFirst);

    const auto bootstrapCompletion = classifyMifCompletion(
        true, false, bootstrapIdentity, P2PProbeTicketIdentity{}, bootstrap);
    assert(bootstrapCompletion.txSucceeded);
    assert(!bootstrapCompletion.grantsOwnFirst);

    // The normal paired MIF has its own exact ticket identity and can grant
    // own-first only when that ticket, rather than the bootstrap ticket, wins.
    P2PTxDiagnosticSnapshot pairedTicket = bootstrap;
    ++pairedTicket.queueGeneration;
    ++pairedTicket.actionGeneration;
    ++pairedTicket.actionQueueId;
    ++pairedTicket.queueId;
    ++pairedTicket.actionDescriptorIndex;
    ++pairedTicket.actionRocToken;
    pairedTicket.actionSequenceControl = 0x1240;
    pairedTicket.ticketSequenceControl = 0x1240;
    pairedTicket.nextSequenceNumber = 0x125;
    const auto pairedIdentity = ticketIdentityFromSnapshot(pairedTicket);
    const auto pairedCompletion = classifyMifCompletion(
        true, true, bootstrapIdentity, pairedIdentity, pairedTicket);
    assert(pairedCompletion.txSucceeded);
    assert(pairedCompletion.grantsOwnFirst);

    const auto lateBootstrapCompletion = classifyMifCompletion(
        true, true, bootstrapIdentity, pairedIdentity, bootstrap);
    assert(!lateBootstrapCompletion.txSucceeded);
    assert(!lateBootstrapCompletion.grantsOwnFirst);

    P2PTxDiagnosticSnapshot wrongPairGeneration = pairedTicket;
    ++wrongPairGeneration.queueGeneration;
    const auto stalePair = classifyMifCompletion(
        true, true, bootstrapIdentity, pairedIdentity,
        wrongPairGeneration);
    assert(!stalePair.txSucceeded);
    assert(!stalePair.grantsOwnFirst);

    P2PTxDiagnosticSnapshot wrongPairStatus = pairedTicket;
    wrongPairStatus.ticketStatus = 2;
    wrongPairStatus.frameAttemptSucceeded = false;
    const auto failedPair = classifyMifCompletion(
        true, true, bootstrapIdentity, pairedIdentity, wrongPairStatus);
    assert(!failedPair.txSucceeded);
    assert(!failedPair.grantsOwnFirst);

    // A negative or unknown firmware completion must not qualify as local
    // ticket success, even though the identity fields still match.
    P2PTxDiagnosticSnapshot failedCompletion = bootstrap;
    failedCompletion.frameAttemptSucceeded = false;
    failedCompletion.ticketStatus = 0;
    assert(ticketIdentityFieldsMatch(bootstrapIdentity, failedCompletion));
    assert(!ticketIdentityMatches(bootstrapIdentity, failedCompletion));
    P2PTxDiagnosticSnapshot unknownStatus = bootstrap;
    unknownStatus.ticketStatus = 2;
    assert(ticketIdentityFieldsMatch(bootstrapIdentity, unknownStatus));
    assert(!ticketIdentityMatches(bootstrapIdentity, unknownStatus));

    P2PTxDiagnosticSnapshot unarmed = bootstrap;
    unarmed.ticketArmed = false;
    assert(!ticketIdentityFieldsMatch(bootstrapIdentity, unarmed));

    // The next ordinary MIF ticket is a different transaction, even though it
    // belongs to the same run, ROC, hardware queue, and action-ring context.
    P2PTxDiagnosticSnapshot normal = bootstrap;
    ++normal.actionDescriptorIndex;
    normal.actionSequenceControl = 0x1240;
    normal.ticketSequenceControl = 0x1240;
    ++normal.nextSequenceNumber;
    assert(!ticketIdentityFieldsMatch(bootstrapIdentity, normal));
    assert(!ticketIdentityMatches(bootstrapIdentity, normal));

    // Each hardware ticket identity component is independently fenced.
    for (unsigned field = 0; field < 13; ++field) {
        P2PTxDiagnosticSnapshot changed = bootstrap;
        switch (field) {
            case 0: ++changed.queueGeneration; break;
            case 1: ++changed.actionGeneration; break;
            case 2: ++changed.queueId; break;
            case 3: ++changed.actionQueueId; break;
            case 4: ++changed.actionDescriptorIndex; break;
            case 5: ++changed.actionRocToken; break;
            case 6: ++changed.actionSequenceControl; ++changed.ticketSequenceControl; break;
            case 7: ++changed.actionFrameControl; ++changed.ticketFrameControl; break;
            case 8: ++changed.actionByteCount; ++changed.ticketByteCount; break;
            case 9: ++changed.ticketSequenceControl; break;
            case 10: ++changed.ticketFrameControl; break;
            case 11: ++changed.ticketByteCount; break;
            case 12: ++changed.nextSequenceNumber; break;
        }
        assert(!ticketIdentityFieldsMatch(bootstrapIdentity, changed));
        assert(!ticketIdentityMatches(bootstrapIdentity, changed));
    }

    P2PProbeRun run{};
    run.mifBootstrapPairClaimed = true;
    run.mifBootstrapPairSlot = 2;
    run.mifBootstrapPairPeerIncarnation = 77;
    run.mifBootstrapPairPsfRevision = 15;
    run.mifBootstrapPairMifRevision = 22;
    run.mifBootstrapPairPsfRxUs = 1001000;
    run.mifBootstrapPairMifRxUs = 1000000;
    run.contextGeneration = 11;
    run.powerGeneration = 12;
    run.stationGeneration = 13;
    run.mifBootstrapBinding.rocGeneration = 11;
    const MifPacingPeerView peer = pairView();
    assert(mifBootstrapPairSnapshotMatches(&run, peer));

    // Pair selection is pinned to one slot, incarnation, same-entry PSF/MIF
    // revisions/times, and the complete live epoch/ROC/channel context.
    for (unsigned field = 0; field < 13; ++field) {
        P2PProbeRun changedRun = run;
        MifPacingPeerView changedPeer = peer;
        switch (field) {
            case 0: changedPeer.slot++; break;
            case 1: changedPeer.peerIncarnation++; break;
            case 2: changedPeer.psfRevision++; break;
            case 3: changedPeer.mifRevision++; break;
            case 4: changedPeer.rxMonotonicUs++; break;
            case 5: changedPeer.mifRxMonotonicUs++; break;
            case 6: changedPeer.contextGeneration++; break;
            case 7: changedPeer.powerGeneration++; break;
            case 8: changedPeer.stationGeneration++; break;
            case 9: changedPeer.rocGeneration++; break;
            case 10: changedRun.mifBootstrapPairSlot++; break;
            case 11: changedRun.mifBootstrapPairPeerIncarnation++; break;
            case 12: changedPeer.rocActive = false; break;
        }
        assert(!mifBootstrapPairSnapshotMatches(&changedRun, changedPeer));
    }

    return 0;
}
"""
    cpp = cpp.replace("__DECLARATIONS__", "\n\n".join(declarations))
    with tempfile.TemporaryDirectory(prefix="test079-probe-integration-") as temp:
        source = Path(temp) / "test079_probe_integration.cpp"
        binary = Path(temp) / "test079_probe_integration"
        source.write_text(cpp)
        subprocess.run(
            [
                "xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
                "-Wextra", "-Werror", "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer", "-fno-sanitize-recover=all",
                str(source), "-o", str(binary),
            ],
            cwd=ROOT,
            check=True,
        )
        subprocess.run([str(binary)], cwd=ROOT, check=True)
    print(
        "PASS: extracted Test079 Probe helpers validate ticket identity, "
        "completion classification, own-first eligibility, and pinned peer "
        "epochs under ASan/UBSan"
    )


if __name__ == "__main__":
    main()
