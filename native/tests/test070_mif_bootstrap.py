#!/usr/bin/env python3
"""Run Test070 bootstrap and real peer-table tests with ASan/UBSan."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
TABLE_H = ROOT / "native/awdl_peer_runtime_table.hpp"
TABLE_CPP = ROOT / "native/awdl_peer_runtime_table.cpp"
HELPER = ROOT / "native/awdl_mif_bootstrap_test070.hpp"
HELPER_TEST = ROOT / "native/tests/awdl_mif_bootstrap_test070.cpp"
TABLE_TEST = ROOT / "native/tests/awdl_peer_runtime_table_test.cpp"


def run(arguments, root=ROOT):
    result = subprocess.run(
        arguments, cwd=root, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(arguments)}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result.stdout


def compile_and_run(source, binary, extras=()):
    run(
        [
            "xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
            "-Wextra", "-Werror", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", "-fno-sanitize-recover=all",
            *[str(path) for path in extras], str(source), "-o", str(binary),
        ]
    )
    run([str(binary)])


def verify_production_contract():
    source = PROBE.read_text(encoding="utf-8")
    table = TABLE_H.read_text(encoding="utf-8")
    helper = HELPER.read_text(encoding="utf-8")
    assert "awdl_mif_bootstrap_test070.hpp" in source
    assert "getMifSnapshot(" in source
    assert "refreshMifBootstrapCandidateInGate(" in source
    assert "evaluateMifBootstrapInGate(" in source
    assert "probe->mifBootstrapSelected" in source
    assert "NativeP2PAwdlMifBootstrapStatus" in source
    assert "NativeP2PAwdlMifBootstrapChecks" in source
    assert "nativeDataAttempts<4" in source
    assert "mifBootstrapSelected" in source[source.index("if(successfulStart"):
        source.index("if(successfulStart") + 500]

    # The worker may use only the owner/channel facts copied under the command
    # gate. The pure state builder must not reach through owner/com on its own.
    local_builder = extract_function(
        source, "static Test070MifBootstrap::LocalState makeMifBootstrapLocalState(")
    assert "bool ownerCurrent, bool rocChannel6Confirmed" in local_builder
    assert "owner->" not in local_builder and "sc_p2p" not in local_builder
    assert "local.rocChannel6Confirmed = rocChannel6Confirmed" in local_builder

    # Every final bootstrap authorization repeats all live local/peer gates,
    # then adds exact same-entry binding checks; it does not use the earlier
    # worker-side ready result as transmit authorization.
    evaluate = extract_function(
        source, "static Test070MifBootstrap::Plan evaluateMifBootstrapInGate(")
    assert "tahoeP2pOnMainGate()" in evaluate
    assert "readMifBootstrapPeerInGate" in evaluate
    assert "blocked = evaluate(local, read.view.peer)" in evaluate
    assert "bindingMismatch(probe->mifBootstrapBinding" in evaluate
    assert "read.view.peer, session.generation" in evaluate
    submit = extract_function(
        source, "static IOReturn tahoeP2pSubmitActionInGate(")
    assert "evaluateMifBootstrapInGate(\n                    probe, finalSnapshot, finalDoorbellUs, true)" in submit

    # A bootstrap remains control-only. It cannot authorize a QM dequeue or
    # data submission by itself; only a separately attempted and successfully
    # completed normal paired MIF can open the existing data path.
    ordinary_mif = extract_function(
        source, "static bool tryPrepareMifAtPacingPoint(")
    assert "probe->mifBootstrapSelected" in ordinary_mif
    ordinary_mif_contract = " ".join(ordinary_mif.split())
    submit_contract = " ".join(submit.split())
    assert (
        "if (probe->mifBootstrapSelected && "
        "!evaluateMifBootstrapPairTransition(probe, peer, false))"
    ) in ordinary_mif_contract
    assert "claimMifBootstrapPairAfterPreparation(" in ordinary_mif
    claim_helper = extract_function(
        source, "static bool claimMifBootstrapPairAfterPreparation(")
    assert "if (!pacingReady || !repeatPrepareReady)" in claim_helper
    assert "evaluateMifBootstrapPairTransition(probe, peer, true)" in claim_helper
    assert "if (probe->mifBootstrapSelected) return false;" in ordinary_mif_contract
    assert (
        "const bool bootstrapMifSubmit = mifFrame && "
        "probe->mifBootstrapCandidatePrepared && "
        "!probe->mifBootstrapSubmitted;"
    ) in submit_contract
    assert (
        "probe->mifBootstrapPairClaimed && !bootstrapMifSubmit && "
        "!probe->mifBootstrapPairMifAttempted"
    ) in submit_contract
    assert (
        "if (mifFrame && probe->mifBootstrapSelected && "
        "probe->mifBootstrapPairClaimed && !bootstrapMifSubmit && "
        "!probe->mifBootstrapPairMifAttempted)"
    ) in submit_contract
    assert "probe->mifBootstrapSubmitted = true" in submit
    worker = extract_function(source, "static int runTxProbeSession(")
    data_guard_start = worker.index("if(successfulStart")
    submit_data_start = worker.index("auto submitData", data_guard_start)
    data_guard = worker[data_guard_start:submit_data_start]
    data_guard_contract = "".join(data_guard.split())
    assert "probe->mifResultCaptured&&probe->mifTxSucceeded&&probe->nativeDataAttempts<4" in data_guard_contract
    assert (
        "&&(!probe->mifBootstrapSelected||"
        "(probe->mifBootstrapPairMifCompleted&&"
        "probe->mifBootstrapPairMifSucceeded))"
    ) in data_guard_contract
    assert "probe->mifBootstrapPairClaimed" not in data_guard_contract
    assert "takeDiscoveryPacket(" in worker[submit_data_start:]
    assert worker.index("mifBootstrapPairMifCompleted") < worker.index(
        "takeDiscoveryPacket(")
    completion_start = worker.index("const auto mifCompletion = classifyMifCompletion(")
    pair_completion = worker.index("probe->mifBootstrapPairMifCompleted = true;",
                                   completion_start)
    pair_completion_end = worker.index("probe->mifBootstrapPairDiagnosticsDirty = true;",
                                       pair_completion)
    pair_completion_contract = " ".join(
        worker[pair_completion:pair_completion_end].split())
    assert "if (probe->mifBootstrapSelected && probe->mifBootstrapPairMifAttempted)" in " ".join(
        worker[completion_start:pair_completion].split())
    assert "probe->mifBootstrapPairMifSucceeded = mifCompletion.txSucceeded;" in pair_completion_contract
    formal_completion = worker.index(
        "probe->discoveryOwnFirstMifCompletionUs =")
    completion_gate = worker[formal_completion - 500:formal_completion]
    assert "const auto mifCompletion = classifyMifCompletion(" in worker[
        worker.index("if (probe->awdlMifFollowupEnabled && probe->mifFrameSubmitted"):
        formal_completion]
    assert "mifCompletion.grantsOwnFirst" in completion_gate
    assert "getPsfSnapshot(" in source
    assert "struct MifPeerSnapshot" in table
    assert "if (!entry.used || !entry.hasMif" in TABLE_CPP.read_text(
        encoding="utf-8"
    )
    assert "kMifFreshnessLimitUs = 16ULL * 1024ULL" in helper
    assert "kMinimumLeaseReserveUs = 20ULL * 1000ULL" in helper
    assert "kBindingIncarnationMismatch" in helper
    assert "kBindingRevisionMismatch" in helper
    assert "kBindingTimestampMismatch" in helper


def extract_function(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    verify_production_contract()
    with tempfile.TemporaryDirectory(prefix="awdl-test070-mif-bootstrap-") as temp:
        directory = Path(temp)
        compile_and_run(HELPER_TEST, directory / "bootstrap")
        compile_and_run(
            TABLE_TEST,
            directory / "peer-table",
            extras=(
                ROOT / "native/awdl_action_frame.cpp",
                ROOT / "native/awdl_peer_election.cpp",
                ROOT / "native/awdl_peer_observer.cpp",
                TABLE_CPP,
                ROOT / "native/awdl_action_encode.cpp",
                ROOT / "native/awdl_mif_encode.cpp",
            ),
        )

    print(
        "PASS: Test070 MIF-only bootstrap tuple replay, 16-TU freshness, "
        "local ROC/PSF/queue/deadline gates, exact binding replacement, "
        "MIF-only runtime-table snapshot, and source integration contracts "
        "under ASan/UBSan"
    )


if __name__ == "__main__":
    main()
