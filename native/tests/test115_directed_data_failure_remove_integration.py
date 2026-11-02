#!/usr/bin/env python3
"""Run the production Operations wiring, HAL Controller, REMOVE, and stop guard.

The failure fixture models the one allowed caller boundary (NoReady followed by
canonical END and the existing exact cleanup protocol). Production worker and
recovery source contracts bind that fixture to the real cleanup/proof fields;
the actual HAL Controller, MAC REMOVE method, and stop-retention predicate are
compiled and executed below.
"""

from __future__ import annotations

import ast
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PROBE_PATH = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
ITL_PATH = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
WORKER_TEST = ROOT / "native/tests/test_iwx_p2p_probe_worker.py"
PROBE = PROBE_PATH.read_text()
ITL = ITL_PATH.read_text()


def extract(source: str, marker: str) -> str:
    start = source.index(marker)
    while True:
        opening = source.index("{", start)
        semicolon = source.find(";", start)
        if semicolon < 0 or opening < semicolon:
            break
        start = source.index(marker, semicolon + 1)
    opening = source.index("{", start)
    depth = 1
    for index in range(opening + 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unterminated production function: {marker}")


def assignment_string(path: Path, name: str) -> str:
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, str):
                return value
    raise AssertionError(f"missing fixture string {name}")


def extend_stop_shim(shim: str) -> str:
    shim = shim.replace(
        "#include <string>",
        '#include <string>\n#include "native/p2p_hal_probe.hpp"',
        1,
    )
    shim = shim.replace(
        "enum { IWX_P2P_RESOURCE_ABSENT = 0 };",
        "enum { IWX_P2P_RESOURCE_ABSENT = 0, IWX_P2P_RESOURCE_ACTIVE = 1, "
        "IWX_P2P_RESOURCE_UNKNOWN = 2, IWX_P2P_UNCERTAIN_MAC_CONTEXT = 1 };\n"
        "enum { IWX_FW_CTXT_ACTION_ADD = 1, IWX_FW_CTXT_ACTION_MODIFY = 2, "
        "IWX_FW_CTXT_ACTION_REMOVE = 3, IWX_MAC_CONTEXT_CMD = 0x28 };",
        1,
    )
    shim = shim.replace(
        "struct iwx_p2p_context {\n    int mac_state = 0, binding_state = 0;\n    bool phy_leased = false;\n    uint32_t fw_generation = 0;\n};",
        "struct iwx_p2p_context {\n    int initialized = 0;\n"
        "    int mac_state = 0, binding_state = 0;\n"
        "    bool phy_leased = false;\n"
        "    uint8_t uncertain_kind = 0, uncertain_action = 0;\n"
        "    uint32_t fw_generation = 0;\n};",
        1,
    )
    shim = shim.replace(
        "struct P2PProbeRun { struct ItlIwx *owner = nullptr; bool canceled = false; };",
        "struct P2PProbeRun {\n"
        "    struct ItlIwx *owner = nullptr; bool canceled = false;\n"
        "    bool rx149ObservationOnly = false, directedPrepareOnly = false;\n"
        "    bool txProbeEnabled = false, directedDataOnly = false;\n"
        "    bool cleanupCompleted = false, recoverySupported = true;\n"
        "    bool canonicalEnd = true, noDoorbell = true, ticketClosed = true;\n"
        "    bool queueDrained = true, resourcesAbsent = true;\n"
        "    bool ownerMatches = true, contextMatches = true, powerMatches = true;\n"
        "    bool firmwareMatches = true, p2pFirmwareMatches = true;\n"
        "    bool stationMatches = true, fullyRestored = true;\n"
        "    bool bindingAbsent = true, phyUnleased = true, rocIdle = true;\n"
        "    bool changeEpochAfterCleanup = false, addAcknowledged = false;\n"
        "    uint32_t contextGeneration = 11, powerGeneration = 7;\n"
        "    uint32_t stationGeneration = 19, p2pFirmwareGeneration = 0;\n"
        "    uint8_t address[6] = {2, 1, 2, 3, 4, 5};\n"
        "};",
        1,
    )
    shim = shim.replace(
        "    void setProperty(const char *key, uint32_t value, unsigned bits) {\n"
        "        assert(bits == 32); properties[key] = value;\n"
        "    }\n};",
        "    void setProperty(const char *key, uint32_t value, unsigned bits) {\n"
        "        assert(bits == 32); properties[key] = value;\n"
        "    }\n"
        "    uint32_t getProperty(const char *) const { return 0; }\n};",
        1,
    )
    shim = shim.replace(
        "    bool busy = false;\n",
        "    bool busy = false;\n"
        "    NativeP2PProbe::Controller nativeP2pProbe_{};\n"
        "    uint32_t nativeP2pProbeGeneration_ = 0;\n"
        "    uint32_t nativeP2pPowerGeneration_ = 0, nativeP2pStationGeneration_ = 0;\n"
        "    bool publishedLease = false;\n"
        "    int addPduResult = 0, removePduResult = 0; unsigned pduSends = 0;\n"
        "    int configureResult = 0;\n"
        "    bool nativeP2pCommandAllowed() const { return true; }\n"
        "    int iwx_p2p_mac_context_configure(iwx_softc *, uint8_t, uint8_t, uint8_t, const uint8_t *);\n"
        "    int iwx_p2p_mac_context_apply(iwx_softc *, uint32_t);\n"
        "    int iwx_p2p_mac_context_add(iwx_softc *);\n"
        "    int iwx_p2p_mac_context_remove(iwx_softc *);\n"
        "    int iwx_send_cmd_pdu(iwx_softc *, uint32_t, uint32_t, uint16_t, const void *);\n"
        "    static NativeP2PProbe::BlockedReason tahoeP2pRevalidate(void *, uint32_t, uint32_t);\n"
        "    static int tahoeP2pConfigure(void *);\n"
        "    static int tahoeP2pAdd(void *);\n"
        "    static int tahoeP2pRemove(void *);\n"
        "    static bool tahoeP2pPublishLease(void *, bool);\n"
        "    static int tahoeP2pExerciseRoc(void *);\n"
        "    static bool tahoeP2pExerciseRecovery(void *, int32_t, NativeP2PProbe::ExerciseRecoveryProof *);\n"
        "    NativeP2PProbe::Operations configuredOperations(P2PProbeRun &);\n"
        "    NativeP2PProbe::Operations legacyOperations(P2PProbeRun &);\n"
        "",
        1,
    )
    if "NativeP2PProbe::Controller nativeP2pProbe_{};" not in shim:
        raise AssertionError("could not extend production stop-guard shim")
    return shim


operations_start = PROBE.index("        NativeP2PProbe::Operations operations{")
operations_end = PROBE.index(
    "        owner->nativeP2pProbe_.executeOnce(operations)", operations_start
)
operations_block = PROBE[operations_start:operations_end]
legacy_block = operations_block.replace(
    "if (run.rx149ObservationOnly\n#if ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332\n"
    "            || run.directedDataOnly\n#endif\n            )",
    "if (run.rx149ObservationOnly)",
    1,
)
if legacy_block == operations_block or "run.directedDataOnly" not in operations_block:
    raise AssertionError("Test115 recovery callback wiring no longer has DirectedData case")

worker = extract(PROBE, "static int exerciseDirectedDataTx(P2PProbeRun *probe)")
not_ready_end = extract(worker, "if (!started) {")
started_cleanup = extract(worker, "auto failStartedSessionCleanly = [&](\n")
recovery_action = extract(
    PROBE, "IOReturn ItlIwx::tahoeP2pExerciseRecoveryAction(")
recovery_entry = extract(PROBE, "bool ItlIwx::tahoeP2pExerciseRecovery(")
controller_recovery = extract(
    (ROOT / "native/p2p_hal_probe.cpp").read_text(),
    "bool safeToRemoveAfterExerciseFailure(")
retained = extract(ITL, "bool ItlIwx::nativeP2pResourcesRetained()")
stop = extract(PROBE, "int ItlIwx::tahoeP2pStopBeforeReset(")
stop_caller = extract(ITL, "int ItlIwx::\niwx_stop(")
init = extract(ITL, "int ItlIwx::\niwx_init(")
mac_apply = extract(ITL, "int ItlIwx::\niwx_p2p_mac_context_apply(")
mac_add = extract(ITL, "int ItlIwx::\niwx_p2p_mac_context_add(")
mac_remove = extract(ITL, "int ItlIwx::\niwx_p2p_mac_context_remove(")
remove_callback = extract(PROBE, "static int remove(void *opaque)")
tahoe_remove = extract(PROBE, "int ItlIwx::tahoeP2pRemove(void *opaque)")
configure_callback = extract(PROBE, "static int configure(void *opaque)")
add_callback = extract(PROBE, "static int add(void *opaque)")
tahoe_configure = extract(PROBE, "int ItlIwx::tahoeP2pConfigure(void *opaque)")
tahoe_add = extract(PROBE, "int ItlIwx::tahoeP2pAdd(void *opaque)")

# Bind the positive fixture to the actual END branch, inner cleanup gates,
# recovery proof producer, outer REMOVE method and reset/init guards.
assert "return failStartedSessionCleanly(failure," in not_ready_end
assert "directedDataSessionEndConfirmed(event.snapshot" in not_ready_end
assert "cleanup_before_session:" not in not_ready_end
assert "directedDataHasNoDoorbell(owner,&noDoorbellCheck)" in started_cleanup
assert "iwx_tahoe_p2p_tvqm_abort_idle_after_end(" in started_cleanup
assert "owner->tahoeP2pRocCleanup(" in started_cleanup
assert "directedDataInnerResourcesAbsent(owner)" in started_cleanup
assert "probe->directedDataFailureCleaned = true;" in started_cleanup
assert "probe->directedDataCleanupAck = true;" in started_cleanup
assert "(run->directedDataOnly && run->directedDataFailureCleaned)" in recovery_entry
for field in (
    "proof->ownerMatches", "proof->contextGenerationMatches",
    "proof->powerGenerationMatches", "proof->firmwareGenerationMatches",
    "proof->p2pFirmwareGenerationMatches", "proof->stationGenerationMatches",
    "proof->directedDataCanonicalEnd", "proof->directedDataNoDoorbell",
    "proof->directedDataTicketClosed", "proof->directedDataQueueDrained",
    "proof->directedDataResourcesAbsent", "proof->fullyRestored",
    "proof->bindingAbsent", "proof->phyUnleased",
):
    assert field in recovery_action, f"recovery proof source lost {field}"
assert "data.originClosed && !data.originTicketBound" in recovery_action
assert "p.directedDataCanonicalEnd" in controller_recovery
assert "p.directedDataNoDoorbell" in controller_recovery
assert "p.directedDataTicketClosed" in controller_recovery
assert "p.directedDataQueueDrained" in controller_recovery
assert "p.directedDataResourcesAbsent" in controller_recovery
assert "return run->owner->iwx_p2p_mac_context_remove(&run->owner->com);" in remove_callback
assert "return remove(opaque);" in tahoe_remove
assert "state == IWX_P2P_RESOURCE_UNKNOWN" in mac_apply
assert "sc->sc_p2p.binding_state != IWX_P2P_RESOURCE_ABSENT" in mac_apply
assert "sc->sc_p2p.mac_state = action == IWX_FW_CTXT_ACTION_REMOVE ?" in mac_apply
assert "if (nativeP2pResourcesRetained())" in stop
assert "if (nativeP2pResourcesRetained())" in init
assert "tahoeP2pStopBeforeReset(sc)" in stop_caller
assert stop_caller.index("tahoeP2pStopBeforeReset(sc)") < stop_caller.index(
    "taskq_try_pause_with_diagnostics")
assert init.index("if (nativeP2pResourcesRetained())") < init.index("memset(sc->sc_tid_data")

base_stop_shim = assignment_string(WORKER_TEST, "stop_shim")
shim = extend_stop_shim(base_stop_shim)

production_removal = "\n\n".join((
    configure_callback,
    add_callback,
    remove_callback,
    tahoe_configure,
    tahoe_add,
    tahoe_remove,
    mac_apply,
    mac_add,
    mac_remove,
))


def operation_method(block: str, name: str) -> str:
    return (
        f"NativeP2PProbe::Operations ItlIwx::{name}(P2PProbeRun &run) {{\n"
        "    ItlIwx *owner = this;\n" + block +
        "    return operations;\n}\n"
    )


class_methods = operation_method(operations_block, "configuredOperations") + "\n" + \
    operation_method(legacy_block, "legacyOperations")

fixture = r"""
#include <array>
#include <cstring>

enum { IWX_P2P_UNCERTAIN_BINDING = 2 };
constexpr int kOSBooleanTrue = 1;
struct iwx_mac_ctx_cmd { uint32_t action = 0; uint8_t bytes[140]{}; };
static_assert(sizeof(iwx_mac_ctx_cmd) == 144, "MAC context fixture size");

static int iwx_p2p_check_fw_contract(ItlIwx *owner, iwx_softc *sc) {
    return owner && sc == &owner->com ? 0 : EINVAL;
}
static void iwx_p2p_fill_mac_context(
    const iwx_p2p_context *, uint32_t action, iwx_mac_ctx_cmd *cmd) {
    cmd->action = action;
}

NativeP2PProbe::BlockedReason ItlIwx::tahoeP2pRevalidate(
    void *opaque, uint32_t powerGeneration, uint32_t stationGeneration) {
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner || !run->owner->nativeP2pCommandAllowed())
        return NativeP2PProbe::kGateActionFailed;
    if (run->powerGeneration != powerGeneration ||
        run->stationGeneration != stationGeneration ||
        run->owner->com.sc_generation != static_cast<int>(powerGeneration) ||
        run->owner->nativeP2pPowerGeneration_ != powerGeneration ||
        run->owner->nativeP2pStationGeneration_ != stationGeneration)
        return NativeP2PProbe::kGenerationChanged;
    return NativeP2PProbe::kNotBlocked;
}

int ItlIwx::iwx_p2p_mac_context_configure(
    iwx_softc *sc, uint8_t, uint8_t, uint8_t, const uint8_t *) {
    if (sc != &com) return EINVAL;
    if (configureResult) return configureResult;
    sc->sc_p2p.initialized = 1;
    sc->sc_p2p.mac_state = IWX_P2P_RESOURCE_ABSENT;
    sc->sc_p2p.binding_state = IWX_P2P_RESOURCE_ABSENT;
    sc->sc_p2p.phy_leased = false;
    sc->sc_p2p.fw_generation = static_cast<uint32_t>(sc->sc_generation);
    return 0;
}

int ItlIwx::iwx_send_cmd_pdu(
    iwx_softc *sc, uint32_t command, uint32_t flags, uint16_t length,
    const void *payload) {
    assert(sc == &com && command == IWX_MAC_CONTEXT_CMD && flags == 0);
    assert(length == sizeof(iwx_mac_ctx_cmd) && payload);
    ++pduSends;
    const auto *cmd = static_cast<const iwx_mac_ctx_cmd *>(payload);
    return cmd->action == IWX_FW_CTXT_ACTION_REMOVE ?
        removePduResult : addPduResult;
}

""" + production_removal + r"""

bool ItlIwx::tahoeP2pPublishLease(void *opaque, bool mayExist) {
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner) return false;
    run->owner->publishedLease = mayExist;
    return true;
}

int ItlIwx::tahoeP2pExerciseRoc(void *opaque) {
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner) return EINVAL;
    auto &owner = *run->owner;
    // The actual worker source above proves this state can be published only
    // after canonical END, no-doorbell, exact ticket close, queue/station drain,
    // and ROC binding/PHY restoration. This fixture models that callback edge.
    owner.com.sc_p2p.binding_state = IWX_P2P_RESOURCE_ACTIVE;
    owner.com.sc_p2p.phy_leased = true;
    owner.nativeP2pStation_.state = TahoeP2PResourceState::kActive;
    owner.nativeP2pTxQueue_.state = TahoeP2PResourceState::kActive;
    run->cleanupCompleted = run->canonicalEnd && run->noDoorbell &&
        run->ticketClosed && run->queueDrained && run->resourcesAbsent &&
        run->fullyRestored && run->bindingAbsent && run->phyUnleased &&
        run->rocIdle;
    if (run->cleanupCompleted) {
        owner.com.sc_p2p.binding_state = IWX_P2P_RESOURCE_ABSENT;
        owner.com.sc_p2p.phy_leased = false;
        owner.nativeP2pStation_.state = TahoeP2PResourceState::kAbsent;
        owner.nativeP2pTxQueue_.state = TahoeP2PResourceState::kAbsent;
    }
    if (run->changeEpochAfterCleanup) {
        ++owner.com.sc_generation;
        ++owner.nativeP2pProbeGeneration_;
        ++owner.nativeP2pPowerGeneration_;
        ++owner.nativeP2pStationGeneration_;
    }
    return ETIMEDOUT;
}

bool ItlIwx::tahoeP2pExerciseRecovery(
    void *opaque, int32_t error,
    NativeP2PProbe::ExerciseRecoveryProof *proof) {
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner || !proof || error == 0 ||
        !run->recoverySupported || !run->cleanupCompleted)
        return false;
    *proof = {};
    proof->directedDataRecovery = true;
    proof->snapshotValid = proof->snapshotStable = true;
    proof->ownerMatches = run->ownerMatches;
    proof->contextGenerationMatches = run->contextMatches &&
        run->owner->nativeP2pProbeGeneration_ == run->contextGeneration;
    proof->powerGenerationMatches = run->powerMatches &&
        static_cast<uint32_t>(run->owner->com.sc_generation) == run->powerGeneration &&
        run->owner->nativeP2pPowerGeneration_ == run->powerGeneration;
    proof->firmwareGenerationMatches = run->firmwareMatches &&
        static_cast<uint32_t>(run->owner->com.sc_generation) == run->powerGeneration;
    proof->p2pFirmwareGenerationMatches = run->p2pFirmwareMatches &&
        run->owner->com.sc_p2p.fw_generation == run->powerGeneration &&
        run->p2pFirmwareGeneration == run->powerGeneration;
    proof->stationGenerationMatches = run->stationMatches &&
        run->owner->nativeP2pStationGeneration_ == run->stationGeneration;
    proof->directedDataSessionSubmitted = true;
    proof->directedDataCanonicalEnd = run->canonicalEnd;
    proof->directedDataNoDoorbell = run->noDoorbell;
    proof->directedDataTicketClosed = run->ticketClosed;
    proof->directedDataQueueDrained = run->queueDrained;
    proof->directedDataResourcesAbsent = run->resourcesAbsent;
    proof->fullyRestored = run->fullyRestored;
    proof->bindingAbsent = run->bindingAbsent;
    proof->phyUnleased = run->phyUnleased;
    proof->rocIdle = run->rocIdle;
    proof->restoreComplete = run->fullyRestored;
    proof->sessionOutcomeUnknown = false;
    proof->txResourcesPresent = !run->queueDrained || !run->resourcesAbsent;
    proof->cleanupErrno = run->resourcesAbsent ? 0 : EBUSY;
    proof->attemptSerial = run->contextGeneration;
    proof->snapshotRevision = 2;
    return true;
}

""" + "\n#define ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332 1\n" + \
    class_methods + "\n#undef ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332\n" + r"""

static int runCase(P2PProbeRun run, bool legacyOps, int removeAck = 0) {
    ItlIwx owner;
    run.owner = &owner;
    owner.com.sc_generation = static_cast<int>(run.powerGeneration);
    owner.nativeP2pProbeGeneration_ = run.contextGeneration;
    owner.nativeP2pPowerGeneration_ = run.powerGeneration;
    owner.nativeP2pStationGeneration_ = run.stationGeneration;
    owner.removePduResult = removeAck;
    NativeP2PProbe::Admission admission{};
    admission.enabled = admission.mainGateAvailable = true;
    admission.mainGateNotOnThread = admission.driverRunning = true;
    admission.associated = admission.portAuthorized = true;
    admission.scanIdle = admission.commandQueueIdle = true;
    admission.stateQueuePaused = admission.noPendingNewstate = true;
    admission.radioAvailable = admission.firmwareHealthy = true;
    admission.p2pContextAbsent = admission.p2pCapabilityAvailable = true;
    admission.contextGeneration = run.contextGeneration;
    admission.powerGeneration = run.powerGeneration;
    admission.stationGeneration = run.stationGeneration;
    assert(owner.nativeP2pProbe_.tryQueue(admission));
    auto operations = legacyOps ? owner.legacyOperations(run) :
                                  owner.configuredOperations(run);
    const auto result = owner.nativeP2pProbe_.executeOnce(operations);
    owner.busy = false; // The production finish action releases worker ownership.
    owner.nativeP2pProbeQueued_ = 0;
    const auto snapshot = owner.nativeP2pProbe_.snapshot();

    if (!legacyOps && run.recoverySupported && run.cleanupCompleted &&
        removeAck == 0 && !run.changeEpochAfterCleanup &&
        run.ownerMatches && run.contextMatches &&
        run.powerMatches && run.firmwareMatches && run.p2pFirmwareMatches &&
        run.stationMatches && run.canonicalEnd && run.noDoorbell &&
        run.ticketClosed && run.queueDrained && run.resourcesAbsent &&
        run.fullyRestored && run.bindingAbsent && run.phyUnleased && run.rocIdle) {
        assert(result == NativeP2PProbe::RunResult::kExerciseFailedCleaned);
        assert(snapshot.exerciseRecoveryProofAccepted == 1);
        assert(snapshot.removeResult == 0);
        assert(owner.com.sc_p2p.mac_state == IWX_P2P_RESOURCE_ABSENT);
        assert(!owner.publishedLease);
        assert(!owner.nativeP2pResourcesRetained());
        assert(owner.tahoeP2pStopBeforeReset(&owner.com) == 0);
        // iwx_init's exact admission test is this actual retained predicate;
        // source-order assertion above proves it runs before state mutation.
        assert(!owner.nativeP2pResourcesRetained());
    } else {
        assert(result == NativeP2PProbe::RunResult::kQuarantined);
        assert(snapshot.resourceMayExist == 1);
        assert(owner.nativeP2pResourcesRetained());
        assert(owner.tahoeP2pStopBeforeReset(&owner.com) == EBUSY);
    }
    return static_cast<int>(result);
}

int main() {
    // Actual production Operations wiring: DirectedData NoReady + canonical
    // END reaches the recovery proof, performs the real MAC_CONTEXT REMOVE,
    // and opens both production retained-resource guards.
    P2PProbeRun good{};
    good.directedDataOnly = true;
    assert(runCase(good, false) ==
           static_cast<int>(NativeP2PProbe::RunResult::kExerciseFailedCleaned));

    // The previous RX149-only callback wiring is a red control: it quarantines
    // the same directed-data failure before the outer REMOVE is submitted.
    P2PProbeRun oldWiring{};
    oldWiring.directedDataOnly = true;
    assert(runCase(oldWiring, true) ==
           static_cast<int>(NativeP2PProbe::RunResult::kQuarantined));

    // A recovery callback that declines/does not support the case stays held.
    P2PProbeRun unsupported{};
    unsupported.directedDataOnly = true;
    unsupported.recoverySupported = false;
    assert(runCase(unsupported, false) ==
           static_cast<int>(NativeP2PProbe::RunResult::kQuarantined));

    // Incomplete cleanup and proof identity failures cannot remove the MAC.
    for (int mutation = 0; mutation < 12; ++mutation) {
        P2PProbeRun invalid{};
        invalid.directedDataOnly = true;
        switch (mutation) {
            case 0: invalid.canonicalEnd = false; break;
            case 1: invalid.noDoorbell = false; break;
            case 2: invalid.ticketClosed = false; break;
            case 3: invalid.queueDrained = false; break;
            case 4: invalid.resourcesAbsent = false; break;
            case 5: invalid.ownerMatches = false; break;
            case 6: invalid.contextMatches = false; break;
            case 7: invalid.powerMatches = false; break;
            case 8: invalid.firmwareMatches = false; break;
            case 9: invalid.p2pFirmwareMatches = false; break;
            case 10: invalid.stationMatches = false; break;
            case 11: invalid.fullyRestored = false; break;
        }
        assert(runCase(invalid, false) ==
               static_cast<int>(NativeP2PProbe::RunResult::kQuarantined));
    }

    // A real REMOVE command error changes the MAC state to UNKNOWN and the
    // outer Controller retains its lease; stop remains blocked.
    P2PProbeRun removeFailure{};
    removeFailure.directedDataOnly = true;
    assert(runCase(removeFailure, false, EIO) ==
           static_cast<int>(NativeP2PProbe::RunResult::kQuarantined));

    // A live owner/power/station epoch change after cleanup invalidates the
    // captured proof before REMOVE and leaves stop blocked.
    P2PProbeRun changedEpoch{};
    changedEpoch.directedDataOnly = true;
    changedEpoch.changeEpochAfterCleanup = true;
    assert(runCase(changedEpoch, false) ==
           static_cast<int>(NativeP2PProbe::RunResult::kQuarantined));
}
"""

fixture = extend_stop_shim(assignment_string(WORKER_TEST, "stop_shim")) + "\n" + fixture

with tempfile.TemporaryDirectory(prefix="test115-directed-remove-") as tmp:
    source = Path(tmp) / "directed_remove.cpp"
    binary = Path(tmp) / "directed_remove"
    # Recovery wiring uses the real DirectedData build branch. The production
    # reset guard bodies are compiled with the optional data snapshot branch
    # disabled; their MAC/binding/PHY/queue/station logic remains verbatim.
    stop_functions = "\n\n".join((retained, stop))
    actual_stop = "\n#undef ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332\n" + stop_functions
    fixture += "\n" + actual_stop + "\n"
    source.write_text(fixture)
    subprocess.run(
        [
            "clang++", "-std=c++14", "-O1", "-g", "-Wall", "-Wextra",
            "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", "-I", str(ROOT), str(source),
            str(ROOT / "native/p2p_hal_probe.cpp"), "-o", str(binary),
        ],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

# Ordinary-Wi-Fi profiles omit P2PProbeRun::directedDataOnly entirely. Compile
# the exact production assignment with that feature macro off to guard the
# field's build boundary while keeping RX149 recovery enabled.
ordinary_prefix = r"""
#include <cassert>
#include <cstdint>
#include "native/p2p_hal_probe.hpp"
#define ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332 0
constexpr int kOSBooleanTrue = 1;
struct P2PProbeRun {
    bool rx149ObservationOnly = false;
    bool directedPrepareOnly = false;
    bool txProbeEnabled = false;
};
struct Controller { uint32_t getProperty(const char *) const { return 0; } };
struct Owner {
    Controller controller;
    Controller *getController() { return &controller; }
    NativeP2PProbe::Controller nativeP2pProbe_{};
};
static NativeP2PProbe::BlockedReason tahoeP2pRevalidate(void *, uint32_t, uint32_t) {
    return NativeP2PProbe::kNotBlocked;
}
static int tahoeP2pConfigure(void *) { return 0; }
static int tahoeP2pAdd(void *) { return 0; }
static int tahoeP2pRemove(void *) { return 0; }
static bool tahoeP2pPublishLease(void *, bool) { return true; }
static int tahoeP2pExerciseRoc(void *) { return 0; }
static bool tahoeP2pExerciseRecovery(void *, int32_t,
                                     NativeP2PProbe::ExerciseRecoveryProof *) {
    return true;
}
Owner globalOwner;
static NativeP2PProbe::Operations ordinaryOperations(P2PProbeRun &run) {
    Owner *owner = &globalOwner;
"""
ordinary_main = r"""
    return operations;
}
int main() {
    P2PProbeRun rx149{};
    rx149.rx149ObservationOnly = true;
    auto rxOps = ordinaryOperations(rx149);
    assert(rxOps.exerciseRecovery != nullptr);
    P2PProbeRun normal{};
    auto normalOps = ordinaryOperations(normal);
    assert(normalOps.exerciseRecovery == nullptr);
}
"""
ordinary_source = ordinary_prefix + operations_block + ordinary_main
with tempfile.TemporaryDirectory(prefix="test115-ordinary-profile-") as tmp:
    source = Path(tmp) / "ordinary_profile.cpp"
    binary = Path(tmp) / "ordinary_profile"
    source.write_text(ordinary_source)
    subprocess.run(
        [
            "clang++", "-std=c++14", "-O1", "-Wall", "-Wextra", "-Werror",
            "-Wno-unused-parameter", "-I", str(ROOT), str(source),
            str(ROOT / "native/p2p_hal_probe.cpp"), "-o", str(binary),
        ],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

print("PASS: DirectedData NoReady/END recovery wiring, actual HAL REMOVE, and stop/init resource gates")
