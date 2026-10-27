// SPDX-License-Identifier: GPL-2.0-only
#include "../p2p_hal_probe.hpp"

#include <assert.h>
#include <stdint.h>

using namespace NativeP2PProbe;

struct FakeCommands {
    int configureResult{0};
    int addResult{0};
    int removeResult{0};
    unsigned configureCalls{0};
    unsigned addCalls{0};
    unsigned removeCalls{0};
    unsigned verifyCalls{0};
    unsigned failVerifyAt{0};
    unsigned leaseTrueCalls{0};
    unsigned leaseFalseCalls{0};
    bool failLeasePublish{false};
    int exerciseResult{0};
    unsigned exerciseCalls{0};

    static BlockedReason revalidate(void *context, uint32_t, uint32_t)
    {
        auto *f = static_cast<FakeCommands *>(context);
        ++f->verifyCalls;
        return f->verifyCalls == f->failVerifyAt
            ? kGenerationChanged : kNotBlocked;
    }
    static int configure(void *context)
    {
        auto *f = static_cast<FakeCommands *>(context);
        ++f->configureCalls;
        return f->configureResult;
    }
    static int add(void *context)
    {
        auto *f = static_cast<FakeCommands *>(context);
        ++f->addCalls;
        return f->addResult;
    }
    static int remove(void *context)
    {
        auto *f = static_cast<FakeCommands *>(context);
        ++f->removeCalls;
        return f->removeResult;
    }
    static bool publishLease(void *context, bool mayExist)
    {
        auto *f = static_cast<FakeCommands *>(context);
        if (mayExist) ++f->leaseTrueCalls;
        else ++f->leaseFalseCalls;
        return !f->failLeasePublish;
    }
    static int exercise(void *context)
    {
        auto *f = static_cast<FakeCommands *>(context);
        ++f->exerciseCalls;
        return f->exerciseResult;
    }
    Operations operations()
    { return {this, revalidate, configure, add, remove, publishLease}; }
};

static Admission readyAdmission()
{
    Admission a{};
    a.enabled = true;
    a.mainGateAvailable = true;
    a.mainGateNotOnThread = true;
    a.driverRunning = true;
    a.associated = true;
    a.portAuthorized = true;
    a.scanIdle = true;
    a.commandQueueIdle = true;
    a.stateQueuePaused = true;
    a.noPendingNewstate = true;
    a.radioAvailable = true;
    a.firmwareHealthy = true;
    a.p2pContextAbsent = true;
    a.p2pCapabilityAvailable = true;
    a.contextGeneration = 37;
    a.powerGeneration = 8;
    a.stationGeneration = 19;
    return a;
}

static void testSharedGateAdmissionPredicates()
{
    Admission a = readyAdmission();
    a.stateQueuePaused = false;
    a.noPendingNewstate = false;
    // The gate's runAction callback may execute on the caller thread. Admission
    // uses the caller's pre-runAction workloop snapshot, not thread inequality.
    assert(admissionBlockReason(a, false) == kNotBlocked);
    assert(admissionBlockReason(a, true) == kStateQueueBusy);

    a.mainGateNotOnThread = false;
    assert(admissionBlockReason(a, false) == kMainGateOnThread);
}

static void testSharedRevalidationPredicates()
{
    Revalidation state{};
    state.generationMatches = true;
    state.radioAvailable = true;
    state.firmwareHealthy = true;
    state.driverRunning = true;
    state.associated = true;
    state.portAuthorized = true;
    state.scanIdle = true;
    state.commandQueueIdle = true;
    state.stateQueuePaused = true;
    state.noPendingNewstate = true;
    state.p2pMacAbsent = true;
    state.p2pBindingAbsent = true;

    // Before configure/ADD, no context is expected yet.
    assert(revalidationBlockReason(state, false) == kNotBlocked);

    state.p2pContextInitialized = true;
    state.p2pGenerationMatches = true;
    state.addAcknowledged = true;
    state.p2pMacAbsent = false;
    state.p2pMacActive = true;
    // After ADD ACK, require the exact live context and generation.
    assert(revalidationBlockReason(state, true) == kNotBlocked);

    state.p2pGenerationMatches = false;
    assert(revalidationBlockReason(state, true) == kGenerationChanged);
    state.p2pGenerationMatches = true;
    state.p2pMacActive = false;
    assert(revalidationBlockReason(state, true) == kFirmwareOutcomeUnknown);
}

static void testCommandGuardKeepsQueuedProbeInert()
{
    const void *worker = reinterpret_cast<const void *>(uintptr_t(0x1110));
    const void *other = reinterpret_cast<const void *>(uintptr_t(0x2220));

    // While the task is only queued, active busy stays false so ordinary
    // firmware commands (including init) continue through their old path.
    assert(!genericCommandBlocked(false, nullptr, other, false, false));

    // Once admission installs the owner, only its worker may submit commands,
    // and never from inside the main gate/workloop callback.
    assert(genericCommandBlocked(true, worker, other, false, false));
    assert(!genericCommandBlocked(true, worker, worker, false, false));
    assert(genericCommandBlocked(true, worker, worker, true, false));
    assert(genericCommandBlocked(true, worker, worker, false, true));
}

static void testAdmissionIsDefaultOffAndDeferrable()
{
    Controller probe;
    Admission a = readyAdmission();
    FakeCommands f;

    a.enabled = false;
    assert(!probe.tryQueue(a));
    Snapshot s = probe.snapshot();
    assert(s.state == kDisabled && s.attempted == 0);
    assert(f.addCalls == 0);

    a.enabled = true;
    a.stateQueuePaused = false;
    assert(!probe.tryQueue(a));
    s = probe.snapshot();
    assert(s.state == kDeferred && s.blocked == kStateQueueBusy);
    assert(s.attempted == 0 && f.addCalls == 0);

    a.stateQueuePaused = true;
    a.portAuthorized = false;
    assert(!probe.tryQueue(a));
    s = probe.snapshot();
    assert(s.state == kDeferred && s.blocked == kPortUnauthorized);
    assert(s.attempted == 0);
}

static void testCanceledBeforeCommandRemainsRetryable()
{
    const BlockedReason reasons[] = {kCanceledBeforeStart, kProbeQueueBusy};
    for (BlockedReason reason : reasons) {
        Controller probe;
        Admission a = readyAdmission();
        assert(!probe.tryQueue(a, reason));
        assert(probe.snapshot().state == kDeferred);
        assert(probe.snapshot().attempted == 0);
        probe.resetDrained(a.powerGeneration + 1);
        assert(probe.snapshot().state == kDeferred);
        ++a.powerGeneration;
        assert(probe.tryQueue(a));
        FakeCommands commands;
        assert(probe.executeOnce(commands.operations()) == RunResult::kCompleted);
        assert(commands.addCalls == 1 && commands.removeCalls == 1);
    }
}

static void testOneAddThenOneRemove()
{
    Controller probe;
    FakeCommands f;
    assert(probe.tryQueue(readyAdmission()));
    assert(probe.executeOnce(f.operations()) == RunResult::kCompleted);
    const Snapshot s = probe.snapshot();
    assert(s.state == kComplete && s.attempted == 1);
    assert(s.addResult == 0 && s.removeResult == 0);
    assert(s.resourceMayExist == 0);
    assert(f.configureCalls == 1 && f.addCalls == 1 && f.removeCalls == 1);
    assert(f.leaseTrueCalls == 1 && f.leaseFalseCalls == 1);

    // Completion is one-shot even if the watchdog ticks again.
    assert(!probe.tryQueue(readyAdmission()));
    assert(f.addCalls == 1 && f.removeCalls == 1);
}

static void testConfigureFailureDoesNotMarkAttempt()
{
    Controller probe;
    FakeCommands f;
    f.configureResult = 22;
    assert(probe.tryQueue(readyAdmission()));
    assert(probe.executeOnce(f.operations()) == RunResult::kDeferred);
    Snapshot s = probe.snapshot();
    assert(s.state == kDeferred && s.attempted == 0);
    assert(s.blocked == kConfigureRejected);
    assert(f.configureCalls == 1 && f.addCalls == 0 && f.removeCalls == 0);

    f.configureResult = 0;
    assert(probe.tryQueue(readyAdmission()));
    assert(probe.executeOnce(f.operations()) == RunResult::kCompleted);
    assert(f.addCalls == 1 && f.removeCalls == 1);
}

static void testUncertainAddIsQuarantinedWithoutRetryOrRemove()
{
    Controller probe;
    FakeCommands f;
    f.addResult = 60;
    assert(probe.tryQueue(readyAdmission()));
    assert(probe.executeOnce(f.operations()) == RunResult::kQuarantined);
    Snapshot s = probe.snapshot();
    assert(s.state == kQuarantined && s.attempted == 1);
    assert(s.addResult == 60 && s.resourceMayExist == 1);
    assert(f.addCalls == 1 && f.removeCalls == 0 && f.leaseTrueCalls == 1);

    assert(!probe.tryQueue(readyAdmission()));
    assert(f.addCalls == 1 && f.removeCalls == 0);
    probe.resetDrained(9);
    s = probe.snapshot();
    assert(s.state == kResetDrained && s.attempted == 1);
    assert(s.resourceMayExist == 0 && s.powerGeneration == 9);
    assert(s.contextGeneration == 38);
    assert(!probe.tryQueue(readyAdmission()));
}

static void testLeasePublishFailureQuarantines()
{
    Controller probe;
    FakeCommands f;
    f.failLeasePublish = true;
    assert(probe.tryQueue(readyAdmission()));
    assert(probe.executeOnce(f.operations()) == RunResult::kQuarantined);
    const Snapshot s = probe.snapshot();
    assert(s.state == kQuarantined && s.attempted == 1);
    assert(s.resourceMayExist == 1);
    assert(f.addCalls == 1 && f.removeCalls == 0);
}

static void testUncertainRemoveAndGenerationChangeStayQuarantined()
{
    Controller removeProbe;
    FakeCommands f;
    f.removeResult = 62;
    assert(removeProbe.tryQueue(readyAdmission()));
    assert(removeProbe.executeOnce(f.operations()) == RunResult::kQuarantined);
    Snapshot s = removeProbe.snapshot();
    assert(s.state == kQuarantined && s.resourceMayExist == 1);
    assert(f.addCalls == 1 && f.removeCalls == 1 && f.leaseTrueCalls == 2);
    assert(!removeProbe.tryQueue(readyAdmission()));

    Controller generationProbe;
    FakeCommands g;
    g.failVerifyAt = 2; // After ADD ACK, before REMOVE.
    assert(generationProbe.tryQueue(readyAdmission()));
    assert(generationProbe.executeOnce(g.operations()) == RunResult::kQuarantined);
    s = generationProbe.snapshot();
    assert(s.state == kQuarantined && s.resourceMayExist == 1);
    assert(g.addCalls == 1 && g.removeCalls == 0);
}

int main()
{
    testSharedGateAdmissionPredicates();
    testSharedRevalidationPredicates();
    testCommandGuardKeepsQueuedProbeInert();
    testCanceledBeforeCommandRemainsRetryable();
    testAdmissionIsDefaultOffAndDeferrable();
    testOneAddThenOneRemove();
    testConfigureFailureDoesNotMarkAttempt();
    testUncertainAddIsQuarantinedWithoutRetryOrRemove();
    testUncertainRemoveAndGenerationChangeStayQuarantined();
    testLeasePublishFailureQuarantines();
    // MAC removal is forbidden if ROC leaves a possible PHY/binding/session.
    Controller exerciseFailure;
    FakeCommands badExercise;
    auto failingOps = badExercise.operations();
    failingOps.exercise = FakeCommands::exercise;
    badExercise.exerciseResult = 60;
    assert(exerciseFailure.tryQueue(readyAdmission()));
    assert(exerciseFailure.executeOnce(failingOps) == RunResult::kQuarantined);
    assert(badExercise.exerciseCalls == 1 && badExercise.removeCalls == 0);
    assert(exerciseFailure.snapshot().resourceMayExist == 1);
    assert(exerciseFailure.snapshot().blocked == kExerciseOutcomeUnknown);

    Controller exerciseSuccess;
    FakeCommands goodExercise;
    auto passingOps = goodExercise.operations();
    passingOps.exercise = FakeCommands::exercise;
    assert(exerciseSuccess.tryQueue(readyAdmission()));
    assert(exerciseSuccess.executeOnce(passingOps) == RunResult::kCompleted);
    assert(goodExercise.exerciseCalls == 1 && goodExercise.removeCalls == 1);
    assert(goodExercise.verifyCalls == 3);
    return 0;
}
