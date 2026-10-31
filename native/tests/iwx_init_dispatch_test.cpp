// SPDX-License-Identifier: GPL-2.0-only
#include "../iwx_init_dispatch.hpp"

#include <cassert>
#include <stdint.h>

using namespace IwxInitDispatch;

static const uint32_t kOn = kPowerStateKnown | kPowerRequestedOn;
static const uint32_t kOff = kPowerStateKnown;

static void testOldPopOffOnDoesNotStandInForNewDispatch()
{
    const Token oldDispatch {10, 40, 7, 3, kOn, 0};
    const CurrentState afterOffOn {41, 7, 5, kOn};
    assert(validate(oldDispatch, afterOffOn, false) ==
           Decision::PowerEpochChanged);

    const Token newDispatch {11, 41, 7, 5, kOn, 0};
    assert(validate(newDispatch, afterOffOn, true) == Decision::Run);
}

static void testSameGenerationInitStillRuns()
{
    const Token dispatch {1, 90, 4, 8, kOn, 0};
    const CurrentState current {90, 4, 8, kOn};
    assert(validate(dispatch, current, true) == Decision::Run);
}

static void testRepeatedQueuedRequestKeepsNewestPendingIdentity()
{
    const Token first {20, 12, 5, 9, kOn, 0};
    const Token coalesced {21, 12, 5, 9, kOn, 0};
    const CurrentState current {12, 5, 9, kOn};

    // The queue still has one pending node. Coalescing replaces its tag before
    // pop; the old copied dispatch is stale if it was already popped.
    assert(validate(first, current, false) == Decision::Superseded);
    assert(validate(coalesced, current, true) == Decision::Run);
}

static void testNewFaultSerialSurvivesAnOlderPoppedDispatch()
{
    const Token older {30, 12, 44, 9, kOn, kFaultRecovery};
    const CurrentState afterNewFault {12, 45, 9, kOn};
    const Token recovery {31, 12, 45, 9, kOn, kFaultRecovery};

    assert(validate(older, afterNewFault, false) == Decision::FaultAdvanced);
    assert(validate(recovery, afterNewFault, true) == Decision::Run);
}

static void testFreshFaultSurvivesGenerationAdvanceBeforeCallback()
{
    const Token recovery {32, 12, 46, 9, kOn, kFaultRecovery};
    const CurrentState afterStop {13, 46, 9, kOn};
    assert(validate(recovery, afterStop, true) == Decision::Run);

    const Token older {31, 12, 45, 9, kOn, kFaultRecovery};
    assert(validate(older, afterStop, true) == Decision::FaultAdvanced);
}

static void testGenerationAndExplicitOffRemainIndependentGates()
{
    const Token dispatch {50, 99, 0, 4, kOn, 0};
    const CurrentState changedDriver {100, 0, 4, kOn};
    assert(validate(dispatch, changedDriver, true) ==
           Decision::DriverGenerationChanged);

    // A historical fault serial on an ordinary dispatch does not turn it
    // into a recovery request that may survive another lifecycle generation.
    const Token ordinaryAfterFault {52, 99, 7, 4, kOn, 0};
    const CurrentState changedDriverAfterFault {100, 7, 4, kOn};
    assert(validate(ordinaryAfterFault, changedDriverAfterFault, true) ==
           Decision::DriverGenerationChanged);

    const Token freshRecoveryAfterFault {53, 99, 7, 4, kOn, kFaultRecovery};
    assert(validate(freshRecoveryAfterFault, changedDriverAfterFault, true) ==
           Decision::Run);

    const Token offDispatch {51, 100, 0, 5, kOff, 0};
    const CurrentState explicitlyOff {100, 0, 5, kOff};
    assert(validate(offDispatch, explicitlyOff, true) ==
           Decision::ExplicitlyOff);
}

static void testDispatchIdSkipsReservedZero()
{
    assert(nextDispatchId(0) == 1);
    assert(nextDispatchId(4) == 5);
    assert(nextDispatchId(UINT64_MAX) == 1);
    assert(dispatchIdIsNewer(1, UINT64_MAX - 1));
    assert(!dispatchIdIsNewer(UINT64_MAX - 1, 1));
    assert(nextFaultSerial(0) == 1);
    assert(nextFaultSerial(4) == 5);
    assert(nextFaultSerial(UINT32_MAX) == 1);
}

int main()
{
    testOldPopOffOnDoesNotStandInForNewDispatch();
    testSameGenerationInitStillRuns();
    testRepeatedQueuedRequestKeepsNewestPendingIdentity();
    testNewFaultSerialSurvivesAnOlderPoppedDispatch();
    testFreshFaultSurvivesGenerationAdvanceBeforeCallback();
    testGenerationAndExplicitOffRemainIndependentGates();
    testDispatchIdSkipsReservedZero();
    return 0;
}
