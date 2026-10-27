// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_interface.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

using NativeAwdl::InterfaceLifecycle;
using NativeAwdl::InterfaceOps;
using NativeAwdl::InterfaceStatus;
using NativeAwdl::VirtualRequestInfo;

namespace {

enum class FailurePoint {
    None,
    Allocate,
    Initialize,
    Prepare,
    Publish,
    Attach,
    Start,
    StopHardware,
    Detach,
    ClearPublished
};

struct Fixture {
    FailurePoint failure {FailurePoint::None};
    bool ready {true};
    bool published {false};
    bool allocated {false};
    bool attached {false};
    bool started {false};
    unsigned int releaseCount {0};
    char trace[128] {};
    size_t traceLength {0};
    int token {1};

    void record(char value)
    {
        assert(traceLength + 1 < sizeof(trace));
        trace[traceLength++] = value;
        trace[traceLength] = '\0';
    }
};

InterfaceStatus failIf(Fixture *fixture, FailurePoint point)
{
    return fixture->failure == point ? InterfaceStatus::NativeFailure
                                     : InterfaceStatus::Success;
}

InterfaceStatus hardwareReady(void *opaque)
{
    auto *fixture = static_cast<Fixture *>(opaque);
    fixture->record('R');
    return fixture->ready ? InterfaceStatus::Success : InterfaceStatus::NotReady;
}

InterfaceStatus alreadyPublished(void *opaque, bool *published)
{
    auto *fixture = static_cast<Fixture *>(opaque);
    fixture->record('Q');
    *published = fixture->published;
    return InterfaceStatus::Success;
}

InterfaceStatus allocate(void *opaque, void **interface)
{
    auto *fixture = static_cast<Fixture *>(opaque);
    fixture->record('A');
    const InterfaceStatus status = failIf(fixture, FailurePoint::Allocate);
    if (status == InterfaceStatus::Success) {
        fixture->allocated = true;
        *interface = &fixture->token;
    }
    return status;
}

InterfaceStatus initialize(void *opaque, void *interface,
                           const VirtualRequestInfo &)
{
    auto *fixture = static_cast<Fixture *>(opaque);
    assert(interface == &fixture->token);
    fixture->record('I');
    return failIf(fixture, FailurePoint::Initialize);
}

InterfaceStatus prepareHardware(void *opaque, void *interface)
{
    auto *fixture = static_cast<Fixture *>(opaque);
    assert(interface == &fixture->token);
    fixture->record('H');
    return failIf(fixture, FailurePoint::Prepare);
}

InterfaceStatus publish(void *opaque, void *interface)
{
    auto *fixture = static_cast<Fixture *>(opaque);
    assert(interface == &fixture->token);
    fixture->record('P');
    const InterfaceStatus status = failIf(fixture, FailurePoint::Publish);
    if (status == InterfaceStatus::Success)
        fixture->published = true;
    return status;
}

InterfaceStatus attach(void *opaque, void *interface)
{
    auto *fixture = static_cast<Fixture *>(opaque);
    assert(interface == &fixture->token);
    fixture->record('T');
    const InterfaceStatus status = failIf(fixture, FailurePoint::Attach);
    if (status == InterfaceStatus::Success)
        fixture->attached = true;
    return status;
}

InterfaceStatus startService(void *opaque, void *interface)
{
    auto *fixture = static_cast<Fixture *>(opaque);
    assert(interface == &fixture->token);
    fixture->record('S');
    const InterfaceStatus status = failIf(fixture, FailurePoint::Start);
    if (status == InterfaceStatus::Success)
        fixture->started = true;
    return status;
}

InterfaceStatus stopHardware(void *opaque, void *interface)
{
    auto *fixture = static_cast<Fixture *>(opaque);
    assert(interface == &fixture->token);
    fixture->record('h');
    return failIf(fixture, FailurePoint::StopHardware);
}

InterfaceStatus detach(void *opaque, void *interface)
{
    auto *fixture = static_cast<Fixture *>(opaque);
    assert(interface == &fixture->token);
    fixture->record('D');
    const InterfaceStatus status = failIf(fixture, FailurePoint::Detach);
    if (status == InterfaceStatus::Success) {
        fixture->attached = false;
        fixture->started = false;
    }
    return status;
}

InterfaceStatus clearPublished(void *opaque, void *interface)
{
    auto *fixture = static_cast<Fixture *>(opaque);
    assert(interface == &fixture->token);
    fixture->record('C');
    const InterfaceStatus status = failIf(fixture, FailurePoint::ClearPublished);
    if (status == InterfaceStatus::Success)
        fixture->published = false;
    return status;
}

void release(void *opaque, void *interface)
{
    auto *fixture = static_cast<Fixture *>(opaque);
    assert(interface == &fixture->token);
    fixture->record('X');
    fixture->allocated = false;
    ++fixture->releaseCount;
}

InterfaceOps opsFor(Fixture *fixture)
{
    return {fixture, hardwareReady, alreadyPublished, allocate, initialize,
            prepareHardware, publish, attach, startService, stopHardware,
            detach, clearPublished, release};
}

VirtualRequestInfo validRequest()
{
    VirtualRequestInfo request {};
    const uint8_t mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(request.address, mac, sizeof(mac));
    request.role = 6;
    return request;
}

void testNotReadyCreatesNothing()
{
    Fixture fixture;
    fixture.ready = false;
    InterfaceLifecycle lifecycle;
    void *result = reinterpret_cast<void *>(1);
    assert(lifecycle.start(validRequest(), opsFor(&fixture), &result) ==
           InterfaceStatus::NotReady);
    assert(result == nullptr);
    assert(!lifecycle.hasObject());
    assert(strcmp(fixture.trace, "R") == 0);
}

void testSuccessfulCreateAndStopOrder()
{
    Fixture fixture;
    InterfaceLifecycle lifecycle;
    void *result = nullptr;
    assert(lifecycle.start(validRequest(), opsFor(&fixture), &result) ==
           InterfaceStatus::Success);
    assert(result == &fixture.token);
    assert(lifecycle.isStarted());
    assert(fixture.published && fixture.attached && fixture.started);
    assert(strcmp(fixture.trace, "RQAIHPTS") == 0);

    assert(lifecycle.stop() == InterfaceStatus::Success);
    assert(strcmp(fixture.trace, "RQAIHPTShDCX") == 0);
    assert(!lifecycle.hasObject());
    assert(!fixture.published && !fixture.attached && !fixture.started);
    assert(fixture.releaseCount == 1);
}

void testInitializeFailureReleasesObject()
{
    Fixture fixture;
    fixture.failure = FailurePoint::Initialize;
    InterfaceLifecycle lifecycle;
    assert(lifecycle.start(validRequest(), opsFor(&fixture)) ==
           InterfaceStatus::NativeFailure);
    assert(strcmp(fixture.trace, "RQAIX") == 0);
    assert(!lifecycle.hasObject());
    assert(fixture.releaseCount == 1);
}

void testAllocationFailureLeavesNoObject()
{
    Fixture fixture;
    fixture.failure = FailurePoint::Allocate;
    InterfaceLifecycle lifecycle;
    assert(lifecycle.start(validRequest(), opsFor(&fixture)) ==
           InterfaceStatus::NativeFailure);
    assert(strcmp(fixture.trace, "RQA") == 0);
    assert(!lifecycle.hasObject());
    assert(fixture.releaseCount == 0);
}

void testPrepareFailureCallsPartialCleanup()
{
    Fixture fixture;
    fixture.failure = FailurePoint::Prepare;
    InterfaceLifecycle lifecycle;
    assert(lifecycle.start(validRequest(), opsFor(&fixture)) ==
           InterfaceStatus::NativeFailure);
    assert(strcmp(fixture.trace, "RQAIHhX") == 0);
    assert(!lifecycle.hasObject());
    assert(fixture.releaseCount == 1);
}

void testPublishFailureDoesNotLeavePointer()
{
    Fixture fixture;
    fixture.failure = FailurePoint::Publish;
    InterfaceLifecycle lifecycle;
    assert(lifecycle.start(validRequest(), opsFor(&fixture)) ==
           InterfaceStatus::NativeFailure);
    assert(strcmp(fixture.trace, "RQAIHPhCX") == 0);
    assert(!fixture.published);
    assert(!lifecycle.hasObject());
}

void testStartFailureUnwinds()
{
    Fixture fixture;
    fixture.failure = FailurePoint::Start;
    InterfaceLifecycle lifecycle;
    assert(lifecycle.start(validRequest(), opsFor(&fixture)) ==
           InterfaceStatus::NativeFailure);
    assert(strcmp(fixture.trace, "RQAIHPTShDCX") == 0);
    assert(!lifecycle.hasObject());
    assert(!fixture.published && !fixture.attached);
    assert(fixture.releaseCount == 1);
}

void testAttachFailureUnwinds()
{
    Fixture fixture;
    fixture.failure = FailurePoint::Attach;
    InterfaceLifecycle lifecycle;
    assert(lifecycle.start(validRequest(), opsFor(&fixture)) ==
           InterfaceStatus::NativeFailure);
    assert(strcmp(fixture.trace, "RQAIHPThCX") == 0);
    assert(!lifecycle.hasObject());
    assert(!fixture.published && !fixture.attached);
    assert(fixture.releaseCount == 1);
}

void testDetachFaultRetainsObjectForRetry()
{
    Fixture fixture;
    InterfaceLifecycle lifecycle;
    assert(lifecycle.start(validRequest(), opsFor(&fixture)) ==
           InterfaceStatus::Success);
    fixture.failure = FailurePoint::Detach;
    assert(lifecycle.stop() == InterfaceStatus::CleanupPending);
    assert(lifecycle.hasObject());
    assert(fixture.attached);
    assert(fixture.published);
    assert(fixture.releaseCount == 0);

    fixture.failure = FailurePoint::None;
    assert(lifecycle.stop() == InterfaceStatus::Success);
    assert(!lifecycle.hasObject());
    assert(!fixture.published && !fixture.attached);
    assert(fixture.releaseCount == 1);
}

void testHardwareStopFaultRetainsObjectForRetry()
{
    Fixture fixture;
    InterfaceLifecycle lifecycle;
    assert(lifecycle.start(validRequest(), opsFor(&fixture)) ==
           InterfaceStatus::Success);
    fixture.failure = FailurePoint::StopHardware;
    assert(lifecycle.stop() == InterfaceStatus::CleanupPending);
    assert(lifecycle.hasObject());
    assert(fixture.attached && fixture.published);
    assert(fixture.releaseCount == 0);

    fixture.failure = FailurePoint::None;
    assert(lifecycle.stop() == InterfaceStatus::Success);
    assert(!lifecycle.hasObject());
    assert(fixture.releaseCount == 1);
}

void testClearPointerFaultRetainsObjectForRetry()
{
    Fixture fixture;
    InterfaceLifecycle lifecycle;
    assert(lifecycle.start(validRequest(), opsFor(&fixture)) ==
           InterfaceStatus::Success);
    fixture.failure = FailurePoint::ClearPublished;
    assert(lifecycle.stop() == InterfaceStatus::CleanupPending);
    assert(lifecycle.hasObject());
    assert(fixture.published);
    assert(!fixture.attached);
    assert(fixture.releaseCount == 0);

    fixture.failure = FailurePoint::None;
    assert(lifecycle.stop() == InterfaceStatus::Success);
    assert(!lifecycle.hasObject());
    assert(!fixture.published);
    assert(fixture.releaseCount == 1);
}

void testPublishedInterfaceBusy()
{
    Fixture fixture;
    fixture.published = true;
    InterfaceLifecycle lifecycle;
    assert(lifecycle.start(validRequest(), opsFor(&fixture)) ==
           InterfaceStatus::Busy);
    assert(strcmp(fixture.trace, "RQ") == 0);
    assert(!fixture.allocated);
}

void testInvalidRoleRejectedBeforeNativeCalls()
{
    Fixture fixture;
    InterfaceLifecycle lifecycle;
    VirtualRequestInfo request = validRequest();
    request.role = 7;
    assert(lifecycle.start(request, opsFor(&fixture)) ==
           InterfaceStatus::InvalidArgument);
    assert(fixture.traceLength == 0);
}

} // namespace

int main()
{
    testNotReadyCreatesNothing();
    testSuccessfulCreateAndStopOrder();
    testAllocationFailureLeavesNoObject();
    testInitializeFailureReleasesObject();
    testPrepareFailureCallsPartialCleanup();
    testPublishFailureDoesNotLeavePointer();
    testStartFailureUnwinds();
    testAttachFailureUnwinds();
    testDetachFaultRetainsObjectForRetry();
    testHardwareStopFaultRetainsObjectForRetry();
    testClearPointerFaultRetainsObjectForRetry();
    testPublishedInterfaceBusy();
    testInvalidRoleRejectedBeforeNativeCalls();
    return 0;
}
