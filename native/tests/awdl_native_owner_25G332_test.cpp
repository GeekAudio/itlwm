// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_native_owner_25G332.hpp"

#include <assert.h>
#include <string.h>

using NativeAwdl25G332::InterfaceOwner;
using NativeAwdl25G332::NativeOps;
using NativeAwdl25G332::Status;
using NativeAwdl25G332::ReleaseState;

namespace {

enum class Failure { None, Allocate, Initialize, Attach, Start, Terminate };

struct Fixture {
    Failure failure {Failure::None};
    int controllerToken {1};
    int objectToken {2};
    int otherToken {3};
    void *published {nullptr};
    const void *initController {nullptr};
    const void *attachProvider {nullptr};
    const void *startProvider {nullptr};
    uint8_t initAddress[6] {};
    uint32_t initRole {0};
    char initName[16] {};
    bool attached {false};
    bool started {false};
    bool controllerOpen {false};
    bool privateResources {false};
    bool cleanupReady {true};
    bool startStateComplete {true};
    unsigned int verifyStartedCount {0};
    unsigned int prepareCount {0};
    ReleaseState lastReleaseState {ReleaseState::InitFailed};
    unsigned int releaseCount {0};
    char trace[128] {};
    size_t traceLength {0};

    void record(char c)
    {
        assert(traceLength + 1 < sizeof(trace));
        trace[traceLength++] = c;
        trace[traceLength] = '\0';
    }
};

void *allocate(void *opaque)
{
    auto &f = *static_cast<Fixture *>(opaque);
    f.record('A');
    return f.failure == Failure::Allocate ? nullptr : &f.objectToken;
}

bool initialize(void *opaque, void *object, void *controller,
                const uint8_t address[6], uint32_t role, const char *name)
{
    auto &f = *static_cast<Fixture *>(opaque);
    assert(object == &f.objectToken);
    f.record('I');
    // A late native init failure may already own resources and an open.
    f.controllerOpen = true;
    f.privateResources = true;
    f.initController = controller;
    memcpy(f.initAddress, address, sizeof(f.initAddress));
    f.initRole = role;
    assert(name);
    strncpy(f.initName, name, sizeof(f.initName) - 1);
    return f.failure != Failure::Initialize;
}

bool attach(void *opaque, void *object, void *provider)
{
    auto &f = *static_cast<Fixture *>(opaque);
    assert(object == &f.objectToken);
    f.record('T');
    f.attachProvider = provider;
    if (f.failure == Failure::Attach)
        return false;
    f.attached = true;
    return true;
}

bool start(void *opaque, void *object, void *provider)
{
    auto &f = *static_cast<Fixture *>(opaque);
    assert(object == &f.objectToken);
    f.record('S');
    f.startProvider = provider;
    if (f.failure == Failure::Start)
        return false;
    f.started = true;
    return true;
}

bool terminate(void *opaque, void *controller, void *object, bool aggressive)
{
    auto &f = *static_cast<Fixture *>(opaque);
    assert(controller == &f.controllerToken);
    assert(object == &f.objectToken);
    assert(!aggressive); // exact helper maps false to terminate(options=1)
    f.record('D');
    if (f.failure == Failure::Terminate)
        return false;
    f.attached = false;
    f.started = false;
    return true;
}

void *getAwdlInterface(void *opaque, void *controller)
{
    auto &f = *static_cast<Fixture *>(opaque);
    assert(controller == &f.controllerToken);
    f.record('G');
    return f.published;
}

void setAwdlInterface(void *opaque, void *controller, void *object)
{
    auto &f = *static_cast<Fixture *>(opaque);
    assert(controller == &f.controllerToken);
    f.record('C');
    f.published = object;
}

void release(void *opaque, void *object)
{
    auto &f = *static_cast<Fixture *>(opaque);
    assert(object == &f.objectToken);
    assert(!f.controllerOpen && !f.privateResources);
    assert(!f.attached && !f.started);
    f.record('X');
    ++f.releaseCount;
}

bool prepareRelease(void *opaque, void *controller, void *object,
                    ReleaseState state)
{
    auto &f = *static_cast<Fixture *>(opaque);
    assert(controller == &f.controllerToken && object == &f.objectToken);
    assert(!f.attached && !f.started);
    f.record('P');
    ++f.prepareCount;
    f.lastReleaseState = state;
    if (!f.cleanupReady)
        return false;
    f.controllerOpen = false;
    f.privateResources = false;
    return true;
}

const uint8_t kAddress[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};

NativeOps opsFor(Fixture &f)
{
    return {&f, allocate, initialize, attach, start, terminate,
            getAwdlInterface, setAwdlInterface, release, prepareRelease,
            [](void *opaque, void *controller, void *object) {
                auto &state = *static_cast<Fixture *>(opaque);
                assert(controller == &state.controllerToken && object == &state.objectToken);
                ++state.verifyStartedCount;
                return state.startStateComplete;
            }};
}

void testTrueNativeStartWithIncompleteStateStaysOwned()
{
    Fixture f;
    f.startStateComplete = false;
    InterfaceOwner owner;
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) ==
           Status::StartStateIncompleteNeedsStop);
    assert(f.started && owner.ownsObject() && owner.isAttached());
    assert(!owner.isStarted() && f.verifyStartedCount == 1 && f.releaseCount == 0);
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) == Status::Busy);
    assert(owner.stop() == Status::Success && f.releaseCount == 1);
}

void testMissingStartWitnessNeverAllocates()
{
    Fixture f;
    InterfaceOwner owner;
    auto ops = opsFor(f);
    ops.verifyStarted = nullptr;
    assert(owner.start(&f.controllerToken, kAddress, ops) == Status::InvalidArgument);
    assert(f.traceLength == 0 && !owner.ownsObject());
}

void testSuccessfulSequenceAndRawSlotClear()
{
    Fixture f;
    InterfaceOwner owner;
    const NativeOps ops = opsFor(f);
    assert(owner.start(&f.controllerToken, kAddress, ops) == Status::Success);
    assert(strcmp(f.trace, "GAITS") == 0);
    assert(f.initController == &f.controllerToken);
    assert(f.attachProvider == &f.controllerToken);
    assert(f.startProvider == &f.controllerToken);
    assert(f.initRole == 6 && strcmp(f.initName, "awdl") == 0);
    assert(memcmp(f.initAddress, kAddress, sizeof(kAddress)) == 0);
    assert(owner.ownsObject() && owner.isAttached() && owner.isStarted());
    assert(f.releaseCount == 0 && f.published == nullptr);

    assert(owner.stop() == Status::Success);
    assert(strcmp(f.trace, "GAITSDPGX") == 0);
    assert(f.lastReleaseState == ReleaseState::Terminated);
    assert(!owner.ownsObject() && !owner.isAttached() && !owner.isStarted());
    assert(!f.attached && !f.started && f.releaseCount == 1);
}

void testExistingNativeAwdlOwnerBlocksAllocation()
{
    Fixture f;
    f.published = &f.otherToken;
    InterfaceOwner owner;
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) == Status::Busy);
    assert(strcmp(f.trace, "G") == 0);
    assert(!owner.ownsObject() && f.releaseCount == 0);
}

void testAllocationFailureDoesNotRelease()
{
    Fixture f;
    f.failure = Failure::Allocate;
    InterfaceOwner owner;
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) ==
           Status::NoMemory);
    assert(strcmp(f.trace, "GA") == 0);
    assert(!owner.ownsObject() && f.releaseCount == 0);
}

void testInitFailureReleasesAllocatedReference()
{
    Fixture f;
    f.failure = Failure::Initialize;
    InterfaceOwner owner;
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) ==
           Status::InitFailed);
    assert(strcmp(f.trace, "GAIPGX") == 0);
    assert(f.lastReleaseState == ReleaseState::InitFailed);
    assert(!owner.ownsObject() && f.releaseCount == 1);
}

void testAttachFailureReleasesWithoutTerminate()
{
    Fixture f;
    f.failure = Failure::Attach;
    InterfaceOwner owner;
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) ==
           Status::AttachFailed);
    assert(strcmp(f.trace, "GAITPGX") == 0);
    assert(f.lastReleaseState == ReleaseState::Initialized);
    assert(!owner.ownsObject() && f.releaseCount == 1);
}

void testStartFailureRetainsOwnerUntilTerminate()
{
    Fixture f;
    f.failure = Failure::Start;
    InterfaceOwner owner;
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) ==
           Status::StartFailedNeedsStop);
    assert(strcmp(f.trace, "GAITS") == 0);
    assert(owner.ownsObject() && owner.isAttached() && !owner.isStarted());
    assert(f.releaseCount == 0);

    assert(owner.stop() == Status::Success);
    assert(strcmp(f.trace, "GAITSDPGX") == 0);
    assert(!owner.ownsObject() && f.releaseCount == 1);
}

void testTerminateFailureKeepsOwnerForRetry()
{
    Fixture f;
    InterfaceOwner owner;
    const NativeOps ops = opsFor(f);
    assert(owner.start(&f.controllerToken, kAddress, ops) == Status::Success);
    f.failure = Failure::Terminate;
    assert(owner.stop() == Status::CleanupPending);
    assert(owner.ownsObject() && owner.isAttached() && owner.isStarted());
    assert(f.releaseCount == 0 && f.published == nullptr);

    f.failure = Failure::None;
    assert(owner.stop() == Status::Success);
    assert(!owner.ownsObject() && f.releaseCount == 1);
}

void testTeardownDoesNotClearAnotherOwnersPointer()
{
    Fixture f;
    InterfaceOwner owner;
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) == Status::Success);
    f.published = &f.otherToken;
    assert(owner.stop() == Status::Success);
    assert(f.published == &f.otherToken);
    assert(f.releaseCount == 1);
    assert(strstr(f.trace, "DGCX") == nullptr);
}

void testTeardownClearsItsOwnRawPointerBeforeRelease()
{
    Fixture f;
    InterfaceOwner owner;
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) == Status::Success);
    f.published = &f.objectToken; // emulate a system-side raw-slot publication
    assert(owner.stop() == Status::Success);
    assert(strcmp(f.trace, "GAITSDPGCX") == 0);
    assert(f.published == nullptr && f.releaseCount == 1);
}

void testInvalidMacNeverAllocates()
{
    Fixture f;
    const uint8_t multicast[6] = {0x01, 0, 0, 0, 0, 1};
    InterfaceOwner owner;
    assert(owner.start(&f.controllerToken, multicast, opsFor(f)) ==
           Status::InvalidArgument);
    assert(f.traceLength == 0 && f.releaseCount == 0);
}

void testMissingCleanupContractNeverAllocates()
{
    Fixture f;
    InterfaceOwner owner;
    auto ops = opsFor(f);
    ops.prepareRelease = nullptr;
    assert(owner.start(&f.controllerToken, kAddress, ops) == Status::InvalidArgument);
    assert(f.traceLength == 0 && !owner.ownsObject());
}

void testFailedInitKeepsPartialOwnerUntilCleanup()
{
    Fixture f;
    f.failure = Failure::Initialize;
    f.cleanupReady = false;
    InterfaceOwner owner;
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) ==
           Status::InitFailedNeedsCleanup);
    assert(owner.ownsObject() && !owner.isAttached() && !owner.isStarted());
    assert(f.controllerOpen && f.privateResources && f.releaseCount == 0);
    f.published = &f.objectToken;
    assert(owner.stop() == Status::CleanupPending);
    assert(f.published == &f.objectToken && f.releaseCount == 0);
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) == Status::Busy);
    f.cleanupReady = true;
    assert(owner.stop() == Status::Success);
    assert(f.lastReleaseState == ReleaseState::InitFailed);
    assert(!owner.ownsObject() && f.published == nullptr && f.releaseCount == 1);
    assert(strchr(f.trace, 'D') == nullptr);
    assert(owner.stop() == Status::Success && f.releaseCount == 1);
}

void testFailedAttachWaitsForUnstartedCleanup()
{
    Fixture f;
    f.failure = Failure::Attach;
    f.cleanupReady = false;
    InterfaceOwner owner;
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) ==
           Status::AttachFailedNeedsCleanup);
    assert(owner.ownsObject() && !owner.isAttached());
    assert(f.controllerOpen && f.releaseCount == 0);
    f.cleanupReady = true;
    assert(owner.stop() == Status::Success);
    assert(f.lastReleaseState == ReleaseState::Initialized);
    assert(f.releaseCount == 1 && strchr(f.trace, 'D') == nullptr);
}

void testCleanupRetryDoesNotRepeatTerminateOrClearNewAlias()
{
    Fixture f;
    InterfaceOwner owner;
    assert(owner.start(&f.controllerToken, kAddress, opsFor(f)) == Status::Success);
    f.published = &f.objectToken;
    f.cleanupReady = false;
    assert(owner.stop() == Status::CleanupPending);
    assert(owner.ownsObject() && !owner.isAttached() && !owner.isStarted());
    assert(f.published == &f.objectToken && f.releaseCount == 0);
    const size_t firstTerminate = f.traceLength;
    assert(owner.stop() == Status::CleanupPending);
    assert(strchr(f.trace + firstTerminate, 'D') == nullptr);
    f.published = &f.otherToken;
    f.cleanupReady = true;
    assert(owner.stop() == Status::Success);
    assert(f.published == &f.otherToken && f.releaseCount == 1);
    assert(f.lastReleaseState == ReleaseState::Terminated);
}

} // namespace

int main()
{
    testTrueNativeStartWithIncompleteStateStaysOwned();
    testMissingStartWitnessNeverAllocates();
    testSuccessfulSequenceAndRawSlotClear();
    testExistingNativeAwdlOwnerBlocksAllocation();
    testAllocationFailureDoesNotRelease();
    testInitFailureReleasesAllocatedReference();
    testAttachFailureReleasesWithoutTerminate();
    testStartFailureRetainsOwnerUntilTerminate();
    testTerminateFailureKeepsOwnerForRetry();
    testTeardownDoesNotClearAnotherOwnersPointer();
    testTeardownClearsItsOwnRawPointerBeforeRelease();
    testInvalidMacNeverAllocates();
    testMissingCleanupContractNeverAllocates();
    testFailedInitKeepsPartialOwnerUntilCleanup();
    testFailedAttachWaitsForUnstartedCleanup();
    testCleanupRetryDoesNotRepeatTerminateOrClearNewAlias();
    return 0;
}
