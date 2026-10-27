// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdint.h>

// Offline lifecycle contract for the 25G332 IO80211AWDLProtocol subclass.
// This helper is deliberately independent of IOKit types and is not linked
// into the active kext target. The callbacks are mockable so ownership and
// call ordering can be tested without constructing a kernel object.
namespace NativeAwdl25G332 {

enum class Status : uint8_t {
    Success,
    InvalidArgument,
    Busy,
    NoMemory,
    InitFailed,
    AttachFailed,
    StartFailedNeedsStop,
    CleanupPending,
    InitFailedNeedsCleanup,
    AttachFailedNeedsCleanup,
    StartStateIncompleteNeedsStop
};

enum class ReleaseState : uint8_t {
    InitFailed,
    Initialized,
    Terminated
};

// A concrete binding would map these callbacks to:
//   MetaClass::alloc(), IO80211VirtualInterface::init/attach/start,
//   IO80211Controller::detachVirtualInterface/getAwdlInterface/
//   setAwdlInterface, and OSObject::release.
// allocate() transfers its one owned reference to InterfaceOwner.
struct NativeOps {
    void *context {nullptr};
    void *(*allocate)(void *context) {nullptr};
    bool (*initialize)(void *context, void *object, void *controller,
                       const uint8_t address[6], uint32_t role,
                       const char *name) {nullptr};
    bool (*attach)(void *context, void *object, void *provider) {nullptr};
    bool (*start)(void *context, void *object, void *provider) {nullptr};
    // A state-aware binding may use detachVirtualInterface(object, false),
    // dispatching terminate(options=1), only after proving partial-start stop
    // prerequisites. Otherwise it must return false and keep ownership.
    bool (*terminate)(void *context, void *controller, void *object,
                      bool aggressive) {nullptr};
    void *(*getAwdlInterface)(void *context, void *controller) {nullptr};
    void (*setAwdlInterface)(void *context, void *controller,
                             void *object) {nullptr};
    void (*release)(void *context, void *object) {nullptr};
    // Required before every final release, including failed init. The exact
    // native binding must close the original controller/client open and prove
    // partial/private resources and dynamic free are safe for this state.
    // False keeps the owned reference for cleanup; this callback must never
    // release the object itself. A mock returning true is not a native proof.
    bool (*prepareRelease)(void *context, void *controller, void *object,
                           ReleaseState state) {nullptr};
    // Required after a true native start result. Exact 25G332 has early exits
    // that preserve AL=true before all native start state exists. The binding
    // must establish role/provider/work-loop, peer manager and later native
    // allocations; this does not establish a BSD interface or a data path.
    bool (*verifyStarted)(void *context, void *controller, void *object) {nullptr};
};

class InterfaceOwner {
public:
    InterfaceOwner() = default;
    InterfaceOwner(const InterfaceOwner &) = delete;
    InterfaceOwner &operator=(const InterfaceOwner &) = delete;

    // Creates a role-6 child with the observed AWDL name. The controller is
    // used as both init provider and start provider. A matching provider and a
    // complete start-state witness are required in addition to the native bool.
    // The generic attach helper's start(nullptr) path ignores that bool and is
    // insufficient for this owner.
    Status start(void *controller, const uint8_t address[6],
                 const NativeOps &ops);

    // Calls the native terminate route first for attached instances. Ownership
    // remains here if terminate or prepareRelease cannot complete. A completed
    // terminate is not repeated on a cleanup retry. The owner must outlive any
    // pending cleanup; there is deliberately no unconditional destructor release.
    Status stop();

    bool ownsObject() const { return object_ != nullptr; }
    bool isAttached() const { return attached_; }
    bool isStarted() const { return started_; }
    void *object() const { return object_; }

private:
    bool retireReference();
    void releaseAndReset();

    NativeOps ops_ {};
    void *controller_ {nullptr};
    void *object_ {nullptr};
    bool attached_ {false};
    bool started_ {false};
    ReleaseState releaseState_ {ReleaseState::InitFailed};
};

} // namespace NativeAwdl25G332
