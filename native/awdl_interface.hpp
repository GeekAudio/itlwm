// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include "awdl_virtual_request.hpp"

#include <stdint.h>

class IO80211Controller;
class IOService;

namespace NativeAwdl {

enum class InterfaceStatus : uint8_t {
    Success,
    NotReady,
    Busy,
    InvalidArgument,
    NoMemory,
    HardwareFailure,
    NativeFailure,
    CleanupPending
};

// The backend is an explicit boundary for Intel firmware and scheduler work.
// A null callback or a false ready() result prevents native interface creation.
// prepare() must tolerate stop() after a partial failure and must not claim the
// interface is on-air; the driver has to report an actual firmware result.
struct AwdlHardwareAdapter {
    void *context {nullptr};
    bool (*ready)(void *context) {nullptr};
    InterfaceStatus (*prepare)(void *context, IOService *interface,
                               const uint8_t address[6]) {nullptr};
    InterfaceStatus (*stop)(void *context, IOService *interface) {nullptr};
};

struct TahoeAwdlContext {
    IO80211Controller *controller {nullptr};
    AwdlHardwareAdapter hardware {};
    VirtualRequestInfo request {};
};

// Native calls are injectable so the exact lifecycle body can be fault-tested
// offline. The Tahoe implementation binds these operations to the 25G241
// IO80211VirtualInterface and IO80211Controller symbols.
struct InterfaceOps {
    void *context {nullptr};
    InterfaceStatus (*hardwareReady)(void *context) {nullptr};
    InterfaceStatus (*alreadyPublished)(void *context, bool *published) {nullptr};
    InterfaceStatus (*allocate)(void *context, void **interface) {nullptr};
    InterfaceStatus (*initialize)(void *context, void *interface,
                                  const VirtualRequestInfo &request) {nullptr};
    InterfaceStatus (*prepareHardware)(void *context, void *interface) {nullptr};
    InterfaceStatus (*publish)(void *context, void *interface) {nullptr};
    InterfaceStatus (*attach)(void *context, void *interface) {nullptr};
    InterfaceStatus (*startService)(void *context, void *interface) {nullptr};
    InterfaceStatus (*stopHardware)(void *context, void *interface) {nullptr};
    InterfaceStatus (*detach)(void *context, void *interface) {nullptr};
    InterfaceStatus (*clearPublished)(void *context, void *interface) {nullptr};
    void (*release)(void *context, void *interface) {nullptr};
};

class InterfaceLifecycle {
public:
    InterfaceStatus start(const VirtualRequestInfo &request,
                          const InterfaceOps &ops,
                          void **startedInterface = nullptr);
    InterfaceStatus stop();

    bool hasObject() const { return interface_ != nullptr; }
    bool isStarted() const { return started_; }
    void *interface() const { return interface_; }

private:
    InterfaceStatus unwind(InterfaceStatus originalStatus);
    void reset();

    InterfaceOps ops_ {};
    void *interface_ {nullptr};
    bool hardwarePrepared_ {false};
    bool published_ {false};
    bool attached_ {false};
    bool started_ {false};
};

// Thin adapter held by the driver. It does not alter the STA interface or set
// link state. The native interface is only created after the hardware adapter
// reports ready and its prepare callback succeeds.
class TahoeAwdlInterfaceAdapter {
public:
    TahoeAwdlInterfaceAdapter();
    // The owner must call stop() and keep this object alive until it succeeds.
    ~TahoeAwdlInterfaceAdapter();

    InterfaceStatus start(IO80211Controller *controller,
                          const VirtualRequestInfo &request,
                          const AwdlHardwareAdapter &hardware);
    InterfaceStatus stop();
    IOService *service() const;

private:
    TahoeAwdlContext context_ {};
    InterfaceLifecycle lifecycle_ {};
};

} // namespace NativeAwdl
