// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_interface.hpp"

#include "../include/Tahoe/IO80211AWDLInterfaceABI.hpp"
class IO80211WorkQueue;
#include "../include/Tahoe/IO80211Controller.h"

#include <string.h>

// These signatures and mangled names were read from the machine's linked
// IO80211Family 25G241 image. They are lifecycle calls for a future concrete
// IO80211AWDLProtocol subtype; they do not make the abstract base allocatable.
extern "C" bool nativeAwdlVifInit(void *, IO80211Controller *, ether_addr *,
                                  unsigned int, const char *)
    __asm__("__ZN23IO80211VirtualInterface4initEP17IO80211ControllerP10ether_addrjPKc");
extern "C" bool nativeAwdlVifAttach(void *, IOService *)
    __asm__("__ZN23IO80211VirtualInterface6attachEP9IOService");
extern "C" bool nativeAwdlVifStart(void *, IOService *)
    __asm__("__ZN23IO80211VirtualInterface5startEP9IOService");
extern "C" IOService *nativeControllerGetAwdl(IO80211Controller *)
    __asm__("__ZN17IO80211Controller16getAwdlInterfaceEv");
extern "C" void nativeControllerSetAwdl(IO80211Controller *, IOService *)
    __asm__("__ZN17IO80211Controller16setAwdlInterfaceEP23IO80211VirtualInterface");
extern "C" bool nativeControllerDetachAwdl(IO80211Controller *, IOService *, bool)
    __asm__("__ZN17IO80211Controller22detachVirtualInterfaceEP23IO80211VirtualInterfaceb");

namespace NativeAwdl {
namespace {

InterfaceStatus hardwareReady(void *opaque)
{
    auto *context = static_cast<TahoeAwdlContext *>(opaque);
    if (!context || !context->hardware.ready || !context->hardware.prepare ||
        !context->hardware.stop)
        return InterfaceStatus::NotReady;
    return context->hardware.ready(context->hardware.context)
               ? InterfaceStatus::Success
               : InterfaceStatus::NotReady;
}

InterfaceStatus alreadyPublished(void *opaque, bool *published)
{
    auto *context = static_cast<TahoeAwdlContext *>(opaque);
    if (!context || !context->controller || !published)
        return InterfaceStatus::InvalidArgument;
    *published = nativeControllerGetAwdl(context->controller) != nullptr;
    return InterfaceStatus::Success;
}

InterfaceStatus allocate(void *, void **interface)
{
    if (!interface)
        return InterfaceStatus::InvalidArgument;
    *interface = nullptr;
    // Both IO80211VirtualInterface and IO80211AWDLProtocol have metaclass
    // alloc() implementations that return null on 25G241. Do not publish a
    // generic VIF: it also cannot satisfy OS cast to IO80211AWDLProtocol.
    // Replace this fail-closed boundary only after a concrete subclass ABI has
    // been reconstructed and compiled against the matching Tahoe image.
    return InterfaceStatus::NotReady;
}

InterfaceStatus initialize(void *opaque, void *interface,
                           const VirtualRequestInfo &request)
{
    auto *context = static_cast<TahoeAwdlContext *>(opaque);
    if (!context || !context->controller || !interface || request.role != 6)
        return InterfaceStatus::InvalidArgument;

    ether_addr address {};
    static_assert(sizeof(address) >= sizeof(request.address),
                  "ether_addr must hold a six-byte hardware address");
    memcpy(&address, request.address, sizeof(request.address));
    return TahoeAwdlABI::initializeVirtualInterface(
               static_cast<IOService *>(interface), context->controller,
               &address, TahoeAwdlABI::kRoleAwdl, "awdl")
               ? InterfaceStatus::Success
               : InterfaceStatus::NativeFailure;
}

InterfaceStatus prepareHardware(void *opaque, void *interface)
{
    auto *context = static_cast<TahoeAwdlContext *>(opaque);
    if (!context || !context->hardware.prepare || !interface)
        return InterfaceStatus::NotReady;
    return context->hardware.prepare(context->hardware.context,
                                     static_cast<IOService *>(interface),
                                     context->request.address);
}

InterfaceStatus publish(void *opaque, void *interface)
{
    auto *context = static_cast<TahoeAwdlContext *>(opaque);
    if (!context || !context->controller || !interface)
        return InterfaceStatus::InvalidArgument;
    if (TahoeAwdlABI::hasPublishedAwdlInterface(context->controller))
        return InterfaceStatus::Busy;
    TahoeAwdlABI::publishAwdlInterface(
        context->controller, static_cast<IOService *>(interface));
    return InterfaceStatus::Success;
}

InterfaceStatus attach(void *opaque, void *interface)
{
    auto *context = static_cast<TahoeAwdlContext *>(opaque);
    if (!context || !context->controller || !interface)
        return InterfaceStatus::InvalidArgument;
    return TahoeAwdlABI::attachVirtualInterface(
               static_cast<IOService *>(interface),
               static_cast<IOService *>(context->controller))
               ? InterfaceStatus::Success
               : InterfaceStatus::NativeFailure;
}

InterfaceStatus startService(void *opaque, void *interface)
{
    auto *context = static_cast<TahoeAwdlContext *>(opaque);
    if (!context || !context->controller || !interface)
        return InterfaceStatus::InvalidArgument;
    return TahoeAwdlABI::startVirtualInterface(
               static_cast<IOService *>(interface),
               static_cast<IOService *>(context->controller))
               ? InterfaceStatus::Success
               : InterfaceStatus::NativeFailure;
}

InterfaceStatus stopHardware(void *opaque, void *interface)
{
    auto *context = static_cast<TahoeAwdlContext *>(opaque);
    if (!context || !context->hardware.stop || !interface)
        return InterfaceStatus::NotReady;
    return context->hardware.stop(context->hardware.context,
                                  static_cast<IOService *>(interface));
}

InterfaceStatus detach(void *opaque, void *interface)
{
    auto *context = static_cast<TahoeAwdlContext *>(opaque);
    if (!context || !context->controller || !interface)
        return InterfaceStatus::InvalidArgument;
    return TahoeAwdlABI::detachVirtualInterface(
               context->controller, static_cast<IOService *>(interface))
               ? InterfaceStatus::Success
               : InterfaceStatus::CleanupPending;
}

InterfaceStatus clearPublished(void *opaque, void *interface)
{
    auto *context = static_cast<TahoeAwdlContext *>(opaque);
    if (!context || !context->controller || !interface)
        return InterfaceStatus::InvalidArgument;
    TahoeAwdlABI::clearAwdlInterface(context->controller,
                                     static_cast<IOService *>(interface));
    return InterfaceStatus::Success;
}

void release(void *, void *interface)
{
    TahoeAwdlABI::releaseVirtualInterface(static_cast<IOService *>(interface));
}

InterfaceOps makeOps(TahoeAwdlContext *context)
{
    return {context, hardwareReady, alreadyPublished, allocate, initialize,
            prepareHardware, publish, attach, startService, stopHardware,
            detach, clearPublished, release};
}

} // namespace

TahoeAwdlInterfaceAdapter::TahoeAwdlInterfaceAdapter() = default;

TahoeAwdlInterfaceAdapter::~TahoeAwdlInterfaceAdapter() = default;

InterfaceStatus TahoeAwdlInterfaceAdapter::start(
    IO80211Controller *controller, const VirtualRequestInfo &request,
    const AwdlHardwareAdapter &hardware)
{
    if (!controller)
        return InterfaceStatus::InvalidArgument;
    context_.controller = controller;
    context_.hardware = hardware;
    context_.request = request;
    return lifecycle_.start(request, makeOps(&context_));
}

InterfaceStatus TahoeAwdlInterfaceAdapter::stop()
{
    return lifecycle_.stop();
}

IOService *TahoeAwdlInterfaceAdapter::service() const
{
    return static_cast<IOService *>(lifecycle_.interface());
}

} // namespace NativeAwdl

namespace TahoeAwdlABI {

bool initializeVirtualInterface(IOService *interface,
                                IO80211Controller *controller,
                                ether_addr *address, unsigned int role,
                                const char *bsdName)
{
    return interface && controller && address && bsdName &&
           nativeAwdlVifInit(interface, controller, address, role, bsdName);
}

bool attachVirtualInterface(IOService *interface, IOService *provider)
{
    return interface && provider && nativeAwdlVifAttach(interface, provider);
}

bool startVirtualInterface(IOService *interface, IOService *provider)
{
    return interface && provider && nativeAwdlVifStart(interface, provider);
}

bool detachVirtualInterface(IO80211Controller *controller,
                            IOService *interface)
{
    return controller && interface &&
           nativeControllerDetachAwdl(controller, interface, false);
}

bool hasPublishedAwdlInterface(IO80211Controller *controller)
{
    return controller && nativeControllerGetAwdl(controller) != nullptr;
}

void publishAwdlInterface(IO80211Controller *controller,
                          IOService *interface)
{
    if (controller)
        nativeControllerSetAwdl(controller, interface);
}

void clearAwdlInterface(IO80211Controller *controller, IOService *interface)
{
    if (controller && nativeControllerGetAwdl(controller) == interface)
        nativeControllerSetAwdl(controller, nullptr);
}

void releaseVirtualInterface(IOService *interface)
{
    if (interface)
        interface->release();
}

} // namespace TahoeAwdlABI
