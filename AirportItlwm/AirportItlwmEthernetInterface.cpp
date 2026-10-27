//
//  AirportItlwmEthernetInterface.cpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#include "AirportItlwmEthernetInterface.hpp"

#include <sys/_if_ether.h>
#include <net80211/ieee80211_var.h>
#ifdef AIRPORT_TAHOE
#include <net/kpi_interface.h>
#endif

#define super IOEthernetInterface
OSDefineMetaClassAndStructors(AirportItlwmEthernetInterface, IOEthernetInterface);

#ifdef AIRPORT_TAHOE
struct AirportItlwmEthernetInterface::NativeBSDContext {
    AirportItlwmEthernetInterface *self {nullptr};
    IO80211SkywalkInterface *native {nullptr};
    IO80211Controller *controller {nullptr};
    IO80211WorkQueue *queue {nullptr};
    ifnet_t ifnet {nullptr};
    char name[IFNAMSIZ] {};
    bool ifnetHeld {false};
    bool finalize {false};
    bool attempted {false};
};

bool AirportItlwmEthernetInterface::acquireNativeBSDContext(NativeBSDContext &c)
{
    c.self = this;
    retain();
    c.native = interface;
    if (!c.native) return false;
    c.native->retain();
    c.controller = OSDynamicCast(IO80211Controller, getController());
    if (!c.controller) return false;
    c.controller->retain();
    c.queue = c.controller->getWorkQueue();
    if (!c.queue) return false;
    c.queue->retain();
    return true;
}

bool AirportItlwmEthernetInterface::acquireNativeBSDIfnet(NativeBSDContext &c)
{
    // The BSD base allocates its ifnet during attach, not during init.
    // Existing detach captures it here before entering the native gate.
    c.ifnet = getIfnet();
    if (!c.ifnet || ifnet_reference(c.ifnet)) return false;
    c.ifnetHeld = true;
    return true;
}

void AirportItlwmEthernetInterface::releaseNativeBSDContext(NativeBSDContext &c)
{
    if (c.ifnetHeld) { ifnet_release(c.ifnet); c.ifnetHeld = false; }
    if (c.queue) { c.queue->release(); c.queue = nullptr; }
    if (c.controller) { c.controller->release(); c.controller = nullptr; }
    if (c.native) { c.native->release(); c.native = nullptr; }
    if (c.self) { c.self->release(); c.self = nullptr; }
}

void AirportItlwmEthernetInterface::quarantineNativeBSD(NativeBSDContext &c, IOReturn result)
{
    // This resident lease is deliberately not released until reboot. It is
    // used only when safe native finalization/BSD detachment cannot be proved.
    if (!__atomic_exchange_n(&nativeBSDQuarantined, 1U, __ATOMIC_ACQ_REL)) retain();
    if (!quarantineInterface && c.native) { quarantineInterface = c.native; c.native = nullptr; }
    if (!quarantineController && c.controller) { quarantineController = c.controller; c.controller = nullptr; }
    if (!quarantineQueue && c.queue) { quarantineQueue = c.queue; c.queue = nullptr; }
    if (!quarantineIfnet && c.ifnetHeld) {
        quarantineIfnet = c.ifnet; c.ifnetHeld = false;
    }
    setProperty("NativeBSDQuarantined", 1U, 32);
    setProperty("NativeBSDQuarantineResult", uint32_t(result), 32);
    setProperty("NativeBSDDetached", uint64_t(0), 32);
}

IOReturn AirportItlwmEthernetInterface::nativeBSDAction(OSObject *target,
    void *argument, void *, void *, void *)
{
    auto c = static_cast<NativeBSDContext *>(argument);
    if (!c || target != c->self || !c->native || !c->controller || !c->queue || !c->ifnetHeld)
        return kIOReturnBadArgument;
    uint32_t context = 0;
    if (c->queue->inGate()) context |= 1;
    if (!c->queue->onThread()) context |= 2;
    if (c->controller->getWorkQueue() == c->queue) context |= 4;
    if (c->native->getControllerWorkQueue() == c->queue) context |= 8;
    if (c->self->getIfnet() == c->ifnet) context |= 16;
    if (c->self->interface == c->native && c->self->getController() == c->controller &&
        c->native->getProvider() == c->controller) context |= 32;
    c->native->setProperty("NativeBSDGateContext", context, 32);
    if (context != 63) return kIOReturnNotReady;
    if (c->finalize) {
        c->native->finalizeBSDInterface(c->ifnet, 0);
        c->self->nativePrepared = false;
        c->native->setProperty("NativeBSDPrepared", uint64_t(0), 32);
        c->native->setProperty("NativeBSDFinalizeResult", uint32_t(kIOReturnSuccess), 32);
        return kIOReturnSuccess;
    }
    if (__atomic_load_n(&c->self->nativeBSDQuarantined, __ATOMIC_ACQUIRE) ||
        c->controller->isInactive() || c->native->isInactive()) return kIOReturnNotReady;
    if (!c->name[0]) return kIOReturnBadArgument;
    // The native Network and Wi-Fi ancestors have separate name caches.
    // Seed the Network cache from the real BSD interface; Wi-Fi's prepare
    // obtains its own name from the ifnet it just cached.
    c->native->setBSDName(c->name);
    c->attempted = true;
    IOReturn result = c->native->prepareBSDInterface(c->ifnet, 0);
    if (result == kIOReturnSuccess) {
        uint32_t identity = 0;
        auto publicProperty = c->native->copyProperty("BSD Name");
        auto wifiProperty = c->native->copyProperty("IOInterfaceName");
        auto publicName = OSDynamicCast(OSString, publicProperty);
        auto wifiName = OSDynamicCast(OSString, wifiProperty);
        const char *cachedName = c->native->getBSDName();
        if (publicName && publicName->isEqualTo(c->name)) identity |= 1;
        if (wifiName && wifiName->isEqualTo(c->name)) identity |= 2;
        if (cachedName && !strcmp(cachedName, c->name)) identity |= 4;
        OSSafeReleaseNULL(publicProperty);
        OSSafeReleaseNULL(wifiProperty);
        c->native->setProperty("NativeBSDIdentity", identity, 32);
        if (identity != 7) result = kIOReturnNotReady;
    }
    c->native->setProperty("NativeBSDPrepareResult", uint32_t(result), 32);
    if (result != kIOReturnSuccess ||
        __atomic_load_n(&c->self->nativeBSDQuarantined, __ATOMIC_ACQUIRE)) {
        // The native base caches the borrowed ifnet before later steps fail.
        c->native->finalizeBSDInterface(c->ifnet, 0);
        c->native->setProperty("NativeBSDPrepared", uint64_t(0), 32);
        c->native->setProperty("NativeBSDFinalizeResult", uint32_t(kIOReturnSuccess), 32);
        return result != kIOReturnSuccess ? result : kIOReturnNotReady;
    }
    c->self->nativePrepared = true;
    c->self->isAttach = true;
    c->native->setProperty("NativeBSDPrepared", 1U, 32);
    c->native->registerService();
    return kIOReturnSuccess;
}
#endif

bool AirportItlwmEthernetInterface::
initWithSkywalkInterfaceAndProvider(IONetworkController *controller, IO80211SkywalkInterface *interface)
{
    bool ret = super::init(controller);
#ifdef AIRPORT_TAHOE
    // Native Apple80211 enumeration uses SIOCGIFTYPE and requires the real
    // BSD interface to carry the Wi-Fi subfamily before it is allocated.
    if (ret && !setInterfaceSubType(3)) ret = false;
#endif
    if (ret)
        this->interface = interface;
    this->isAttach = false;
    return ret;
}

IOReturn AirportItlwmEthernetInterface::
attachToDataLinkLayer( IOOptionBits options, void *parameter )
{
    XYLog("%s\n", __FUNCTION__);
#ifdef AIRPORT_TAHOE
    if (__atomic_load_n(&nativeBSDQuarantined, __ATOMIC_ACQUIRE)) return kIOReturnNotPermitted;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&nativeBSDOperation, &expected, 1U, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return kIOReturnBusy;
    NativeBSDContext c;
    IOReturn ret = kIOReturnNotReady;
    bool bsdAttached = false;
    if (nativePrepared || isAttach) ret = kIOReturnBusy;
    else if (acquireNativeBSDContext(c) && !c.queue->onThread() && !c.queue->inGate()) {
        c.native->setProperty("NativeBSDGateContext", uint64_t(0), 32);
        c.native->setProperty("NativeBSDFinalizeResult", ~uint32_t(0), 32);
        ret = super::attachToDataLinkLayer(options, parameter);
        if (ret == kIOReturnSuccess) {
            bsdAttached = true;
            c.native->setProperty("NativeBSDDetached", uint64_t(0), 32);
            UInt8 builtIn = 0;
            char infName[IFNAMSIZ];
            const char *prefix = nullptr;
            int nameLength = -1;
            if (!acquireNativeBSDIfnet(c)) ret = kIOReturnNotReady;
            else {
                prefix = ifnet_name(c.ifnet);
                if (prefix) nameLength = snprintf(infName, sizeof(infName), "%s%u", prefix,
                    ifnet_unit(c.ifnet));
            }
            if (ret != kIOReturnSuccess) {}
            else if (!prefix || nameLength < 0 || nameLength >= int(sizeof(infName))) ret = kIOReturnBadArgument;
            else if (!c.native->setProperty("built-in", &builtIn, sizeof(builtIn)) ||
                !c.native->setProperty("BSD Name", infName) ||
                !c.native->setProperty("IOInterfaceName", infName) ||
                !c.native->setProperty(kIOInterfaceUnit, uint64_t(ifnet_unit(c.ifnet)), 32) ||
                !c.native->setProperty(kIOInterfaceNamePrefix, prefix)) ret = kIOReturnNoMemory;
            else {
                memcpy(c.name, infName, size_t(nameLength) + 1);
                IOEthernetAddress address;
                ret = c.controller->getHardwareAddress(&address);
                if (ret == kIOReturnSuccess && !setProperty(kIOMACAddress, &address,
                        kIOEthernetAddressSize)) ret = kIOReturnNoMemory;
                if (ret == kIOReturnSuccess)
                    ret = c.queue->runAction(nativeBSDAction, this, &c);
            }
        }
    }
    if (ret != kIOReturnSuccess && bsdAttached) {
        // Synchronous runAction has released the native gate before BSD waits.
        if (getIfnet() == c.ifnet && !c.queue->inGate()) {
            isAttach = false;
            super::detachFromDataLinkLayer(options, parameter);
            c.native->setProperty("NativeBSDDetached", 1U, 32);
        } else quarantineNativeBSD(c, ret);
    }
    if (__atomic_load_n(&nativeBSDQuarantined, __ATOMIC_ACQUIRE) && ret == kIOReturnSuccess)
        ret = kIOReturnNotReady;
    if (c.native) c.native->setProperty("NativeBSDPrepareResult", uint32_t(ret), 32);
    if (__atomic_load_n(&nativeBSDQuarantined, __ATOMIC_ACQUIRE)) quarantineNativeBSD(c, ret);
    __atomic_store_n(&nativeBSDOperation, 0U, __ATOMIC_RELEASE);
    releaseNativeBSDContext(c);
    return ret;
#else
    char infName[IFNAMSIZ];
    IOReturn ret = super::attachToDataLinkLayer(options, parameter);
    if (ret == kIOReturnSuccess && interface) {
        UInt8 builtIn = 0;
        IOEthernetAddress addr;
        interface->setProperty("built-in", OSData::withBytes(&builtIn, sizeof(builtIn)));
        snprintf(infName, sizeof(infName), "%s%u", ifnet_name(getIfnet()), ifnet_unit(getIfnet()));
        interface->setProperty("IOInterfaceName", OSString::withCString(infName));
        interface->setProperty(kIOInterfaceUnit, OSNumber::withNumber(ifnet_unit(getIfnet()), 8));
        interface->setProperty(kIOInterfaceNamePrefix, OSString::withCString(ifnet_name(getIfnet())));
        if (OSDynamicCast(IOEthernetController, getController())->getHardwareAddress(&addr) == kIOReturnSuccess)
            setProperty(kIOMACAddress,  (void *) &addr,
                        kIOEthernetAddressSize);
        interface->registerService();
        interface->prepareBSDInterface(getIfnet(), 0);
//        ret = bpf_attach(getIfnet(), DLT_RAW, 0x48, &AirportItlwmEthernetInterface::bpfOutputPacket, &AirportItlwmEthernetInterface::bpfTap);
    }
    isAttach = true;
    return ret;
#endif
}

void AirportItlwmEthernetInterface::
detachFromDataLinkLayer(IOOptionBits options, void *parameter)
{
#ifdef AIRPORT_TAHOE
    if (__atomic_load_n(&nativeBSDQuarantined, __ATOMIC_ACQUIRE)) return;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&nativeBSDOperation, &expected, 1U, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        // The active synchronous operation owns the object/ifnet references.
        // It observes this mark and transfers that lease before returning.
        if (!__atomic_exchange_n(&nativeBSDQuarantined, 1U, __ATOMIC_ACQ_REL)) retain();
        setProperty("NativeBSDQuarantined", 1U, 32);
        setProperty("NativeBSDDetached", uint64_t(0), 32);
        return;
    }
    NativeBSDContext c;
    IOReturn result = kIOReturnSuccess;
    if (nativePrepared) {
        if (!acquireNativeBSDContext(c) || !acquireNativeBSDIfnet(c) ||
            c.queue->onThread() || c.queue->inGate()) result = kIOReturnNotReady;
        else {
            c.finalize = true;
            result = c.queue->runAction(nativeBSDAction, this, &c);
        }
        if (result != kIOReturnSuccess || !c.queue || c.queue->inGate())
            quarantineNativeBSD(c, result != kIOReturnSuccess ? result : kIOReturnNotReady);
        else {
            isAttach = false;
            super::detachFromDataLinkLayer(options, parameter);
            c.native->setProperty("NativeBSDDetached", 1U, 32);
        }
    }
    if (__atomic_load_n(&nativeBSDQuarantined, __ATOMIC_ACQUIRE)) quarantineNativeBSD(c, result);
    __atomic_store_n(&nativeBSDOperation, 0U, __ATOMIC_RELEASE);
    releaseNativeBSDContext(c);
#else
    super::detachFromDataLinkLayer(options, parameter);
    isAttach = false;
#endif
}

/**
 Add another hack to fake that the provider is IOSkywalkNetworkInterface, to avoid skywalkfamily instance cast panic.
 */
IOService *AirportItlwmEthernetInterface::
getProvider() const
{
    return isAttach ? this->interface : super::getProvider();
}

errno_t AirportItlwmEthernetInterface::
bpfOutputPacket(ifnet_t interface, u_int32_t data_link_type, mbuf_t packet)
{
    XYLog("%s data_link_type: %d\n", __FUNCTION__, data_link_type);
    AirportItlwmEthernetInterface *networkInterface = (AirportItlwmEthernetInterface *)ifnet_softc(interface);
    return networkInterface->enqueueOutputPacket(packet);
}

errno_t AirportItlwmEthernetInterface::
bpfTap(ifnet_t interface, u_int32_t data_link_type, bpf_tap_mode direction)
{
    XYLog("%s data_link_type: %d direction: %d\n", __FUNCTION__, data_link_type, direction);
    return 0;
}

bool AirportItlwmEthernetInterface::
setLinkState(IO80211LinkState state)
{
    if (state == kIO80211NetworkLinkUp) {
        ifnet_set_flags(getIfnet(), ifnet_flags(getIfnet()) | (IFF_UP | IFF_RUNNING), (IFF_UP | IFF_RUNNING));
    } else {
#ifdef AIRPORT_TAHOE
        ifnet_set_flags(getIfnet(), 0, IFF_UP | IFF_RUNNING);
#else
        ifnet_set_flags(getIfnet(), ifnet_flags(getIfnet()) & ~(IFF_UP | IFF_RUNNING), 0);
#endif
    }
    return true;
}

extern const char* hexdump(uint8_t *buf, size_t len);

UInt32 AirportItlwmEthernetInterface::
inputPacket(mbuf_t packet, UInt32 length, IOOptionBits options, void *param)
{
#ifndef AIRPORT_TAHOE
    ether_header_t *eh;
    size_t len = mbuf_len(packet);
    
    eh = (ether_header_t *)mbuf_data(packet);
    if (len >= sizeof(ether_header_t) && eh->ether_type == htons(ETHERTYPE_PAE)) { // EAPOL packet
        const char* dump = hexdump((uint8_t*)mbuf_data(packet), len);
        XYLog("input EAPOL packet, len: %zu, data: %s\n", len, dump ? dump : "Failed to allocate memory");
        if (dump)
            IOFree((void*)dump, 3 * len + 1);
    }
#endif
    return IOEthernetInterface::inputPacket(packet, length, options, param);
}
