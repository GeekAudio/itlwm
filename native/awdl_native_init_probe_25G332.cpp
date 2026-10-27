// SPDX-License-Identifier: GPL-2.0-only
// A manually invoked, unpublished init/cleanup observation. No attach/start,
// interface registration, native peer manager, radio command or packet path.
#if defined(ITL_NATIVE_AWDL_INIT_OBSERVATION_25G332)
#include "awdl_native_init_probe_25G332.hpp"
#include "awdl_native_concrete_25G332.hpp"
#include "awdl_unpublished_cleanup.hpp"
#include "runtime_guard.hpp"
#include <IOKit/pwr_mgt/IOPM.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSBoolean.h>
#include <string.h>

namespace {
// Module-lifetime storage: PM may hold a reference after our release request.
// Never retain a pointer to a worker's stack in an asynchronously freed object.
uint32_t observationFlags;
uint32_t deregisterResult = ~uint32_t(0);
uint32_t referencesBeforeRelease;
uint32_t observationClassSize;
OSObject *observationOwnedReference;
void note(uint32_t flag) {
    __atomic_fetch_or(&observationFlags, flag, __ATOMIC_RELEASE);
}
}

class ItlAwdlNativeInitGate25G332 final : public ItlAwdlNativeConcreteGate25G332 {
    OSDeclareDefaultStructors(ItlAwdlNativeInitGate25G332)
public:
    bool initializeForObservation(IOService *controller, const uint8_t address[6]);
    NativeAwdlInit::Disposal prepareDisposal();
    void free() override;
    bool init() override { return false; }
    bool init(OSDictionary *) override { return false; }
    bool init(IOService *, ether_addr *) override { return false; }
    bool init(IO80211Controller *, ether_addr *, unsigned int, const char *) override {
        return false;
    }
    bool attach(IOService *) override { return false; }
    bool start(IOService *) override { return false; }
    bool terminate(IOOptionBits = 0) override { return false; }
    void stop(IOService *) override {}
    // Interested-driver callbacks can run before native start. This temporary
    // object has no PM policy; acknowledge without touching native ivars/gates.
    IOReturn powerStateWillChangeTo(IOPMPowerFlags, unsigned long, IOService *) override {
        return kIOPMAckImplied;
    }
    IOReturn powerStateDidChangeTo(IOPMPowerFlags, unsigned long, IOService *) override {
        return kIOPMAckImplied;
    }
private:
    IOService *originalController_ = nullptr;
    NativeAwdlInit::Disposal disposal_ = NativeAwdlInit::Disposal::ServiceBase;
    bool bpfCleaned_ = false;
};

OSDefineMetaClassAndStructors(ItlAwdlNativeInitGate25G332,
                             ItlAwdlNativeConcreteGate25G332)
static_assert(sizeof(ItlAwdlNativeInitGate25G332) == 0x140,
              "25G332 unpublished observation subclass layout changed");

bool ItlAwdlNativeInitGate25G332::initializeForObservation(
    IOService *controller, const uint8_t address[6])
{
    originalController_ = controller;
    originalController_->retain();
    disposal_ = NativeAwdlInit::Disposal::Quarantine;
    ether_addr mac{};
    memcpy(&mac, address, 6);
    note(NativeAwdlInit::InitCalled);
    const bool initialized = IO80211VirtualInterface::init(
        reinterpret_cast<IO80211Controller *>(controller), &mac, 6, "awdl");
    note(NativeAwdlInit::InitReturned |
         (initialized ? NativeAwdlInit::InitSucceeded : NativeAwdlInit::InitFailed));
    return initialized;
}

NativeAwdlInit::Disposal ItlAwdlNativeInitGate25G332::prepareDisposal()
{
    struct Operations {
        IOService *controller;
        ItlAwdlNativeInitGate25G332 *object;
        bool quiesceInterest() {
            const IOReturn result = controller->deRegisterInterestedDriver(object);
            __atomic_store_n(&deregisterResult, uint32_t(result), __ATOMIC_RELEASE);
            if (result != kIOReturnSuccess && result != kIOReturnNotFound &&
                result != IOPMNotPowerManaged)
                return false;
            note(NativeAwdlInit::InterestQuiesced);
            return true;
        }
        bool isOpen() { return controller->isOpen(object); }
        void close() { controller->close(object); }
        void freeBpfResources() { object->IO80211VirtualInterface::freeBpfResources(); }
    } ops{originalController_, this};
    NativeAwdlInit::CleanupFacts facts{
        hasNativePrivate25G332(), hasVirtualPrivate25G332(), bpfCleaned_};
    disposal_ = NativeAwdlInit::prepareUnpublished(facts, ops);
    bpfCleaned_ = facts.bpfCleaned;
    if (bpfCleaned_)
        note(NativeAwdlInit::BpfCleaned);
    if (disposal_ != NativeAwdlInit::Disposal::Quarantine)
        note(NativeAwdlInit::ControllerClosed);
    return disposal_;
}

void ItlAwdlNativeInitGate25G332::free()
{
    note(NativeAwdlInit::FreeEntered);
    // Capture locals before a qualified base free can delete this instance.
    IOService *const controller = originalController_;
    const auto disposal = disposal_;
    if (disposal == NativeAwdlInit::Disposal::Quarantine) {
        note(NativeAwdlInit::Quarantined);
        return; // This path must not be reached by the observation wrapper.
    }
    originalController_ = nullptr;
    if (disposal == NativeAwdlInit::Disposal::VirtualInterfaceBase) {
        IO80211VirtualInterface::free();
        note(NativeAwdlInit::VirtualBaseFreed);
    } else {
        // Super-init may have failed before native +0x120 exists. No native
        // private allocation exists on this branch; use IOService's partial
        // initialization cleanup, avoiding native free's early null deref.
        IOService::free();
        note(NativeAwdlInit::ServiceBaseFreed);
    }
    if (controller)
        controller->release();
    note(NativeAwdlInit::FreeReturned);
}

namespace NativeAwdlInit {
void observeOnce(IOService *controller, const uint8_t address[6])
{
    uint32_t unused = 0;
    if (!__atomic_compare_exchange_n(&observationFlags, &unused,
            uint32_t(Attempted), false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    uint8_t any = 0;
    if (address) for (unsigned int i = 0; i < 6; ++i) any |= address[i];
    if (!controller || !address || !any || (address[0] & 1) ||
        !controller->metaCast("IO80211Controller") ||
        controller->getProperty("NativeAwdlInitObservationOnly") != kOSBooleanTrue ||
        controller->getProperty("NativeP2PManualTrigger") != kOSBooleanTrue ||
        !NativeWifi::verifyTahoeRuntime(true)) {
        note(IdentityRejected);
        return;
    }
    OSObject *buildObject = IORegistryEntry::getRegistryRoot()->copyProperty("OS Build Version");
    auto build = OSDynamicCast(OSString, buildObject);
    const bool exactBuild = build && build->isEqualTo("25G332");
    if (buildObject) buildObject->release();
    if (!exactBuild) { note(IdentityRejected); return; }
    const OSMetaClass *meta = ItlAwdlNativeInitGate25G332::metaClass;
    if (!meta || meta->getSuperClass() != ItlAwdlNativeConcreteGate25G332::metaClass ||
        meta->getSuperClass()->getSuperClass() != IO80211AWDLProtocol::metaClass ||
        meta->getClassSize() != sizeof(ItlAwdlNativeInitGate25G332)) {
        note(IdentityRejected);
        return;
    }
    __atomic_store_n(&observationClassSize, uint32_t(meta->getClassSize()), __ATOMIC_RELEASE);
    note(MetaVerified);
    auto object = static_cast<ItlAwdlNativeInitGate25G332 *>(meta->alloc());
    if (!object) { note(AllocationFailed); return; }
    note(Allocated);
    observationOwnedReference = object;
    object->initializeForObservation(controller, address);
    if (object->prepareDisposal() == Disposal::Quarantine) {
        // Preserve the allocation and controller reference. Never attempt an
        // unsafe free or a second observation after ambiguous cleanup.
        note(Quarantined);
        return;
    }
    __atomic_store_n(&referencesBeforeRelease, uint32_t(object->getRetainCount()), __ATOMIC_RELEASE);
    note(ReleaseRequested);
    observationOwnedReference = nullptr;
    object->release();
    // No instance access after release. An IOPM reference can delay free.
    if (!(snapshot().flags & FreeReturned))
        note(DeferredRelease);
}

Snapshot snapshot()
{
    return {__atomic_load_n(&observationFlags, __ATOMIC_ACQUIRE),
            __atomic_load_n(&deregisterResult, __ATOMIC_ACQUIRE),
            __atomic_load_n(&referencesBeforeRelease, __ATOMIC_ACQUIRE),
            __atomic_load_n(&observationClassSize, __ATOMIC_ACQUIRE)};
}

bool completedSuccessfully()
{
    const uint32_t flags = snapshot().flags;
    constexpr uint32_t required = Attempted | MetaVerified | Allocated |
        InitSucceeded | InterestQuiesced | ControllerClosed | BpfCleaned |
        ReleaseRequested | VirtualBaseFreed | FreeReturned;
    return (flags & required) == required &&
        !(flags & (Quarantined | AllocationFailed | IdentityRejected | InitFailed));
}
} // namespace NativeAwdlInit
#endif
