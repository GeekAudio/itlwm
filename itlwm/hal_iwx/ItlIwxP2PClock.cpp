// SPDX-License-Identifier: GPL-2.0-only
#include "ItlIwx.hpp"

#ifdef AIRPORT_TAHOE
#include "../../native/intel_gp2_sampler.hpp"
#include <kern/clock.h>
#include <libkern/c++/OSBoolean.h>

namespace {
static_assert(uint32_t(IntelGp2Clock::SamplerDeviceFamily::kFamily22000) ==
              IWX_DEVICE_FAMILY_22000, "22000 GP2 family changed");
static_assert(uint32_t(IntelGp2Clock::SamplerDeviceFamily::kAx210) ==
              IWX_DEVICE_FAMILY_AX210, "AX210 GP2 family changed");
struct ClockRequest {
    ItlIwx *owner;
    thread_t worker;
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
    uint32_t phase;
};

bool acquireClockNic(void *opaque)
{
    auto *owner = static_cast<ItlIwx *>(opaque);
    auto *sc = &owner->com;
    if (sc->sc_nic_locks > 0) {
        owner->iwx_nic_assert_locked(sc);
        ++sc->sc_nic_locks;
        return true;
    }

    // The generic NIC lock can wait 150 ms. This observation is optional and
    // must not stall the main workloop; preserve nested-lock accounting while
    // keeping the nominal polling budget within 2 ms. Scheduler/interrupt
    // preemption is outside this bound.
    IWX_SETBITS(sc, IWX_CSR_GP_CNTRL,
                IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
    DELAY(2);
    if (owner->iwx_poll_bit(sc, IWX_CSR_GP_CNTRL,
            IWX_CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN,
            IWX_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY |
                IWX_CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP,
            1980)) {
        ++sc->sc_nic_locks;
        return true;
    }

    // iwx_nic_lock() leaves MAC_ACCESS_REQ set on timeout. Do not leak that
    // request from this diagnostic-only acquisition attempt.
    IWX_CLRBITS(sc, IWX_CSR_GP_CNTRL,
                IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
    return false;
}

void releaseClockNic(void *opaque)
{
    auto *owner = static_cast<ItlIwx *>(opaque);
    owner->iwx_nic_unlock(&owner->com);
}

uint64_t clockHostNs(void *)
{
    uint64_t absolute = 0, nanoseconds = 0;
    clock_get_uptime(&absolute);
    absolutetime_to_nanoseconds(absolute, &nanoseconds);
    return nanoseconds;
}

uint32_t readClockPrph(void *opaque, uint32_t address)
{
    auto *owner = static_cast<ItlIwx *>(opaque);
    return owner->iwx_read_prph(&owner->com, address);
}

bool clockResourcesAbsent(ItlIwx *owner)
{
    if (!owner || !owner->nativeP2pTxLock_)
        return false;

    const IOInterruptState interruptState = IOSimpleLockLockDisableInterrupt(
        owner->nativeP2pTxLock_);
    const auto queue = owner->nativeP2pTxQueue_.lifecycle.snapshot();
    const auto stations = owner->nativeP2pStationRegistry_.snapshot();
    const auto ticket = owner->nativeP2pActionTx_.completion.snapshot();
    // CompletionTracker intentionally keeps the last completed ticket for
    // diagnostics (armed=1, completed=1). Only an armed, incomplete ticket
    // represents outstanding descriptor ownership; reject inconsistent flags.
    const bool ticketStateAllowsProbe =
        (!ticket.armed && !ticket.completed) ||
        (ticket.armed && ticket.completed);
    const bool absent =
        owner->nativeP2pActionTx_.state == TahoeP2PActionTxState::kIdle &&
        ticketStateAllowsProbe &&
        owner->nativeP2pTxQueue_.state == TahoeP2PResourceState::kAbsent &&
        owner->nativeP2pTxQueue_.pendingRing == nullptr &&
        !owner->nativeP2pTxQueue_.submissionBusy &&
        queue.state == IntelP2PTx::QueueState::kAbsent &&
        queue.outstandingTx == 0 && !queue.ringMustRemainOwned &&
        owner->nativeP2pStation_.state == TahoeP2PResourceState::kAbsent &&
        IntelP2PTx::noP2pResourcesRetained(stations, queue) &&
        owner->com.sc_p2p.mac_state == IWX_P2P_RESOURCE_ABSENT &&
        owner->com.sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT &&
        !owner->com.sc_p2p.phy_leased;
    IOSimpleLockUnlockEnableInterrupt(owner->nativeP2pTxLock_,
                                      interruptState);
    return absent;
}

IOReturn observeClockOnGate(OSObject *, void *opaque,
                            void *, void *, void *)
{
    auto *request = static_cast<ClockRequest *>(opaque);
    if (!request || !request->owner || request->phase > 1)
        return kIOReturnBadArgument;
    ItlIwx *owner = request->owner;
    auto *controller = owner->tahoeP2pController();
    if (!controller || !owner->tahoeP2pOnMainGate())
        return kIOReturnNotReady;

    const char *statusKey = request->phase == 0 ?
        "NativeP2PGp2PreStatus" : "NativeP2PGp2PostStatus";
    // The entire signed manual profile is required independently of the
    // worker's profile validation. Normal Wi-Fi never touches this register.
    const char *profile[] = {"NativeP2PGp2Observation", "NativeP2PProbe",
        "NativeP2PRocProbe", "NativeP2PTxProbe", "NativeP2PManualTrigger",
        "NativeP2PAwdlPsfObservationOnly", "NativeP2PAwdlMifFollowup"};
    for (const char *key : profile) {
        if (controller->getProperty(key) != kOSBooleanTrue) {
            controller->setProperty(statusKey, 16u, 32);
            return kIOReturnUnsupported;
        }
    }

    auto *sc = &owner->com;
    if (request->contextGeneration == 0 ||
        owner->nativeP2pProbeGeneration_ != request->contextGeneration ||
        uint32_t(sc->sc_generation) != request->powerGeneration ||
        __atomic_load_n(&sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE) !=
            request->stationGeneration) {
        controller->setProperty(statusKey, 17u, 32);
        return kIOReturnNotReady;
    }
    if (!owner->nativeP2pBusy() ||
        __atomic_load_n(&owner->nativeP2pProbeOwner_, __ATOMIC_ACQUIRE) !=
            reinterpret_cast<void *>(request->worker) ||
        __atomic_load_n(&owner->nativeP2pCancelRequested_, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&owner->nativeP2pNswqPaused_, __ATOMIC_ACQUIRE) == 0 ||
        sc->sc_ic.ic_state != IEEE80211_S_RUN ||
        (sc->sc_flags & (IWX_FLAG_SHUTDOWN | IWX_FLAG_HW_ERR)) != 0 ||
        !clockResourcesAbsent(owner)) {
        // Never use a new hardware read as recovery from uncertain DMA.
        controller->setProperty(statusKey, 18u, 32);
        return kIOReturnBusy;
    }

    const IntelGp2Clock::SampleBackend backend {owner, acquireClockNic,
        releaseClockNic, clockHostNs, readClockPrph};
    IntelGp2Clock::RawBracketedSample sample{};
    const auto family = static_cast<IntelGp2Clock::SamplerDeviceFamily>(
        sc->sc_device_family);
    const auto status = IntelGp2Clock::readBracketedGp2(&backend, family,
        request->contextGeneration, &sample);
    // 0 is untouched; 1..5 are SampleStatus+1; 16..18 are outer gates.
    controller->setProperty(statusKey, uint32_t(status) + 1, 32);
    controller->setProperty("NativeP2PGp2MappingProven", uint64_t(0), 32);
    controller->setProperty("NativeP2PGp2DriftBoundProven", uint64_t(0), 32);
    if (status != IntelGp2Clock::SampleStatus::kOk)
        return kIOReturnError;
    if (owner->nativeP2pProbeGeneration_ != request->contextGeneration ||
        uint32_t(sc->sc_generation) != request->powerGeneration ||
        __atomic_load_n(&sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE) !=
            request->stationGeneration) {
        // A station-rate epoch can advance outside the main gate. Do not
        // publish a bracket labeled with generations that changed mid-read.
        controller->setProperty(statusKey, 17u, 32);
        return kIOReturnNotReady;
    }

    if (request->phase == 0) {
        controller->setProperty("NativeP2PGp2PreValue", sample.gp2Us, 32);
        controller->setProperty("NativeP2PGp2PreHostBeforeUs", sample.hostBeforeUs, 64);
        controller->setProperty("NativeP2PGp2PreHostAfterUs", sample.hostAfterUs, 64);
        controller->setProperty("NativeP2PGp2PreGeneration", sample.generation, 64);
    } else {
        controller->setProperty("NativeP2PGp2PostValue", sample.gp2Us, 32);
        controller->setProperty("NativeP2PGp2PostHostBeforeUs", sample.hostBeforeUs, 64);
        controller->setProperty("NativeP2PGp2PostHostAfterUs", sample.hostAfterUs, 64);
        controller->setProperty("NativeP2PGp2PostGeneration", sample.generation, 64);
    }
    controller->setProperty("NativeP2PGp2PrphAddress", sample.prphAddress, 32);
    controller->setProperty("NativeP2PGp2DeviceFamily", uint32_t(sample.family), 32);
    controller->setProperty("NativeP2PGp2PowerGeneration", request->powerGeneration, 32);
    controller->setProperty("NativeP2PGp2StationGeneration", request->stationGeneration, 32);
    return kIOReturnSuccess;
}
} // namespace

void ItlIwx::tahoeP2pObserveGp2(uint32_t contextGeneration,
                              uint32_t powerGeneration,
                              uint32_t stationGeneration, uint32_t phase)
{
    auto *controller = tahoeP2pController();
    auto *loop = getMainWorkLoop();
    auto *gate = getMainCommandGate();
    if (!controller || controller->getProperty("NativeP2PGp2Observation") !=
            kOSBooleanTrue || !loop || !gate || phase > 1 ||
        loop->inGate() || loop->onThread())
        return;
    ClockRequest request {this, current_thread(), contextGeneration,
                           powerGeneration, stationGeneration, phase};
    (void)gate->runAction(observeClockOnGate, &request);
}
#endif
