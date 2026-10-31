#!/usr/bin/env python3
"""Static path checks for the kernel adapter and teardown ordering."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ITL_IWX_CPP = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
ITL_IWX_HPP = (ROOT / "itlwm/hal_iwx/ItlIwx.hpp").read_text()
HAL_VAR_HPP = (ROOT / "itlwm/hal_iwx/if_iwxvar.h").read_text()
KERNEL_ADAPTER = (ROOT / "native/iwx_completion_observer_kernel.hpp").read_text()
P2P_CPP = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()
AIRPORT_V2_CPP = (ROOT / "AirportItlwm/AirportItlwmV2.cpp").read_text()
PROJECT_PBX = (ROOT / "itlwm.xcodeproj/project.pbxproj").read_text()
TAHOE_SCHEME = (ROOT / "itlwm.xcodeproj/xcshareddata/xcschemes/AirportItlwm-Tahoe.xcscheme").read_text()


def method_body(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    end = source.index("\n}\n", opening)
    return source[opening + 1:end]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    require("IOInterruptEventSource *sc_ih;" in HAL_VAR_HPP,
            "HAL still owns the actual sc_ih source")
    tahoe_target_start = PROJECT_PBX.index(
        "89C850F42963928C0C2B5F39 /* AirportItlwm-Tahoe */ = {")
    tahoe_target = PROJECT_PBX[tahoe_target_start:]
    tahoe_source_phase_id = "B6C8B08A53446C0EB3402898 /* Sources */"
    require(tahoe_source_phase_id in tahoe_target and
            "BlueprintIdentifier=\"89C850F42963928C0C2B5F39\"" in TAHOE_SCHEME,
            "the shared Tahoe scheme selects the Tahoe native target")
    source_phase_start = PROJECT_PBX.index(
        "B6C8B08A53446C0EB3402898 /* Sources */ = {")
    source_phase = PROJECT_PBX[source_phase_start:
                                PROJECT_PBX.index("\n\t\t};", source_phase_start)]
    require("AirportItlwmV2.cpp in Sources" in source_phase,
            "Tahoe target compiles AirportItlwmV2 watchdog lifecycle")
    require("IOSimpleLockAlloc()" in KERNEL_ADAPTER and
            "IOSimpleLockTryLock(lock_)" in KERNEL_ADAPTER and
            "Registry<IOSimpleLockAdapter, 1>" in KERNEL_ADAPTER,
            "kernel adapter must use one stable IOSimpleLock-backed registry")

    attach = method_body(ITL_IWX_CPP,
                         "bool ItlIwx::attach(IOPCIDevice *device)")
    observer_init = attach.index("nativeRxCompletionObserver_.initialize()")
    driver_attach = attach.index("if (!iwx_attach(&com, &pci))")
    require(observer_init < driver_attach,
            "registry initialization precedes all RX-ring callers")
    require("detach(device);" in attach and
            attach.index("detach(device);") < attach.index("releaseAll();"),
            "partial iwx_attach failure uses detach before final release")

    iwx_attach = method_body(ITL_IWX_CPP,
        "iwx_attach(struct iwx_softc *sc, struct pci_attach_args *pa)")
    create_source = iwx_attach.index("sc->sc_ih =")
    record_owner = iwx_attach.index("rxInterruptWorkloop_ = pa->workloop;")
    add_source = iwx_attach.index("rxInterruptWorkloop_->addEventSource(sc->sc_ih)")
    registered = iwx_attach.index("rxInterruptSourceRegistered_ = true;")
    enable_source = iwx_attach.index("sc->sc_ih->enable();")
    require(create_source < record_owner < add_source < registered < enable_source,
            "event source records its owner and successful registration in order")

    detach = method_body(ITL_IWX_CPP, "detach(IOPCIDevice *device)")
    p2p_retirement = detach.index("if (nativeP2pTxQueue_.retainedRing)")
    quiesce = detach.index("quiesceRxInterruptSource();")
    first_ring_free = detach.index("iwx_free_tx_ring(sc,")
    require(p2p_retirement < quiesce < first_ring_free,
            "IRQ source removal follows stop/retained-owner branch and precedes every ring free")

    quiesce_body = method_body(ITL_IWX_CPP,
                               "void ItlIwx::quiesceRxInterruptSource()")
    require("if (rxInterruptSourceRegistered_ && workloop != nullptr)" in quiesce_body and
            "workloop->removeEventSource(source)" in quiesce_body and
            quiesce_body.index("removeEventSource(source)") <
            quiesce_body.index("source->release()"),
            "registered source removal synchronizes before its creator reference is released")
    require("com.sc_ih = nullptr;" in quiesce_body and
            "rxInterruptSourceRegistered_ = false;" in quiesce_body and
            "rxInterruptWorkloop_ = nullptr;" in quiesce_body,
            "partial and complete source cleanup is idempotent")
    require("intrHandler->intr = sc->sc_ih" not in ITL_IWX_CPP and
            "intrHandler->intr = source" not in ITL_IWX_CPP,
            "sc_ih has one creator reference; pci_intr_handle does not alias it")

    release = method_body(ITL_IWX_CPP, "void ItlIwx::\nreleaseAll()")
    require(release.index("quiesceRxInterruptSource();") <
            release.index("pci.workloop = NULL;"),
            "releaseAll quiesces actual sc_ih before clearing its workloop owner")
    free = method_body(ITL_IWX_CPP, "void ItlIwx::free()")
    require(free.index("KASSERT(com.sc_ih == nullptr") <
            free.index("nativeRxCompletionObserver_.shutdown()"),
            "registry lock shutdown asserts all IRQ callers have left")

    alloc = method_body(ITL_IWX_CPP,
                        "iwx_alloc_rx_ring(struct iwx_softc *sc, struct iwx_rx_ring *ring)")
    reserve = alloc.index("nativeRxCompletionObserver_.reserve(&ring->used_desc_dma)")
    rx_dma_alloc = alloc.index("iwx_dma_contig_alloc(sc->sc_dmat, &ring->used_desc_dma")
    publish = alloc.index("nativeRxCompletionObserver_.publish(")
    require(reserve < rx_dma_alloc < publish and
            "completionReservationCreated" in alloc and
            "completionAllocationHandle" in alloc,
            "reservation precedes alloc; only the fresh local reservation can publish")

    free_ring = method_body(ITL_IWX_CPP,
                            "iwx_free_rx_ring(struct iwx_softc *sc, struct iwx_rx_ring *ring)")
    unpublish = free_ring.index("nativeRxCompletionObserver_.unpublish(")
    dma_free = free_ring.index("iwx_dma_contig_free(&ring->used_desc_dma)")
    require(unpublish < dma_free,
            "writer retires the view under the lock before legacy DMA free")

    reset = method_body(ITL_IWX_CPP,
                        "iwx_reset_rx_ring(struct iwx_softc *sc, struct iwx_rx_ring *ring)")
    require("nativeRxCompletionObserver_" not in reset,
            "ordinary RX reset preserves the published completion view")

    notif = method_body(ITL_IWX_CPP,
                        "iwx_notif_intr(struct iwx_softc *sc)")
    copy = notif.index("tryCopyForIdentity(")
    record = notif.index("recordAttempt(")
    legacy_drain = notif.index("iwx_rx_pkt(sc, data, &ml, ringSlot);")
    require("nativeRxPreOwner_.enabled()" in notif and copy < record < legacy_drain,
            "bounded observation runs only in the existing window and never changes drain")
    require("setProperty" not in notif and "OSData" not in notif,
            "IRQ path performs no property publication or OSData allocation")

    watchdog_close = method_body(AIRPORT_V2_CPP,
                                 "void AirportItlwm::detachWatchdogTimer()")
    stop = method_body(AIRPORT_V2_CPP, "void AirportItlwm::stop(IOService *provider)")
    require("removeEventSource(watchdogTimer)" in watchdog_close and
            stop.index("detachWatchdogTimer();") <
            stop.index("fHalService->detach(pciNub);"),
            "Tahoe watchdog source is synchronously removed before HAL detach")

    print("PASS Tahoe target selection, stable kernel lock, and actual sc_ih owner")
    print("PASS successful and partial-attach source cleanup before ring free")
    print("PASS unpublish-before-free, exact reservation, and reset persistence")
    print("PASS bounded IRQ observation and Tahoe watchdog-before-HAL order")


if __name__ == "__main__":
    main()
