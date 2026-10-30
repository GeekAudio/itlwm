/*
* Copyright (C) 2020  钟先耀
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*/
/*    $OpenBSD: if_iwx.c,v 1.43 2020/08/02 11:11:07 stsp Exp $    */

/*
 * Copyright (c) 2014, 2016 genua gmbh <info@genua.de>
 *   Author: Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2014 Fixup Software Ltd.
 * Copyright (c) 2017, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*-
 * Based on BSD-licensed source modules in the Linux iwlwifi driver,
 * which were used as the reference documentation for this implementation.
 *
 ******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 - 2019 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * BSD LICENSE
 *
 * Copyright(c) 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 - 2019 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************
 */

/*-
 * Copyright (c) 2007-2010 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef _ITLWMX_H
#define _ITLWMX_H
#include <compat.h>
#include <linux/kernel.h>

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/kpi_mbuf.h>

#include "if_iwxreg.h"
#include "if_iwxvar.h"
#include <sys/pcireg.h>

#include <IOKit/network/IOEthernetController.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <libkern/c++/OSString.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <IOKit/IOFilterInterruptEventSource.h>
#include <IOKit/IOLocks.h>

#include <HAL/ItlHalService.hpp>
#include <HAL/ItlDriverInfo.hpp>
#include <HAL/ItlDriverController.hpp>
#include "../../native/iwx_tx_watchdog.hpp"
#include "../../native/iwx_output_kick.hpp"

#ifdef AIRPORT_TAHOE
#include "../../native/intel_p2p_rx_router.hpp"
#include "../../native/awdl_rx_event_timeline.hpp"
#include "../../native/awdl_data_frame.hpp"
#include "../../native/awdl_rx_entry_telemetry.hpp"
#include "../../native/rx_preowner_observation.hpp"
#include "../../native/p2p_rx149_data_input.hpp"
#include "../../native/awdl_rx_entry_publisher.hpp"
#include "../../native/awdl_peer_observer.hpp"
#include "../../native/awdl_peer_runtime_table.hpp"
#include "../../native/p2p_hal_probe.hpp"
#include "../../native/intel_roc_event_state.hpp"
#include "../../native/iwx_reset_trace.hpp"
#include "../../native/iwx_link_state_trace.hpp"
#include "../../native/iwx_mcc_refresh_policy.hpp"
#include "../../native/iwx_fw_diagnostics.hpp"
#include "ItlIwxP2PTx.hpp"
#include "ItlIwxP2PAction.hpp"
#endif

/* A command-local value snapshot. Never retains ic pointers or user storage. */
struct itl_iwx_scan_policy {
    uint8_t ssid[32];
    uint8_t ssid_len;
    bool active;
    bool requested;
    uint8_t channels[32];
    bool restricted;
    uint32_t generation;
    uint8_t source_addr[6];
};

#ifdef AIRPORT_TAHOE
// Numeric-only RX stage evidence for one active native P2P probe generation.
// Action parsing and data-candidate classification read bounded headers only;
// the data counters mean AWDL-BSSID candidates, not decoded/delivered packets.
// No frame, address, TLV value, or user data is stored.
struct TahoeAwdlRxStageCounters {
    enum FrameKind : uint8_t {
        kNotAwdl = 0,
        kPsf = 1,
        kMif = 2
    };
    enum Stage : uint8_t {
        kEarly = 0,
        kAfterDecrypt = 1,
        kDecryptRejected = 2,
        kAfterDuplicate = 3,
        kDuplicateRejected = 4,
        kTap = 5,
        kStageCount = 6
    };
    enum { kKindCount = 2 };
    enum DataStage : uint8_t {
        kDataEarlyCandidate = 0,
        kDataAfterDecryptCandidate = 1,
        kDataDecryptRejected = 2,
        kDataAfterDuplicateCandidate = 3,
        kDataDuplicateRejected = 4,
        kDataTapCandidate = 5,
        kDataTapRejected = 6,
        kDataStageCount = 7
    };

    struct Snapshot {
        uint32_t ownerGeneration;
        uint32_t active;
        uint32_t counts[kStageCount][kKindCount];
        uint32_t dataCounts[kDataStageCount];
    };

    static FrameKind classify(const uint8_t *frame, size_t length)
    {
        // Safe only after the MPDU descriptor and its declared length passed
        // validation. Retain independent bounds checks for every byte read.
        if (!frame || length < 2)
            return kNotAwdl;
        const uint16_t fc = uint16_t(frame[0]) |
                            (uint16_t(frame[1]) << 8);
        const uint8_t version = uint8_t(fc & 0x3u);
        const uint8_t type = uint8_t((fc >> 2) & 0x3u);
        const uint8_t subtype = uint8_t((fc >> 4) & 0xfu);
        if (version != 0 || type != 0 || subtype != 13 ||
            (fc & 0x0300u) != 0 || (fc & 0x4000u) != 0)
            return kNotAwdl;

        const size_t macHeaderLength = 24u + ((fc & 0x8000u) ? 4u : 0u);
        if (length < macHeaderLength + 8u)
            return kNotAwdl;
        const uint8_t *body = frame + macHeaderLength;
        if (body[0] != 127 || body[1] != 0x00 || body[2] != 0x17 ||
            body[3] != 0xf2 || body[4] != 8 || body[5] != 0x10 ||
            body[7] != 0)
            return kNotAwdl;
        if (body[6] == 0)
            return kPsf;
        if (body[6] == 3)
            return kMif;
        return kNotAwdl;
    }

    void beginOwner(uint32_t generation)
    {
        if (!generation)
            return;
        const uint32_t owner = __atomic_load_n(&ownerGeneration_, __ATOMIC_ACQUIRE);
        const uint32_t active = __atomic_load_n(&active_, __ATOMIC_ACQUIRE);
        if (owner == generation && active)
            return;

        // Callers synchronize this transition on the main workloop gate.
        __atomic_store_n(&active_, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&ownerGeneration_, 0u, __ATOMIC_RELEASE);
        for (unsigned stage = 0; stage < kStageCount; ++stage)
            for (unsigned kind = 0; kind < kKindCount; ++kind)
                __atomic_store_n(&counts_[stage][kind], 0u, __ATOMIC_RELAXED);
        for (unsigned stage = 0; stage < kDataStageCount; ++stage)
            __atomic_store_n(&dataCounts_[stage], 0u, __ATOMIC_RELAXED);
        __atomic_store_n(&ownerGeneration_, generation, __ATOMIC_RELEASE);
        __atomic_store_n(&active_, 1u, __ATOMIC_RELEASE);
    }

    void endOwner(uint32_t generation)
    {
        if (generation &&
            __atomic_load_n(&ownerGeneration_, __ATOMIC_ACQUIRE) == generation)
            __atomic_store_n(&active_, 0u, __ATOMIC_RELEASE);
    }

    bool record(uint32_t generation, FrameKind kind, Stage stage)
    {
        if (!generation || (kind != kPsf && kind != kMif) ||
            stage >= kStageCount ||
            !__atomic_load_n(&active_, __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&ownerGeneration_, __ATOMIC_ACQUIRE) != generation)
            return false;
        __atomic_fetch_add(&counts_[stage][unsigned(kind) - 1u], 1u,
                           __ATOMIC_RELAXED);
        return true;
    }

    bool recordData(uint32_t generation, DataStage stage)
    {
        if (!generation || stage >= kDataStageCount ||
            !__atomic_load_n(&active_, __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&ownerGeneration_, __ATOMIC_ACQUIRE) != generation)
            return false;
        __atomic_fetch_add(&dataCounts_[stage], 1u, __ATOMIC_RELAXED);
        return true;
    }

    Snapshot snapshot() const
    {
        Snapshot result{};
        result.ownerGeneration =
            __atomic_load_n(&ownerGeneration_, __ATOMIC_ACQUIRE);
        result.active = __atomic_load_n(&active_, __ATOMIC_ACQUIRE);
        for (unsigned stage = 0; stage < kStageCount; ++stage)
            for (unsigned kind = 0; kind < kKindCount; ++kind)
                result.counts[stage][kind] =
                    __atomic_load_n(&counts_[stage][kind], __ATOMIC_RELAXED);
        for (unsigned stage = 0; stage < kDataStageCount; ++stage)
            result.dataCounts[stage] =
                __atomic_load_n(&dataCounts_[stage], __ATOMIC_RELAXED);
        return result;
    }

private:
    uint32_t ownerGeneration_ {0};
    uint32_t active_ {0};
    uint32_t counts_[kStageCount][kKindCount] {};
    uint32_t dataCounts_[kDataStageCount] {};
};
#endif

class ItlIwx : public ItlHalService, ItlDriverInfo, ItlDriverController {
    OSDeclareDefaultStructors(ItlIwx)
    
public:
    
    //kext
    void free() override;
    virtual bool attach(IOPCIDevice *device) override;
    virtual void detach(IOPCIDevice *device) override;
    IOReturn enable(IONetworkInterface *netif) override;
    IOReturn disable(IONetworkInterface *netif) override;
    virtual struct ieee80211com *get80211Controller() override;
    
    static bool intrFilter(OSObject *object, IOFilterInterruptEventSource *src);
    static IOReturn _iwx_start_task(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);
#ifdef AIRPORT_TAHOE
    IwxOutputKick::DrainResult iwx_start_drain(struct _ifnet *, uint32_t epoch);
    static IOReturn _iwx_watchdog_task(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);
    static void iwx_native_mcc_refresh_task(void *);
    static IOReturn iwx_native_mcc_capture_action(
        OSObject *, void *, void *, void *, void *);
    static IOReturn iwx_native_mcc_apply_action(
        OSObject *, void *, void *, void *, void *);
#endif
    
    virtual ItlDriverInfo *getDriverInfo() override;
    
    virtual ItlDriverController *getDriverController() override;
    
    //driver info
    virtual const char *getFirmwareVersion() override;
    
    virtual int16_t getBSSNoise() override;
    
    virtual bool is5GBandSupport() override;
    
    virtual int getTxNSS() override;
    
    virtual const char *getFirmwareName() override;
    
    virtual UInt32 supportedFeatures() override;

    virtual const char *getFirmwareCountryCode() override;

    virtual uint32_t getTxQueueSize() override;
    
    //driver controller
    virtual void clearScanningFlags() override;
    
    virtual IOReturn setMulticastList(IOEthernetAddress *addr, int count) override;
    
    void releaseAll();
#ifdef AIRPORT_TAHOE
    /* Serializes synchronous per-device firmware work against power stop. */
    IORecursiveLock *nativeLifecycleLock_ {nullptr};
    uint32_t nativeLifecycleDepth_ {0};
    uint32_t nativeLifecycleDeferredTasks_ {0};
    uint32_t nativeLifecycleTearingDown_ {0};
    uint64_t nativeLifecycleStopRejectFingerprint_ {0};
    IwxResetTrace::Trace nativeResetTrace_ {};
    IwxLinkStateTrace::Trace nativeLinkTransitionTrace_ {};
    IwxFirmwareDiagnostics::TraceRing nativeFwDiagnosticTrace_ {};
    IwxFirmwareDiagnostics::TraceSnapshot nativeFwDiagnosticPendingTrace_ {};
    IwxFirmwareDiagnostics::TraceWireBuffer nativeFwDiagnosticWireBuffer_ {};
    IwxFirmwareDiagnostics::FirmwareErrorSnapshot nativeFwErrorSnapshot_ {};
    // Pending trace/error snapshots and all publication fingerprints are
    // owned by the main command gate. The lock-free HCMD/RX producers touch
    // only nativeFwDiagnosticTrace_; generation/status handoff words below
    // are atomic because those producers and the command gate cross threads.
    uint32_t nativeFwDiagnosticPendingTraceGeneration_ {0};
    uint32_t nativeFwDiagnosticPendingWatchdogSequence_ {0};
    uint32_t nativeFwDiagnosticPendingTracePresent_ {0};
    uint32_t nativeFwDiagnosticTraceFrozen_ {0};
    uint32_t nativeFwDiagnosticTraceManualLatched_ {0};
    uint64_t nativeFwDiagnosticTraceLastSampleNs_ {0};
    uint32_t nativeFwDiagnosticAliveGeneration_ {0};
    uint32_t nativeFwDiagnosticTlvGeneration_ {0};
    uint32_t nativeFwDiagnosticExpectedLmacTable_[2] {};
    uint32_t nativeFwDiagnosticExpectedUmacTable_ {0};
    uint32_t nativeFwDiagnosticCaptureStatus_ {0};
    uint32_t nativeFwDiagnosticCaptureGeneration_ {0};
    uint32_t nativeFwDiagnosticCaptureSerial_ {0};
    uint32_t nativeFwDiagnosticCaptureResetSequence_ {0};
    uint32_t nativeFwDiagnosticCaptureWatchdogSequence_ {0};
    uint32_t nativeFwDiagnosticCaptureWatchdogPresent_ {0};
    uint32_t nativeFwDiagnosticCaptureResetReason_ {0};
    uint32_t nativeFwDiagnosticPublishRevision_ {0};
    uint32_t nativeHcmdRxTracePublishRevision_ {0};
    uint32_t nativeFwDiagnosticLastPublishedCaptureSerial_ {0};
    uint64_t nativeFwDiagnosticLastPublishedTraceSerial_ {0};
    uint32_t nativeFwDiagnosticLastPublishedAttemptStatus_ {0};
    uint32_t nativeFwDiagnosticLastPublishedAttemptSerial_ {0};
    uint64_t nativeFwDiagnosticLastPublishedTraceFingerprint_ {0};
    uint64_t nativeFwDiagnosticLastPublishedErrorFingerprint_ {0};
    uint32_t nativeFirmwareIdentityPublishedGeneration_ {0};
    uint32_t nativeResetTracePublishedSequence_ {UINT32_MAX};
    uint32_t nativeResetTracePublishedTriggerSequence_ {UINT32_MAX};
    uint32_t nativeResetTracePublishedTriggerRevision_ {UINT32_MAX};
    uint32_t nativeResetTracePublishedTxProgressWatchdogSequence_ {UINT32_MAX};
    uint32_t nativeResetTracePublishVersion_ {0};
    bool nativeResetTracePublishedOnce_ {false};
    uint32_t nativeLinkTransitionResetSequence_ {0};
    uint32_t nativeLinkTransitionWatchdogSequence_ {0};
    uint32_t nativeLinkTransitionPublishedVersion_ {0};
    uint32_t nativeLinkTransitionPublishedDropped_ {0};
    bool nativeLinkTransitionPublishedOnce_ {false};
    void tahoeRecordLinkTransition(struct iwx_softc *,
        IwxLinkStateTrace::Event, uint32_t, uint32_t, int, int,
        uint32_t resetSequence = UINT32_MAX,
        bool resetSequenceValid = false);
    bool tahoePublishLinkTransitionTrace(IOEthernetController *);
    void tahoeRecordFirmwareMetadata(
        struct iwx_softc *, IwxFirmwareDiagnostics::Entry);
    void tahoeFreezeFirmwareMetadata(
        struct iwx_softc *, uint32_t watchdogSequence);
    void tahoeRecordFirmwareErrorInterrupt(
        struct iwx_softc *, uint32_t interruptStatus,
        uint32_t detailStatus = 0);
    void tahoeCapturePreResetFirmwareErrorSnapshot(
        struct iwx_softc *, IwxResetTrace::ResetReason, uint32_t resetSequence);
    bool tahoePublishFirmwareDiagnostics(IOEthernetController *,
                                         struct iwx_softc *,
                                         bool forceTraceSample = false);
    static IOReturn _tahoe_fw_error_snapshot_action(
        OSObject *, void *, void *, void *, void *);
    static IOReturn _tahoe_fw_diagnostics_publish_action(
        OSObject *, void *, void *, void *, void *);
    bool tahoeTryLifecycleFence();
    bool tahoeReleaseLifecycleFence(bool flushDeferredTasks = true);
    void tahoeDeferLifecycleTasks(uint32_t);
    void tahoeFlushLifecycleTasks();
    void tahoeClearStopBlockState();
    void tahoeRecordInitTaskTrigger(IwxResetTrace::InitTaskTrigger);
    void tahoeRecordTxWatchdogSnapshot(struct iwx_softc *, uint32_t);
    void tahoePublishTxProgressSnapshot(IOEthernetController *, struct iwx_softc *);
    bool tahoePublishStaTxSnapshot(IOEthernetController *, struct iwx_softc *);
    uint32_t tahoeRecordReset(IwxResetTrace::ResetReason, struct iwx_softc *);
    void tahoePublishResetTrace(IOEthernetController *);
    void tahoePublishMccSnapshot(IOEthernetController *);
    void tahoeMccScheduleIfReady(struct iwx_softc *);
    int iwx_request_mcc_profile(struct iwx_softc *, uint16_t requestMcc,
        uint8_t requestSource, IwxMccRefreshPolicy::ProfileResponse *,
        bool requireMultiSource);

    void nativeP2pTick() override;
    bool nativeP2pBusy() override;
    IOReturn nativeP2pArmProbe() override;
    bool nativeP2pCommandAllowed() const;
    void tahoeP2pInitializeTask();
    int tahoeP2pStopBeforeReset(struct iwx_softc *);
    void tahoeP2pResetDrained(struct iwx_softc *, uint32_t drainedGeneration);
    static void tahoeP2pProbeTask(void *);
    static NativeP2PProbe::BlockedReason tahoeP2pRevalidate(
        void *, uint32_t, uint32_t);
    static int tahoeP2pConfigure(void *);
    static int tahoeP2pAdd(void *);
    static int tahoeP2pRemove(void *);
    static bool tahoeP2pPublishLease(void *, bool);
    static IOReturn tahoeP2pAdmitAction(OSObject *, void *, void *, void *, void *);
    static IOReturn tahoeP2pValidateAction(OSObject *, void *, void *, void *, void *);
    static IOReturn tahoeP2pCancelAction(OSObject *, void *, void *, void *, void *);
    static IOReturn tahoeP2pLeaseAction(OSObject *, void *, void *, void *, void *);
    static IOReturn tahoeP2pFinishAction(OSObject *, void *, void *, void *, void *);
    static IOReturn tahoeP2pResetAction(OSObject *, void *, void *, void *, void *);
    static IOReturn tahoeRetireStoppedQueuesAction(
        OSObject *, void *, void *, void *, void *);
    void tahoeRetireStoppedQueuesAfterSoftStop(struct iwx_softc *, int);
    void tahoeP2pTapTimeEvent(struct iwx_softc *, const uint8_t *, size_t);
    void tahoeP2pTapAction(struct iwx_softc *, const uint8_t *, size_t, bool,
                           uint16_t, uint32_t, bool, uint32_t, bool,
                           const NativeP2PRx149DataInput::OriginalDescriptor * = nullptr);
    bool tahoeP2pRx149DataLease(NativeP2PRx149DataInput::Lease *);
    void tahoeP2pRxConsume();
    void tahoeP2pRxDrain();
    static IOReturn tahoeP2pRxDrainAction(OSObject *, void *, void *, void *, void *);
    bool tahoeP2pCurrentRxDiagnosticEpochs(
        struct iwx_softc *, NativeAwdlRxEntry::Epochs *, uint32_t * = nullptr);
    void tahoeRxPreOwnerEvent(NativeRxPreOwner::EventKind,
        uint32_t = UINT32_MAX, uint32_t = UINT32_MAX,
        uint32_t = UINT32_MAX, uint32_t = 0, uint32_t = 0);
    void tahoeRxPreOwnerIrq(uint32_t cause, bool msix);
    void tahoeRxPreOwnerStop();
    void tahoeRxPreOwnerPublish(IOEthernetController *);
    void tahoeP2pSyncRxDiagnosticOwner(bool closeOnly);
    void tahoeP2pPublishRxStageCounters(IOEthernetController *);
    void tahoeP2pPublishRxEntryTelemetry(IOEthernetController *);
    void tahoeP2pPublishRxEventTimeline(IOEthernetController *);
    void tahoeP2pPublishNativeAwdlAttachTrace(IOEthernetController *);
    void tahoeP2pPublishProbeState();
    void tahoeP2pObserveGp2(uint32_t, uint32_t, uint32_t, uint32_t);
    static int tahoeP2pExerciseRoc(void *);
    static bool tahoeP2pExerciseRecovery(
        void *, int32_t, NativeP2PProbe::ExerciseRecoveryProof *);
    static IOReturn tahoeP2pExerciseRecoveryAction(
        OSObject *, void *, void *, void *, void *);
    static bool tahoeP2pArmRoc(void *, uint32_t, uint32_t, uint32_t);
    static IOReturn tahoeP2pRocEventAction(OSObject *, void *, void *, void *, void *);
    void tahoeP2pTapSessionEvent(struct iwx_softc *, const uint8_t *, size_t);
    void tahoeP2pPublishRocState();

    IntelROCEvent::SessionTracker nativeP2pRocEvents_;
    bool tahoeP2pOnMainGate() {
        IOWorkLoop *loop = getMainWorkLoop();
        return loop && loop->inGate();
    }
    IOCommandGate *tahoeP2pCommandGate() { return getMainCommandGate(); }
    IOEthernetController *tahoeP2pController() { return getController(); }
    bool nativeP2pResourcesRetained();
    IOSimpleLock *nativeP2pTxLock_ {nullptr};
    IntelP2PTx::StationRegistry nativeP2pStationRegistry_;
    TahoeP2PStationLease nativeP2pStation_ {};
    TahoeP2PTxQueueLease nativeP2pTxQueue_ {};
    TahoeP2PActionTxContext nativeP2pActionTx_;
    uint32_t nativeP2pRocStage_ {0};
    uint32_t nativeP2pRocResult_ {0};
    uint32_t nativeP2pRocGeneration_ {0};
    uint32_t nativeP2pRocConfiguration_ {0};
    uint32_t nativeP2pRocChannel_ {0};
    uint32_t nativeP2pRocDurationMs_ {0};
    uint32_t nativeP2pRocStartSeen_ {0};
    uint32_t nativeP2pRocEndSeen_ {0};
    uint32_t nativeP2pRocStartStatus_ {0};
    uint32_t nativeP2pRocEndStatus_ {0};
    uint32_t nativeP2pRocCommandResult_ {0};
    uint32_t nativeP2pRocObserved_ {0};
    uint32_t nativeP2pRocCleanupAllowed_ {0};
    uint32_t nativeP2pRocUnknown_ {0};
    uint32_t nativeP2pRocPublishedStage_ {0xffffffff};

    NativeP2PProbe::Controller nativeP2pProbe_;
    struct task tahoe_p2p_probe_task_;
    uint32_t tahoe_p2p_probe_task_initialized_ {0};
    uint32_t nativeP2pProbeQueued_ {0};
    uint32_t nativeP2pProbeRunAllocationFailed_ {0};
    uint32_t nativeP2pManualArmRequested_ {0};
    uint32_t nativeP2pCancelRequested_ {0};
    uint32_t nativeP2pProbeBusy_ {0};
    void *nativeP2pProbeOwner_ {nullptr};
    uint32_t nativeP2pNswqPaused_ {0};
    uint32_t nativeP2pProbeGeneration_ {0};
    uint64_t nativeP2pStopRejectFingerprint_ {0};
    uint64_t nativeStateQueueStopRejectFingerprint_ {0};
    bool nativeP2pProbePublishedOnce_ {false};
    NativeP2PProbe::Snapshot nativeP2pProbePublished_{};

    IntelP2PRx::Router tahoe_p2p_rx_router_;
    NativeAwdlRxTrace::Timeline nativeAwdlRxEventTimeline_{};
    uint64_t nativeAwdlRxEventOwnerSerial_ {0};
    uint64_t nativeAwdlRxEventNextOwnerSerial_ {0};
    uint64_t nativeAwdlRxEventPublishedRevision_ {UINT64_MAX};
    uint64_t nativeAwdlRxEventPublishVersion_ {0};
    bool nativeAwdlRxEventPublishedOnce_ {false};
    uint64_t nativeAwdlAttachTracePublishedRevision_ {UINT64_MAX};
    uint32_t nativeAwdlAttachTracePublishVersion_ {0};
    bool nativeAwdlAttachTracePublishedOnce_ {false};
    bool nativeAwdlAttachTraceInvalidated_ {false};
    IntelP2PRx::LeaseSnapshot tahoe_p2p_rx_lease_{};
    IntelP2PRx::Counters tahoe_p2p_rx_published_{};
    bool tahoe_p2p_rx_published_once_ {false};
    TahoeAwdlRxStageCounters tahoe_awdl_rx_stage_counters_{};
    TahoeAwdlRxStageCounters::Snapshot tahoe_awdl_rx_stage_published_{};
    bool tahoe_awdl_rx_stage_published_once_ {false};
    NativeAwdlRxEntry::Telemetry nativeAwdlRxEntryTelemetry_{};
    NativeRxPreOwner::Observer nativeRxPreOwner_{};
    uint32_t nativeRxPreOwnerArmed_ {0};
    uint64_t nativeRxPreOwnerStopSerial_ {0};
    uint32_t nativeRxPreOwnerStopDepth_ {0};
    bool nativeRxPreOwnerPublished_ {false};
    NativeRxPreOwner::Snapshot nativeRxPreOwnerPublishSnapshot_{};
    uint64_t nativeRxPreOwnerPublishWords_[1024] {};
    NativeAwdlRxEntry::Snapshot nativeAwdlRxEntryPublished_{};
    uint32_t nativeAwdlRxEntryAttemptVersion_ {0};
    uint32_t nativeAwdlRxEntryPublishVersion_ {0};
    bool nativeAwdlRxEntryPublishedOnce_ {false};
    IntelAwdlPeer::Observer tahoe_awdl_peer_observer_;
    IntelAwdlPeerRuntime::Table tahoe_awdl_peer_runtime_;
    uint64_t tahoe_awdl_runtime_published_[176] {};
    uint32_t tahoe_awdl_runtime_last_result_ {UINT32_MAX};
    bool tahoe_awdl_runtime_published_once_ {false};
    void tahoeP2pPublishPeerRuntime();
    IntelAwdlPeer::Snapshot tahoe_awdl_peer_published_{};
    uint32_t tahoe_awdl_peer_accepted_frames_ {0};
    uint32_t tahoe_awdl_peer_rejected_records_ {0};
    uint32_t tahoe_awdl_peer_last_result_ {UINT32_MAX}; // No observation yet.
    bool tahoe_awdl_peer_dirty_ {true};

    /* Synchronous, nonblocking event notification; receiver owns its drain. */
    void tahoeDriverEvent(int code);
    IOSimpleLock *tahoe_scan_lock_ = nullptr;
    uint32_t tahoe_scan_phase_ = ITL_TAHOE_SCAN_STOPPED;
    uint32_t tahoe_scan_serial_ = 0;
    uint32_t tahoe_scan_generation_ = 0;
    bool tahoe_scan_online_ = false;
    bool tahoe_scan_starting_ = false;
    bool tahoe_scan_terminal_pending_ = false;
    bool tahoe_scan_terminal_processing_ = false;
    uint32_t tahoe_scan_terminal_status_ = 0;
    int tahoe_newstate_generation_ = -1;
    struct task tahoe_scan_abort_task_;
    static uint32_t tahoeScanState(struct ieee80211com *);
    static int tahoeScanCancel(struct ieee80211com *);
    static void tahoeScanAbortTask(void *);
    void tahoeScanOnline(bool);
    void tahoeScanResetComplete(); // Only after firmware stop and RX ring reset.
    static IOReturn tahoeScanResetAction(OSObject *, void *, void *, void *, void *);
    int tahoeCommitScanStart(struct iwx_softc *, uint32_t);
    static IOReturn tahoeScanTerminalAction(OSObject *, void *, void *, void *, void *);
#endif
    void joinSSID(const char *ssid, const char *pwd);
    
    //utils
    static void *mallocarray(size_t, size_t, int, int);
    
//    static void onLoadFW(OSKextRequestTag requestTag, OSReturn result, const void *resourceData, uint32_t resourceDataLength, void *context);
    
    uint8_t    iwx_lookup_cmd_ver(struct iwx_softc *, uint8_t, uint8_t);
    uint8_t    iwx_lookup_notif_ver(struct iwx_softc *, uint8_t, uint8_t);
    uint32_t    iwx_lmac_id(struct iwx_softc *, ieee80211_channel *);
    int    iwx_store_cscheme(struct iwx_softc *, uint8_t *, size_t);
    int    iwx_alloc_fw_monitor_block(struct iwx_softc *, uint8_t, uint8_t);
    int    iwx_alloc_fw_monitor(struct iwx_softc *, uint8_t);
    int    iwx_apply_debug_destination(struct iwx_softc *);
    int    iwx_ctxt_info_init(struct iwx_softc *, const struct iwx_fw_sects *);
    int    iwx_ctxt_info_gen3_init(struct iwx_softc *, const struct iwx_fw_sects *);
    void iwx_ctxt_info_free_fw_img(struct iwx_softc *sc);
    int iwx_ctxt_info_alloc_dma(struct iwx_softc *sc,
                                const struct iwx_fw_onesect *sec, struct iwx_dma_info *dram);
    void    iwx_ctxt_info_free_paging(struct iwx_softc *);
    int iwx_get_num_sections(const struct iwx_fw_sects *fws, int start);
    int    iwx_init_fw_sec(struct iwx_softc *, const struct iwx_fw_sects *,
            struct iwx_context_info_dram *);
    void    iwx_fw_version_str(char *, size_t, uint32_t, uint32_t, uint32_t);
    int    iwx_firmware_store_section(struct iwx_softc *, enum iwx_ucode_type,
            uint8_t *, size_t);
    int    iwx_set_default_calib(struct iwx_softc *, const void *);
    void    iwx_fw_info_free(struct iwx_fw_info *);
    void    iwx_pnvm_free(struct iwx_fw_info *);
    int    iwx_read_firmware(struct iwx_softc *);
    int    iwx_read_pnvm(struct iwx_softc *);
    int     iwx_load_pnvm(struct iwx_softc *);
    int     iwx_pnvm_handle_section(struct iwx_softc *, const uint8_t *, size_t);
    uint32_t iwx_read_prph_unlocked(struct iwx_softc *, uint32_t);
    uint32_t iwx_read_prph(struct iwx_softc *, uint32_t);
    uint32_t iwx_read_umac_prph(struct iwx_softc *, uint32_t);
    void    iwx_write_prph(struct iwx_softc *, uint32_t, uint32_t);
    void    iwx_write_prph_unlocked(struct iwx_softc *, uint32_t, uint32_t);
    void    iwx_write_umac_prph(struct iwx_softc *, uint32_t, uint32_t);
    void iwx_write_prph64(struct iwx_softc *sc, uint64_t addr, uint64_t val);
    int    iwx_read_mem(struct iwx_softc *, uint32_t, void *, int);
    int    iwx_write_mem(struct iwx_softc *, uint32_t, const void *, int);
    int    iwx_write_mem32(struct iwx_softc *, uint32_t, uint32_t);
    int    iwx_poll_bit(struct iwx_softc *, int, uint32_t, uint32_t, int);
    int    iwx_nic_lock(struct iwx_softc *);
    void    iwx_nic_assert_locked(struct iwx_softc *);
    void    iwx_nic_unlock(struct iwx_softc *);
    void    iwx_set_bits_mask_prph(struct iwx_softc *, uint32_t, uint32_t,
            uint32_t);
    void    iwx_set_bits_prph(struct iwx_softc *, uint32_t, uint32_t);
    void    iwx_clear_bits_prph(struct iwx_softc *, uint32_t, uint32_t);
    int    iwx_dma_contig_alloc(bus_dma_tag_t, struct iwx_dma_info *, bus_size_t,
            bus_size_t);
    void    iwx_dma_contig_free(struct iwx_dma_info *);
    int    iwx_alloc_rx_ring(struct iwx_softc *, struct iwx_rx_ring *);
    void    iwx_disable_rx_dma(struct iwx_softc *);
    void    iwx_reset_rx_ring(struct iwx_softc *, struct iwx_rx_ring *);
    void    iwx_free_rx_ring(struct iwx_softc *, struct iwx_rx_ring *);
    void    iwx_tx_ring_init(struct iwx_softc *, struct iwx_tx_ring *, int);
    int    iwx_alloc_tx_ring(struct iwx_softc *, struct iwx_tx_ring *, int);
    void    iwx_reset_tx_ring(struct iwx_softc *, struct iwx_tx_ring *);
    void    iwx_free_tx_ring(struct iwx_softc *, struct iwx_tx_ring *);
    void    iwx_enable_rfkill_int(struct iwx_softc *);
    int    iwx_check_rfkill(struct iwx_softc *);
    void    iwx_enable_interrupts(struct iwx_softc *);
    void    iwx_enable_fwload_interrupt(struct iwx_softc *);
    void    iwx_restore_interrupts(struct iwx_softc *);
    void    iwx_disable_interrupts(struct iwx_softc *);
    void    iwx_ict_reset(struct iwx_softc *);
    int    iwx_set_hw_ready(struct iwx_softc *);
    int    iwx_prepare_card_hw(struct iwx_softc *);
    void    iwx_force_power_gating(struct iwx_softc *);
    void    iwx_clear_persistence_bit(struct iwx_softc *);
    void    iwx_apm_config(struct iwx_softc *);
    int    iwx_apm_init(struct iwx_softc *);
    int     iwx_apm_stop(struct iwx_softc *);
    int    iwx_allow_mcast(struct iwx_softc *);
    void    iwx_init_msix_hw(struct iwx_softc *);
    void    iwx_conf_msix_hw(struct iwx_softc *, int);
    int    iwx_start_hw(struct iwx_softc *);
    int     iwx_stop_device(struct iwx_softc *);
    void    iwx_nic_config(struct iwx_softc *);
    int    iwx_nic_rx_init(struct iwx_softc *);
    int    iwx_nic_init(struct iwx_softc *);
    int    iwx_enable_txq(struct iwx_softc *, int, int, int, int);
    int     iwx_tvqm_alloc_txq(struct iwx_softc *, int, int);
    int     iwx_tvqm_enable_txq(struct iwx_softc *, int, int, uint32_t);
    void    iwx_post_alive(struct iwx_softc *);
    int iwx_send_time_event_cmd(struct iwx_softc *sc,
                            const struct iwx_time_event_cmd *cmd);
    void    iwx_protect_session(struct iwx_softc *, struct iwx_node *, uint32_t,
            uint32_t);
    int    iwx_schedule_protect_session(struct iwx_softc *, struct iwx_node *, uint32_t);
    int     iwx_cancel_session_protection(struct iwx_softc *, struct iwx_node *);
    void    iwx_unprotect_session(struct iwx_softc *, struct iwx_node *);
    uint8_t iwx_fw_valid_tx_ant(struct iwx_softc *sc);
    uint8_t iwx_fw_valid_rx_ant(struct iwx_softc *sc);
    void    iwx_init_channel_map(struct iwx_softc *, uint16_t *, uint32_t *, int);
    void    iwx_setup_ht_rates(struct iwx_softc *);
    void    iwx_setup_vht_rates(struct iwx_softc *);
    void    iwx_setup_he_rates(struct iwx_softc *);
    int    iwx_mimo_enabled(struct iwx_softc *);
    static void    iwx_mac_ctxt_task(void *);
    static void    iwx_chan_ctxt_task(void *);
    static void    iwx_updateprot(struct ieee80211com *);
    static void    iwx_updateslot(struct ieee80211com *);
    static void    iwx_updateedca(struct ieee80211com *);
    static void    iwx_updatedtim(struct ieee80211com *);
    void    iwx_init_reorder_buffer(struct iwx_reorder_buffer *, uint16_t,
            uint16_t);
    void    iwx_clear_reorder_buffer(struct iwx_softc *, struct iwx_rxba_data *);
    static int    iwx_ampdu_rx_start(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    static void    iwx_ampdu_rx_stop(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    static void    iwx_rx_ba_session_expired(void *);
    static void    iwx_reorder_timer_expired(void *);
    static void    iwx_update_chw(struct ieee80211com *);
    void    iwx_sta_rx_agg(struct iwx_softc *, struct ieee80211_node *, uint8_t,
                           uint16_t, uint16_t, int, int);
    static int    iwx_ampdu_tx_start(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    static void    iwx_ampdu_tx_stop(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    static void    iwx_ba_task(void *);

    int    iwx_set_mac_addr_from_csr(struct iwx_softc *, struct iwx_nvm_data *);
    int    iwx_is_valid_mac_addr(const uint8_t *);
    int    iwx_nvm_get(struct iwx_softc *);
    int    iwx_load_firmware(struct iwx_softc *);
    void   iwx_set_ltr(struct iwx_softc *);
    int    iwx_start_fw(struct iwx_softc *);
    int    iwx_send_tx_ant_cfg(struct iwx_softc *, uint8_t);
    int    iwx_send_phy_cfg_cmd(struct iwx_softc *);
    int    iwx_load_ucode_wait_alive(struct iwx_softc *);
    int    iwx_send_dqa_cmd(struct iwx_softc *);
    int    iwx_run_init_mvm_ucode(struct iwx_softc *, int);
    int    iwx_config_ltr(struct iwx_softc *);
    void    iwx_update_rx_desc(struct iwx_softc *, struct iwx_rx_ring *, int);
    int    iwx_rx_addbuf(struct iwx_softc *, int, int);
    int    iwx_rxmq_get_signal_strength(struct iwx_softc *, struct iwx_rx_mpdu_desc *);
    void    iwx_rx_rx_phy_cmd(struct iwx_softc *, struct iwx_rx_packet *,
            struct iwx_rx_data *);
    int    iwx_get_noise(const uint8_t *);
    int    iwx_rx_hwdecrypt(struct iwx_softc *, mbuf_t, uint32_t,
            struct ieee80211_rxinfo *);
    int    iwx_ccmp_decap(struct iwx_softc *, mbuf_t,
                          struct ieee80211_node *, struct ieee80211_rxinfo *);
    void    iwx_rx_frame(struct iwx_softc *, mbuf_t, int, uint32_t, int, int,
           uint32_t, struct ieee80211_rxinfo *, struct mbuf_list *
#ifdef AIRPORT_TAHOE
           , uint32_t rxStageOwnerGeneration = 0,
           uint8_t rxStageKind = TahoeAwdlRxStageCounters::kNotAwdl,
           uint32_t rxMacPhyIndex = 0,
           bool rxMacPhyIndexPresent = false,
           const NativeP2PRx149DataInput::OriginalDescriptor *originalData = nullptr
#endif
           );
    void iwx_rx_mpdu_mq(struct iwx_softc *sc, mbuf_t m, void *pktdata,
                        size_t actualPayloadLength, bool rpaEnabled,
                        size_t maxlen,
                        struct mbuf_list *ml, uint32_t rxRingSlot,
                        uint32_t transportNotificationQid,
                        uint32_t transportNotificationIndex,
                        uint64_t hostRxMonotonicUs,
                        bool hostRxMonotonicUsPresent);
    void    iwx_rx_tx_cmd_single(struct iwx_softc *, struct iwx_rx_packet *,
            struct iwx_tx_data *);
    void iwx_txd_done(struct iwx_softc *sc, struct iwx_tx_data *txd);
    void iwx_clear_oactive(struct iwx_softc *sc, struct iwx_tx_ring *ring);
    void iwx_ampdu_txq_advance(struct iwx_softc *sc, struct iwx_tx_ring *ring, int idx);
    void iwx_rx_tx_ba_notif(struct iwx_softc *sc, struct iwx_rx_packet *pkt, struct iwx_rx_data *data);
    void    iwx_rx_tx_cmd(struct iwx_softc *, struct iwx_rx_packet *,
            struct iwx_rx_data *);
    void    iwx_rx_bmiss(struct iwx_softc *, struct iwx_rx_packet *,
            struct iwx_rx_data *);
    int    iwx_binding_cmd(struct iwx_softc *, struct iwx_node *, uint32_t);
    int    iwx_phy_ctxt_cmd_uhb(struct iwx_softc *, struct iwx_phy_ctxt *, uint8_t,
                                uint8_t, uint32_t, uint32_t);
    int    iwx_phy_ctxt_cmd_v3(struct iwx_softc *, struct iwx_phy_ctxt *, uint8_t,
                                uint8_t, uint32_t, uint32_t);
    int    iwx_phy_ctxt_cmd(struct iwx_softc *, struct iwx_phy_ctxt *, uint8_t,
            uint8_t, uint32_t, uint32_t);
    int    iwx_send_cmd(struct iwx_softc *, struct iwx_host_cmd *);
    int    iwx_send_cmd_pdu(struct iwx_softc *, uint32_t, uint32_t, uint16_t,
            const void *);
    int    iwx_send_cmd_status(struct iwx_softc *, struct iwx_host_cmd *,
            uint32_t *);
    int    iwx_send_cmd_pdu_status(struct iwx_softc *, uint32_t, uint16_t,
            const void *, uint32_t *);
    void    iwx_free_resp(struct iwx_softc *, struct iwx_host_cmd *);
    void    iwx_cmd_done(struct iwx_softc *, int, int, int);
    const struct iwx_rate *iwx_tx_fill_cmd(struct iwx_softc *, struct iwx_node *,
            struct ieee80211_frame *, uint32_t *, uint32_t *);
    uint32_t iwx_get_tx_ant(struct iwx_softc *sc, struct ieee80211_node *ni,
                            const struct iwx_rate *rinfo, int type, struct ieee80211_frame *wh);
    void    iwx_toggle_tx_ant(struct iwx_softc *sc, uint8_t *ant);
    void    iwx_tx_update_byte_tbl(struct iwx_softc *, struct iwx_tx_ring *, int, uint16_t, uint16_t);
    int    iwx_tx(struct iwx_softc *, mbuf_t, struct ieee80211_node *, int
#ifdef AIRPORT_TAHOE
                  , uint64_t * = nullptr
#endif
                  );
    int    iwx_flush_sta_tids(struct iwx_softc *, int, uint16_t);
    int    iwx_flush_sta(struct iwx_softc *, struct iwx_node *);
    int    iwx_drain_sta(struct iwx_softc *sc, struct iwx_node *, int);
    int    iwx_beacon_filter_send_cmd(struct iwx_softc *,
            struct iwx_beacon_filter_cmd *);
    int    iwx_update_beacon_abort(struct iwx_softc *, struct iwx_node *, int);
    void    iwx_power_build_cmd(struct iwx_softc *, struct iwx_node *,
            struct iwx_mac_power_cmd *);
    int    iwx_power_mac_update_mode(struct iwx_softc *, struct iwx_node *);
    int    iwx_power_update_device(struct iwx_softc *);
    int    iwx_enable_beacon_filter(struct iwx_softc *, struct iwx_node *);
    int    iwx_disable_beacon_filter(struct iwx_softc *);
    int    iwx_add_sta_cmd(struct iwx_softc *, struct iwx_node *, int);
    int    iwx_add_aux_sta(struct iwx_softc *);
    int    iwx_rm_sta_cmd(struct iwx_softc *, struct iwx_node *);
    int    iwx_rm_sta(struct iwx_softc *, struct iwx_node *);
    uint8_t iwx_umac_scan_fill_channels(struct iwx_softc *sc,
                                struct iwx_scan_channel_cfg_umac *chan, int n_ssids, int bgscan,
                                const struct itl_iwx_scan_policy *scan);
    int iwx_fill_probe_req_v1(struct iwx_softc *sc, struct iwx_scan_probe_req_v1 *preq1, const uint8_t *);
    int    iwx_fill_probe_req(struct iwx_softc *, struct iwx_scan_probe_req *, const uint8_t *);
    int    iwx_config_umac_scan(struct iwx_softc *);
    int    iwx_config_legacy_umac_scan(struct iwx_softc *);
    int iwx_umac_scan_size(struct iwx_softc *sc);
    struct iwx_scan_umac_chan_param *iwx_get_scan_req_umac_chan_param(struct iwx_softc *sc, struct iwx_scan_req_umac *req);
    void *iwx_get_scan_req_umac_data(struct iwx_softc *sc, struct iwx_scan_req_umac *req);
    int    iwx_umac_scan(struct iwx_softc *, int, uint32_t *);
    int    iwx_capture_scan_policy(struct iwx_softc *, int, struct itl_iwx_scan_policy *);
    int    iwx_send_scan_cmd(struct iwx_softc *, struct iwx_host_cmd *,
                            const struct itl_iwx_scan_policy *, uint32_t *);
    int    iwx_umac_scan_v12(struct iwx_softc *, int, const struct itl_iwx_scan_policy *, uint32_t *);
    int    iwx_umac_scan_v14(struct iwx_softc *, int, const struct itl_iwx_scan_policy *, uint32_t *);
    void    iwx_mcc_update(struct iwx_softc *, struct iwx_mcc_chub_notif *);
    uint8_t    iwx_ridx2rate(struct ieee80211_rateset *, int);
    int    iwx_rval2ridx(int);
    int    iwx_rate2idx(int);
    void    iwx_ack_rates(struct iwx_softc *, struct iwx_node *, int *, int *);
    void    iwx_mac_ctxt_cmd_common(struct iwx_softc *, struct iwx_node *,
            struct iwx_mac_ctx_cmd *, uint32_t);
#ifdef AIRPORT_TAHOE
    using TahoeP2pRocArmTracker = bool (*)(void *, uint32_t, uint32_t,
                                            uint32_t);
    int iwx_p2p_mac_context_configure(struct iwx_softc *, uint8_t, uint8_t,
                                      uint8_t, const uint8_t[6]);
    int iwx_p2p_mac_context_apply(struct iwx_softc *, uint32_t);
    int iwx_p2p_mac_context_add(struct iwx_softc *);
    int iwx_p2p_mac_context_modify(struct iwx_softc *);
    int iwx_p2p_mac_context_remove(struct iwx_softc *);
    int iwx_p2p_phy_lease(struct iwx_softc *, uint8_t *);
    int iwx_p2p_phy_release(struct iwx_softc *);
    int iwx_p2p_binding_add(struct iwx_softc *);
    int iwx_p2p_binding_remove(struct iwx_softc *);
    int iwx_p2p_context_reset_after_fw_reset(struct iwx_softc *, uint32_t);
    int tahoeP2pRocPrepare(struct iwx_softc *, struct ieee80211_channel *,
                           uint32_t, uint32_t,
                           bool receiveObservation149 = false);
    int tahoeP2pRocSubmit(struct iwx_softc *, uint32_t, uint32_t, uint32_t,
                          TahoeP2pRocArmTracker, void *);
    int tahoeP2pRocCleanup(struct iwx_softc *, uint32_t, uint32_t, bool);
    // Abort only a fully prepared lease whose session was never submitted.
    int tahoeP2pRocAbortPrepared(struct iwx_softc *, uint32_t, uint32_t, bool);
#endif
    void    iwx_mac_ctxt_cmd_fill_sta(struct iwx_softc *, struct iwx_node *,
            struct iwx_mac_data_sta *, int);
    int    iwx_mac_ctxt_cmd(struct iwx_softc *, struct iwx_node *, uint32_t, int);
    int    iwx_clear_statistics(struct iwx_softc *);
    int    iwx_update_quotas(struct iwx_softc *, struct iwx_node *, int);
    void    iwx_add_task(struct iwx_softc *, struct taskq *, struct task *);
    void    iwx_del_task(struct iwx_softc *, struct taskq *, struct task *);
    int    iwx_scan(struct iwx_softc *);
    static int    iwx_bgscan(struct ieee80211com *);
    int    iwx_umac_scan_abort(struct iwx_softc *);
    int    iwx_scan_abort(struct iwx_softc *);
    int    iwx_rs_rval2idx(uint8_t);
    uint16_t iwx_rs_ht_rates(struct iwx_softc *, struct ieee80211_node *, int);
    uint16_t iwx_rs_fw_get_config_flags(struct iwx_softc *sc);
    int    iwx_rs_init(struct iwx_softc *, struct iwx_node *, bool update);
    void iwx_rs_update(struct iwx_softc *sc, struct iwx_tlc_update_notif *notif);
    int    iwx_enable_mgmt_queue(struct iwx_softc *);
    int    iwx_phy_ctxt_update(struct iwx_softc *, struct iwx_phy_ctxt *,
                               struct ieee80211_channel *, uint8_t, uint8_t, uint32_t);
    int    iwx_auth(struct iwx_softc *);
    int    iwx_deauth(struct iwx_softc *);
    int    iwx_run(struct iwx_softc *);
    int    iwx_run_stop(struct iwx_softc *);
    static struct ieee80211_node *iwx_node_alloc(struct ieee80211com *);
    static int    iwx_set_key(struct ieee80211com *, struct ieee80211_node *,
           struct ieee80211_key *);
    static void    iwx_delete_key(struct ieee80211com *,
           struct ieee80211_node *, struct ieee80211_key *);
    int    iwx_media_change(struct _ifnet *);
    static void    iwx_newstate_task(void *);
    static int    iwx_newstate(struct ieee80211com *, enum ieee80211_state, int);
    void    iwx_endscan(struct iwx_softc *, uint32_t = 0, uint32_t = 1);
    void    iwx_fill_sf_command(struct iwx_softc *, struct iwx_sf_cfg_cmd *,
            struct ieee80211_node *);
    int    iwx_sf_config(struct iwx_softc *, int);
    int    iwx_send_bt_init_conf(struct iwx_softc *);
    int    iwx_send_soc_conf(struct iwx_softc *);
    int    iwx_send_update_mcc_cmd(struct iwx_softc *, const char *);
    int    iwx_send_temp_report_ths_cmd(struct iwx_softc *);
    int    iwx_init_hw(struct iwx_softc *);
    int    iwx_init(struct _ifnet *);
    static void    iwx_start(struct _ifnet *);
    int     iwx_stop(struct _ifnet *,
                     IwxResetTrace::ResetReason = IwxResetTrace::ResetReason::kUnknown);
    static void    iwx_watchdog(struct _ifnet *);
    static int    iwx_ioctl(struct _ifnet *, u_long, caddr_t);
    const char *iwx_desc_lookup(uint32_t);
    void    iwx_nic_error(struct iwx_softc *);
    void    iwx_nic_umac_error(struct iwx_softc *);
    void    iwx_flip_address(uint8_t *);
    int    iwx_detect_duplicate(struct iwx_softc *, mbuf_t,
            struct iwx_rx_mpdu_desc *, struct ieee80211_rxinfo *);
    int    iwx_is_sn_less(uint16_t, uint16_t, uint16_t);
    void    iwx_release_frames(struct iwx_softc *, struct ieee80211_node *,
            struct iwx_rxba_data *, struct iwx_reorder_buffer *, uint16_t,
            struct mbuf_list *);
    int    iwx_oldsn_workaround(struct iwx_softc *, struct ieee80211_node *,
            int, struct iwx_reorder_buffer *, uint32_t, uint32_t);
    int    iwx_rx_reorder(struct iwx_softc *, mbuf_t, int,
            struct iwx_rx_mpdu_desc *, int, int, uint32_t,
            struct ieee80211_rxinfo *, struct mbuf_list *);
    int    iwx_rx_pkt_valid(struct iwx_rx_packet *);
    void    iwx_rx_pkt(struct iwx_softc *, struct iwx_rx_data *,
            struct mbuf_list *, uint32_t rxRingSlot);
    void    iwx_notif_intr(struct iwx_softc *);
    static int    iwx_intr(OSObject *object, IOInterruptEventSource* sender, int count);
    static int    iwx_intr_msix(OSObject *object, IOInterruptEventSource* sender, int count);
    static int    iwx_match(IOPCIDevice *);
    int    iwx_preinit(struct iwx_softc *);
    void    iwx_attach_hook(struct device *);
    bool    iwx_attach(struct iwx_softc *, struct pci_attach_args *);
    static void    iwx_init_task(void *);
    int    iwx_activate(struct iwx_softc *, int);
    int    iwx_resume(struct iwx_softc *);
    
public:
    IOInterruptEventSource* fInterrupt;
    struct pci_attach_args pci;
    struct iwx_softc com;
};

#endif
