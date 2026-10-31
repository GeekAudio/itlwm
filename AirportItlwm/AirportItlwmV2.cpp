//
//  AirportItlwmV2.cpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#include "AirportItlwmV2.hpp"
#include <sys/_netstat.h>
#include <crypto/sha1.h>
#include <net80211/ieee80211_priv.h>
#include <net80211/ieee80211_var.h>

#include "AirportItlwmSkywalkInterface.hpp"
#include "IOPCIEDeviceWrapper.hpp"
#ifdef AIRPORT_TAHOE
#include "../native/registration.hpp"
#include "../native/runtime_guard.hpp"
#include "../native/fault_reporter.hpp"
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
#include "../native/awdl_native_lifecycle_25G332.hpp"
#endif
#include <IOKit/IOUserClient.h>
#include <libkern/c++/OSData.h>
#include <kern/clock.h>
#include <kern/task.h>
#endif

#define super IO80211Controller
OSDefineMetaClassAndStructors(AirportItlwm, IO80211Controller);
OSDefineMetaClassAndStructors(CTimeout, OSObject)

IO80211WorkQueue *_fWorkloop;
IOCommandGate *_fCommandGate;

#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
static IOReturn publishNativeAwdlClosingAction(
    OSObject *target, void *, void *, void *, void *)
{
    return NativeAwdlLifecycle::publishClosingInGate(
        static_cast<IOService *>(target)) ? kIOReturnSuccess :
                                            kIOReturnNotReady;
}
#endif

#ifdef AIRPORT_TAHOE
namespace {
bool validRx149RunToken(OSObject *object)
{
    auto token = OSDynamicCast(OSString, object);
    if (!token || token->getLength() != 32)
        return false;
    const char *text = token->getCStringNoCopy();
    if (!text)
        return false;
    for (size_t index = 0; index < 32; ++index) {
        const char value = text[index];
        if (!((value >= '0' && value <= '9') ||
              (value >= 'a' && value <= 'f')))
            return false;
    }
    return true;
}

struct NativeRx149ArmContext {
    OSString *runToken;
};

IOReturn armNativeRx149OnMainGate(OSObject *target, void *argument,
                                  void *, void *, void *)
{
    auto controller = OSDynamicCast(AirportItlwm, target);
    auto context = static_cast<NativeRx149ArmContext *>(argument);
    auto hal = controller ? OSDynamicCast(ItlIwx, controller->fHalService) : nullptr;
    if (!controller || !context || !validRx149RunToken(context->runToken) ||
        !hal || !controller->fHalService ||
        hal->tahoeP2pCommandGate() != _fCommandGate ||
        controller->getProperty("NativeP2PRx149ObservationOnly") !=
            kOSBooleanTrue)
        return kIOReturnNotReady;

    // Publish the controller identity before HAL's release-arm CAS. The HAL
    // copies its local token before returning; the worker's first admission
    // action must acquire this same gate, so it cannot observe the interval
    // between the arm latch and that copy.
    if (!controller->setProperty("NativeP2PRx149RunToken", context->runToken) ||
        controller->getProperty("NativeP2PRx149RunToken") != context->runToken) {
        controller->removeProperty("NativeP2PRx149RunToken");
        return kIOReturnNotReady;
    }
    const IOReturn result = controller->fHalService->nativeP2pArmProbe();
    if (result != kIOReturnSuccess)
        controller->removeProperty("NativeP2PRx149RunToken");
    return result;
}

struct NativePowerActionContext {
    apple80211_power_data request;
    uint32_t traceCallId;
};

uint64_t nativePowerUptimeNanoseconds()
{
    AbsoluteTime uptime = 0;
    uint64_t nanoseconds = 0;
    clock_get_uptime(&uptime);
    absolutetime_to_nanoseconds(uptime, &nanoseconds);
    return nanoseconds;
}

bool nativeStartupResult(IOService *controller, IOService *provider,
                         const char *stage, bool result)
{
    // The provider survives a failed child start. Keep only stage/result, never
    // addresses, packets or credentials. XYLog uses kprintf, not unified logs.
    if (provider) {
        // The packager derives this personality property from AirportTahoeBuild.
        // A second hard-coded source tag can silently lag the actual binary.
        OSObject *build = controller ? controller->getProperty("NativeTestBuild") : nullptr;
        if (build)
            provider->setProperty("NativeTestBuild", build);
        else
            provider->setProperty("NativeTestBuild", "unlabelled");
        provider->setProperty("NativeControllerStage", stage);
        provider->setProperty("NativeControllerStageResult", result ? 1U : 0U, 32);
    }
    IOLog("AirportItlwm[Tahoe] startup %s=%u\n", stage, result ? 1U : 0U);
    return result;
}
}
#define ITL_STARTUP_RESULT(provider, stage, result) nativeStartupResult(this, provider, stage, result)
#else
#define ITL_STARTUP_RESULT(provider, stage, result) (result)
#endif

void AirportItlwm::detachWatchdogTimer()
{
    if (!watchdogTimer)
        return;
    watchdogTimer->cancelTimeout();
    watchdogTimer->disable();
    // removeEventSource takes the source off its workloop after any current
    // watchdogAction returns. stop() calls this before detaching the HAL.
    if (watchdogSourceAttached && fWatchdogWorkLoop) {
        fWatchdogWorkLoop->removeEventSource(watchdogTimer);
        watchdogSourceAttached = false;
    }
    // The callback may have re-armed itself just before removal drained it.
    watchdogTimer->cancelTimeout();
    watchdogTimer->disable();
}

void AirportItlwm::releaseAll()
{
#ifdef AIRPORT_TAHOE
    // A partial-start cleanup can bypass stop(). Close PM admission and drain
    // its callouts before releasing either the HAL or the command gate.
    setNativePowerStopping(true);
    if (!retireNativePMPowerCallouts()) return;
#endif
    detachWatchdogTimer();
#ifdef AIRPORT_TAHOE
    // Parent stop must first destroy its monitor, which borrows nativeLogger.
    releaseNativeCapture();
#else
    OSSafeReleaseNULL(driverLogPipe);
    OSSafeReleaseNULL(driverDataPathPipe);
    OSSafeReleaseNULL(driverSnapshotsPipe);
    OSSafeReleaseNULL(driverFaultReporter);
#endif
#ifdef AIRPORT_TAHOE
    releaseNativePowerHAL();
#else
    if (fHalService) {
        fHalService->release();
        fHalService = NULL;
    }
#endif
    if (_fWorkloop) {
        if (_fCommandGate) {
//            _fCommandGate->disable();
            _fWorkloop->removeEventSource(_fCommandGate);
            _fCommandGate->release();
            _fCommandGate = NULL;
        }
        if (scanSource) {
            scanSource->cancelTimeout();
            scanSource->disable();
            _fWorkloop->removeEventSource(scanSource);
            scanSource->release();
            scanSource = NULL;
        }
        _fWorkloop->release();
        _fWorkloop = NULL;
    }
    OSSafeReleaseNULL(watchdogTimer);
    OSSafeReleaseNULL(fWatchdogWorkLoop);
#ifndef AIRPORT_TAHOE
    unregistPM();
#endif
}

#ifdef AIRPORT_TAHOE
bool AirportItlwm::initializeNativePowerLocks()
{
    if (!nativePowerStateLock) nativePowerStateLock = IOSimpleLockAlloc();
    if (!nativePowerStateLock) {
        releaseNativePowerLocks();
        return false;
    }
    if (!nativePowerTraceLock) nativePowerTraceLock = IOSimpleLockAlloc();
    if (!nativePowerTraceLock) {
        releaseNativePowerLocks();
        return false;
    }
    return true;
}

void AirportItlwm::setNativePowerStopping(bool stopping)
{
    IOSimpleLock *lock = nativePowerStateLock;
    if (lock) {
        const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock);
        __atomic_store_n(&nativePowerStopping, stopping, __ATOMIC_RELEASE);
        IOSimpleLockUnlockEnableInterrupt(lock, irq);
        return;
    }
    // Lock allocation failure already prevents start from succeeding. Keep
    // teardown fail-closed if a partial initialization reaches this path.
    __atomic_store_n(&nativePowerStopping, stopping, __ATOMIC_RELEASE);
}

void AirportItlwm::releaseNativePowerLocks()
{
    if (nativePowerTraceLock) {
        IOSimpleLockFree(nativePowerTraceLock);
        nativePowerTraceLock = nullptr;
    }
    if (nativePowerStateLock) {
        IOSimpleLockFree(nativePowerStateLock);
        nativePowerStateLock = nullptr;
    }
}

void AirportItlwm::releaseNativePowerHAL()
{
    ItlHalService *hal = nullptr;
    bool cancelledRestart = false;
    IOSimpleLock *lock = nativePowerStateLock;
    if (lock) {
        const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock);
        hal = fHalService;
        fHalService = nullptr;
        const uint32_t flags = __atomic_load_n(&nativePowerFlags, __ATOMIC_RELAXED);
        __atomic_store_n(&nativePowerFlags, flags & ~1U, __ATOMIC_RELEASE);
        cancelledRestart = nativeAddressRestartNotification.active();
        nativeAddressRestartNotification.cancel(
            NativePowerTrace::AddressRestartOutcome::kCancelledManual);
        nativeAddressRestartPublishedId = 0;
        nativeAddressRestartPublishedEpoch = 0;
        nativeAddressRestartStartRevision = 0;
        IOSimpleLockUnlockEnableInterrupt(lock, irq);
    } else {
        // Without the state lock GET_POWER never dereferences the HAL for a
        // restart grace decision. Keep teardown fail-closed on partial init.
        hal = fHalService;
        fHalService = nullptr;
        __atomic_fetch_and(&nativePowerFlags, ~1U, __ATOMIC_ACQ_REL);
        cancelledRestart = nativeAddressRestartNotification.active();
        nativeAddressRestartNotification.cancel(
            NativePowerTrace::AddressRestartOutcome::kCancelledManual);
        nativeAddressRestartPublishedId = 0;
        nativeAddressRestartPublishedEpoch = 0;
        nativeAddressRestartStartRevision = 0;
    }
    if (cancelledRestart)
        noteNativeAddressRestartOutcome(
            NativePowerTrace::AddressRestartOutcome::kCancelledManual);
    // HAL release can run destructors and must never run under the spin lock.
    if (hal)
        hal->release();
}

void AirportItlwm::releaseNativeCapture()
{
    // The native fault wrapper owns its corecapture reporter and timer. Keep
    // the real workloop and stream alive until that wrapper has released them.
    OSSafeReleaseNULL(nativeFaultReporter);
    OSSafeReleaseNULL(nativeLogger);
    OSSafeReleaseNULL(driverFaultReporter);
    // Stream producers and the native fault timer are gone before stopping
    // their pipes. Native stop/detach owns each pipe's timer and queued blobs.
    if (nativeCaptureStarted & 4U) NativeWifi::stopNativeCapturePipe(driverSnapshotsPipe, this);
    if (nativeCaptureStarted & 2U) NativeWifi::stopNativeCapturePipe(driverDataPathPipe, this);
    if (nativeCaptureStarted & 1U) NativeWifi::stopNativeCapturePipe(driverLogPipe, this);
    nativeCaptureStarted = 0;
    OSSafeReleaseNULL(driverSnapshotsPipe);
    OSSafeReleaseNULL(driverDataPathPipe);
    OSSafeReleaseNULL(driverLogPipe);
}
#endif

void AirportItlwm::
eventHandler(struct ieee80211com *ic, int msgCode, void *data)
{
    AirportItlwm *that = OSDynamicCast(AirportItlwm, ic->ic_ac.ac_if.controller);
    if (!that) return;
    IO80211SkywalkInterface *interface = that->fNetIf;
    if (!interface)
        return;
#ifdef AIRPORT_TAHOE
    NativePowerTrace::PowerIngressContext powerContext {};
    that->observeNativePowerEvent(msgCode, &powerContext);
    static_cast<AirportItlwmSkywalkInterface *>(interface)->captureNativeEvent(
        msgCode, data, &powerContext);
    return;
#else
    switch (msgCode) {
        case IEEE80211_EVT_COUNTRY_CODE_UPDATE:
            interface->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED, NULL, 0, 0);
            break;
        case IEEE80211_EVT_STA_ASSOC_DONE:
            interface->postMessage(APPLE80211_M_ASSOC_DONE, NULL, 0, 0);
            break;
        case IEEE80211_EVT_STA_DEAUTH:
            interface->postMessage(APPLE80211_M_DEAUTH_RECEIVED, NULL, 0, 0);
            break;
        default:
            break;
    }
#endif
}

void AirportItlwm::watchdogAction(IOTimerEventSource *timer)
{
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    (*ifp->if_watchdog)(ifp);
#ifdef AIRPORT_TAHOE
    if (fNetIf) static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->captureNativeTick(kWatchDogTimerPeriod);
    if (fHalService) fHalService->nativeP2pTick();
#endif
    watchdogTimer->setTimeoutMS(kWatchDogTimerPeriod);
}

void AirportItlwm::fakeScanDone(OSObject *owner, IOTimerEventSource *sender)
{
#ifndef AIRPORT_TAHOE
    UInt32 msg = 0;
    AirportItlwm *that = (AirportItlwm *)owner;
    that->fNetIf->postMessage(APPLE80211_M_SCAN_DONE, &msg, 4, 0);
#endif
}

bool AirportItlwm::init(OSDictionary *properties)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    bool ret = ITL_STARTUP_RESULT(nullptr, "parent-init", super::init(properties));
#ifdef AIRPORT_TAHOE
    if (!ret || !initializeNativePowerLocks()) return false;
    awdlSyncEnable = false;
#else
    awdlSyncEnable = true;
#endif
    power_state = 0;
    memset(geo_location_cc, 0, sizeof(geo_location_cc));
    return ret;
}

#ifdef AIRPORT_TAHOE
IOReturn AirportItlwm::setProperties(OSObject *properties)
{
    OSDictionary *request = OSDynamicCast(OSDictionary, properties);
    // These values describe the signed test profile or read-only status.
    // Do not allow the parent property setter to bypass the manual gate.
    if (request && (request->getObject("NativeP2PManualTrigger") ||
                    request->getObject("NativeP2PManualArmed") ||
                    request->getObject("NativeP2PProbe") ||
                    request->getObject("NativeP2PRocProbe") ||
                    request->getObject("NativeP2PTxProbe") ||
                    request->getObject("NativeP2PAwdlPsfObservationOnly") ||
                    request->getObject("NativeP2PAwdlMifFollowup") ||
                    request->getObject("NativeP2PGp2Observation") ||
                    request->getObject("NativeP2PRx149ObservationOnly") ||
                    request->getObject("NativeP2PRx149DataInputExperiment") ||
                    request->getObject("NativeP2PRx149DataInputProfileEnabled") ||
                    request->getObject("NativeP2PRx149ProfileEnabled") ||
                    request->getObject("NativeP2PRx149Selected") ||
                    request->getObject("NativeP2PRx149HostTxBlocked") ||
                    request->getObject("NativeP2PRx149LiveStartSnapshot") ||
                    request->getObject("NativeP2PTxProbeEverDoorbelled") ||
                    request->getObject("NativeP2PAwdlActionFramesSubmitted") ||
                    request->getObject("NativeP2PAwdlPsfFrameSubmitted") ||
                    request->getObject("NativeP2PAwdlMifFrameSubmitted") ||
                    request->getObject("NativeP2PAwdlMifBootstrapSubmitted") ||
                    request->getObject("NativeAwdlInitObservationOnly") ||
                    request->getObject("NativeAwdlInitObservationCompiled") ||
                    request->getObject("NativeAwdlLifecycleObservationOnly") ||
                    request->getObject("NativeAwdlLifecycleCompiled") ||
                    request->getObject("NativeAwdlTxEvidenceEnabled") ||
                    request->getObject("NativeAwdlDiscoveryExperimentEnabled") ||
                    request->getObject("NativeAwdlDiscoveryMifCurrentSlotEnabled") ||
                    request->getObject("NativeAwdlDiscoveryCurrentAwFallbackEnabled") ||
                    request->getObject("NativeAwdlResidentEnabled") ||
                    request->getObject("NativeAwdlResidentCompiled")))
        return kIOReturnUnsupported;
    OSObject *arm = request ? request->getObject("NativeP2PArmOnce") : nullptr;
    OSObject *rxArm = request ? request->getObject("NativeP2PRx149ArmOnce") : nullptr;
    OSObject *rxToken = request ? request->getObject("NativeP2PRx149RunToken") : nullptr;
    if (!arm && !rxArm)
        if (rxToken)
            return kIOReturnUnsupported;
    if (!arm && !rxArm)
        return super::setProperties(properties);
    if (!request || (rxArm && (arm || request->getCount() != 2 ||
                               rxArm != kOSBooleanTrue ||
                               !validRx149RunToken(rxToken))) ||
        (!rxArm && (request->getCount() != 1 ||
                    arm != kOSBooleanTrue)))
        return kIOReturnBadArgument;
    IOReturn privilege = IOUserClient::clientHasPrivilege(
        current_task(), kIOClientPrivilegeAdministrator);
    if (privilege != kIOReturnSuccess)
        return privilege;
    if (!fHalService)
        return kIOReturnNotReady;
    const bool receive149Profile =
        getProperty("NativeP2PRx149ObservationOnly") == kOSBooleanTrue;
    if (rxArm) {
#if defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332)
        if (!receive149Profile)
            return kIOReturnUnsupported;
#else
        return kIOReturnUnsupported;
#endif
    } else if (receive149Profile) {
        return kIOReturnUnsupported; // A legacy helper cannot arm this profile.
    }
    if (rxArm) {
        auto token = OSDynamicCast(OSString, rxToken);
        if (!token || !_fCommandGate || !_fWorkloop) {
            removeProperty("NativeP2PRx149RunToken");
            return kIOReturnNotReady;
        }
        NativeRx149ArmContext context {token};
        if (_fWorkloop->inGate())
            return armNativeRx149OnMainGate(
                this, &context, nullptr, nullptr, nullptr);
        return _fCommandGate->runAction(
            armNativeRx149OnMainGate, &context);
    }
    // Arm only: the existing watchdog and admission gates submit the probe.
    // The HAL latches legacy vs RX149 mode before the worker is queued.
    // This call never resets the radio, releases DMA, or retries a probe.
    return fHalService->nativeP2pArmProbe();
}
#endif

IOService* AirportItlwm::probe(IOService *provider, SInt32 *score)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    IOPCIEDeviceWrapper *wrapper = OSDynamicCast(IOPCIEDeviceWrapper, provider);
    if (!ITL_STARTUP_RESULT(wrapper, "probe-wrapper", wrapper != nullptr)) {
        XYLog("%s Not a IOPCIEDeviceWrapper instance\n", __FUNCTION__);
        return NULL;
    }
    pciNub = wrapper->pciNub;
    fHalService = wrapper->fHalService;
    if (!ITL_STARTUP_RESULT(wrapper, "probe-pci-hal", pciNub && fHalService)) {
        XYLog("%s Not a valid IOPCIEDeviceWrapper instance\n", __FUNCTION__);
        return NULL;
    }
#ifdef AIRPORT_TAHOE
    // Take ownership of the original HAL reference exactly once. A child
    // rejected before HAL attach must not leave a freed pointer in its provider.
    wrapper->fHalService = nullptr;
#endif
    IOService *result = super::probe(provider, score);
#ifdef AIRPORT_TAHOE
    nativeStartupResult(this, wrapper, "parent-probe", result != nullptr);
#endif
    return result;
}

#define LOWER32(x)  ((uint64_t)(x) & 0xffffffff)
#define HIGHER32(x) ((uint64_t)(x) >> 32)

bool AirportItlwm::
initCCLogs()
{
#ifdef AIRPORT_TAHOE
    if (!_fWorkloop || _fWorkloop->inGate()) return false;
    uint32_t ready = 0;
    auto record = [&]() {
        if (auto provider = getProvider()) {
            provider->setProperty("NativeCaptureReady", ready, 32);
            provider->setProperty("NativeCaptureStarted", nativeCaptureStarted, 32);
        }
    };
    CCPipeOptions options {};
    options.log_data_type = 1;
    options.pipe_size = 0x200000;
    options.min_log_size_notify = 0xccccc;
    options.notify_threshold = 1000;
    options.pad9 = 0x1000000;
    options.pad10 = 2;
    strlcpy(options.file_name, "AirportItlwm", sizeof(options.file_name));
    strlcpy(options.directory_name, "WiFi", sizeof(options.directory_name));
    driverLogPipe = CCPipe::withOwnerNameCapacity(this, "org.geekaudio.AirportItlwm", "DriverLogs", &options);
    if (!driverLogPipe) return false;
    if (!NativeWifi::startNativeCapturePipe(driverLogPipe)) return false;
    nativeCaptureStarted |= 1U;
    ready |= 1; record();
    // Factory (log pipe, stream_type 0) yields a genuine native CCLogStream.
    CCStreamOptions streamOptions {};
    // The two native signed levels at +8/+c both accept -1. Flags stay zero.
    streamOptions.console_level = ~uint64_t(0);
    nativeLogger = CCStream::withPipeAndName(driverLogPipe, "DriverLog", &streamOptions);
    if (!nativeLogger || !nativeLogger->metaCast("CCLogStream")) return false;
    ready |= 2; record();
    options.log_data_type = 0;
    options.pad9 = HIGHER32(0x202800000);
    options.pad10 = LOWER32(0x202800000);
    strlcpy(options.file_name, "IntelWiFi_DataPath", sizeof(options.file_name));
    driverDataPathPipe = CCPipe::withOwnerNameCapacity(this, "org.geekaudio.AirportItlwm", "DatapathEvents", &options);
    if (!driverDataPathPipe) return false;
    if (!NativeWifi::startNativeCapturePipe(driverDataPathPipe)) return false;
    nativeCaptureStarted |= 2U;
    ready |= 4; record();
    options = {};
    options.pipe_type = 0x200000001;
    options.log_data_type = 2;
    options.pipe_size = 128;
    strlcpy(options.file_name, "StateSnapshots", sizeof(options.file_name));
    strlcpy(options.name, "0", sizeof(options.name));
    strlcpy(options.directory_name, "WiFi", sizeof(options.directory_name));
    driverSnapshotsPipe = CCPipe::withOwnerNameCapacity(this, "org.geekaudio.AirportItlwm", "StateSnapshots", &options);
    if (!driverSnapshotsPipe) return false;
    // CCDataPipe::start allocates its notify timer. enqueueBlob dereferences
    // that timer when no capture client is connected, including fault reports.
    // Complete native startup before exposing any CCDataStream/reporter.
    if (!NativeWifi::startNativeCapturePipe(driverSnapshotsPipe)) return false;
    nativeCaptureStarted |= 4U;
    ready |= 8; record();
    streamOptions = {};
    streamOptions.stream_type = 1;
    driverFaultReporter = CCStream::withPipeAndName(driverSnapshotsPipe, "FaultReporter", &streamOptions);
    if (!driverFaultReporter || !driverFaultReporter->metaCast("CCDataStream")) return false;
    ready |= 16; record();
    nativeFaultReporter = NativeWifi::createNativeFaultReporter(driverFaultReporter, _fWorkloop);
    if (!nativeFaultReporter) return false;
    ready |= 32; record();
    return true;
#else
    CCPipeOptions driverLogOptions = { 0 };
    driverLogOptions.pipe_type = 0;
    driverLogOptions.log_data_type = 1;
    driverLogOptions.pipe_size = 0x200000;
    driverLogOptions.min_log_size_notify = 0xccccc;
    driverLogOptions.notify_threshold = 1000;
    strlcpy(driverLogOptions.file_name, "Itlwm_Logs", sizeof(driverLogOptions.file_name));
    snprintf(driverLogOptions.name, sizeof(driverLogOptions.name), "wlan%d", 0);
    strlcpy(driverLogOptions.directory_name, "WiFi", sizeof(driverLogOptions.directory_name));
    driverLogOptions.pad9 = 0x1000000;
    driverLogOptions.pad10 = 2;
    driverLogOptions.file_options = 0;
    driverLogOptions.log_policy = 0;
    driverLogPipe = CCPipe::withOwnerNameCapacity(this, "com.zxystd.AirportItlwm", "DriverLogs", &driverLogOptions);
    XYLog("%s driverLogPipeRet %d\n", __FUNCTION__, driverLogPipe != NULL);
    
    memset(&driverLogOptions, 0, sizeof(driverLogOptions));
    driverLogOptions.pipe_type = 0;
    driverLogOptions.log_data_type = 0;
    driverLogOptions.pipe_size = 0x200000;
    driverLogOptions.min_log_size_notify = 0xccccc;
    driverLogOptions.notify_threshold = 1000;
    strlcpy(driverLogOptions.file_name, "AppleBCMWLAN_Datapath", sizeof(driverLogOptions.file_name));
    strlcpy(driverLogOptions.directory_name, "WiFi", sizeof(driverLogOptions.directory_name));
    driverLogOptions.pad9 = HIGHER32(0x202800000);
    driverLogOptions.pad10 = LOWER32(0x202800000);
    driverLogOptions.file_options = 0;
    driverLogOptions.log_policy = 0;
    driverDataPathPipe = CCPipe::withOwnerNameCapacity(this, "com.zxystd.AirportItlwm", "DatapathEvents", &driverLogOptions);
    XYLog("%s driverDataPathPipeRet %d\n", __FUNCTION__, driverDataPathPipe != NULL);
    
    memset(&driverLogOptions, 0, sizeof(driverLogOptions));
    driverLogOptions.pipe_type = 0x200000001;
    driverLogOptions.log_data_type = 2;
    strlcpy(driverLogOptions.file_name, "StateSnapshots", sizeof(driverLogOptions.file_name));
    strlcpy(driverLogOptions.name, "0", sizeof(driverLogOptions.name));
    strlcpy(driverLogOptions.directory_name, "WiFi", sizeof(driverLogOptions.directory_name));
    driverLogOptions.pipe_size = 128;
    driverSnapshotsPipe = CCPipe::withOwnerNameCapacity(this, "com.zxystd.AirportItlwm", "StateSnapshots", &driverLogOptions);
    XYLog("%s driverSnapshotsPipeRet %d\n", __FUNCTION__, driverSnapshotsPipe != NULL);
    
    CCStreamOptions faultReportOptions = { 0 };
    faultReportOptions.stream_type = 1;
    faultReportOptions.console_level = 0xFFFFFFFFFFFFFFFF;
    driverFaultReporter = CCStream::withPipeAndName(driverSnapshotsPipe, "FaultReporter", &faultReportOptions);
    XYLog("%s driverFaultReporterRet %d\n", __FUNCTION__, driverFaultReporter != NULL);
    return driverLogPipe && driverDataPathPipe && driverSnapshotsPipe && driverFaultReporter;
#endif
}

bool AirportItlwm::start(IOService *provider)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
#ifdef AIRPORT_TAHOE
    // A successfully stopped controller may be matched again by the service
    // plane. Each new start owns a fresh power-stop lifecycle.
    __atomic_store_n(&nativePowerStopping, false, __ATOMIC_RELEASE);
    nativeStartupResult(this, provider, "start-entry", true);
    if (!nativeStartupResult(this, provider, "runtime", NativeWifi::verifyTahoeRuntime())) return false;
#endif
    struct IOSkywalkEthernetInterface::RegistrationInfo registInfo;
    int boot_value = 0;
    
    UInt8 builtIn = 0;
    setProperty("built-in", OSData::withBytes(&builtIn, sizeof(builtIn)));
    setProperty("DriverKitDriver", kOSBooleanFalse);
#ifdef AIRPORT_TAHOE
    if (!nativeStartupResult(this, provider, "capture", initCCLogs())) {
        releaseNativeCapture();
        return false;
    }
#endif
    if (!ITL_STARTUP_RESULT(provider, "parent-start", super::start(provider))) {
#ifdef AIRPORT_TAHOE
        // Native start can already have created a monitor borrowing our
        // logger. Its partial-stop path is null-safe and must run first.
        super::stop(provider);
        releaseAll();
#endif
        return false;
    }
    pciNub->setBusMasterEnable(true);
    pciNub->setIOEnable(true);
    pciNub->setMemoryEnable(true);
    pciNub->configWrite8(0x41, 0);
    if (!ITL_STARTUP_RESULT(provider, "pci-power", pciNub->requestPowerDomainState(kIOPMPowerOn,
                                        (IOPowerConnection *) getParentEntry(gIOPowerPlane), IOPMLowestState) == IOPMNoErr)) {
        super::stop(provider);
        return false;
    }
    if (!ITL_STARTUP_RESULT(provider, "pci-pm", initPCIPowerManagment(pciNub))) {
        super::stop(pciNub);
        return false;
    }
    if (!ITL_STARTUP_RESULT(provider, "workloop", _fWorkloop != nullptr)) {
        XYLog("No _fWorkloop!!\n");
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    _fCommandGate = IOCommandGate::commandGate(this, (IOCommandGate::Action)AirportItlwm::tsleepHandler);
    if (!ITL_STARTUP_RESULT(provider, "command-gate", _fCommandGate != nullptr)) {
        XYLog("No command gate!!\n");
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    _fWorkloop->addEventSource(_fCommandGate);
    const IONetworkMedium *primaryMedium;
    if (!ITL_STARTUP_RESULT(provider, "medium", createMediumTables(&primaryMedium) &&
        setCurrentMedium(primaryMedium) && setSelectedMedium(primaryMedium))) {
        XYLog("setup medium fail\n");
#ifdef AIRPORT_TAHOE
        super::stop(provider);
#endif
        releaseAll();
        return false;
    }
    fHalService->initWithController(this, _fWorkloop, _fCommandGate);
    fHalService->get80211Controller()->ic_event_handler = eventHandler;
    
    if (PE_parse_boot_argn("-novht", &boot_value, sizeof(boot_value)))
        fHalService->get80211Controller()->ic_userflags |= IEEE80211_F_NOVHT;
    if (PE_parse_boot_argn("-noht40", &boot_value, sizeof(boot_value)))
        fHalService->get80211Controller()->ic_userflags |= IEEE80211_F_NOHT40;
    
    if (!ITL_STARTUP_RESULT(provider, "hal-attach", fHalService->attach(pciNub))) {
        XYLog("attach fail\n");
        super::stop(pciNub);
        releaseAll();
        return false;
    }
#ifdef AIRPORT_TAHOE
    bool skywalkAttached = false;
    bool controllerAttached = false;
    bool bsdAttached = false;
    // No interface is published until the complete adapter is ready. Failure
    // must drain our ingress before releasing its gate, HAL or owner leases.
    auto failNativeStart = [&]() -> bool {
        // A failed match must not hand this HAL to another controller while
        // its original gate and callbacks may still be alive.
        auto wrapper = OSDynamicCast(IOPCIEDeviceWrapper, provider);
        if (wrapper && wrapper->fHalService == fHalService) wrapper->fHalService = nullptr;
        detachWatchdogTimer();
        bool drained = !fNetIf ||
            static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->stopNative();
        struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
        if (!drained || nativeActivationAttempted || (ifp->if_flags & (IFF_UP | IFF_RUNNING))) {
            // The inherited HAL detach does not establish an active-task
            // drain before freeing DMA. Keep its owner, gate, BSD interface
            // and allocations alive until reboot on this startup-only path.
            retain();
            if (drained && (ifp->if_flags & IFF_UP)) fHalService->disable(bsdInterface);
            XYLog("Native startup failed; HAL resources retained until reboot\n");
            return false;
        }
        OSSafeReleaseNULL(watchdogTimer);
        OSSafeReleaseNULL(fWatchdogWorkLoop);
        // HAL teardown may still reference ifp->iface. Keep BSD alive through
        // it, then remove that borrowed pointer before terminating BSD.
        fHalService->detach(pciNub);
        ether_ifdetach(ifp);
        if (bsdAttached) {
            IONetworkController::detachInterface(bsdInterface, true);
            OSSafeReleaseNULL(bsdInterface);
        }
        if (fNetIf) static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->releaseNative();
        if (controllerAttached) super::detachInterface(fNetIf, true);
        if (skywalkAttached) fNetIf->detach(this);
        OSSafeReleaseNULL(fNetIf);
        super::stop(provider);
        releaseAll();
        return false;
    };
#endif
    fWatchdogWorkLoop = IOWorkLoop::workLoop();
    if (!ITL_STARTUP_RESULT(provider, "watchdog-loop", fWatchdogWorkLoop != nullptr)) {
        XYLog("init watchdog workloop fail\n");
#ifdef AIRPORT_TAHOE
        return failNativeStart();
#else
        fHalService->detach(pciNub);
        super::stop(pciNub);
        releaseAll();
        return false;
#endif
    }
    watchdogTimer = IOTimerEventSource::timerEventSource(this, OSMemberFunctionCast(IOTimerEventSource::Action, this, &AirportItlwm::watchdogAction));
    if (!ITL_STARTUP_RESULT(provider, "watchdog-timer", watchdogTimer != nullptr)) {
        XYLog("init watchdog fail\n");
#ifdef AIRPORT_TAHOE
        return failNativeStart();
#else
        fHalService->detach(pciNub);
        super::stop(pciNub);
        releaseAll();
        return false;
#endif
    }
#ifdef AIRPORT_TAHOE
    if (!nativeStartupResult(this, provider, "watchdog-source",
            fWatchdogWorkLoop->addEventSource(watchdogTimer) == kIOReturnSuccess))
        return failNativeStart();
    watchdogSourceAttached = true;
#else
    watchdogSourceAttached =
        fWatchdogWorkLoop->addEventSource(watchdogTimer) == kIOReturnSuccess;
#endif
#ifndef AIRPORT_TAHOE
    scanSource = IOTimerEventSource::timerEventSource(this, &fakeScanDone);
    _fWorkloop->addEventSource(scanSource);
    scanSource->enable();
#endif

    fNetIf = new AirportItlwmSkywalkInterface;
    if (!ITL_STARTUP_RESULT(provider, "skywalk-init", fNetIf &&
            static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->init(this))) {
        XYLog("Skywalk interface init fail\n");
#ifdef AIRPORT_TAHOE
        return failNativeStart();
#else
        super::stop(provider);
        releaseAll();
        return false;
#endif
    }
    fNetIf->setInterfaceRole(1);
    fNetIf->setInterfaceId(1);
    
#ifndef AIRPORT_TAHOE
    if (!initCCLogs()) {
        XYLog("CCLog init fail\n");
        super::stop(provider);
        releaseAll();
        return false;
    }
#endif
    if (!ITL_STARTUP_RESULT(provider, "skywalk-attach", fNetIf->attach(this))) {
        XYLog("attach to service fail\n");
#ifdef AIRPORT_TAHOE
        return failNativeStart();
#else
        super::stop(provider);
        releaseAll();
        return false;
#endif
    }
#ifdef AIRPORT_TAHOE
    skywalkAttached = true;
#endif
    if (!ITL_STARTUP_RESULT(provider, "controller-attach", attachInterface(fNetIf, this))) {
        XYLog("attach to interface fail\n");
#ifdef AIRPORT_TAHOE
        return failNativeStart();
#else
        super::stop(provider);
        releaseAll();
        return false;
#endif
    }
#ifdef AIRPORT_TAHOE
    controllerAttached = true;
    if (!nativeStartupResult(this, provider, "bsd-attach",
            IONetworkController::attachInterface((IONetworkInterface **)&bsdInterface, false))) {
        XYLog("attach to IONetworkController interface fail\n");
        return failNativeStart();
    }
    bsdAttached = true;
#else
    if (!IONetworkController::attachInterface((IONetworkInterface **)&bsdInterface, true)) {
        XYLog("attach to IONetworkController interface fail\n");
        super::stop(provider);
        releaseAll();
        return false;
    }
#endif
#ifdef AIRPORT_TAHOE
    // Native registration uses typed framework-owned cache allocation. The
    // adapter is implemented separately from the legacy expansion-data layout.
    if (!nativeStartupResult(this, provider, "registration",
            static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->prepareNativeRegistration())) {
        XYLog("Native registration unavailable\n");
        return failNativeStart();
    }
    // The upstream BSD interface is the data path. Do not attach a second BSD
    // interface from metadata-only Skywalk registration.
    fNetIf->deferBSDAttach(true);
#else
    memset(&registInfo, 0, sizeof(registInfo));
    if (!fNetIf->initRegistrationInfo(&registInfo, 1, sizeof(registInfo))) {
        XYLog("initRegistrationInfo fail\n");
        super::stop(provider);
        releaseAll();
        return false;
    }
    if (!fNetIf->initRegistrationInfo(&registInfo, 1, sizeof(registInfo))) {
        XYLog("initRegistrationInfo fail\n");
        super::stop(provider);
        releaseAll();
        return false;
    }
    fNetIf->mExpansionData->fRegistrationInfo = (struct IOSkywalkNetworkInterface::RegistrationInfo *)IOMalloc(sizeof(struct IOSkywalkNetworkInterface::RegistrationInfo));
    fNetIf->mExpansionData2->fRegistrationInfo = (struct IOSkywalkEthernetInterface::RegistrationInfo *)IOMalloc(sizeof(struct IOSkywalkEthernetInterface::RegistrationInfo));
    memcpy(fNetIf->mExpansionData->fRegistrationInfo, &registInfo, sizeof(registInfo));
    memcpy(fNetIf->mExpansionData2->fRegistrationInfo, &registInfo, sizeof(registInfo));
    if (fNetIf->getInterfaceRole() == 1)
        fNetIf->deferBSDAttach(true);
#endif
    if (!ITL_STARTUP_RESULT(provider, "skywalk-start", fNetIf->start(this))) {
#ifdef AIRPORT_TAHOE
        return failNativeStart();
#else
        return false;
#endif
    }

    setLinkStatus(kIONetworkLinkValid);
#ifndef AIRPORT_TAHOE
    if (TAILQ_EMPTY(&fHalService->get80211Controller()->ic_ess))
        fHalService->get80211Controller()->ic_flags |= IEEE80211_F_AUTO_JOIN;
#else
    fHalService->get80211Controller()->ic_flags &= ~IEEE80211_F_AUTO_JOIN;
    bsdInterface->registerService();
#endif
    registerService();
#ifdef AIRPORT_TAHOE
    nativeStartupResult(this, provider, "ready", true);
#endif
    return true;
}

void AirportItlwm::stop(IOService *provider)
{
#ifdef AIRPORT_TAHOE
    // Close admission before any stop/drain work can yield. A request already
    // inside the command gate is retired by the terminal action below.
    setNativePowerStopping(true);
#endif
#if defined(ITL_NATIVE_AWDL_RESIDENT_25G332)
    // The HAL uses this same command gate for the final address check and
    // Action-frame doorbell. Publish the close bit here before the off-gate
    // detach/drain so no submit can pass its final gate check afterward.
    IOReturn closingResult = kIOReturnNotReady;
    if (_fWorkloop && _fWorkloop->inGate())
        closingResult = NativeAwdlLifecycle::publishClosingInGate(this) ?
            kIOReturnSuccess : kIOReturnNotReady;
    else if (_fCommandGate)
        closingResult = _fCommandGate->runAction(
            publishNativeAwdlClosingAction, this);
    if (closingResult != kIOReturnSuccess) {
        XYLog("Native AWDL close publication failed; owner retained\n");
        return;
    }
    if(!NativeAwdlLifecycle::stopResident(this)) {
        XYLog("Native AWDL stop pending; owner retained\n");return;
    }
#endif
    XYLog("%s\n", __PRETTY_FUNCTION__);XYLog("%s\n", __PRETTY_FUNCTION__);
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    detachWatchdogTimer();
#ifdef AIRPORT_TAHOE
    // This barrier must run outside the radio gate. HAL producers are detached
    // afterwards; only then may the ingress allocation and its owner refs go.
    if (fNetIf && !static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->stopNative()) {
        XYLog("Native ingress closing; stop cannot wait in radio gate\n");
        return;
    }
    // The terminal policy/epoch writer must share the SET_POWER command gate.
    // Keep the ingress drain above outside the radio gate so it cannot wait
    // while blocking the HAL producer it is trying to retire.
    IOReturn terminalPowerResult = kIOReturnNotReady;
    if (_fWorkloop && _fWorkloop->inGate())
        terminalPowerResult = nativePowerStopAction(this, nullptr, nullptr,
                                                     nullptr, nullptr);
    else if (_fCommandGate)
        terminalPowerResult = _fCommandGate->runAction(
            nativePowerStopAction, nullptr);
    if (terminalPowerResult != kIOReturnSuccess) {
        XYLog("Native power stop gate unavailable; owner retained\n");
        return;
    }
#endif
#ifdef AIRPORT_TAHOE
    // PM setPowerState callouts are external to the controller gate. Drain
    // them now, while the HAL, workloop, and policy maker are still alive.
    // setPowerState rejects new callouts after the stop latch is published.
    if (!retireNativePMPowerCallouts()) {
        XYLog("Native PM callout retirement failed; owner retained\n");
        return;
    }
#endif
    super::stop(provider);
    disableAdapter(bsdInterface);
    setLinkStatus(kIONetworkLinkValid);
    fHalService->detach(pciNub);
#ifdef AIRPORT_TAHOE
    if (fNetIf) static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->releaseNative();
#endif
    ether_ifdetach(ifp);
    detachInterface(fNetIf, true);
    OSSafeReleaseNULL(fNetIf);
    releaseAll();
}

void AirportItlwm::free()
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
#ifdef AIRPORT_TAHOE
    releaseNativePowerHAL();
#else
    if (fHalService != NULL) {
        fHalService->release();
        fHalService = NULL;
    }
#endif
    if (syncFrameTemplate != NULL && syncFrameTemplateLength > 0) {
        IOFree(syncFrameTemplate, syncFrameTemplateLength);
        syncFrameTemplateLength = 0;
        syncFrameTemplate = NULL;
    }
    if (roamProfile != NULL) {
        IOFree(roamProfile, sizeof(struct apple80211_roam_profile_band_data));
        roamProfile = NULL;
    }
    if (btcProfile != NULL) {
        IOFree(btcProfile, sizeof(struct apple80211_btc_profiles_data));
        btcProfile = NULL;
    }
#ifdef AIRPORT_TAHOE
    releaseNativeCapture();
    releaseNativePowerLocks();
#endif
    super::free();
}

bool AirportItlwm::createWorkQueue()
{
    XYLog("%s %d\n", __FUNCTION__, _fWorkloop != 0);
    return _fWorkloop != 0;
}

#ifdef AIRPORT_TAHOE
IO80211WorkQueue *AirportItlwm::getWorkQueue() const { return _fWorkloop; }
IOCommandGate *AirportItlwm::getIO80211CommandGate() const { return IO80211Controller::getIO80211CommandGate(); }
void *AirportItlwm::getLogger() const { return nativeLogger; }
#else
IO80211WorkQueue *AirportItlwm::getWorkQueue() { return _fWorkloop; }
#endif

void *AirportItlwm::getFaultReporterFromDriver()
{
#ifdef AIRPORT_TAHOE
    return nativeFaultReporter;
#else
    return driverFaultReporter;
#endif
}

IOReturn AirportItlwm::enable(IO80211SkywalkInterface *netif)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
#ifndef AIRPORT_TAHOE
    super::enable(netif);
#endif
    _fCommandGate->enable();
#ifdef AIRPORT_TAHOE
    if ((__atomic_load_n(&nativePowerFlags, __ATOMIC_ACQUIRE) & 1U))
#else
    if (power_state)
#endif
        return enableAdapter(bsdInterface);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::disable(IO80211SkywalkInterface *netif)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
#ifndef AIRPORT_TAHOE
    super::disable(netif);
#endif
    setLinkStatus(kIONetworkLinkValid);
    return kIOReturnSuccess;
}

bool AirportItlwm::configureInterface(IONetworkInterface *netif)
{
    IONetworkData *nd;
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    
    if (super::configureInterface(netif) == false) {
        XYLog("super failed\n");
        return false;
    }
    
    nd = netif->getParameter(kIONetworkStatsKey);
    if (!nd || !(fpNetStats = (IONetworkStats *)nd->getBuffer())) {
        XYLog("network statistics buffer unavailable?\n");
        return false;
    }
    ifp->netStat = fpNetStats;
    ether_ifattach(ifp, OSDynamicCast(IOEthernetInterface, netif));
    fpNetStats->collisions = 0;
#ifdef __PRIVATE_SPI__
    netif->configureOutputPullModel(fHalService->getDriverInfo()->getTxQueueSize(), 0, 0, IOEthernetInterface::kOutputPacketSchedulingModelNormal, 0);
#endif
    
    return true;
}

IONetworkInterface *AirportItlwm::createInterface()
{
    AirportItlwmEthernetInterface *netif = new AirportItlwmEthernetInterface;
    if (!netif)
        return NULL;
    if (!netif->initWithSkywalkInterfaceAndProvider(this, fNetIf)) {
        netif->release();
        return NULL;
    }
    return netif;
}

bool AirportItlwm::createMediumTables(const IONetworkMedium **primary)
{
    IONetworkMedium    *medium;

    OSDictionary *mediumDict = OSDictionary::withCapacity(2);
    if (mediumDict == NULL) {
        XYLog("Cannot allocate OSDictionary\n");
        return false;
    }
    
    medium = IONetworkMedium::medium(kIOMediumIEEE80211, 54000000);
    IONetworkMedium::addMedium(mediumDict, medium);
    medium->release();
    if (primary) {
        *primary = medium;
    }
    medium = IONetworkMedium::medium(kIOMediumIEEE80211None, 0);
    IONetworkMedium::addMedium(mediumDict, medium);
    medium->release();
    
    bool result = publishMediumDictionary(mediumDict);
    if (!result) {
        XYLog("Cannot publish medium dictionary!\n");
    }

    mediumDict->release();
    return result;
}

IOReturn AirportItlwm::selectMedium(const IONetworkMedium *medium) {
    setSelectedMedium(medium);
    return kIOReturnSuccess;
}

bool AirportItlwm::
setLinkStatus(UInt32 status, const IONetworkMedium * activeMedium, UInt64 speed, OSData * data)
{
    struct _ifnet *ifq = &fHalService->get80211Controller()->ic_ac.ac_if;
    if (status == currentStatus) {
        return true;
    }
    bool ret = super::setLinkStatus(status, activeMedium, speed, data);
    currentStatus = status;
    if (fNetIf) {
        if (status & kIONetworkLinkActive) {
#ifdef __PRIVATE_SPI__
            bsdInterface->startOutputThread();
#endif
#ifdef AIRPORT_TAHOE
            if (bsdInterface && bsdInterface->getIfnet())
                bsdInterface->setLinkState(kIO80211NetworkLinkUp);
            static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->captureNativeAuthorization(true);
#else
            getCommandGate()->runAction(setLinkStateGated, (void *)kIO80211NetworkLinkUp, (void *)0);
#endif
//            fNetIf->setLinkQualityMetric(100);
        } else if (!(status & kIONetworkLinkNoNetworkChange)) {
#ifdef __PRIVATE_SPI__
            bsdInterface->stopOutputThread();
            bsdInterface->flushOutputQueue();
#endif
            ifq_flush(&ifq->if_snd);
            mq_purge(&fHalService->get80211Controller()->ic_mgtq);
#ifdef AIRPORT_TAHOE
            if (bsdInterface && bsdInterface->getIfnet())
                bsdInterface->setLinkState(kIO80211NetworkLinkDown);
            static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->captureNativeAuthorization(false);
#else
            getCommandGate()->runAction(setLinkStateGated, (void *)kIO80211NetworkLinkDown, (void *)fHalService->get80211Controller()->ic_deauth_reason);
#endif
        }
    }
    return ret;
}

IOReturn AirportItlwm::
setLinkStateGated(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3)
{
#ifdef AIRPORT_TAHOE
    return kIOReturnUnsupported;
#else
    AirportItlwm *that = OSDynamicCast(AirportItlwm, target);
    IOReturn ret = that->fNetIf->setLinkState((IO80211LinkState)(uint64_t)arg0, (unsigned int)(uint64_t)arg1);
    that->fNetIf->setRunningState((IO80211LinkState)(uint64_t)arg0 == kIO80211NetworkLinkUp);
    that->fNetIf->postMessage(APPLE80211_M_LINK_CHANGED, NULL, 0, false);
    that->fNetIf->postMessage(APPLE80211_M_BSSID_CHANGED, NULL, 0, false);
    that->fNetIf->postMessage(APPLE80211_M_SSID_CHANGED, NULL, 0, false);
    if ((IO80211LinkState)(uint64_t)arg0 == kIO80211NetworkLinkUp) {
        that->fNetIf->reportLinkStatus(3, 0x80);
    } else {
        that->fNetIf->reportLinkStatus(1, 0);
    }
    that->bsdInterface->setLinkState((IO80211LinkState)(uint64_t)arg0);
    return ret;
#endif
}

#ifdef __PRIVATE_SPI__
IOReturn AirportItlwm::outputStart(IONetworkInterface *interface, IOOptionBits options)
{
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    mbuf_t m = NULL;
    if (ifq_is_oactive(&ifp->if_snd))
        return kIOReturnNoResources;
    while (kIOReturnSuccess == interface->dequeueOutputPackets(1, &m)) {
        if (outputPacket(m, NULL)!= kIOReturnOutputSuccess ||
            ifq_is_oactive(&ifp->if_snd))
            return kIOReturnNoResources;
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::networkInterfaceNotification(
                    IONetworkInterface * interface,
                    uint32_t              type,
                    void *                  argument )
{
    XYLog("%s\n", __FUNCTION__);
    return kIOReturnSuccess;
}
#endif

extern const char* hexdump(uint8_t *buf, size_t len);

UInt32 AirportItlwm::outputPacket(mbuf_t m, void *param)
{
//    XYLog("%s\n", __FUNCTION__);
    IOReturn ret = kIOReturnOutputSuccess;
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    
    if (fHalService->get80211Controller()->ic_state != IEEE80211_S_RUN || ifp->if_snd.queue == NULL) {
        if (m && mbuf_type(m) != MBUF_TYPE_FREE)
            freePacket(m);
        return kIOReturnOutputDropped;
    }
    if (m == NULL) {
        XYLog("%s m==NULL!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        ret = kIOReturnOutputDropped;
    }
    if (!(mbuf_flags(m) & MBUF_PKTHDR) ){
        XYLog("%s pkthdr is NULL!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        freePacket(m);
        ret = kIOReturnOutputDropped;
    }
    if (mbuf_type(m) == MBUF_TYPE_FREE) {
        XYLog("%s mbuf is FREE!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        ret = kIOReturnOutputDropped;
    }
    size_t len = mbuf_len(m);
    ether_header_t *eh = (ether_header_t *)mbuf_data(m);
#ifndef AIRPORT_TAHOE
    if (len >= sizeof(ether_header_t) && eh->ether_type == htons(ETHERTYPE_PAE)) { // EAPOL packet
        const char* dump = hexdump((uint8_t*)mbuf_data(m), len);
        XYLog("output EAPOL packet, len: %zu, data: %s\n", len, dump ? dump : "Failed to allocate memory");
        if (dump)
            IOFree((void*)dump, 3 * len + 1);
    }
#endif
    if (!ifp->if_snd.queue->lockEnqueue(m)) {
        freePacket(m);
        ret = kIOReturnOutputDropped;
    }
    (*ifp->if_start)(ifp);
    return ret;
}

const OSString * AirportItlwm::newVendorString() const
{
    return OSString::withCString("Apple");
}

const OSString * AirportItlwm::newModelString() const
{
    return OSString::withCString(fHalService->getDriverInfo()->getFirmwareName());
}

IOReturn AirportItlwm::getHardwareAddress(IOEthernetAddress *addrP)
{
    if (IEEE80211_ADDR_EQ(etheranyaddr, fHalService->get80211Controller()->ic_myaddr))
        return kIOReturnError;
    else {
        IEEE80211_ADDR_COPY(addrP, fHalService->get80211Controller()->ic_myaddr);
        return kIOReturnSuccess;
    }
}

IOReturn AirportItlwm::setHardwareAddress(const void *addrP, UInt32 addrBytes)
{
#ifdef AIRPORT_TAHOE
    return fNetIf ? static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->applyNativeAddress(addrP, addrBytes) : kIOReturnNotReady;
#else
    if (!fNetIf || !addrP)
        return kIOReturnError;
    if_setlladdr(&fHalService->get80211Controller()->ic_ac.ac_if, (const UInt8 *)addrP);
    if (fHalService->get80211Controller()->ic_state > IEEE80211_S_INIT) {
        fHalService->disable(bsdInterface);
        fHalService->enable(bsdInterface);
    }
    return kIOReturnSuccess;
#endif
}

UInt32 AirportItlwm::getFeatures() const
{
    return fHalService->getDriverInfo()->supportedFeatures();
}

IOReturn AirportItlwm::setPromiscuousMode(IOEnetPromiscuousMode mode)
{
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::setMulticastMode(IOEnetMulticastMode mode)
{
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::setMulticastList(IOEthernetAddress* addr, UInt32 len)
{
    return fHalService->getDriverController()->setMulticastList(addr, len);
}

IOReturn AirportItlwm::getPacketFilters(const OSSymbol *group, UInt32 *filters) const
{
    IOReturn    rtn = kIOReturnSuccess;
    if (group == gIOEthernetWakeOnLANFilterGroup && magicPacketSupported)
        *filters = kIOEthernetWakeOnMagicPacket;
    else if (group == gIONetworkFilterGroup)
        *filters = kIOPacketFilterMulticast | kIOPacketFilterPromiscuous;
    else
        rtn = IOEthernetController::getPacketFilters(group, filters);
    return rtn;
}

SInt32 AirportItlwm::
enableFeature(IO80211FeatureCode code, void *data)
{
    if (code == kIO80211Feature80211n) {
        return 0;
    }
    return 102;
}

bool AirportItlwm::getLogPipes(CCPipe**logPipe, CCPipe**eventPipe, CCPipe**snapshotsPipe)
{
    bool ret = false;
    if (logPipe) {
        *logPipe = driverLogPipe;
        ret = true;
    }
    if (eventPipe) {
        *eventPipe = driverDataPathPipe;
        ret = true;
    }
    if (snapshotsPipe) {
        *snapshotsPipe = driverSnapshotsPipe;
        ret = true;
    }
    return ret;
}

#define APPLE80211_CAPA_AWDL_FEATURE_AUTO_UNLOCK    0x00000004
#define APPLE80211_CAPA_AWDL_FEATURE_WOW            0x00000080

IOReturn AirportItlwm::
getCARD_CAPABILITIES(OSObject *object,
                                     struct apple80211_capability_data *cd)
{
    if (!cd) return kIOReturnBadArgument;
    uint32_t caps = fHalService->get80211Controller()->ic_caps;
    memset(cd, 0, sizeof(struct apple80211_capability_data));
#ifdef AIRPORT_TAHOE
    cd->version = APPLE80211_VERSION;
    if (caps & IEEE80211_C_RSN) {
        cd->capabilities[0] = 1U << APPLE80211_CAP_AES_CCM;
        cd->capabilities[1] = 1U << (APPLE80211_CAP_WPA2 - 8);
    }
    if (caps & IEEE80211_C_SHSLOT)
        cd->capabilities[1] |= 1U << (APPLE80211_CAP_SHSLOT - 8);
    if (caps & IEEE80211_C_SHPREAMBLE)
        cd->capabilities[1] |= 1U << (APPLE80211_CAP_SHPREAMBLE - 8);
    // Native IO80211.framework tests capability byte 5, bit 6 before
    // waiting for SCAN_DONE. Our firmware scan is asynchronous: WCL receives
    // real terminal event 237 and produces SCAN_DONE after collecting BSSes.
    // Without this bit, GET11 is issued immediately and returns WCL busy.
    cd->capabilities[5] |= 0x40;
    // Legacy upper capability bytes contain unimplemented features. This
    // native subset does not advertise AWDL, WPA3, PMF, MLO, or enterprise AKMs.
    return kIOReturnSuccess;
#endif
    
    if (caps & IEEE80211_C_WEP)
        cd->capabilities[0] |= 1 << APPLE80211_CAP_WEP;
    if (caps & IEEE80211_C_RSN)
        cd->capabilities[0] |= 1 << APPLE80211_CAP_TKIP | 1 << APPLE80211_CAP_AES_CCM;
    // Disable not implemented capabilities
    // if (caps & IEEE80211_C_PMGT)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_PMGT;
    // if (caps & IEEE80211_C_IBSS)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_IBSS;
    // if (caps & IEEE80211_C_HOSTAP)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_HOSTAP;
    // AES not enabled, like on Apple cards
    
    if (caps & IEEE80211_C_SHSLOT)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_SHSLOT - 8);
    if (caps & IEEE80211_C_SHPREAMBLE)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_SHPREAMBLE - 8);
    if (caps & IEEE80211_C_RSN)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_WPA1 - 8) | 1 << (APPLE80211_CAP_WPA2 - 8) | 1 << (APPLE80211_CAP_TKIPMIC - 8);
    // Disable not implemented capabilities
    // if (caps & IEEE80211_C_TXPMGT)
    //     cd->capabilities[1] |= 1 << (APPLE80211_CAP_TXPMGT - 8);
    // if (caps & IEEE80211_C_MONITOR)
    //     cd->capabilities[1] |= 1 << (APPLE80211_CAP_MONITOR - 8);
    // WPA not enabled, like on Apple cards

    cd->version = APPLE80211_VERSION;
    cd->capabilities[2] = 0xFF; // BURST, WME, SHORT_GI_40MHZ, SHORT_GI_20MHZ, WOW, TSN, ?, ?
    cd->capabilities[3] = 0x2B;
    cd->capabilities[5] = 0x40;
    cd->capabilities[6] = (
//                           1 |    //MFP capable
                           0x8 |
                           0x4 |
                           0x80
                           );
    *(uint16_t *)&cd->capabilities[8] = 0x201;
//
//    cd->capabilities[2] |= 0x10;
//    cd->capabilities[5] |= 0x1;
//
//    cd->capabilities[2] |= 0x2;
//
//    cd->capabilities[3] |= 0x20;
//
//    cd->capabilities[0] |= 0x80;
//
//    cd->capabilities[3] |= 0x80;
//    cd->capabilities[4] |= 0x4;
//
//    cd->capabilities[4] |= 0x1;
//    cd->capabilities[3] |= 0x1;
//    cd->capabilities[6] |= 0x8;
//
//    cd->capabilities[3] |= 3;
//    cd->capabilities[4] |= 2;
//    cd->capabilities[6] |= 0x10;
//    cd->capabilities[5] |= 0x20;
//    cd->capabilities[5] |= 0x80;
//
//    if (cd->capabilities[6] & 0x20) {
//        cd->capabilities[2] |= 8;
//    }
//    cd->capabilities[5] |= 8;
//    cd->capabilities[8] |= 2;
//
//    cd->capabilities[11] |= (2 | 4 | 8 | 0x10 | 0x20 | 0x40 | 0x80);
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getDRIVER_VERSION(OSObject *object,
                                  struct apple80211_version_data *hv)
{
    if (!hv)
        return kIOReturnError;
    hv->version = APPLE80211_VERSION;
    snprintf(hv->string, sizeof(hv->string), "itlwm: %s%s fw: %s", ITLWM_VERSION, GIT_COMMIT, fHalService->getDriverInfo()->getFirmwareVersion());
    hv->string_len = strlen(hv->string);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getHARDWARE_VERSION(OSObject *object,
                                    struct apple80211_version_data *hv)
{
    if (!hv)
        return kIOReturnError;
    hv->version = APPLE80211_VERSION;
    strncpy(hv->string, fHalService->getDriverInfo()->getFirmwareVersion(), sizeof(hv->string));
    hv->string_len = strlen(fHalService->getDriverInfo()->getFirmwareVersion());
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getCOUNTRY_CODE(OSObject *object,
                                struct apple80211_country_code_data *cd)
{
    char user_override_cc[3];
    const char *cc_fw = fHalService->getDriverInfo()->getFirmwareCountryCode();
    
    if (!cd)
        return kIOReturnError;
    cd->version = APPLE80211_VERSION;
    memset(user_override_cc, 0, sizeof(user_override_cc));
    PE_parse_boot_argn("itlwm_cc", user_override_cc, 3);
    /* user_override_cc > firmware_cc > geo_location_cc */
    strncpy((char*)cd->cc, user_override_cc[0] ? user_override_cc : ((cc_fw[0] == 'Z' && cc_fw[1] == 'Z' && geo_location_cc[0]) ? geo_location_cc : cc_fw), sizeof(cd->cc));
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setCOUNTRY_CODE(OSObject *object, struct apple80211_country_code_data *data)
{
    XYLog("%s cc=%s\n", __FUNCTION__, data->cc);
    if (data && data->cc[0] != 120 && data->cc[0] != 88) {
        memcpy(geo_location_cc, data->cc, sizeof(geo_location_cc));
        fNetIf->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED, NULL, 0, 0);
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getPOWER(OSObject *object,
                         struct apple80211_power_data *pd)
{
    if (!pd)
        return kIOReturnError;
#ifdef AIRPORT_TAHOE
    __atomic_fetch_add(&nativePowerGetCount, 1U, __ATOMIC_RELAXED);
    // Keep explicit Off and system sleep visible immediately. A missing READY
    // bit is held On only for the bounded dip of one committed address restart;
    // the HAL READY bit itself remains unchanged for diagnostics and waiters.
    uint32_t powerFlags = 0;
    uint64_t restartDeadline = 0;
    bool committedRestartGrace = false;
    IOSimpleLock *lock = nativePowerStateLock;
    if (lock) {
        const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock);
        powerFlags = __atomic_load_n(&nativePowerFlags, __ATOMIC_RELAXED);
        const uint32_t powerEpoch = __atomic_load_n(&nativePowerEpoch, __ATOMIC_RELAXED);
        if ((powerFlags & 1U) && !(powerFlags & 2U) &&
            fHalService && nativeAddressRestartNotification.active() &&
            nativeAddressRestartNotification.committed()) {
            const uint64_t restartId = nativeAddressRestartNotification.id();
            uint32_t faultSerial = 0;
            const bool faultSerialValid =
                fHalService->readNativePowerFaultSerial(&faultSerial);
            committedRestartGrace = restartId != 0 &&
                restartId == nativeAddressRestartPublishedId &&
                nativeAddressRestartNotification.powerEpoch() == powerEpoch &&
                nativeAddressRestartPublishedEpoch == powerEpoch &&
                nativeAddressRestartNotification.startRevision() ==
                    nativeAddressRestartStartRevision &&
                faultSerialValid && faultSerial ==
                    nativeAddressRestartNotification.faultSerial();
            restartDeadline = nativeAddressRestartNotification.deadlineNanoseconds();
        }
        IOSimpleLockUnlockEnableInterrupt(lock, irq);
    } else {
        // Missing the lifecycle lock fails closed: do not preserve transient
        // On intent without a coherent restart/fault snapshot.
        powerFlags = __atomic_load_n(&nativePowerFlags, __ATOMIC_ACQUIRE);
    }
    const bool restartStillInWindow = committedRestartGrace &&
        nativePowerUptimeNanoseconds() < restartDeadline;
    const bool systemPowerOn = __atomic_load_n(&pmPowerState, __ATOMIC_ACQUIRE) !=
        kPowerStateOff;
    const uint8_t state = systemPowerOn && (powerFlags & 1U) &&
        ((powerFlags & 2U) || restartStillInWindow) ? 1 : 0;
    pd->version = APPLE80211_VERSION;
    pd->num_radios = APPLE80211_MAX_RADIO;
    for (unsigned i = 0; i < APPLE80211_MAX_RADIO; ++i) pd->power_state[i] = state;
    publishNativePowerState();
    return kIOReturnSuccess;
#else
    pd->version = APPLE80211_VERSION;
    pd->num_radios = 4;
    pd->power_state[0] = power_state;
    pd->power_state[1] = power_state;
    pd->power_state[2] = power_state;
    pd->power_state[3] = power_state;
    return kIOReturnSuccess;
#endif
}

#ifdef AIRPORT_TAHOE
uint32_t AirportItlwm::updateNativePowerFlags(uint32_t clearMask,
                                               uint32_t setMask,
                                               bool readyRequiresRequested,
    NativePowerTrace::PowerIngressContext *context)
{
    if (context) *context = NativePowerTrace::PowerIngressContext {};
    IOSimpleLock *lock = nativePowerStateLock;
    if (!lock) {
        // Defensive fallback during partial teardown or a broken lifecycle.
        // Normal startup refuses to continue unless this state lock exists.
        uint32_t flags = __atomic_load_n(&nativePowerFlags, __ATOMIC_ACQUIRE);
        uint32_t updated = 0;
        for (;;) {
            uint32_t effectiveSetMask = setMask;
            if (readyRequiresRequested && !(flags & 1U)) effectiveSetMask &= ~2U;
            updated = (flags & ~clearMask) | effectiveSetMask;
            if (__atomic_compare_exchange_n(&nativePowerFlags, &flags, updated,
                    false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                break;
        }
        if ((flags & 2U) != (updated & 2U))
            __atomic_fetch_add(&nativePowerTransitionRevision, uint64_t(1), __ATOMIC_ACQ_REL);
        if (context) {
            // Missing the state lock is a fail-open ingress snapshot. It may
            // still describe current flags, but cannot carry a coalescing id.
            context->powerFlags = updated;
            context->transitionRevision = __atomic_load_n(
                &nativePowerTransitionRevision, __ATOMIC_ACQUIRE);
            context->powerEpoch = __atomic_load_n(&nativePowerEpoch,
                                                   __ATOMIC_ACQUIRE);
        }
        return flags;
    }

    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock);
    const uint32_t flags = __atomic_load_n(&nativePowerFlags, __ATOMIC_RELAXED);
    uint32_t effectiveSetMask = setMask;
    if (readyRequiresRequested && !(flags & 1U)) effectiveSetMask &= ~2U;
    const uint32_t updated = (flags & ~clearMask) | effectiveSetMask;
    if ((flags & 2U) != (updated & 2U))
        __atomic_fetch_add(&nativePowerTransitionRevision, uint64_t(1), __ATOMIC_RELAXED);
    __atomic_store_n(&nativePowerFlags, updated, __ATOMIC_RELEASE);
    if (context) {
        context->powerFlags = updated;
        context->transitionRevision = __atomic_load_n(
            &nativePowerTransitionRevision, __ATOMIC_RELAXED);
        context->powerEpoch = __atomic_load_n(&nativePowerEpoch, __ATOMIC_RELAXED);
        if (nativeAddressRestartPublishedId &&
            nativeAddressRestartPublishedEpoch == context->powerEpoch) {
            context->addressRestartId = nativeAddressRestartPublishedId;
            context->addressRestartStartRevision =
                nativeAddressRestartStartRevision;
        }
        uint32_t faultSerial = 0;
        context->faultSerialValid = fHalService &&
            fHalService->readNativePowerFaultSerial(&faultSerial);
        context->faultSerial = context->faultSerialValid ? faultSerial : 0;
    }
    IOSimpleLockUnlockEnableInterrupt(lock, irq);
    return flags;
}

uint32_t AirportItlwm::advanceNativePowerEpoch(bool requestedOn)
{
    // nativePowerAction runs on the serialized controller command gate. Tell
    // the HAL first so a popped init callback cannot pass the old epoch while
    // the public request epoch is being published.
    const uint32_t epoch =
        __atomic_load_n(&nativePowerEpoch, __ATOMIC_RELAXED) + 1U;
    if (fHalService)
        fHalService->setNativePowerRequestState(epoch, requestedOn);
    IOSimpleLock *lock = nativePowerStateLock;
    if (lock) {
        const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock);
        __atomic_store_n(&nativePowerEpoch, epoch, __ATOMIC_RELEASE);
        const bool canceled =
            nativeAddressRestartNotification.cancelForEpoch(epoch);
        if (canceled || (nativeAddressRestartPublishedId &&
                nativeAddressRestartPublishedEpoch != epoch)) {
            nativeAddressRestartPublishedId = 0;
            nativeAddressRestartPublishedEpoch = 0;
            nativeAddressRestartStartRevision = 0;
        }
        IOSimpleLockUnlockEnableInterrupt(lock, irq);
        if (canceled) {
            noteNativeAddressRestartOutcome(
                NativePowerTrace::AddressRestartOutcome::kCancelledEpochOrOff);
            publishNativeAddressRestartMetrics();
        }
    } else {
        __atomic_store_n(&nativePowerEpoch, epoch, __ATOMIC_RELEASE);
        const bool wasActive = nativeAddressRestartNotification.active();
        nativeAddressRestartNotification.cancel();
        if (wasActive) {
            noteNativeAddressRestartOutcome(
                NativePowerTrace::AddressRestartOutcome::kCancelledEpochOrOff);
            publishNativeAddressRestartMetrics();
        }
    }
    return epoch;
}

bool AirportItlwm::nativePowerStateSnapshot(uint32_t *powerFlags,
                                            uint64_t *revision) const
{
    IOSimpleLock *lock = nativePowerStateLock;
    if (!lock || !powerFlags || !revision) return false;
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock);
    *powerFlags = __atomic_load_n(&nativePowerFlags, __ATOMIC_RELAXED);
    *revision = __atomic_load_n(&nativePowerTransitionRevision, __ATOMIC_RELAXED);
    IOSimpleLockUnlockEnableInterrupt(lock, irq);
    return true;
}

IOReturn AirportItlwm::beginNativeAddressRestartNotification(uint64_t *idOut)
{
    if (!idOut) return kIOReturnBadArgument;
    *idOut = 0;
    IOSimpleLock *lock = nativePowerStateLock;
    if (!lock || !fHalService) return kIOReturnNotReady;
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock);
    const uint64_t nowNanoseconds = nativePowerUptimeNanoseconds();
    uint32_t powerFlags = __atomic_load_n(&nativePowerFlags, __ATOMIC_RELAXED);
    const uint64_t revision = __atomic_load_n(
        &nativePowerTransitionRevision, __ATOMIC_RELAXED);
    const uint32_t epoch = __atomic_load_n(&nativePowerEpoch, __ATOMIC_RELAXED);
    uint32_t faultSerial = 0;
    const bool faultSerialValid =
        fHalService->readNativePowerFaultSerial(&faultSerial);
    IOReturn result = kIOReturnNotReady;
    if ((powerFlags & 3U) != 3U) {
        result = kIOReturnNotReady;
    } else if (nativeAddressRestartPublishedId ||
               nativeAddressRestartNotification.active()) {
        result = kIOReturnBusy;
    } else if (!faultSerialValid) {
        // The address change itself remains supported; only event coalescing
        // is unavailable when the HAL cannot provide a fault serial.
        result = kIOReturnUnsupported;
    } else {
        const uint64_t id = nativeAddressRestartNotification.begin(epoch,
            revision, faultSerial, true, powerFlags, nowNanoseconds);
        if (id) {
            nativeAddressRestartPublishedId = id;
            nativeAddressRestartPublishedEpoch = epoch;
            nativeAddressRestartStartRevision = revision;
            *idOut = id;
            result = kIOReturnSuccess;
        }
    }
    IOSimpleLockUnlockEnableInterrupt(lock, irq);
    if (*idOut) {
        noteNativeAddressRestartOutcome(
            NativePowerTrace::AddressRestartOutcome::kStarted);
        publishNativeAddressRestartMetrics();
    } else if (result == kIOReturnUnsupported) {
        noteNativeAddressRestartOutcome(
            NativePowerTrace::AddressRestartOutcome::kUnsupportedHal);
        publishNativeAddressRestartMetrics();
    }
    return result;
}

bool AirportItlwm::commitNativeAddressRestartNotification(
    uint64_t id, bool commitSucceeded, bool enableSucceeded)
{
    if (!id) return false;
    IOSimpleLock *lock = nativePowerStateLock;
    if (!lock || !fHalService) {
        nativeAddressRestartNotification.cancel();
        return false;
    }
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock);
    uint32_t faultSerial = 0;
    const bool faultSerialValid =
        fHalService->readNativePowerFaultSerial(&faultSerial);
    const uint32_t epoch = __atomic_load_n(&nativePowerEpoch, __ATOMIC_RELAXED);
    const bool committed = nativeAddressRestartNotification.commit(
        id, epoch, faultSerial, faultSerialValid,
        commitSucceeded, enableSucceeded);
    if (!committed && nativeAddressRestartNotification.active() &&
        nativeAddressRestartNotification.id() == id)
        nativeAddressRestartNotification.cancel(
            NativePowerTrace::AddressRestartOutcome::kCancelledCommitOrEnable);
    if (!committed && nativeAddressRestartPublishedId == id) {
        nativeAddressRestartPublishedId = 0;
        nativeAddressRestartPublishedEpoch = 0;
        nativeAddressRestartStartRevision = 0;
    }
    IOSimpleLockUnlockEnableInterrupt(lock, irq);
    if (!committed) {
        noteNativeAddressRestartOutcome(nativeAddressRestartNotification.lastOutcome());
        publishNativeAddressRestartMetrics();
    }
    return committed;
}

void AirportItlwm::cancelNativeAddressRestartNotification(uint64_t id)
{
    IOSimpleLock *lock = nativePowerStateLock;
    if (!lock) {
        const bool wasActive = nativeAddressRestartNotification.active();
        nativeAddressRestartNotification.cancel();
        if (wasActive) {
            noteNativeAddressRestartOutcome(
                NativePowerTrace::AddressRestartOutcome::kCancelledManual);
            publishNativeAddressRestartMetrics();
        }
        return;
    }
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock);
    const bool wasActive = nativeAddressRestartNotification.active() &&
        (!id || nativeAddressRestartNotification.id() == id);
    if (!id || nativeAddressRestartPublishedId == id) {
        nativeAddressRestartNotification.cancel(
            NativePowerTrace::AddressRestartOutcome::kCancelledManual);
        nativeAddressRestartPublishedId = 0;
        nativeAddressRestartPublishedEpoch = 0;
        nativeAddressRestartStartRevision = 0;
    }
    IOSimpleLockUnlockEnableInterrupt(lock, irq);
    if (wasActive) {
        noteNativeAddressRestartOutcome(
            NativePowerTrace::AddressRestartOutcome::kCancelledManual);
        publishNativeAddressRestartMetrics();
    }
}

NativePowerTrace::AddressRestartDecision
AirportItlwm::observeNativeAddressRestartEvent(
    NativePowerTrace::AddressRestartEvent event,
    const NativePowerTrace::PowerIngressContext &entry)
{
    const uint64_t nowNanoseconds = nativePowerUptimeNanoseconds();
    IOSimpleLock *lock = nativePowerStateLock;
    if (!lock || !fHalService) {
        nativeAddressRestartNotification.cancel();
        return NativePowerTrace::AddressRestartDecision::kPass;
    }
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock);
    const bool wasActive = nativeAddressRestartNotification.active();
    const uint32_t powerFlags = __atomic_load_n(&nativePowerFlags, __ATOMIC_RELAXED);
    const uint64_t revision = __atomic_load_n(
        &nativePowerTransitionRevision, __ATOMIC_RELAXED);
    const uint32_t epoch = __atomic_load_n(&nativePowerEpoch, __ATOMIC_RELAXED);
    uint32_t faultSerial = 0;
    const bool faultSerialValid =
        fHalService->readNativePowerFaultSerial(&faultSerial);
    if (!wasActive) {
        const bool eventReady =
            event == NativePowerTrace::AddressRestartEvent::kDriverReady;
        const bool stale = entry.powerEpoch != epoch ||
            entry.transitionRevision != revision ||
            ((entry.powerFlags & 3U) != (powerFlags & 3U)) ||
            (eventReady && (!(entry.powerFlags & 2U) || !(powerFlags & 2U))) ||
            (!eventReady && ((entry.powerFlags & 2U) || (powerFlags & 2U))) ||
            (entry.faultSerialValid && (!faultSerialValid ||
                entry.faultSerial != faultSerial));
        IOSimpleLockUnlockEnableInterrupt(lock, irq);
        if (stale) {
            noteNativeAddressRestartOutcome(
                NativePowerTrace::AddressRestartOutcome::kStaleEvent);
            publishNativeAddressRestartMetrics();
            return NativePowerTrace::AddressRestartDecision::kStale;
        }
        return NativePowerTrace::AddressRestartDecision::kPass;
    }
    const uint64_t activeId = nativeAddressRestartNotification.id();
    const auto decision = nativeAddressRestartNotification.observe(
        event, entry, epoch, powerFlags, revision, faultSerial,
        faultSerialValid, nowNanoseconds);
    if (!nativeAddressRestartNotification.active() &&
        nativeAddressRestartPublishedId == activeId) {
        nativeAddressRestartPublishedId = 0;
        nativeAddressRestartPublishedEpoch = 0;
        nativeAddressRestartStartRevision = 0;
    }
    IOSimpleLockUnlockEnableInterrupt(lock, irq);
    if (decision == NativePowerTrace::AddressRestartDecision::kSuppress) {
        noteNativeAddressRestartOutcome(nativeAddressRestartNotification.lastOutcome());
        publishNativeAddressRestartMetrics();
    } else if (decision == NativePowerTrace::AddressRestartDecision::kComplete) {
        noteNativeAddressRestartOutcome(
            NativePowerTrace::AddressRestartOutcome::kCompletedReady);
        publishNativeAddressRestartMetrics();
    } else if (wasActive && !nativeAddressRestartNotification.active()) {
        // A stale queued event can reveal that the current transaction expired
        // or was invalidated by OFF/fault. Count and publish that real terminal
        // reason while the event consumer independently discards its payload.
        noteNativeAddressRestartOutcome(nativeAddressRestartNotification.lastOutcome());
        publishNativeAddressRestartMetrics();
    } else if (decision == NativePowerTrace::AddressRestartDecision::kStale) {
        noteNativeAddressRestartOutcome(
            NativePowerTrace::AddressRestartOutcome::kStaleEvent);
        publishNativeAddressRestartMetrics();
    }
    return decision;
}

bool AirportItlwm::tickNativeAddressRestartNotification()
{
    const uint64_t nowNanoseconds = nativePowerUptimeNanoseconds();
    IOSimpleLock *lock = nativePowerStateLock;
    if (!lock || !fHalService) {
        nativeAddressRestartNotification.cancel();
        return false;
    }
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(lock);
    const bool wasActive = nativeAddressRestartNotification.active();
    const uint32_t powerFlags = __atomic_load_n(&nativePowerFlags, __ATOMIC_RELAXED);
    const uint32_t epoch = __atomic_load_n(&nativePowerEpoch, __ATOMIC_RELAXED);
    uint32_t faultSerial = 0;
    const bool faultSerialValid =
        fHalService->readNativePowerFaultSerial(&faultSerial);
    const uint64_t activeId = nativeAddressRestartNotification.id();
    (void)nativeAddressRestartNotification.tick(nowNanoseconds, epoch,
        powerFlags, faultSerial, faultSerialValid);
    const bool suppress = nativeAddressRestartNotification.active();
    if (!suppress && nativeAddressRestartPublishedId == activeId) {
        nativeAddressRestartPublishedId = 0;
        nativeAddressRestartPublishedEpoch = 0;
        nativeAddressRestartStartRevision = 0;
    }
    IOSimpleLockUnlockEnableInterrupt(lock, irq);
    if (wasActive && !suppress) {
        noteNativeAddressRestartOutcome(nativeAddressRestartNotification.lastOutcome());
        publishNativeAddressRestartMetrics();
    }
    return suppress;
}

void AirportItlwm::noteNativeAddressRestartOutcome(
    NativePowerTrace::AddressRestartOutcome outcome)
{
    nativeAddressRestartLastOutcome = static_cast<uint32_t>(outcome);
    switch (outcome) {
        case NativePowerTrace::AddressRestartOutcome::kStarted:
            ++nativeAddressRestartStartedCount; break;
        case NativePowerTrace::AddressRestartOutcome::kSuppressedResetBegin:
        case NativePowerTrace::AddressRestartOutcome::kSuppressedDriverStopped:
            ++nativeAddressRestartSuppressedCount; break;
        case NativePowerTrace::AddressRestartOutcome::kCompletedReady:
            ++nativeAddressRestartCompletedCount; break;
        case NativePowerTrace::AddressRestartOutcome::kExpired:
            ++nativeAddressRestartExpiredCount; break;
        case NativePowerTrace::AddressRestartOutcome::kCancelledFaultSerial:
        case NativePowerTrace::AddressRestartOutcome::kCancelledEpochOrOff:
        case NativePowerTrace::AddressRestartOutcome::kCancelledCommitOrEnable:
        case NativePowerTrace::AddressRestartOutcome::kCancelledIdentity:
        case NativePowerTrace::AddressRestartOutcome::kCancelledManual:
            ++nativeAddressRestartCancelledCount; break;
        default: break;
    }
}

void AirportItlwm::publishNativeAddressRestartMetrics()
{
    if (ml_at_interrupt_context()) return;
    setProperty("NativeAddressRestartStartedCount",
        nativeAddressRestartStartedCount, 32);
    setProperty("NativeAddressRestartSuppressedCount",
        nativeAddressRestartSuppressedCount, 32);
    setProperty("NativeAddressRestartCompletedCount",
        nativeAddressRestartCompletedCount, 32);
    setProperty("NativeAddressRestartCancelledCount",
        nativeAddressRestartCancelledCount, 32);
    setProperty("NativeAddressRestartExpiredCount",
        nativeAddressRestartExpiredCount, 32);
    setProperty("NativeAddressRestartLastOutcome",
        nativeAddressRestartLastOutcome, 32);
}

uint32_t AirportItlwm::observeNativePowerEvent(
    int event, NativePowerTrace::PowerIngressContext *context)
{
    if (context) *context = NativePowerTrace::PowerIngressContext {};
    // HAL ingress may run at interrupt level. Keep this path to counters,
    // bounded lock-protected metadata, and atomic state; never publish IOKit
    // properties or allocate here.
    if (event == ITL_TAHOE_EVT_DRIVER_READY) {
        __atomic_fetch_add(&nativePowerReadyCount, 1U, __ATOMIC_RELAXED);
        updateNativePowerFlags(0, 2U, true, context);
    } else if (event == ITL_TAHOE_EVT_DRIVER_STOPPED) {
        __atomic_fetch_add(&nativePowerStoppedCount, 1U, __ATOMIC_RELAXED);
        updateNativePowerFlags(2U, 0, false, context);
    } else if (event == ITL_TAHOE_EVT_RESET_BEGIN) {
        __atomic_fetch_add(&nativePowerResetCount, 1U, __ATOMIC_RELAXED);
        updateNativePowerFlags(2U, 0, false, context);
    } else {
        return __atomic_load_n(&nativePowerFlags, __ATOMIC_ACQUIRE);
    }
    __atomic_store_n(&nativePowerLastEvent, uint32_t(event), __ATOMIC_RELEASE);
    beginNativeControlTrace(NativePowerTrace::Operation::kHalEvent,
        NativePowerTrace::Phase::kDriverEvent, uint32_t(event), 0);
    return __atomic_load_n(&nativePowerFlags, __ATOMIC_ACQUIRE);
}

uint32_t AirportItlwm::beginNativeControlTrace(
    NativePowerTrace::Operation operation, NativePowerTrace::Phase phase,
    uint32_t detail, int32_t result, uint32_t auxiliary)
{
    IOSimpleLock *traceLock = nativePowerTraceLock;
    if (!traceLock) return 0;

    uint32_t powerFlags = __atomic_load_n(&nativePowerFlags, __ATOMIC_ACQUIRE);
    uint64_t revision = UINT64_MAX;
    nativePowerStateSnapshot(&powerFlags, &revision);
    uint32_t interfaceFlags = 0;
    if (_fWorkloop && _fWorkloop->inGate() && fHalService &&
        !__atomic_load_n(&nativePowerStopping, __ATOMIC_ACQUIRE))
        interfaceFlags = fHalService->get80211Controller()->ic_if.if_flags &
            (IFF_UP | IFF_RUNNING);
    const uint32_t epoch = __atomic_load_n(&nativePowerEpoch, __ATOMIC_ACQUIRE);
    const uint64_t monotonicNs = nativePowerUptimeNanoseconds();

    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(traceLock);
    const uint32_t callId = nativePowerTrace.begin(operation, phase,
        monotonicNs, epoch, powerFlags, interfaceFlags,
        revision, detail, result, auxiliary);
    IOSimpleLockUnlockEnableInterrupt(traceLock, irq);
    return callId;
}

void AirportItlwm::recordNativeControlTrace(
    uint32_t callId, NativePowerTrace::Operation operation,
    NativePowerTrace::Phase phase, uint32_t detail, int32_t result,
    uint32_t auxiliary)
{
    IOSimpleLock *traceLock = nativePowerTraceLock;
    if (!traceLock || !callId) return;

    uint32_t powerFlags = __atomic_load_n(&nativePowerFlags, __ATOMIC_ACQUIRE);
    uint64_t revision = UINT64_MAX;
    nativePowerStateSnapshot(&powerFlags, &revision);
    uint32_t interfaceFlags = 0;
    if (_fWorkloop && _fWorkloop->inGate() && fHalService &&
        !__atomic_load_n(&nativePowerStopping, __ATOMIC_ACQUIRE))
        interfaceFlags = fHalService->get80211Controller()->ic_if.if_flags &
            (IFF_UP | IFF_RUNNING);
    const uint32_t epoch = __atomic_load_n(&nativePowerEpoch, __ATOMIC_ACQUIRE);
    const uint64_t monotonicNs = nativePowerUptimeNanoseconds();

    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(traceLock);
    nativePowerTrace.record(callId, operation, phase,
        monotonicNs, epoch, powerFlags, interfaceFlags,
        revision, detail, result, auxiliary);
    IOSimpleLockUnlockEnableInterrupt(traceLock, irq);
}

void AirportItlwm::publishNativePowerTrace()
{
    if (ml_at_interrupt_context()) return;
    IOSimpleLock *traceLock = nativePowerTraceLock;
    if (!traceLock) return;

    NativePowerTrace::Snapshot snapshot {};
    uint32_t sequence = 0;
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(traceLock);
    sequence = nativePowerTrace.sequence();
    if (sequence == __atomic_load_n(&nativePowerTracePublishedSequence,
                                     __ATOMIC_RELAXED)) {
        IOSimpleLockUnlockEnableInterrupt(traceLock, irq);
        return;
    }
    nativePowerTrace.snapshot(&snapshot);
    IOSimpleLockUnlockEnableInterrupt(traceLock, irq);

    OSData *data = OSData::withBytes(&snapshot, sizeof(snapshot));
    if (!data) return;
    if (setProperty("NativePowerTrace", data)) {
        setProperty("NativePowerTraceSchema", NativePowerTrace::kSchemaVersion, 32);
        setProperty("NativePowerTraceSequence", sequence, 32);
        __atomic_store_n(&nativePowerTracePublishedSequence, sequence, __ATOMIC_RELEASE);
    }
    data->release();
}

bool AirportItlwm::postNativePowerChangedIfNeeded()
{
    if (ml_at_interrupt_context() || !fNetIf) return false;
    uint32_t powerFlags = 0;
    uint64_t revision = 0;
    if (!nativePowerStateSnapshot(&powerFlags, &revision)) return false;
    const uint32_t ready = (powerFlags & 2U) ? 1U : 0U;
    if (!nativePowerNotificationState.changed(ready, revision)) return false;

    const uint32_t callId = beginNativeControlTrace(
        NativePowerTrace::Operation::kHalEvent,
        NativePowerTrace::Phase::kNotificationCall, ready, 0);
    // POWER_CHANGED carries no state payload; consumers query GET_POWER. This
    // records only that the call was made, not an OS acknowledgement.
    fNetIf->postMessage(APPLE80211_M_POWER_CHANGED, nullptr, 0, true);
    nativePowerNotificationState.didPost(ready, revision);
    recordNativeControlTrace(callId, NativePowerTrace::Operation::kHalEvent,
        NativePowerTrace::Phase::kCallEnd, ready, 0);
    return true;
}

void AirportItlwm::publishNativePowerState()
{
    if (ml_at_interrupt_context()) return;
    uint32_t powerFlags = __atomic_load_n(&nativePowerFlags, __ATOMIC_ACQUIRE);
    uint64_t revision = UINT64_MAX;
    const bool stableState = nativePowerStateSnapshot(&powerFlags, &revision);
    ItlHalService *hal = nullptr;
    IOSimpleLock *stateLock = nativePowerStateLock;
    if (stateLock) {
        const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(stateLock);
        hal = fHalService;
        // Retain while the teardown path is excluded by this same lock. Any
        // diagnostics below run unlocked, and releaseNativePowerHAL can then
        // drop the controller's owner reference without racing this snapshot.
        if (hal) hal->retain();
        IOSimpleLockUnlockEnableInterrupt(stateLock, irq);
    }
    setProperty("NativePowerGetCount", __atomic_load_n(&nativePowerGetCount, __ATOMIC_RELAXED), 32);
    setProperty("NativePowerSetCount", __atomic_load_n(&nativePowerSetCount, __ATOMIC_RELAXED), 32);
    setProperty("NativePowerRequested", powerFlags & 1U, 32);
    setProperty("NativePowerReady", (powerFlags >> 1) & 1U, 32);
    setProperty("NativePowerReadyTransitionRevision",
        stableState ? revision : UINT64_MAX, 64);
    setProperty("NativePowerLastResult", __atomic_load_n(&nativePowerLastResult, __ATOMIC_ACQUIRE), 32);
    setProperty("NativePowerLastEvent", __atomic_load_n(&nativePowerLastEvent, __ATOMIC_ACQUIRE), 32);
    setProperty("NativePowerReadyCount", __atomic_load_n(&nativePowerReadyCount, __ATOMIC_RELAXED), 32);
    setProperty("NativePowerStoppedCount", __atomic_load_n(&nativePowerStoppedCount, __ATOMIC_RELAXED), 32);
    setProperty("NativePowerResetCount", __atomic_load_n(&nativePowerResetCount, __ATOMIC_RELAXED), 32);
    setProperty("NativePowerOffAttempts", __atomic_load_n(&nativePowerOffAttempts, __ATOMIC_RELAXED), 32);
    setProperty("NativePowerOffRetries", __atomic_load_n(&nativePowerOffRetries, __ATOMIC_RELAXED), 32);
    setProperty("NativePowerOffResult", __atomic_load_n(&nativePowerOffResult, __ATOMIC_ACQUIRE), 32);
    setProperty("NativePowerOffPending",
        __atomic_load_n(&nativePowerOffPending, __ATOMIC_ACQUIRE) ? 1U : 0U, 32);
    if (hal) {
        auto ic = hal->get80211Controller();
        if (ic) {
            setProperty("NativePowerHALFlags",
                uint32_t(ic->ic_if.if_flags & (IFF_UP | IFF_RUNNING)), 32);
            setProperty("NativePowerInitStage", ic->ic_tahoe_init_stage, 32);
            setProperty("NativePowerInitError", uint32_t(ic->ic_tahoe_init_error), 32);
            if (ic->ic_tahoe_scan_state)
                setProperty("NativePowerScanPhase", ic->ic_tahoe_scan_state(ic), 32);
        }
        hal->release();
    } else {
        setProperty("NativePowerHALFlags", uint64_t(0), 32);
    }
    publishNativePowerTrace();
}

IOReturn AirportItlwm::nativePowerStopAction(OSObject *owner, void *,
    void *, void *, void *)
{
    auto self = OSDynamicCast(AirportItlwm, owner);
    if (!self || !_fWorkloop || !_fWorkloop->inGate() ||
        !self->fHalService ||
        !__atomic_load_n(&self->nativePowerStopping, __ATOMIC_ACQUIRE))
        return kIOReturnNotReady;

    // This action is the final requested-state/epoch writer for service stop.
    // Hardware disable remains in stop() after the gate action, exactly once.
    self->updateNativePowerFlags(1U, 0);
    (void)self->advanceNativePowerEpoch(false);
    __atomic_store_n(&self->nativePowerOffPending, false, __ATOMIC_RELEASE);
    self->wakeNativePowerWaiters();
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::nativePowerAction(OSObject *owner, void *argument,
    void *, void *, void *)
{
    auto self = OSDynamicCast(AirportItlwm, owner);
    auto context = static_cast<const NativePowerActionContext *>(argument);
    auto request = context ? &context->request : nullptr;
    if (!self || !request || !_fWorkloop || !_fWorkloop->inGate() ||
        _fWorkloop->onThread() || !self->fHalService || !self->bsdInterface ||
        !self->fNetIf || self->fNetIf->getControllerWorkQueue() != _fWorkloop ||
        !self->watchdogTimer) return kIOReturnNotReady;
    if (__atomic_load_n(&self->nativePowerStopping, __ATOMIC_ACQUIRE))
        return kIOReturnNotReady;
    const uint32_t traceCallId = context->traceCallId;
    self->recordNativeControlTrace(traceCallId,
        NativePowerTrace::Operation::kPowerSet,
        NativePowerTrace::Phase::kNativeActionBegin,
        request->power_state[0] ? 1U : 0U, 0);
    auto ifp = &self->fHalService->get80211Controller()->ic_if;
    const bool on = request->power_state[0] != 0;
    if (on) {
        // A native SET_POWER caller expects completion, not just admission of
        // the asynchronous Intel init task. Sleep releases the same real gate.
        const auto flags = ifp->if_flags & (IFF_UP | IFF_RUNNING);
        if (__atomic_load_n(&self->nativePowerOffPending, __ATOMIC_ACQUIRE)) {
            // RESET_BEGIN can clear the real READY bit before a pending stop
            // retries. Let this newer On own policy/epoch, then wait for a real
            // READY event if the interface is still activating.
            __atomic_store_n(&self->nativePowerOffPending, false, __ATOMIC_RELEASE);
            const uint32_t previous = self->updateNativePowerFlags(0, 1U);
            const uint32_t epoch = self->advanceNativePowerEpoch(true);
            self->wakeNativePowerWaiters();
            if (flags == (IFF_UP | IFF_RUNNING) && (previous & 2U))
                return kIOReturnSuccess;
            if (flags & IFF_UP) return self->waitForNativePower(epoch, traceCallId);
            if (flags & IFF_RUNNING) return kIOReturnBusy;
            // The radio reached fully down while the action gate was yielded;
            // continue through the ordinary enable path below.
        }
        if (flags) {
            if (flags == (IFF_UP | IFF_RUNNING) &&
                (__atomic_load_n(&self->nativePowerFlags, __ATOMIC_ACQUIRE) & 2U)) {
                const uint32_t previous = self->updateNativePowerFlags(0, 1U);
                // An On request can arrive while a bounded Off retry sleeps
                // outside this gate. Advance the serialized epoch and wake it
                // so it cannot stop a radio that the caller just re-enabled.
                if (!(previous & 1U)) {
                    (void)self->advanceNativePowerEpoch(true);
                    self->wakeNativePowerWaiters();
                }
                return kIOReturnSuccess;
            }
            if ((flags & IFF_UP) &&
                (__atomic_load_n(&self->nativePowerFlags, __ATOMIC_ACQUIRE) & 1U))
                return self->waitForNativePower(
                    __atomic_load_n(&self->nativePowerEpoch, __ATOMIC_ACQUIRE),
                    traceCallId);
            return kIOReturnBusy;
        }
        self->updateNativePowerFlags(2U, 1U);
        __atomic_store_n(&self->nativePowerOffPending, false, __ATOMIC_RELEASE);
        const uint32_t epoch = self->advanceNativePowerEpoch(true);
        self->recordNativeControlTrace(traceCallId,
            NativePowerTrace::Operation::kPowerSet,
            NativePowerTrace::Phase::kEnableBegin, epoch, 0);
        const IOReturn result = self->enableAdapter(self->bsdInterface);
        if (result != kIOReturnSuccess) {
            self->updateNativePowerFlags(3U, 0);
            self->fHalService->setNativePowerRequestState(epoch, false);
        }
        self->recordNativeControlTrace(traceCallId,
            NativePowerTrace::Operation::kPowerSet,
            NativePowerTrace::Phase::kEnableEnd,
            0, result);
        return result == kIOReturnSuccess
            ? self->waitForNativePower(epoch, traceCallId) : result;
    }
    const uint32_t previousPolicy = self->updateNativePowerFlags(1U, 0);
    const uint32_t epoch = self->advanceNativePowerEpoch(false);
    __atomic_store_n(&self->nativePowerOffPending, true, __ATOMIC_RELEASE);
    __atomic_store_n(&self->nativePowerOffAttempts, 0U, __ATOMIC_RELAXED);
    __atomic_store_n(&self->nativePowerOffRetries, 0U, __ATOMIC_RELAXED);
    __atomic_store_n(&self->nativePowerOffResult, uint32_t(kIOReturnNotReady), __ATOMIC_RELEASE);
    const IOReturn stopped = self->disableAdapterWithRetry(epoch, traceCallId);
    const uint32_t finalIfFlags = ifp->if_flags & (IFF_UP | IFF_RUNNING);
    const IOReturn stopResult = stopped == kIOReturnSuccess && finalIfFlags
        ? kIOReturnNotReady : stopped;
    const bool currentEpoch = epoch == __atomic_load_n(
        &self->nativePowerEpoch, __ATOMIC_ACQUIRE);
    if (currentEpoch) {
        if (stopResult != kIOReturnSuccess && (previousPolicy & 1U) && finalIfFlags &&
            !(__atomic_load_n(&self->nativePowerFlags, __ATOMIC_ACQUIRE) & 1U)) {
            self->updateNativePowerFlags(0, 1U);
            self->fHalService->setNativePowerRequestState(epoch, true);
        }
        __atomic_store_n(&self->nativePowerOffPending, false, __ATOMIC_RELEASE);
        __atomic_store_n(&self->nativePowerOffResult, uint32_t(stopResult), __ATOMIC_RELEASE);
    }
    self->wakeNativePowerWaiters();
    if (stopResult != kIOReturnSuccess) return stopResult;
    self->updateNativePowerFlags(2U, 0);
    self->recordNativeControlTrace(traceCallId,
        NativePowerTrace::Operation::kPowerSet,
        NativePowerTrace::Phase::kNativeActionEnd, 0, stopResult);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::disableAdapterWithRetry(uint32_t epoch, uint32_t traceCallId)
{
    // iwx_stop may return Busy while a net80211 state task is active. Each
    // commandSleep releases this gate so the worker and its interrupt path can
    // progress. The retry deadline is a caller wait budget, not a proven upper
    // bound on every possible state-task command sequence.
    constexpr unsigned kRetryDelayMilliseconds = 25;
    constexpr unsigned kRetryWindowMilliseconds = 12U * 1000U;
    constexpr unsigned kRetryCount =
        1U + kRetryWindowMilliseconds / kRetryDelayMilliseconds;
    constexpr uint64_t kNanosecondsPerMillisecond = 1000000ULL;
    constexpr uint64_t kRetryDelayNanoseconds =
        uint64_t(kRetryDelayMilliseconds) * kNanosecondsPerMillisecond;
    constexpr uint64_t kRetryWindowNanoseconds =
        uint64_t(kRetryWindowMilliseconds) * kNanosecondsPerMillisecond;
    const uint64_t retryDeadlineNanoseconds =
        nativePowerUptimeNanoseconds() + kRetryWindowNanoseconds;
    recordNativeControlTrace(traceCallId,
        NativePowerTrace::Operation::kPowerSet,
        NativePowerTrace::Phase::kDisableBegin,
        kRetryWindowMilliseconds, 0);

    for (unsigned attempt = 0; attempt < kRetryCount; ++attempt) {
        const uint32_t policy = __atomic_load_n(&nativePowerFlags, __ATOMIC_ACQUIRE);
        if (epoch != __atomic_load_n(&nativePowerEpoch, __ATOMIC_ACQUIRE) ||
            (policy & 1U)) {
            recordNativeControlTrace(traceCallId,
                NativePowerTrace::Operation::kPowerSet,
                NativePowerTrace::Phase::kDisableEnd, attempt,
                kIOReturnAborted);
            return kIOReturnAborted;
        }
        if (nativePowerUptimeNanoseconds() >= retryDeadlineNanoseconds) {
            recordNativeControlTrace(traceCallId,
                NativePowerTrace::Operation::kPowerSet,
                NativePowerTrace::Phase::kTimeout, attempt, kIOReturnBusy);
            return kIOReturnBusy;
        }

        __atomic_fetch_add(&nativePowerOffAttempts, 1U, __ATOMIC_RELAXED);
        const IOReturn result = disableAdapter(bsdInterface);
        if (result != kIOReturnBusy) {
            recordNativeControlTrace(traceCallId,
                NativePowerTrace::Operation::kPowerSet,
                NativePowerTrace::Phase::kDisableEnd, attempt + 1U, result);
            return result;
        }
        __atomic_fetch_add(&nativePowerOffRetries, 1U, __ATOMIC_RELAXED);
        if (attempt + 1U == kRetryCount) {
            recordNativeControlTrace(traceCallId,
                NativePowerTrace::Operation::kPowerSet,
                NativePowerTrace::Phase::kDisableEnd, attempt + 1U,
                kIOReturnBusy);
            return kIOReturnBusy;
        }

        const uint64_t nowNanoseconds = nativePowerUptimeNanoseconds();
        if (nowNanoseconds >= retryDeadlineNanoseconds) {
            recordNativeControlTrace(traceCallId,
                NativePowerTrace::Operation::kPowerSet,
                NativePowerTrace::Phase::kTimeout, attempt + 1U, kIOReturnBusy);
            return kIOReturnBusy;
        }
        const uint64_t remainingNanoseconds =
            retryDeadlineNanoseconds - nowNanoseconds;
        const uint64_t sleepNanoseconds = remainingNanoseconds < kRetryDelayNanoseconds
            ? remainingNanoseconds : kRetryDelayNanoseconds;
        const uint64_t nextRetryNanoseconds = nowNanoseconds + sleepNanoseconds;

        AbsoluteTime deadline;
        clock_interval_to_deadline(static_cast<uint32_t>(sleepNanoseconds),
                                   kNanosecondScale, &deadline);
        for (;;) {
            const IOReturn wake = _fCommandGate->commandSleep(
                &nativePowerFlags, deadline, THREAD_INTERRUPTIBLE);
            if (wake != THREAD_AWAKENED && wake != THREAD_TIMED_OUT) {
                recordNativeControlTrace(traceCallId,
                    NativePowerTrace::Operation::kPowerSet,
                    NativePowerTrace::Phase::kDisableEnd, attempt + 1U,
                    kIOReturnAborted);
                return kIOReturnAborted;
            }
            const uint32_t wakePolicy = __atomic_load_n(
                &nativePowerFlags, __ATOMIC_ACQUIRE);
            if (epoch != __atomic_load_n(&nativePowerEpoch, __ATOMIC_ACQUIRE) ||
                (wakePolicy & 1U)) {
                recordNativeControlTrace(traceCallId,
                    NativePowerTrace::Operation::kPowerSet,
                    NativePowerTrace::Phase::kDisableEnd, attempt + 1U,
                    kIOReturnAborted);
                return kIOReturnAborted;
            }
            // Power/event notifications can wake commandSleep before the
            // retry interval ends. Keep sleeping to this deadline instead of
            // burning an off attempt on every early wake.
            if (nativePowerUptimeNanoseconds() >= nextRetryNanoseconds)
                break;
        }
    }
    recordNativeControlTrace(traceCallId,
        NativePowerTrace::Operation::kPowerSet,
        NativePowerTrace::Phase::kDisableEnd, kRetryCount, kIOReturnBusy);
    return kIOReturnBusy;
}

IOReturn AirportItlwm::waitForNativePower(uint32_t epoch, uint32_t traceCallId)
{
    constexpr unsigned kWaitSliceMilliseconds = 50;
    AbsoluteTime deadline;
    clock_interval_to_deadline(12, kSecondScale, &deadline);
    recordNativeControlTrace(traceCallId,
        NativePowerTrace::Operation::kPowerSet,
        NativePowerTrace::Phase::kWaitBegin, 12000, 0);
    for (;;) {
        const uint32_t policy = __atomic_load_n(&nativePowerFlags, __ATOMIC_ACQUIRE);
        if (__atomic_load_n(&nativePowerStopping, __ATOMIC_ACQUIRE) ||
            epoch != __atomic_load_n(&nativePowerEpoch, __ATOMIC_ACQUIRE) ||
            !(policy & 1U)) {
            recordNativeControlTrace(traceCallId,
                NativePowerTrace::Operation::kPowerSet,
                NativePowerTrace::Phase::kWaitEnd, 0, kIOReturnAborted);
            return kIOReturnAborted;
        }
        const auto flags = fHalService->get80211Controller()->ic_if.if_flags & (IFF_UP | IFF_RUNNING);
        if ((policy & 2U) && flags == (IFF_UP | IFF_RUNNING)) {
            recordNativeControlTrace(traceCallId,
                NativePowerTrace::Operation::kPowerSet,
                NativePowerTrace::Phase::kWaitEnd, flags, kIOReturnSuccess);
            return kIOReturnSuccess;
        }
        if (!(flags & IFF_UP)) {
            recordNativeControlTrace(traceCallId,
                NativePowerTrace::Operation::kPowerSet,
                NativePowerTrace::Phase::kWaitEnd, flags, kIOReturnError);
            return kIOReturnError;
        }

        AbsoluteTime now;
        clock_get_uptime(&now);
        if (now >= deadline) {
            recordNativeControlTrace(traceCallId,
                NativePowerTrace::Operation::kPowerSet,
                NativePowerTrace::Phase::kTimeout, 12000, kIOReturnTimeout);
            return kIOReturnTimeout;
        }

        // READY may update the atomics without waking this gate waiter. Poll
        // in short slices, keeping one absolute deadline for the whole request.
        AbsoluteTime sliceDeadline;
        clock_interval_to_deadline(kWaitSliceMilliseconds, kMillisecondScale,
                                   &sliceDeadline);
        if (sliceDeadline > deadline) sliceDeadline = deadline;
        const IOReturn wake = _fCommandGate->commandSleep(
            &nativePowerFlags, sliceDeadline, THREAD_INTERRUPTIBLE);
        if (wake != THREAD_AWAKENED && wake != THREAD_TIMED_OUT) {
            recordNativeControlTrace(traceCallId,
                NativePowerTrace::Operation::kPowerSet,
                NativePowerTrace::Phase::kWaitEnd, 0, kIOReturnAborted);
            return kIOReturnAborted;
        }
        // Both an event wake and a slice timeout return to the state checks at
        // the top of the loop before the total deadline can report a timeout.
    }
}

void AirportItlwm::wakeNativePowerWaiters()
{
    if (_fCommandGate && _fWorkloop && _fWorkloop->inGate())
        _fCommandGate->commandWakeup(&nativePowerFlags, false);
}
#endif

IOReturn AirportItlwm::
setPOWER(OSObject *object,
                         struct apple80211_power_data *pd)
{
#ifdef AIRPORT_TAHOE
    __atomic_fetch_add(&nativePowerSetCount, 1U, __ATOMIC_RELAXED);
    IOReturn result = kIOReturnBadArgument;
    uint32_t traceCallId = 0;
    if (pd && pd->version == APPLE80211_VERSION && pd->num_radios > 0 &&
        pd->num_radios <= APPLE80211_MAX_RADIO) {
        // Intel has one radio policy. TX-only/RX-only and mixed requests are
        // unsupported rather than silently being treated as ordinary On.
        result = kIOReturnUnsupported;
        bool uniform = pd->power_state[0] <= APPLE80211_POWER_ON;
        for (unsigned i = 1; i < pd->num_radios; ++i)
            uniform = uniform && pd->power_state[i] == pd->power_state[0];
        if (uniform) {
            result = kIOReturnNotReady;
            if (!ml_at_interrupt_context() && _fCommandGate && _fWorkloop &&
                !_fWorkloop->onThread()) {
                const apple80211_power_data request = *pd;
                traceCallId = beginNativeControlTrace(
                    NativePowerTrace::Operation::kPowerSet,
                    NativePowerTrace::Phase::kCallBegin,
                    request.power_state[0] ? 1U : 0U, 0);
                NativePowerActionContext context {request, traceCallId};
                result = _fCommandGate->runAction(nativePowerAction,
                    &context);
            }
        }
    }
    recordNativeControlTrace(traceCallId,
        NativePowerTrace::Operation::kPowerSet,
        NativePowerTrace::Phase::kCallEnd,
        pd && pd->num_radios ? pd->power_state[0] : UINT32_MAX,
        result);
    __atomic_store_n(&nativePowerLastResult, uint32_t(result), __ATOMIC_RELEASE);
    publishNativePowerState();
    return result;
#else
    if (!pd)
        return kIOReturnError;
    IOLog("itlwm: setPOWER: num_radios[%d]  power_state(0:%u  1:%u  2:%u  3:%u)\n", pd->num_radios, pd->power_state[0], pd->power_state[1], pd->power_state[2], pd->power_state[3]);
    if (pd->num_radios > 0) {
        bool isRunning = (fHalService->get80211Controller()->ic_ac.ac_if.if_flags & (IFF_UP | IFF_RUNNING)) != 0;
        if (pd->power_state[0] == 0) {
            changePowerStateToPriv(1);
            if (isRunning) {
                net80211_ifstats(fHalService->get80211Controller());
                disableAdapter(bsdInterface);
            }
        } else {
            changePowerStateToPriv(2);
            if (!isRunning)
                enableAdapter(bsdInterface);
        }
        power_state = (pd->power_state[0]);
    }
    
    return kIOReturnSuccess;
#endif
}

SInt32 AirportItlwm::apple80211_ioctl(IO80211SkywalkInterface *interface,unsigned long cmd,void *data, bool b1, bool b2)
{
    if (!ml_at_interrupt_context())
        XYLog("%s cmd: %s b1: %d b2: %d\n", __FUNCTION__, convertApple80211IOCTLToString((unsigned int)cmd), b1, b2);
#ifdef AIRPORT_TAHOE
    return kIOReturnUnsupported; // Native WCL dispatches typed InfraProtocol slots.
#else
    return super::apple80211_ioctl(interface, cmd, data, b1, b2);
#endif
}

SInt32 AirportItlwm::apple80211SkywalkRequest(UInt request,int cmd,IO80211SkywalkInterface *interface,void *data)
{
    if (!ml_at_interrupt_context())
        XYLog("%s 1 cmd: %s request: %d\n", __FUNCTION__, convertApple80211IOCTLToString(cmd), request);
    return kIOReturnUnsupported;
}

SInt32 AirportItlwm::apple80211SkywalkRequest(UInt request,int cmd,IO80211SkywalkInterface *interface,void *data,void *)
{
    if (!ml_at_interrupt_context())
        XYLog("%s 2 cmd: %s request: %d\n", __FUNCTION__, convertApple80211IOCTLToString(cmd), request);
    return kIOReturnUnsupported;
}

IOReturn AirportItlwm::enableAdapter(IONetworkInterface *netif)
{
#ifdef AIRPORT_TAHOE
    nativeActivationAttempted = true;
#endif
    IOReturn result = fHalService->enable(netif);
#ifdef AIRPORT_TAHOE
    if (result != kIOReturnSuccess) return result;
#endif
    watchdogTimer->setTimeoutMS(kWatchDogTimerPeriod);
    watchdogTimer->enable();
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::disableAdapter(IONetworkInterface *netif)
{
#ifdef AIRPORT_TAHOE
    // A state task can still own a firmware command. A rejected stop keeps
    // the live watchdog/LQM stream running and must not masquerade as Off.
    const IOReturn result = fHalService->disable(netif);
    if (result != kIOReturnSuccess) return result;
#endif
    watchdogTimer->cancelTimeout();
    watchdogTimer->disable();
#ifndef AIRPORT_TAHOE
    fHalService->disable(netif);
#endif
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
tsleepHandler(OSObject* owner, void* arg0, void* arg1, void* arg2, void* arg3)
{
    AirportItlwm* dev = OSDynamicCast(AirportItlwm, owner);
    if (dev == 0)
        return kIOReturnError;
    
    if (arg1 == 0) {
        if (_fCommandGate->commandSleep(arg0, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    } else {
        AbsoluteTime deadline;
        clock_interval_to_deadline((*(int*)arg1), kNanosecondScale, reinterpret_cast<uint64_t*> (&deadline));
        if (_fCommandGate->commandSleep(arg0, deadline, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    }
}

bool AirportItlwm::initPCIPowerManagment(IOPCIDevice *provider)
{
    UInt16 reg16;

    reg16 = provider->configRead16(kIOPCIConfigCommand);

    reg16 |= ( kIOPCICommandBusMaster       |
               kIOPCICommandMemorySpace     |
               kIOPCICommandMemWrInvalidate );

    reg16 &= ~kIOPCICommandIOSpace;  // disable I/O space

    provider->configWrite16( kIOPCIConfigCommand, reg16 );
    provider->findPCICapability(kIOPCIPowerManagementCapability,
                                &pmPCICapPtr);
    if (pmPCICapPtr) {
        UInt16 pciPMCReg = provider->configRead32( pmPCICapPtr ) >> 16;
        if (pciPMCReg & kPCIPMCPMESupportFromD3Cold)
            magicPacketSupported = true;
        provider->configWrite16((pmPCICapPtr + 4), 0x8000 );
        IOSleep(10);
    }
    return true;
}

static IOPMPowerState powerStateArray[kPowerStateCount] =
{
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, kIOPMDeviceUsable, kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0}
};

void AirportItlwm::unregistPM()
{
    if (powerOffThreadCall) {
#ifdef AIRPORT_TAHOE
        const bool cancelled = thread_call_cancel_wait(powerOffThreadCall);
        if (cancelled) {
            if (pmPolicyMaker)
                pmPolicyMaker->acknowledgeSetPowerState();
            release(); // balance the retain paired with the cancelled callout
            // A successful cancel_wait only retired that pending instance.
            // With enqueue admission closed, the second call must drain the
            // running invocation; if it instead cancels another queued one,
            // balance it and keep the handle for a later teardown retry.
            const bool cancelledAfterDrain =
                thread_call_cancel_wait(powerOffThreadCall);
            if (cancelledAfterDrain) {
                if (pmPolicyMaker)
                    pmPolicyMaker->acknowledgeSetPowerState();
                release();
                return;
            }
        }
#endif
        if (thread_call_free(powerOffThreadCall))
            powerOffThreadCall = NULL;
    }
    if (powerOnThreadCall) {
#ifdef AIRPORT_TAHOE
        const bool cancelled = thread_call_cancel_wait(powerOnThreadCall);
        if (cancelled) {
            if (pmPolicyMaker)
                pmPolicyMaker->acknowledgeSetPowerState();
            release(); // balance the retain paired with the cancelled callout
            const bool cancelledAfterDrain =
                thread_call_cancel_wait(powerOnThreadCall);
            if (cancelledAfterDrain) {
                if (pmPolicyMaker)
                    pmPolicyMaker->acknowledgeSetPowerState();
                release();
                return;
            }
        }
#endif
        if (thread_call_free(powerOnThreadCall))
            powerOnThreadCall = NULL;
    }
}

bool AirportItlwm::retireNativePMPowerCallouts()
{
    // cancel_wait can wait for a PM worker that is itself waiting for this
    // command gate. Require the stop latch and an off-gate caller before drain.
    if (!__atomic_load_n(&nativePowerStopping, __ATOMIC_ACQUIRE))
        return false;
    if (!powerOffThreadCall && !powerOnThreadCall) return true;
    if (!_fWorkloop || _fWorkloop->inGate()) return false;
    unregistPM();
    return powerOffThreadCall == nullptr && powerOnThreadCall == nullptr;
}

IOReturn AirportItlwm::setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker)
{
    IOReturn result = IOPMAckImplied;
#ifdef AIRPORT_TAHOE
    IOSimpleLock *stateLock = nativePowerStateLock;
    if (!stateLock) return result;
    const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(stateLock);
    if (__atomic_load_n(&nativePowerStopping, __ATOMIC_ACQUIRE)) {
        IOSimpleLockUnlockEnableInterrupt(stateLock, irq);
        return result;
    }
    if ((__atomic_load_n(&nativePowerPMRequestValid, __ATOMIC_ACQUIRE) &&
         __atomic_load_n(&nativePowerPMRequestedState, __ATOMIC_RELAXED) ==
             powerStateOrdinal) ||
        (powerStateOrdinal != kPowerStateOff &&
         powerStateOrdinal != kPowerStateOn)) {
        IOSimpleLockUnlockEnableInterrupt(stateLock, irq);
        return result;
    }
    thread_call_t call = powerStateOrdinal == kPowerStateOff
        ? powerOffThreadCall : powerOnThreadCall;
    if (!call) {
        IOSimpleLockUnlockEnableInterrupt(stateLock, irq);
        return result;
    }
    uint32_t requestEpoch = __atomic_load_n(
        &nativePowerPMRequestEpoch, __ATOMIC_RELAXED) + 1U;
    if (requestEpoch == 0) requestEpoch = 1U;
    __atomic_store_n(&nativePowerPMRequestEpoch, requestEpoch, __ATOMIC_RELEASE);
    __atomic_store_n(&nativePowerPMRequestedState,
        uint32_t(powerStateOrdinal), __ATOMIC_RELAXED);
    if (powerStateOrdinal == kPowerStateOff)
        __atomic_store_n(&nativePowerPMOffCalloutEpoch,
            requestEpoch, __ATOMIC_RELAXED);
    else
        __atomic_store_n(&nativePowerPMOnCalloutEpoch,
            requestEpoch, __ATOMIC_RELAXED);
    __atomic_store_n(&nativePowerPMRequestValid, true, __ATOMIC_RELEASE);
    retain();
    if (thread_call_enter(call))
        release();
    result = 5000000;
    IOSimpleLockUnlockEnableInterrupt(stateLock, irq);
#else
    if (__atomic_load_n(&pmPowerState, __ATOMIC_ACQUIRE) == powerStateOrdinal)
        return result;
    switch (powerStateOrdinal) {
        case kPowerStateOff:
            if (powerOffThreadCall) {
                retain();
                if (thread_call_enter(powerOffThreadCall))
                    release();
                result = 5000000;
            }
            break;
        case kPowerStateOn:
            if (powerOnThreadCall) {
                retain();
                if (thread_call_enter(powerOnThreadCall))
                    release();
                result = 5000000;
            }
            break;
            
        default:
            break;
    }
#endif
    return result;
}

IOReturn AirportItlwm::setWakeOnMagicPacket(bool active)
{
    magicPacketEnabled = active;
    return kIOReturnSuccess;
}

static IOReturn dispatchSetPowerStateOff(OSObject *owner, void *,
    void *, void *, void *)
{
    auto self = OSDynamicCast(AirportItlwm, owner);
    if (!self) return kIOReturnBadArgument;
    self->setPowerStateOff();
    self->release();
    return kIOReturnSuccess;
}

static IOReturn dispatchSetPowerStateOn(OSObject *owner, void *,
    void *, void *, void *)
{
    auto self = OSDynamicCast(AirportItlwm, owner);
    if (!self) return kIOReturnBadArgument;
    self->setPowerStateOn();
    self->release();
    return kIOReturnSuccess;
}

static void handleSetPowerStateOff(thread_call_param_t param0,
                             thread_call_param_t)
{
    auto self = static_cast<AirportItlwm *>(param0);
    if (!self) return;
    auto gate = self->getCommandGate();
    const IOReturn result = gate
        ? gate->runAction(dispatchSetPowerStateOff, nullptr)
        : kIOReturnNotReady;
    if (result != kIOReturnSuccess) {
        if (self->pmPolicyMaker)
            self->pmPolicyMaker->acknowledgeSetPowerState();
        self->release();
    }
}

static void handleSetPowerStateOn(thread_call_param_t param0,
                            thread_call_param_t)
{
    auto self = static_cast<AirportItlwm *>(param0);
    if (!self) return;
    auto gate = self->getCommandGate();
    const IOReturn result = gate
        ? gate->runAction(dispatchSetPowerStateOn, nullptr)
        : kIOReturnNotReady;
    if (result != kIOReturnSuccess) {
        if (self->pmPolicyMaker)
            self->pmPolicyMaker->acknowledgeSetPowerState();
        self->release();
    }
}

IOReturn AirportItlwm::registerWithPolicyMaker(IOService *policyMaker)
{
    IOReturn ret;
    
    __atomic_store_n(&pmPowerState, kPowerStateOn, __ATOMIC_RELEASE);
#ifdef AIRPORT_TAHOE
    if (nativePowerStateLock) {
        const IOInterruptState irq = IOSimpleLockLockDisableInterrupt(
            nativePowerStateLock);
        __atomic_store_n(&nativePowerPMRequestEpoch, 1U, __ATOMIC_RELAXED);
        __atomic_store_n(&nativePowerPMRequestedState,
            uint32_t(kPowerStateOn), __ATOMIC_RELAXED);
        __atomic_store_n(&nativePowerPMOffCalloutEpoch, 0U, __ATOMIC_RELAXED);
        __atomic_store_n(&nativePowerPMOnCalloutEpoch, 1U, __ATOMIC_RELAXED);
        __atomic_store_n(&nativePowerPMRequestValid, true, __ATOMIC_RELEASE);
        IOSimpleLockUnlockEnableInterrupt(nativePowerStateLock, irq);
    }
#endif
    pmPolicyMaker = policyMaker;
    
    powerOffThreadCall = thread_call_allocate(
                                            (thread_call_func_t)handleSetPowerStateOff,
                                            (thread_call_param_t)this);
    powerOnThreadCall  = thread_call_allocate(
                                            (thread_call_func_t)handleSetPowerStateOn,
                                              (thread_call_param_t)this);
    ret = pmPolicyMaker->registerPowerDriver(this,
                                             powerStateArray,
                                             kPowerStateCount);
    return ret;
}

void AirportItlwm::setPowerStateOff()
{
    XYLog("%s\n", __FUNCTION__);
#ifdef AIRPORT_TAHOE
    const uint32_t pmEpoch = __atomic_load_n(
        &nativePowerPMOffCalloutEpoch, __ATOMIC_ACQUIRE);
    const uint32_t traceCallId = beginNativeControlTrace(
        NativePowerTrace::Operation::kSystemPower,
        NativePowerTrace::Phase::kSystemPowerBegin,
        uint32_t(NativePowerTrace::SystemPowerDetail::kSleep), 0, pmEpoch);
#endif
    IOReturn disableResult = kIOReturnNotReady;
#ifdef AIRPORT_TAHOE
    const bool pmRequestValid = __atomic_load_n(
        &nativePowerPMRequestValid, __ATOMIC_ACQUIRE);
    const uint32_t requestedState = __atomic_load_n(
        &nativePowerPMRequestedState, __ATOMIC_ACQUIRE);
    const bool stopping = __atomic_load_n(&nativePowerStopping,
                                          __ATOMIC_ACQUIRE);
    const bool supersededByNewerOn = pmRequestValid &&
        (requestedState != kPowerStateOff ||
         __atomic_load_n(&nativePowerPMRequestEpoch, __ATOMIC_ACQUIRE) !=
             pmEpoch);
    uint32_t outcome = stopping
        ? uint32_t(NativePowerTrace::SystemPowerDetail::kSleepStopping)
        : (supersededByNewerOn
            ? uint32_t(NativePowerTrace::SystemPowerDetail::kSleepSupersededByNewerOn)
            : uint32_t(NativePowerTrace::SystemPowerDetail::kSleep));
    if (stopping) {
        disableResult = kIOReturnNotReady;
    } else if (supersededByNewerOn) {
        disableResult = kIOReturnAborted;
    } else {
        __atomic_store_n(&pmPowerState, kPowerStateOff, __ATOMIC_RELEASE);
        disableResult = disableAdapter(bsdInterface);
    }
    const uint32_t finalPmEpoch = __atomic_load_n(
        &nativePowerPMRequestEpoch, __ATOMIC_ACQUIRE);
    const bool supersededDuringDisable = __atomic_load_n(
        &nativePowerPMRequestValid, __ATOMIC_ACQUIRE) &&
        (__atomic_load_n(&nativePowerPMRequestedState, __ATOMIC_ACQUIRE) !=
             kPowerStateOff || finalPmEpoch != pmEpoch);
    if (!stopping && supersededDuringDisable)
        outcome = uint32_t(
            NativePowerTrace::SystemPowerDetail::kSleepSupersededByNewerOn);
#else
    __atomic_store_n(&pmPowerState, kPowerStateOff, __ATOMIC_RELEASE);
    disableResult = disableAdapter(bsdInterface);
#endif
#ifdef AIRPORT_TAHOE
    recordNativeControlTrace(traceCallId,
        NativePowerTrace::Operation::kSystemPower,
        NativePowerTrace::Phase::kSystemPowerAdapterEnd,
        outcome, disableResult,
        __atomic_load_n(&nativePowerPMRequestEpoch, __ATOMIC_ACQUIRE));
#endif
    pmPolicyMaker->acknowledgeSetPowerState();
#ifdef AIRPORT_TAHOE
    recordNativeControlTrace(traceCallId,
        NativePowerTrace::Operation::kSystemPower,
        NativePowerTrace::Phase::kSystemPowerAck,
        uint32_t(NativePowerTrace::SystemPowerDetail::kSleep),
        kIOReturnSuccess, pmEpoch);
    publishNativePowerTrace();
#endif
}

void AirportItlwm::setPowerStateOn()
{
    XYLog("%s\n", __FUNCTION__);
#ifdef AIRPORT_TAHOE
    const uint32_t pmEpoch = __atomic_load_n(
        &nativePowerPMOnCalloutEpoch, __ATOMIC_ACQUIRE);
    const uint32_t traceCallId = beginNativeControlTrace(
        NativePowerTrace::Operation::kSystemPower,
        NativePowerTrace::Phase::kSystemPowerBegin,
        uint32_t(NativePowerTrace::SystemPowerDetail::kWake), 0, pmEpoch);
    // System sleep quiesces the HAL through disableAdapter(), which also
    // clears the BSD interface's IFF_UP bit. The system-power callback alone
    // does not guarantee that IO80211 will issue a second user Wi-Fi On
    // request after wake. Restore only an interface that is fully down while
    // the user's native Wi-Fi request is still On. In particular, an explicit
    // user Off remains authoritative across sleep.
    uint32_t outcome = uint32_t(
        NativePowerTrace::SystemPowerDetail::kWakeRequestedOff);
    IOReturn restoreResult = kIOReturnSuccess;
    const bool pmRequestValid = __atomic_load_n(
        &nativePowerPMRequestValid, __ATOMIC_ACQUIRE);
    const uint32_t pmRequestedState = __atomic_load_n(
        &nativePowerPMRequestedState, __ATOMIC_ACQUIRE);
    const bool supersededByNewerOff = pmRequestValid &&
        (pmRequestedState != kPowerStateOn ||
         __atomic_load_n(&nativePowerPMRequestEpoch, __ATOMIC_ACQUIRE) !=
             pmEpoch);
    const uint32_t requestedFlags = __atomic_load_n(
        &nativePowerFlags, __ATOMIC_ACQUIRE);
    const bool stopping = __atomic_load_n(&nativePowerStopping,
                                          __ATOMIC_ACQUIRE);
    if (supersededByNewerOff) {
        outcome = uint32_t(
            NativePowerTrace::SystemPowerDetail::kWakeSupersededByNewerOff);
        restoreResult = kIOReturnAborted;
    } else {
        // The OS PM request is awake even when user Wi-Fi remains Off.
        __atomic_store_n(&pmPowerState, kPowerStateOn, __ATOMIC_RELEASE);
    }
    if (supersededByNewerOff) {
        recordNativeControlTrace(traceCallId,
            NativePowerTrace::Operation::kSystemPower,
            NativePowerTrace::Phase::kWakeRestoreDecision,
            outcome, restoreResult, pmEpoch);
    } else if (!(requestedFlags & 1U)) {
        outcome = uint32_t(
            NativePowerTrace::SystemPowerDetail::kWakeRequestedOff);
        recordNativeControlTrace(traceCallId,
            NativePowerTrace::Operation::kSystemPower,
            NativePowerTrace::Phase::kWakeRestoreDecision,
            uint32_t(NativePowerTrace::SystemPowerDetail::kWakeRequestedOff),
            kIOReturnSuccess, pmEpoch);
    } else if (stopping) {
        outcome = uint32_t(
            NativePowerTrace::SystemPowerDetail::kWakeStopping);
        restoreResult = kIOReturnNotReady;
        recordNativeControlTrace(traceCallId,
            NativePowerTrace::Operation::kSystemPower,
            NativePowerTrace::Phase::kWakeRestoreDecision,
            uint32_t(NativePowerTrace::SystemPowerDetail::kWakeStopping),
            kIOReturnNotReady, pmEpoch);
    } else if (!fHalService) {
        outcome = uint32_t(
            NativePowerTrace::SystemPowerDetail::kWakeHalUnavailable);
        restoreResult = kIOReturnNotReady;
        recordNativeControlTrace(traceCallId,
            NativePowerTrace::Operation::kSystemPower,
            NativePowerTrace::Phase::kWakeRestoreDecision,
            uint32_t(NativePowerTrace::SystemPowerDetail::kWakeHalUnavailable),
            kIOReturnNotReady, pmEpoch);
    } else if (!bsdInterface) {
        outcome = uint32_t(
            NativePowerTrace::SystemPowerDetail::kWakeInterfaceUnavailable);
        restoreResult = kIOReturnNotReady;
        recordNativeControlTrace(traceCallId,
            NativePowerTrace::Operation::kSystemPower,
            NativePowerTrace::Phase::kWakeRestoreDecision,
            uint32_t(NativePowerTrace::SystemPowerDetail::kWakeInterfaceUnavailable),
            kIOReturnNotReady, pmEpoch);
    } else {
        auto controller = fHalService->get80211Controller();
        if (controller) {
            const uint32_t interfaceFlags = controller->ic_if.if_flags &
                (IFF_UP | IFF_RUNNING);
            if (interfaceFlags == 0) {
                outcome = uint32_t(
                    NativePowerTrace::SystemPowerDetail::kWakeRestoreAttempt);
                recordNativeControlTrace(traceCallId,
                    NativePowerTrace::Operation::kSystemPower,
                    NativePowerTrace::Phase::kWakeRestoreDecision,
                    uint32_t(NativePowerTrace::SystemPowerDetail::kWakeRestoreAttempt),
                    kIOReturnSuccess, pmEpoch);
                restoreResult = enableAdapter(bsdInterface);
                recordNativeControlTrace(traceCallId,
                    NativePowerTrace::Operation::kSystemPower,
                    NativePowerTrace::Phase::kSystemPowerAdapterEnd,
                    uint32_t(NativePowerTrace::SystemPowerDetail::kWakeRestoreAttempt),
                    restoreResult, pmEpoch);
                const uint32_t finalPmEpoch = __atomic_load_n(
                    &nativePowerPMRequestEpoch, __ATOMIC_ACQUIRE);
                const bool supersededDuringEnable = __atomic_load_n(
                    &nativePowerPMRequestValid, __ATOMIC_ACQUIRE) &&
                    (__atomic_load_n(&nativePowerPMRequestedState,
                                     __ATOMIC_ACQUIRE) != kPowerStateOn ||
                     finalPmEpoch != pmEpoch);
                if (supersededDuringEnable) {
                    outcome = uint32_t(
                        NativePowerTrace::SystemPowerDetail::kWakeSupersededByNewerOff);
                    restoreResult = kIOReturnAborted;
                }
            } else if (interfaceFlags != (IFF_UP | IFF_RUNNING)) {
                outcome = uint32_t(
                    NativePowerTrace::SystemPowerDetail::kWakePartialInterface);
                restoreResult = kIOReturnBusy;
                // A partially active interface may still own an init task.
                // Leave it to that lifecycle rather than start a second one.
                recordNativeControlTrace(traceCallId,
                    NativePowerTrace::Operation::kSystemPower,
                    NativePowerTrace::Phase::kWakeRestoreDecision,
                    uint32_t(NativePowerTrace::SystemPowerDetail::kWakePartialInterface),
                    kIOReturnBusy, pmEpoch);
            } else {
                outcome = uint32_t(
                    NativePowerTrace::SystemPowerDetail::kWakeAlreadyActive);
                recordNativeControlTrace(traceCallId,
                    NativePowerTrace::Operation::kSystemPower,
                    NativePowerTrace::Phase::kWakeRestoreDecision,
                    uint32_t(NativePowerTrace::SystemPowerDetail::kWakeAlreadyActive),
                    kIOReturnSuccess, pmEpoch);
            }
        } else {
            outcome = uint32_t(
                NativePowerTrace::SystemPowerDetail::kWakeHalUnavailable);
            restoreResult = kIOReturnNotReady;
            recordNativeControlTrace(traceCallId,
                NativePowerTrace::Operation::kSystemPower,
                NativePowerTrace::Phase::kWakeRestoreDecision,
                uint32_t(NativePowerTrace::SystemPowerDetail::kWakeHalUnavailable),
                kIOReturnNotReady, pmEpoch);
        }
    }
    // Pair every wake begin with a final outcome, including intentional skips.
    // The separate ack entry below proves PM was acknowledged once even when
    // no adapter operation was attempted or enableAdapter returned an error.
    recordNativeControlTrace(traceCallId,
        NativePowerTrace::Operation::kSystemPower,
        NativePowerTrace::Phase::kWakeRestoreEnd,
        outcome, restoreResult,
        __atomic_load_n(&nativePowerPMRequestEpoch, __ATOMIC_ACQUIRE));
#else
    __atomic_store_n(&pmPowerState, kPowerStateOn, __ATOMIC_RELEASE);
#endif
    pmPolicyMaker->acknowledgeSetPowerState();
#ifdef AIRPORT_TAHOE
    recordNativeControlTrace(traceCallId,
        NativePowerTrace::Operation::kSystemPower,
        NativePowerTrace::Phase::kSystemPowerAck,
        uint32_t(NativePowerTrace::SystemPowerDetail::kWake),
        kIOReturnSuccess, pmEpoch);
    publishNativePowerTrace();
#endif
}
