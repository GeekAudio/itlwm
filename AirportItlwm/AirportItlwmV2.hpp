//
//  AirportItlwmV2.hpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef AirportItlwmV2_hpp
#define AirportItlwmV2_hpp

#include "Apple80211.h"
#ifdef AIRPORT_TAHOE
#define ITL_CONTROLLER_OVERRIDE
#else
#define ITL_CONTROLLER_OVERRIDE override
#endif

#include "IOKit/network/IOGatedOutputQueue.h"
#include <libkern/c++/OSString.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <IOKit/IOFilterInterruptEventSource.h>

#include "ItlIwm.hpp"
#include "ItlIwx.hpp"
#include "ItlIwn.hpp"

#include "AirportItlwmEthernetInterface.hpp"
#ifdef AIRPORT_TAHOE
#include "../native/native_power_trace.hpp"
#endif

enum
{
    kPowerStateOff = 0,
    kPowerStateOn,
    kPowerStateCount
};

#define kWatchDogTimerPeriod 1000

extern "C" {
const char *convertApple80211IOCTLToString(signed int cmd);
}

class AirportItlwm : public IO80211Controller {
    OSDeclareDefaultStructors(AirportItlwm)
#define IOCTL(REQ_TYPE, REQ, DATA_TYPE) \
if (REQ_TYPE == SIOCGA80211) { \
ret = get##REQ(interface, (struct DATA_TYPE* )data); \
} else { \
ret = set##REQ(interface, (struct DATA_TYPE* )data); \
}
    
#define IOCTL_GET(REQ_TYPE, REQ, DATA_TYPE) \
if (REQ_TYPE == SIOCGA80211) { \
ret = get##REQ(interface, (struct DATA_TYPE* )data); \
}
#define IOCTL_SET(REQ_TYPE, REQ, DATA_TYPE) \
if (REQ_TYPE == SIOCSA80211) { \
ret = set##REQ(interface, (struct DATA_TYPE* )data); \
}
#define FUNC_IOCTL(REQ, DATA_TYPE) \
FUNC_IOCTL_GET(REQ, DATA_TYPE) \
FUNC_IOCTL_SET(REQ, DATA_TYPE)
#define FUNC_IOCTL_GET(REQ, DATA_TYPE) \
IOReturn get##REQ(OSObject *object, struct DATA_TYPE *data);
#define FUNC_IOCTL_SET(REQ, DATA_TYPE) \
IOReturn set##REQ(OSObject *object, struct DATA_TYPE *data);
    
public:
    virtual bool init(OSDictionary *properties) ITL_CONTROLLER_OVERRIDE;
#ifdef AIRPORT_TAHOE
    virtual IOReturn setProperties(OSObject *properties) override;
#endif
    virtual void free() ITL_CONTROLLER_OVERRIDE;
    virtual IOService* probe(IOService* provider, SInt32* score) ITL_CONTROLLER_OVERRIDE;
    virtual bool start(IOService *provider) ITL_CONTROLLER_OVERRIDE;
    virtual void stop(IOService *provider) ITL_CONTROLLER_OVERRIDE;
    virtual IOReturn enable(IO80211SkywalkInterface *netif) ITL_CONTROLLER_OVERRIDE;
    virtual IOReturn disable(IO80211SkywalkInterface *netif) ITL_CONTROLLER_OVERRIDE;
    virtual IOReturn setHardwareAddress(const void *addr, UInt32 addrBytes) ITL_CONTROLLER_OVERRIDE;
    virtual IOReturn getHardwareAddress(IOEthernetAddress* addrP) ITL_CONTROLLER_OVERRIDE;
    virtual IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const ITL_CONTROLLER_OVERRIDE;
    virtual IOReturn setPromiscuousMode(IOEnetPromiscuousMode mode) ITL_CONTROLLER_OVERRIDE;
    virtual IOReturn setMulticastMode(IOEnetMulticastMode mode) ITL_CONTROLLER_OVERRIDE;
    virtual IOReturn setMulticastList(IOEthernetAddress* addr, UInt32 len) ITL_CONTROLLER_OVERRIDE;
    virtual UInt32 getFeatures() const ITL_CONTROLLER_OVERRIDE;
    virtual const OSString * newVendorString() const ITL_CONTROLLER_OVERRIDE;
    virtual const OSString * newModelString() const ITL_CONTROLLER_OVERRIDE;
    virtual IOReturn selectMedium(const IONetworkMedium *medium) ITL_CONTROLLER_OVERRIDE;
    virtual bool createWorkQueue() ITL_CONTROLLER_OVERRIDE;
    virtual IONetworkInterface * createInterface() ITL_CONTROLLER_OVERRIDE;
    virtual bool configureInterface(IONetworkInterface *netif) ITL_CONTROLLER_OVERRIDE;
    virtual UInt32 outputPacket(mbuf_t, void * param) ITL_CONTROLLER_OVERRIDE;
#ifdef __PRIVATE_SPI__
    virtual IOReturn outputStart(IONetworkInterface *interface, IOOptionBits options) ITL_CONTROLLER_OVERRIDE;
    virtual IOReturn networkInterfaceNotification(
                        IONetworkInterface * interface,
                        uint32_t              type,
                        void *                  argument ) ITL_CONTROLLER_OVERRIDE;
#endif
    virtual bool setLinkStatus(
                               UInt32                  status,
                               const IONetworkMedium * activeMedium = 0,
                               UInt64                  speed        = 0,
                               OSData *                data         = 0) ITL_CONTROLLER_OVERRIDE;
    static IOReturn setLinkStateGated(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);
    
    static IOReturn tsleepHandler(OSObject* owner, void* arg0 = 0, void* arg1 = 0, void* arg2 = 0, void* arg3 = 0);
    static void eventHandler(struct ieee80211com *, int, void *);
    IOReturn enableAdapter(IONetworkInterface *netif);
    IOReturn disableAdapter(IONetworkInterface *netif);
    bool initCCLogs();
    
    #ifdef AIRPORT_TAHOE
    virtual IO80211WorkQueue *getWorkQueue() const;
    virtual void *getLogger() const;
    virtual IOCommandGate *getIO80211CommandGate() const;
#else
    virtual IO80211WorkQueue *getWorkQueue() override;
#endif
    virtual bool requiresExplicitMBufRelease() ITL_CONTROLLER_OVERRIDE {
        return false;
    }
    virtual bool flowIdSupported() ITL_CONTROLLER_OVERRIDE {
        return false;
    }
    virtual SInt32 monitorModeSetEnabled(bool, UInt) ITL_CONTROLLER_OVERRIDE {
        return kIOReturnSuccess;
    }
    virtual IOReturn requestQueueSizeAndTimeout(unsigned short *queue, unsigned short *timeout) ITL_CONTROLLER_OVERRIDE {
        XYLog("%s\n", __FUNCTION__);
        return kIOReturnSuccess;
    }
    
    virtual bool getLogPipes(CCPipe**, CCPipe**, CCPipe**) ITL_CONTROLLER_OVERRIDE;
    
    virtual void *getFaultReporterFromDriver() ITL_CONTROLLER_OVERRIDE;
    
    virtual SInt32 apple80211_ioctl(IO80211SkywalkInterface *,unsigned long,void *, bool, bool) ITL_CONTROLLER_OVERRIDE;
    virtual SInt32 apple80211SkywalkRequest(UInt,int,IO80211SkywalkInterface *,void *) ITL_CONTROLLER_OVERRIDE;
    virtual SInt32 apple80211SkywalkRequest(UInt,int,IO80211SkywalkInterface *,void *,void *) ITL_CONTROLLER_OVERRIDE;

    bool createMediumTables(const IONetworkMedium **primary);
    void releaseAll();
    void detachWatchdogTimer();
    void watchdogAction(IOTimerEventSource *timer);
    
    virtual SInt32 enableFeature(IO80211FeatureCode, void*) ITL_CONTROLLER_OVERRIDE;
    virtual bool isCommandProhibited(int command) ITL_CONTROLLER_OVERRIDE {
//        if (!ml_at_interrupt_context())
//            XYLog("%s %s\n", __FUNCTION__, convertApple80211IOCTLToString(command));
        return false;
    };
    virtual SInt32 handleCardSpecific(IO80211SkywalkInterface *,unsigned long,void *,bool) ITL_CONTROLLER_OVERRIDE {
        XYLog("%s\n", __FUNCTION__);
        return 0;
    };
    virtual IOReturn getDRIVER_VERSION(IO80211SkywalkInterface *interface,apple80211_version_data *data) ITL_CONTROLLER_OVERRIDE {
        XYLog("%s\n", __FUNCTION__);
        return getDRIVER_VERSION((OSObject *)interface, data);
    };
    virtual IOReturn getHARDWARE_VERSION(IO80211SkywalkInterface *interface,apple80211_version_data *data) ITL_CONTROLLER_OVERRIDE {
        XYLog("%s\n", __FUNCTION__);
        return getHARDWARE_VERSION((OSObject *)interface, data);
    };
    virtual IOReturn getCARD_CAPABILITIES(IO80211SkywalkInterface *interface,apple80211_capability_data *data) ITL_CONTROLLER_OVERRIDE {
//        XYLog("%s\n", __FUNCTION__);
        return getCARD_CAPABILITIES((OSObject *)interface, data);
    }
    virtual IOReturn getPOWER(IO80211SkywalkInterface *interface,apple80211_power_data *data) ITL_CONTROLLER_OVERRIDE {
//        XYLog("%s\n", __FUNCTION__);
        return getPOWER((OSObject *)interface, data);
    }
    virtual IOReturn setPOWER(IO80211SkywalkInterface *interface,apple80211_power_data *data) ITL_CONTROLLER_OVERRIDE {
//        XYLog("%s\n", __FUNCTION__);
        return setPOWER((OSObject *)interface, data);
    }
    virtual IOReturn getCOUNTRY_CODE(IO80211SkywalkInterface *interface,apple80211_country_code_data *data) ITL_CONTROLLER_OVERRIDE {
//        XYLog("%s\n", __FUNCTION__);
        return getCOUNTRY_CODE((OSObject *)interface, data);
    }
    virtual IOReturn setCOUNTRY_CODE(IO80211SkywalkInterface *interface,apple80211_country_code_data *data) ITL_CONTROLLER_OVERRIDE {
//        XYLog("%s\n", __FUNCTION__);
        return setCOUNTRY_CODE((OSObject *)interface, data);
    }
    virtual IOReturn setGET_DEBUG_INFO(IO80211SkywalkInterface *interface,apple80211_debug_command *data) ITL_CONTROLLER_OVERRIDE {
        XYLog("%s\n", __FUNCTION__);
        return kIOReturnSuccess;
    }
    
    //scan
    static void fakeScanDone(OSObject *owner, IOTimerEventSource *sender);
    
    //-----------------------------------------------------------------------
    // Power management support.
    //-----------------------------------------------------------------------
    virtual IOReturn registerWithPolicyMaker( IOService * policyMaker ) ITL_CONTROLLER_OVERRIDE;
    virtual IOReturn setPowerState( unsigned long powerStateOrdinal,
                                    IOService *   policyMaker) ITL_CONTROLLER_OVERRIDE;
    virtual IOReturn setWakeOnMagicPacket( bool active ) ITL_CONTROLLER_OVERRIDE;
    void setPowerStateOff(void);
    void setPowerStateOn(void);
    void unregistPM();
    bool initPCIPowerManagment(IOPCIDevice *provider);

    FUNC_IOCTL_GET(CARD_CAPABILITIES, apple80211_capability_data)
    FUNC_IOCTL(POWER, apple80211_power_data)
    FUNC_IOCTL_GET(DRIVER_VERSION, apple80211_version_data)
    FUNC_IOCTL_GET(HARDWARE_VERSION, apple80211_version_data)
    FUNC_IOCTL(COUNTRY_CODE, apple80211_country_code_data)
    
public:
    IOInterruptEventSource* fInterrupt;
    IOTimerEventSource *watchdogTimer;
    bool watchdogSourceAttached {false};
    IOPCIDevice *pciNub;
    IONetworkStats *fpNetStats;
    AirportItlwmEthernetInterface *bsdInterface;
    IO80211SkywalkInterface *fNetIf;
    IOWorkLoop *fWatchdogWorkLoop;
    ItlHalService *fHalService;
    
    //IO80211
    uint8_t power_state;
    struct ieee80211_node *fNextNodeToSend;
    bool fScanResultWrapping;
    IOTimerEventSource *scanSource;
    
    u_int32_t current_authtype_lower;
    u_int32_t current_authtype_upper;
    UInt64 currentSpeed;
    UInt32 currentStatus;
    bool disassocIsVoluntary;
    char geo_location_cc[3];
    
    //pm
    thread_call_t powerOnThreadCall;
    thread_call_t powerOffThreadCall;
    UInt32 pmPowerState;
    IOService *pmPolicyMaker;
    UInt8 pmPCICapPtr;
    bool magicPacketEnabled;
    bool magicPacketSupported;
    
    //AWDL
    uint8_t *syncFrameTemplate;
    uint32_t syncFrameTemplateLength;
    uint8_t awdlBSSID[6];
    uint32_t awdlSyncState;
    uint32_t awdlElectionId;
    uint32_t awdlPresenceMode;
    uint16_t awdlMasterChannel;
    uint16_t awdlSecondaryMasterChannel;
    uint8_t *roamProfile;
    struct apple80211_btc_profiles_data *btcProfile;
    struct apple80211_btc_config_data btcConfig;
    uint32_t btcMode;
    uint32_t btcOptions;
    bool awdlSyncEnable;
    
    CCPipe *driverLogPipe;
    CCPipe *driverDataPathPipe;
    CCPipe *driverSnapshotsPipe;
    
    CCStream *driverFaultReporter;
#ifdef AIRPORT_TAHOE
    bool nativeActivationAttempted {false};
    // Atomic bit0=requested On, bit1=real READY; updated as one word.
    uint32_t nativePowerFlags {0};
    // Set before stop drains native ingress. It rejects new SET_POWER actions;
    // the terminal Off policy/epoch transition is still serialized by the
    // controller command gate after that drain completes.
    bool nativePowerStopping {false};
    uint32_t nativePowerGetCount {0};
    uint32_t nativePowerSetCount {0};
    uint32_t nativePowerLastResult {uint32_t(kIOReturnNotReady)};
    uint32_t nativePowerLastEvent {0};
    uint32_t nativePowerReadyCount {0};
    uint32_t nativePowerStoppedCount {0};
    uint32_t nativePowerResetCount {0};
    uint32_t nativePowerEpoch {0}; // Atomic; serialized transitions still run on the command gate.
    uint64_t nativePowerTransitionRevision {0}; // Atomic accesses, serialized with nativePowerStateLock when available.
    uint32_t nativePowerTracePublishedSequence {0};
    NativePowerTrace::NotificationState nativePowerNotificationState {};
    NativePowerTrace::AddressRestartNotification nativeAddressRestartNotification {};
    // The following producer-visible tuple is copied under nativePowerStateLock
    // into each ingress entry. Never reconstruct an old entry from current id.
    uint64_t nativeAddressRestartPublishedId {0};
    uint64_t nativeAddressRestartStartRevision {0};
    uint32_t nativeAddressRestartPublishedEpoch {0};
    uint32_t nativeAddressRestartStartedCount {0};
    uint32_t nativeAddressRestartSuppressedCount {0};
    uint32_t nativeAddressRestartCompletedCount {0};
    uint32_t nativeAddressRestartCancelledCount {0};
    uint32_t nativeAddressRestartExpiredCount {0};
    uint32_t nativeAddressRestartLastOutcome {0};
    IOSimpleLock *nativePowerStateLock {nullptr};
    IOSimpleLock *nativePowerTraceLock {nullptr};
    NativePowerTrace::Ledger nativePowerTrace {};
    uint32_t nativePowerOffAttempts {0};
    uint32_t nativePowerOffRetries {0};
    uint32_t nativePowerOffResult {uint32_t(kIOReturnNotReady)};
    bool nativePowerOffPending {false}; // Atomic snapshots; transitions serialized by the native command gate.
    bool nativePowerRequested() const {
        return (__atomic_load_n(&nativePowerFlags, __ATOMIC_ACQUIRE) & 1U) != 0;
    }
    bool initializeNativePowerLocks();
    void releaseNativePowerLocks();
    IOReturn waitForNativePower(uint32_t, uint32_t traceCallId);
    IOReturn disableAdapterWithRetry(uint32_t, uint32_t traceCallId);
    void wakeNativePowerWaiters();
    static IOReturn nativePowerAction(OSObject *, void *, void *, void *, void *);
    static IOReturn nativePowerStopAction(OSObject *, void *, void *, void *, void *);
    void publishNativePowerState();
    uint32_t observeNativePowerEvent(int,
        NativePowerTrace::PowerIngressContext *context = nullptr);
    // Call only from the serialized native event/tick consumer, never HAL IRQ
    // ingress. The cache belongs to that consumer and stores the pair sampled
    // before the postMessage call, not an assumed OS acknowledgement.
    bool postNativePowerChangedIfNeeded();
    bool nativePowerStateSnapshot(uint32_t *powerFlags, uint64_t *revision) const;
    IOReturn beginNativeAddressRestartNotification(uint64_t *id);
    bool commitNativeAddressRestartNotification(uint64_t id,
                                                bool commitSucceeded,
                                                bool enableSucceeded);
    void cancelNativeAddressRestartNotification(uint64_t id = 0);
    NativePowerTrace::AddressRestartDecision observeNativeAddressRestartEvent(
        NativePowerTrace::AddressRestartEvent,
        const NativePowerTrace::PowerIngressContext &);
    bool tickNativeAddressRestartNotification();
    void noteNativeAddressRestartOutcome(
        NativePowerTrace::AddressRestartOutcome outcome);
    void publishNativeAddressRestartMetrics();
    uint32_t updateNativePowerFlags(uint32_t clearMask, uint32_t setMask,
                                    bool readyRequiresRequested = false,
        NativePowerTrace::PowerIngressContext *context = nullptr);
    uint32_t advanceNativePowerEpoch(bool requestedOn);
    uint32_t beginNativeControlTrace(NativePowerTrace::Operation,
        NativePowerTrace::Phase, uint32_t detail, int32_t result);
    void recordNativeControlTrace(uint32_t callId,
        NativePowerTrace::Operation, NativePowerTrace::Phase,
        uint32_t detail, int32_t result);
    void publishNativePowerTrace();
    CCStream *nativeLogger {nullptr};
    OSObject *nativeFaultReporter {nullptr};
    uint32_t nativeCaptureStarted {0};
    void releaseNativeCapture();
    void releaseNativePowerHAL();
#endif
};

#undef ITL_CONTROLLER_OVERRIDE
#endif /* AirportItlwmV2_hpp */
