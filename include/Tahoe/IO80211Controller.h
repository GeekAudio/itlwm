// Independently reconstructed from this machine's Apple25G241 BootKC.
// No third-party port header was copied. See evidence/25G241-native-vtables.json.
#pragma once
#include "Types.h"
#include <IOKit/network/IOEthernetController.h>

class IO80211Controller : public IOEthernetController {
    OSDeclareAbstractStructors(IO80211Controller)
#if !defined(__PRIVATE_SPI__)
private:
    // SDK inherited slot 0xa28; native implementation only.
    virtual void _RESERVEDIONetworkController2() __asm__("__ZN19IONetworkController11outputStartEP18IONetworkInterfacej") override;
private:
    // SDK inherited slot 0xa30; native implementation only.
    virtual void _RESERVEDIONetworkController3() __asm__("__ZN19IONetworkController27setInputPacketPollingEnableEP18IONetworkInterfaceb") override;
private:
    // SDK inherited slot 0xa38; native implementation only.
    virtual void _RESERVEDIONetworkController4() __asm__("__ZN19IONetworkController16pollInputPacketsEP18IONetworkInterfacejP11IOMbufQueuePv") override;
private:
    // SDK inherited slot 0xa40; native implementation only.
    virtual void _RESERVEDIONetworkController5() __asm__("__ZN19IONetworkController28networkInterfaceNotificationEP18IONetworkInterfacejPv") override;
#endif
private:
    // SDK inherited slot 0xa48; native implementation only.
    virtual void _RESERVEDIONetworkController6() __asm__("__ZN19IONetworkController20allocatePacketNoWaitEj") override;
private:
    // SDK inherited slot 0xa50; native implementation only.
    virtual void _RESERVEDIONetworkController7() __asm__("__ZN19IONetworkController18setHardwareAssistsEjj") override;

    // native virtual slot 0x90
public:
    virtual void free() override;

    // native virtual slot 0x248
public:
    virtual bool init(OSDictionary*) override;

    // native virtual slot 0x428
public:
    virtual IOReturn configureReport(IOReportChannelList*, unsigned int, void*, void*) override;

    // native virtual slot 0x430
public:
    virtual IOReturn updateReport(IOReportChannelList*, unsigned int, void*, void*) override;

    // native virtual slot 0x5c0
public:
    virtual bool start(IOService*) override;

    // native virtual slot 0x5c8
public:
    virtual void stop(IOService*) override;

    // native virtual slot 0x688
public:
    virtual IOWorkLoop * getWorkLoop() const override;

    // native virtual slot 0x780
public:
    virtual const char * stringFromReturn(int) override;

    // native virtual slot 0x788
public:
    virtual int errnoFromReturn(int) override;

    // native virtual slot 0x860
public:
    virtual UInt32 getFeatures() const override;

    // native virtual slot 0x868
public:
    virtual const OSString * newVendorString() const override;

    // native virtual slot 0x870
public:
    virtual const OSString * newModelString() const override;

    // native virtual slot 0x990
public:
    virtual bool createWorkLoop() override;

    // native virtual slot 0xb20
public:
    virtual IOReturn getHardwareAddress(IOEthernetAddress*) override;

    // native virtual slot 0xb30
public:
    virtual IOReturn setMulticastMode(bool) override;

    // native virtual slot 0xb40
public:
    virtual IOReturn setPromiscuousMode(bool) override;

    // native virtual slot 0xc50
public:
    virtual bool isCommandProhibited(int) = 0;

    // native virtual slot 0xc58
public:
    virtual bool createWorkQueue();

    // native virtual slot 0xc60
private:
    virtual void __tahoe_slot_c60() __asm__("__ZN17IO80211Controller14debugStateInitEv");

    // native virtual slot 0xc68
public:
    virtual IO80211WorkQueue * getWorkQueue() const;

    // native virtual slot 0xc70
public:
    virtual void requestPacketTx(void*, unsigned int);

    // native virtual slot 0xc78
public:
    virtual IOCommandGate * getIO80211CommandGate() const;

    // native virtual slot 0xc80
public:
    virtual IO80211SkywalkInterface * getPrimarySkywalkInterface();

    // native virtual slot 0xc88
public:
    virtual int bpfOutputPacket(OSObject*, unsigned int, __mbuf*);

    // native virtual slot 0xc90
public:
    virtual SInt32 monitorModeSetEnabled(bool, unsigned int);

    // native virtual slot 0xc98
public:
    virtual SInt32 handleCardSpecific(IO80211SkywalkInterface*, unsigned long, void*, bool) = 0;

    // native virtual slot 0xca0
public:
    virtual UInt32 hardwareOutputQueueDepth();

    // native virtual slot 0xca8
public:
    virtual SInt32 performCountryCodeOperation(IO80211CountryCodeOp);

    // native virtual slot 0xcb0
public:
    virtual void dataLinkLayerAttachComplete();

    // native virtual slot 0xcb8
public:
    virtual SInt32 enableFeature(IO80211FeatureCode, void*);

    // native virtual slot 0xcc0
public:
    virtual IOReturn getDRIVER_VERSION(IO80211SkywalkInterface*, apple80211_version_data*) = 0;

    // native virtual slot 0xcc8
public:
    virtual IOReturn getHARDWARE_VERSION(IO80211SkywalkInterface*, apple80211_version_data*) = 0;

    // native virtual slot 0xcd0
public:
    virtual IOReturn getCARD_CAPABILITIES(IO80211SkywalkInterface*, apple80211_capability_data*) = 0;

    // native virtual slot 0xcd8
public:
    virtual IOReturn getPOWER(IO80211SkywalkInterface*, apple80211_power_data*) = 0;

    // native virtual slot 0xce0
public:
    virtual IOReturn setPOWER(IO80211SkywalkInterface*, apple80211_power_data*) = 0;

    // native virtual slot 0xce8
public:
    virtual IOReturn getCOUNTRY_CODE(IO80211SkywalkInterface*, apple80211_country_code_data*) = 0;

    // native virtual slot 0xcf0
public:
    virtual IOReturn setCOUNTRY_CODE(IO80211SkywalkInterface*, apple80211_country_code_data*) = 0;

    // native virtual slot 0xcf8
public:
    virtual IOReturn setGET_DEBUG_INFO(IO80211SkywalkInterface*, apple80211_debug_command*) = 0;

    // native virtual slot 0xd00
private:
    virtual void __tahoe_slot_d00() __asm__("__ZN17IO80211Controller18getPLATFORM_CONFIGEP23IO80211SkywalkInterfaceP26apple80211_platform_config");

    // native virtual slot 0xd08
public:
    virtual SInt32 enableVirtualInterface(IO80211VirtualInterface*);

    // native virtual slot 0xd10
public:
    virtual SInt32 disableVirtualInterface(IO80211VirtualInterface*);

    // native virtual slot 0xd18
public:
    virtual bool requiresExplicitMBufRelease();

    // native virtual slot 0xd20
public:
    virtual bool flowIdSupported();

    // native virtual slot 0xd28
public:
    virtual IO80211FlowQueueLegacy * requestFlowQueue(FlowIdMetadata const*);

    // native virtual slot 0xd30
public:
    virtual void releaseFlowQueue(IO80211FlowQueue*);

    // native virtual slot 0xd38
public:
    virtual bool getLogPipes(CCPipe**, CCPipe**, CCPipe**);

    // native virtual slot 0xd40
public:
    virtual void *getLogger() const = 0;

    // native virtual slot 0xd48
public:
    virtual void enableFeatureForLoggingFlags(unsigned long long);

    // native virtual slot 0xd50
public:
    virtual IOReturn requestQueueSizeAndTimeout(unsigned short*, unsigned short*);

    // native virtual slot 0xd58
public:
    virtual IOReturn enablePacketTimestamping();

    // native virtual slot 0xd60
public:
    virtual IOReturn disablePacketTimestamping();

    // native virtual slot 0xd68
public:
    virtual UInt getPacketTSCounter();

    // native virtual slot 0xd70
public:
    virtual void * getDriverTextLog();

    // native virtual slot 0xd78
public:
    virtual UInt32 selfDiagnosticsReport(int, char const*, unsigned int);

    // native virtual slot 0xd80
public:
    virtual void * getFaultReporterFromDriver() = 0;

    // native virtual slot 0xd88
private:
    virtual void __tahoe_slot_d88() __asm__("__ZN17IO80211Controller25allocIO80211RecursiveLockEv");

    // native virtual slot 0xd90
public:
    virtual UInt32 getDataQueueDepth(OSObject*);

    // native virtual slot 0xd98
public:
    virtual bool wasDynSARInFailSafeMode();

    // native virtual slot 0xda0
public:
    virtual void updateAdvisoryScoresIfNeed();

    // native virtual slot 0xda8
public:
    virtual UInt64 getAVCAdvisoryInfo(IO80211InterfaceAVCAdvisory*);

    // native virtual slot 0xdb0
private:
    virtual void __tahoe_slot_db0() __asm__("__ZN17IO80211Controller26getActionFramePoolCapacityEv");

    // native virtual slot 0xdb8
private:
    virtual void __tahoe_slot_db8() __asm__("__ZN17IO80211Controller13getPostOfficeEv");

    // native virtual slot 0xdc0
private:
    virtual void __tahoe_slot_dc0() __asm__("__ZN17IO80211Controller16CreatePostOfficeEv");

    // native virtual slot 0xdc8
public:
    virtual bool attachInterface(OSObject*, IOService*);

    // native virtual slot 0xdd0
public:
    virtual void detachInterface(OSObject*, bool);

    // native virtual slot 0xdd8
public:
    virtual IO80211VirtualInterface * createVirtualInterface(ether_addr*, unsigned int);

    // native virtual slot 0xde0
public:
    virtual bool attachVirtualInterface(IO80211VirtualInterface**, ether_addr*, unsigned int, bool);

    // native virtual slot 0xde8
public:
    virtual bool detachVirtualInterface(IO80211VirtualInterface*, bool);

    // native virtual slot 0xdf0
public:
    virtual void _RESERVEDIO80211Controller0();

    // native virtual slot 0xdf8
public:
    virtual void _RESERVEDIO80211Controller1();

    // native virtual slot 0xe00
public:
    virtual void _RESERVEDIO80211Controller2();

    // native virtual slot 0xe08
public:
    virtual void _RESERVEDIO80211Controller3();

    // native virtual slot 0xe10
public:
    virtual void _RESERVEDIO80211Controller4();

    // native virtual slot 0xe18
public:
    virtual void _RESERVEDIO80211Controller5();

    // native virtual slot 0xe20
public:
    virtual void _RESERVEDIO80211Controller6();

    // native virtual slot 0xe28
public:
    virtual void _RESERVEDIO80211Controller7();

    // native virtual slot 0xe30
public:
    virtual void _RESERVEDIO80211Controller8();

    // native virtual slot 0xe38
public:
    virtual void _RESERVEDIO80211Controller9();

    // native virtual slot 0xe40
public:
    virtual void _RESERVEDIO80211Controller10();

    // native virtual slot 0xe48
public:
    virtual void _RESERVEDIO80211Controller11();

    // native virtual slot 0xe50
public:
    virtual void _RESERVEDIO80211Controller12();

    // native virtual slot 0xe58
public:
    virtual void _RESERVEDIO80211Controller13();

    // native virtual slot 0xe60
public:
    virtual void _RESERVEDIO80211Controller14();

    // native virtual slot 0xe68
public:
    virtual void _RESERVEDIO80211Controller15();

    // native virtual slot 0xe70
public:
    virtual IOReturn setMulticastList(ether_addr const*, unsigned int);

protected:
    uint8_t __tahoe_opaque_state[0x10];
};
static_assert(sizeof(IO80211Controller) == 0x128, "25G241 IO80211Controller size");
