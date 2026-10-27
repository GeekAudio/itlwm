// Independently reconstructed from this machine's Apple25G241 BootKC.
// No third-party port header was copied. See evidence/25G241-native-vtables.json.
#pragma once
#include "Types.h"
#include "IOSkywalkEthernetInterface.h"

class IO80211WorkQueue;

class IO80211SkywalkInterface : public IOSkywalkEthernetInterface {
    OSDeclareAbstractStructors(IO80211SkywalkInterface)
public:
    // Exact 25G332 failure-path witness. No private memory is modified.
    bool hasNativePrivate25G332() const {
        void *value = nullptr;
        __builtin_memcpy(&value, __tahoe_opaque_state, sizeof(value));
        return value != nullptr;
    }
    // Native nonvirtual helpers: no private ivar layout is exposed.
    OSString *setInterfaceRole(unsigned int);
    unsigned int getInterfaceRole();
    void setInterfaceId(unsigned int);
    void setInitMacAddress(ether_addr &);
    IO80211WorkQueue *getControllerWorkQueue();

    // native virtual slot 0x88
public:
    virtual bool init() override;

    // native virtual slot 0x90
public:
    virtual void free() override;

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

    // native virtual slot 0x770
public:
    virtual IOReturn newUserClient(task*, void*, unsigned int, OSDictionary*, IOUserClient**) override;

    // native virtual slot 0x780
public:
    virtual const char * stringFromReturn(int) override;

    // native virtual slot 0x788
public:
    virtual int errnoFromReturn(int) override;

    // native virtual slot 0x7e8
public:
    virtual IOReturn setPowerState(unsigned long, IOService*) override;

    // native virtual slot 0x7f0
public:
    virtual unsigned long maxCapabilityForDomainState(unsigned long) override;

    // native virtual slot 0x7f8
public:
    virtual unsigned long initialPowerStateForDomainState(unsigned long) override;

    // native virtual slot 0x850
public:
    virtual IOReturn enable(unsigned int) override;

    // native virtual slot 0x858
public:
    virtual IOReturn disable(unsigned int) override;

    // native virtual slot 0x8e0
public:
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams*, sockaddr_dl**) override;

    // native virtual slot 0x8e8
public:
    virtual IOReturn prepareBSDInterface(__ifnet*, unsigned int) override;

    // native virtual slot 0x910
public:
    virtual IOReturn processBSDCommand(__ifnet*, unsigned int, void*) override;

    // native virtual slot 0x930
public:
    virtual SInt32 setInterfaceEnable(bool) override;

    // native virtual slot 0x938
public:
    virtual SInt32 setRunningState(bool) override;

    // native virtual slot 0x940
public:
    virtual IOReturn handleChosenMedia(unsigned int) override;

    // native virtual slot 0x948
public:
    virtual void * getSupportedMediaArray(unsigned int*, unsigned int*) override;

    // native virtual slot 0x9b8
public:
    virtual UInt getFeatureFlags() override;

    // native virtual slot 0x9f8
public:
    virtual const char * classNameOverride() override;

    // native virtual slot 0xa68
public:
    virtual void getHardwareAddress(ether_addr*) override;

    // native virtual slot 0xa70
public:
    virtual void setHardwareAddress(ether_addr*) override;

    // native virtual slot 0xa98
public:
    virtual IOReturn setPromiscuousModeEnable(bool, unsigned int) override;

    // native virtual slot 0xb08
public:
    virtual void * createPeerManager();

    // native virtual slot 0xb10
private:
    virtual void __tahoe_slot_b10() __asm__("__ZN23IO80211SkywalkInterface10createPeerEPKhP18IO80211PeerManager");

    // native virtual slot 0xb18
public:
    virtual void postMessage(unsigned int, void*, unsigned long, bool);

    // native virtual slot 0xb20
public:
    virtual IOReturn reportDataPathEvents(unsigned int, void*, unsigned long, bool);

    // native virtual slot 0xb28
public:
    virtual IOReturn recordOutputPackets(TxSubmissionDequeueStats*, TxSubmissionDequeueStats*);

    // native virtual slot 0xb30
public:
    virtual IOReturn recordOutputPacket(apple80211_wme_ac, int, int);

    // native virtual slot 0xb38
public:
    virtual void logTxPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, apple80211_wme_ac, bool);

    // native virtual slot 0xb40
public:
    virtual void logTxCompletionPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, unsigned char*, apple80211_wme_ac, int, unsigned int, bool, bool);

    // native virtual slot 0xb48
public:
    virtual IOReturn recordCompletionPackets(TxCompletionEnqueueStats*, TxCompletionEnqueueStats*);

    // native virtual slot 0xb50
public:
    virtual IOReturn inputPacket(IO80211NetworkPacket*, packet_info_tag*, ether_header*, bool*, bool);

    // native virtual slot 0xb58
public:
    virtual IOReturn forwardInfraRelayPackets(IO80211NetworkPacket*, ether_header*);

    // native virtual slot 0xb60
public:
    virtual void logSkywalkTxReqPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, unsigned char*, apple80211_wme_ac, bool);

    // native virtual slot 0xb68
public:
    virtual SInt64 pendingPackets(unsigned char);

    // native virtual slot 0xb70
public:
    virtual SInt64 packetSpace(unsigned char);

    // native virtual slot 0xb78
public:
    virtual bool isChipInterfaceReady();

    // native virtual slot 0xb80
public:
    virtual bool isDebounceOnGoing();

    // native virtual slot 0xb88
public:
    virtual IO80211LinkState linkState();

    // native virtual slot 0xb90
public:
    virtual void setScanningState(unsigned int, bool, apple80211_scan_data*, int);

    // native virtual slot 0xb98
public:
    virtual void setDataPathState(bool);

    // native virtual slot 0xba0
public:
    virtual void * getScanManager();

    // native virtual slot 0xba8
private:
    virtual void __tahoe_slot_ba8() __asm__("__ZN23IO80211SkywalkInterface13getControllerEv");

    // native virtual slot 0xbb0
public:
    virtual void updateLinkParameters(apple80211_interface_availability*);

    // native virtual slot 0xbb8
public:
    virtual void updateInterfaceCoexRiskPct(unsigned long long);

    // native virtual slot 0xbc0
public:
    virtual void setLQM(unsigned long long);

    // native virtual slot 0xbc8
public:
    virtual void updateLinkStatus();

    // native virtual slot 0xbd0
public:
    virtual void updateLinkStatusGated();

    // native virtual slot 0xbd8
public:
    virtual void setInterfaceExtendedCCA(apple80211_channel, apple80211_cca_report*);

    // native virtual slot 0xbe0
public:
    virtual void setInterfaceCCA(apple80211_channel, int);

    // native virtual slot 0xbe8
public:
    virtual void setInterfaceNF(apple80211_channel, long long);

    // native virtual slot 0xbf0
public:
    virtual void setInterfaceOFDMDesense(apple80211_channel, long long);

    // native virtual slot 0xbf8
public:
    virtual void removePacketQueue(IO80211FlowQueueHash*);

    // native virtual slot 0xc00
public:
    virtual void setDebugFlags(unsigned long long, unsigned int);

    // native virtual slot 0xc08
public:
    virtual SInt64 debugFlags();

    // native virtual slot 0xc10
public:
    virtual void setInterfaceChipCounters(apple80211_stat_report*, apple80211_chip_counters_tx*, apple80211_chip_error_counters_tx*, apple80211_chip_counters_rx*);

    // native virtual slot 0xc18
public:
    virtual void setInterfaceMIBdot11(apple80211_stat_report*, apple80211_ManagementInformationBasedot11_counters*);

    // native virtual slot 0xc20
public:
    virtual void setFrameStats(apple80211_stat_report*, apple80211_frame_counters*);

    // native virtual slot 0xc28
public:
    virtual void setInfraSpecificFrameStats(apple80211_stat_report*, apple80211_infra_specific_stats*);

    // native virtual slot 0xc30
private:
    virtual void __tahoe_slot_c30() __asm__("__ZN23IO80211SkywalkInterface19setRxDataStallStatsEP22apple80211_stat_reportP31apple80211_rx_data_stall_report");

    // native virtual slot 0xc38
public:
    virtual SInt64 getWmeTxCounters(unsigned long long*);

    // native virtual slot 0xc40
public:
    virtual void setPeerManagerLogFlag(unsigned int, unsigned int, unsigned int);

    // native virtual slot 0xc48
public:
    virtual void setWoWEnabled(bool);

    // native virtual slot 0xc50
public:
    virtual bool wowEnabled();

    // native virtual slot 0xc58
public:
    virtual void printDataPath(userPrintCtx*);

    // native virtual slot 0xc60
public:
    virtual UInt32 getDataQueueDepth();

    // native virtual slot 0xc68
public:
    virtual bool findOrCreateFlowQueue(IO80211FlowQueueHash);

    // native virtual slot 0xc70
public:
    virtual UInt64 findOrCreateFlowQueueWithCache(IO80211FlowQueueHash, bool*);

    // native virtual slot 0xc78
public:
    virtual UInt64 findExistingFlowQueue(IO80211FlowQueueHash);

    // native virtual slot 0xc80
public:
    virtual void removePacketQueue(IO80211FlowQueueHash const*);

    // native virtual slot 0xc88
public:
    virtual void flushPacketQueues();

    // native virtual slot 0xc90
public:
    virtual void cachePeer(ether_addr*, unsigned int*);

    // native virtual slot 0xc98
public:
    virtual bool shouldLog(unsigned long long);

    // native virtual slot 0xca0
public:
    virtual void vlogDebug(unsigned long long, char const*, va_list);

    // native virtual slot 0xca8
public:
    virtual void vlogDebugBPF(unsigned long long, char const*, va_list);

    // native virtual slot 0xcb0
public:
    virtual UInt64 createLinkQualityMonitor(IO80211Peer*, bool);

    // native virtual slot 0xcb8
public:
    virtual void releaseLinkQualityMonitor(IO80211Peer*);

    // native virtual slot 0xcc0
public:
    virtual void * getP2PSkywalkPeerMgr();

    // native virtual slot 0xcc8
public:
    virtual bool isCommandProhibited(int);

    // native virtual slot 0xcd0
private:
    virtual void __tahoe_slot_cd0() __asm__("__ZN23IO80211SkywalkInterface8findPeerER10ether_addr");

    // native virtual slot 0xcd8
public:
    virtual void setNotificationProperty(OSSymbol const*, OSObject const*);

    // native virtual slot 0xce0
public:
    virtual void * getWorkerMatchingDict(OSString*);

    // native virtual slot 0xce8
public:
    virtual bool init(IOService*, ether_addr*);

    // native virtual slot 0xcf0
public:
    virtual bool isInterfaceEnabled();

    // native virtual slot 0xcf8
public:
    virtual ether_addr * getSelfMacAddr();

    // native virtual slot 0xd00
public:
    virtual void * getPacketPool(OSString*);

    // native virtual slot 0xd08
public:
    virtual void * getLogger() const;

    // native virtual slot 0xd10
public:
    virtual IOReturn handleSIOCSIFADDR();

    // native virtual slot 0xd18
public:
    virtual IOReturn debugHandler(apple80211_debug_command*);

    // native virtual slot 0xd20
public:
    virtual void statsDump();

    // native virtual slot 0xd28
public:
    virtual void powerOnNotification();

    // native virtual slot 0xd30
public:
    virtual void powerOffNotification();

    // native virtual slot 0xd38
public:
    virtual UInt64 getTxQueueDepth();

    // native virtual slot 0xd40
public:
    virtual UInt64 getRxQueueCapacity();

    // native virtual slot 0xd48
public:
    virtual void updateRxCounter(unsigned long long);

    // native virtual slot 0xd50
public:
    virtual void * getMultiCastQueue();

    // native virtual slot 0xd58
public:
    virtual int getAssocState();

    // native virtual slot 0xd60
public:
    virtual void notifyQueueState(apple80211_wme_ac, unsigned short);

    // native virtual slot 0xd68
public:
    virtual int getTxHeadroom();

    // native virtual slot 0xd70
public:
    virtual void * getRxCompQueue();

    // native virtual slot 0xd78
public:
    virtual void * getTxCompQueue();

    // native virtual slot 0xd80
public:
    virtual void * getTxSubQueue(apple80211_wme_ac);

    // native virtual slot 0xd88
public:
    virtual void * getTxPacketPool();

    // native virtual slot 0xd90
public:
    virtual void * getRxPacketPool();

    // native virtual slot 0xd98
public:
    virtual void enableDatapath();

    // native virtual slot 0xda0
public:
    virtual void disableDatapath();

    // native virtual slot 0xda8
public:
    virtual int getNumTxQueues();

    // native virtual slot 0xdb0
public:
    virtual void * getLQMSummary(apple80211_lqm_summary*);

    // native virtual slot 0xdb8
public:
    virtual int getEventPipeSize();

    // native virtual slot 0xdc0
public:
    virtual UInt64 createEventPipe(IO80211APIUserClient*);

    // native virtual slot 0xdc8
public:
    virtual void destroyEventPipe(IO80211APIUserClient*);

    // native virtual slot 0xdd0
private:
    virtual void __tahoe_slot_dd0() __asm__("__ZN23IO80211SkywalkInterface17setUserBufferInfoEP18IOMemoryDescriptory");

    // native virtual slot 0xdd8
public:
    virtual void postMessageIOUC(char const*, unsigned int, void*, unsigned long);

    // native virtual slot 0xde0
public:
    virtual bool isIOUCPipeOpened();

    // native virtual slot 0xde8
public:
    virtual void * getRingMD(IO80211APIUserClient*, unsigned long long);

    // native virtual slot 0xdf0
private:
    virtual void __tahoe_slot_df0() __asm__("__ZN23IO80211SkywalkInterface10attachPeerEP10ether_addr");

    // native virtual slot 0xdf8
private:
    virtual void __tahoe_slot_df8() __asm__("__ZN23IO80211SkywalkInterface10detachPeerEP10ether_addr");

    // native virtual slot 0xe00
private:
    virtual void __tahoe_slot_e00() __asm__("__ZN23IO80211SkywalkInterface21setDebugTrafficReportEb");

    // native virtual slot 0xe08
private:
    virtual void __tahoe_slot_e08() __asm__("__ZN23IO80211SkywalkInterface25getDataPathInterfaceStatsEP36apple80211_data_path_interface_stats");

    // native virtual slot 0xe10
private:
    virtual void __tahoe_slot_e10() __asm__("__ZN23IO80211SkywalkInterface20getDataPathPeerStatsEP31apple80211_data_path_peer_stats");

    // native virtual slot 0xe18
private:
    virtual void __tahoe_slot_e18() __asm__("__ZN23IO80211SkywalkInterface22getLastQueuePacketTimeEP10ether_addr");

    // native virtual slot 0xe20
private:
    virtual void __tahoe_slot_e20() __asm__("__ZN23IO80211SkywalkInterface32getLastRxUnicastLinkActivityTimeEP10ether_addr");

    // native virtual slot 0xe28
private:
    virtual void __tahoe_slot_e28() __asm__("__ZN23IO80211SkywalkInterface24updateInterfaceDataStatsEP36apple80211_data_path_interface_stats");

    // native virtual slot 0xe30
private:
    virtual void __tahoe_slot_e30() __asm__("__ZN23IO80211SkywalkInterface19updatePeerDataStatsEP31apple80211_data_path_peer_stats");

    // native virtual slot 0xe38
private:
    virtual void __tahoe_slot_e38() __asm__("__ZN23IO80211SkywalkInterface12logTxLatencyEPhjy");

    // native virtual slot 0xe40
private:
    virtual void __tahoe_slot_e40() __asm__("__ZN23IO80211SkywalkInterface12logRxLatencyEjy");

    // native virtual slot 0xe48
private:
    virtual void __tahoe_slot_e48() __asm__("__ZN23IO80211SkywalkInterface20getNClearTxRxLatencyEP25apple80211_latency_all_acS1_");

    // native virtual slot 0xe50
private:
    virtual void __tahoe_slot_e50() __asm__("__ZN23IO80211SkywalkInterface18getLastTxTimeStampERy");

    // native virtual slot 0xe58
private:
    virtual void __tahoe_slot_e58() __asm__("__ZN23IO80211SkywalkInterface18getLastRxTimeStampERy");

    // native virtual slot 0xe60
private:
    virtual void __tahoe_slot_e60() __asm__("__ZN23IO80211SkywalkInterface12syncDPSStatsEP26apple82011_postMessage_dps");

protected:
    uint8_t __tahoe_opaque_state[0x8];
};
static_assert(sizeof(IO80211SkywalkInterface) == 0x128, "25G241 IO80211SkywalkInterface size");
