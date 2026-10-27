// Independently reconstructed from this machine's Apple25G241 BootKC.
// No third-party port header was copied. See evidence/25G241-native-vtables.json.
#pragma once
#include "Types.h"
#include "IO80211SkywalkInterface.h"

class IO80211InfraInterface : public IO80211SkywalkInterface {
    OSDeclareAbstractStructors(IO80211InfraInterface)

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

    // native virtual slot 0x7e8
public:
    virtual IOReturn setPowerState(unsigned long, IOService*) override;

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

    // native virtual slot 0x990
public:
    virtual UInt getHardwareAssists() override;

    // native virtual slot 0x9e0
public:
    virtual bool bpfTap(unsigned int, unsigned int) override;

    // native virtual slot 0xaa8
public:
    virtual void hwConfigNicProxyData(nicproxy_info_s*) override;

    // native virtual slot 0xb18
public:
    virtual void postMessage(unsigned int, void*, unsigned long, bool) override;

    // native virtual slot 0xb28
public:
    virtual IOReturn recordOutputPackets(TxSubmissionDequeueStats*, TxSubmissionDequeueStats*) override;

    // native virtual slot 0xb38
public:
    virtual void logTxPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, apple80211_wme_ac, bool) override;

    // native virtual slot 0xb40
public:
    virtual void logTxCompletionPacket(IO80211NetworkPacket*, PacketSkywalkScratch*, unsigned char*, apple80211_wme_ac, int, unsigned int, bool, bool) override;

    // native virtual slot 0xb48
public:
    virtual IOReturn recordCompletionPackets(TxCompletionEnqueueStats*, TxCompletionEnqueueStats*) override;

    // native virtual slot 0xb50
public:
    virtual IOReturn inputPacket(IO80211NetworkPacket*, packet_info_tag*, ether_header*, bool*, bool) override;

    // native virtual slot 0xb68
public:
    virtual SInt64 pendingPackets(unsigned char) override;

    // native virtual slot 0xb70
public:
    virtual SInt64 packetSpace(unsigned char) override;

    // native virtual slot 0xb80
public:
    virtual bool isDebounceOnGoing() override;

    // native virtual slot 0xb88
public:
    virtual IO80211LinkState linkState() override;

    // native virtual slot 0xb90
public:
    virtual void setScanningState(unsigned int, bool, apple80211_scan_data*, int) override;

    // native virtual slot 0xb98
public:
    virtual void setDataPathState(bool) override;

    // native virtual slot 0xba0
public:
    virtual void * getScanManager() override;

    // native virtual slot 0xbb0
public:
    virtual void updateLinkParameters(apple80211_interface_availability*) override;

    // native virtual slot 0xbb8
public:
    virtual void updateInterfaceCoexRiskPct(unsigned long long) override;

    // native virtual slot 0xbc0
public:
    virtual void setLQM(unsigned long long) override;

    // native virtual slot 0xbc8
public:
    virtual void updateLinkStatus() override;

    // native virtual slot 0xbd0
public:
    virtual void updateLinkStatusGated() override;

    // native virtual slot 0xbd8
public:
    virtual void setInterfaceExtendedCCA(apple80211_channel, apple80211_cca_report*) override;

    // native virtual slot 0xbe0
public:
    virtual void setInterfaceCCA(apple80211_channel, int) override;

    // native virtual slot 0xbe8
public:
    virtual void setInterfaceNF(apple80211_channel, long long) override;

    // native virtual slot 0xbf0
public:
    virtual void setInterfaceOFDMDesense(apple80211_channel, long long) override;

    // native virtual slot 0xc00
public:
    virtual void setDebugFlags(unsigned long long, unsigned int) override;

    // native virtual slot 0xc08
public:
    virtual SInt64 debugFlags() override;

    // native virtual slot 0xc10
public:
    virtual void setInterfaceChipCounters(apple80211_stat_report*, apple80211_chip_counters_tx*, apple80211_chip_error_counters_tx*, apple80211_chip_counters_rx*) override;

    // native virtual slot 0xc18
public:
    virtual void setInterfaceMIBdot11(apple80211_stat_report*, apple80211_ManagementInformationBasedot11_counters*) override;

    // native virtual slot 0xc20
public:
    virtual void setFrameStats(apple80211_stat_report*, apple80211_frame_counters*) override;

    // native virtual slot 0xc28
public:
    virtual void setInfraSpecificFrameStats(apple80211_stat_report*, apple80211_infra_specific_stats*) override;

    // native virtual slot 0xc30
private:
    virtual void __tahoe_slot_c30() __asm__("__ZN21IO80211InfraInterface19setRxDataStallStatsEP22apple80211_stat_reportP31apple80211_rx_data_stall_report") override;

    // native virtual slot 0xc38
public:
    virtual SInt64 getWmeTxCounters(unsigned long long*) override;

    // native virtual slot 0xc40
public:
    virtual void setPeerManagerLogFlag(unsigned int, unsigned int, unsigned int) override;

    // native virtual slot 0xc48
public:
    virtual void setWoWEnabled(bool) override;

    // native virtual slot 0xc50
public:
    virtual bool wowEnabled() override;

    // native virtual slot 0xcb0
public:
    virtual UInt64 createLinkQualityMonitor(IO80211Peer*, bool) override;

    // native virtual slot 0xcb8
public:
    virtual void releaseLinkQualityMonitor(IO80211Peer*) override;

    // native virtual slot 0xd58
public:
    virtual int getAssocState() override;

    // native virtual slot 0xdb0
public:
    virtual void * getLQMSummary(apple80211_lqm_summary*) override;

    // native virtual slot 0xe68
public:
    virtual bool setLinkState(IO80211LinkState, unsigned int, bool, unsigned int, unsigned int);

    // native virtual slot 0xe70
public:
    virtual IOReturn setLinkStateInternal(IO80211LinkState, unsigned int, bool, unsigned int, unsigned int);

    // native virtual slot 0xe78
private:
    virtual void __tahoe_slot_e78() __asm__("__ZN21IO80211InfraInterface19setCurrentApAddressEP10ether_addr");

    // native virtual slot 0xe80
public:
    virtual void setWCL_ADVISORTY_INFO(apple80211_wcl_advisory_info*);

    // native virtual slot 0xe88
public:
    virtual void * getWCL_TX_RX_LATENCY(apple80211_wcl_tx_rx_latency*);

    // native virtual slot 0xe90
public:
    virtual IOReturn setWCL_LINK_STATE_UPDATE(apple80211_wcl_update_link_state*);

    // native virtual slot 0xe98
private:
    virtual void __tahoe_slot_e98() __asm__("__ZN21IO80211InfraInterface13createLQMDataEv");

    // native virtual slot 0xea0
public:
    virtual IOReturn setMacAddress(mloAddrArray &) = 0;

protected:
    uint8_t __tahoe_opaque_state[0x8];
};
static_assert(sizeof(IO80211InfraInterface) == 0x130, "25G241 IO80211InfraInterface size");
