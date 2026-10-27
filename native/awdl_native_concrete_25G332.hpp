// 25G332 ABI-reconstructed, offline-only native AWDL subclass gate.
//
// These declarations are compiled by the offline ABI gate and the explicitly
// selected 25G332 unpublished init/cleanup observation.
// They reconstruct the local Tahoe ABI witness with genuine Apple class names so
// the generated metaclass references the native IO80211AWDLProtocol symbols.
// They are not a supported Apple header or a functional AWDL interface. The
// observation child rejects attach/start and does not activate these protocol
// callbacks, a scheduler, a peer manager or a packet path.
#pragma once

#include <stdint.h>

#include "Tahoe/Types.h"
#include "Tahoe/IO80211SkywalkInterface.h"

using Status32 = int32_t;
struct apple80211_awdl_election_params;
struct apple80211_awdl_device_capabilities;
struct apple80211_encrypt;
struct apple80211_awdl_txcal_period;
struct apple80211_awdl_dev_stats;
struct apple80211_awdl_dfsp_config;
struct apple80211_awdl_cca;
struct apple80211_llw_params;
struct apple80211_peer_cache_control;
struct awdl_peer_advert_add;
struct apple80211_awdl_dfsp_ucsa_config;
struct apple80211_companion_skywalk_if_create;
struct apple80211_awdl_af_sec_payload_request;
struct apple80211_tx_rate;
struct apple80211_p2p_coex_protection;
struct apple80211_awdl_psf_dwell_params;
struct apple80211_awdl_config_request;
struct apple80211_rtg_peer_stats_cfg;
struct peerSlotDataStats;
struct packetCounters_t;

class IO80211VirtualInterface
    : public IO80211SkywalkInterface {
public:
    bool hasVirtualPrivate25G332() const {
        return __opaque_private_pointer != nullptr;
    }
    void freeBpfResources();
    virtual ~IO80211VirtualInterface() override;
    const OSMetaClass *getMetaClass() const override;
    void free() override;
    IOReturn configureReport(IOReportChannelList *, unsigned int, void *, void *) override;
    IOReturn updateReport(IOReportChannelList *, unsigned int, void *, void *) override;
    bool start(IOService *) override;
    void stop(IOService *) override;
    bool terminate(IOOptionBits options = 0) override;
    bool attach(IOService *) override;
    void detach(IOService *) override;
    IOReturn newUserClient(task *, void *, unsigned int, OSDictionary *, IOUserClient **) override;
    const char *stringFromReturn(int) override;
    IOReturn enable(unsigned int) override;
    IOReturn prepareBSDInterface(__ifnet *, unsigned int) override;
    IOReturn processBSDCommand(__ifnet *, unsigned int, void *) override;
    SInt32 setInterfaceEnable(bool) override;
    UInt getFeatureFlags() override;
    bool bpfTap(unsigned int, unsigned int) override;
    bool setMulticastAddresses(ether_addr const *, unsigned int) override;
    void *createPeerManager() override;
    void postMessage(unsigned int, void *, unsigned long, bool) override;
    void logTxPacket(IO80211NetworkPacket *, PacketSkywalkScratch *, apple80211_wme_ac, bool) override;
    void logTxCompletionPacket(IO80211NetworkPacket *, PacketSkywalkScratch *, unsigned char *, apple80211_wme_ac, int, unsigned int, bool, bool) override;
    IOReturn inputPacket(IO80211NetworkPacket *, packet_info_tag *, ether_header *, bool *, bool) override;
    void logSkywalkTxReqPacket(IO80211NetworkPacket *, PacketSkywalkScratch *, unsigned char *, apple80211_wme_ac, bool) override;
    SInt64 pendingPackets(unsigned char) override;
    SInt64 packetSpace(unsigned char) override;
    IO80211LinkState linkState() override;
    void setScanningState(unsigned int, bool, apple80211_scan_data *, int) override;
    void updateLinkParameters(apple80211_interface_availability *) override;
    void updateInterfaceCoexRiskPct(unsigned long long) override;
    void setInterfaceNF(apple80211_channel, long long) override;
    void setDebugFlags(unsigned long long, unsigned int) override;
    SInt64 debugFlags() override;
    void setInterfaceChipCounters(apple80211_stat_report *, apple80211_chip_counters_tx *, apple80211_chip_error_counters_tx *, apple80211_chip_counters_rx *) override;
    void setInterfaceMIBdot11(apple80211_stat_report *, apple80211_ManagementInformationBasedot11_counters *) override;
    void setFrameStats(apple80211_stat_report *, apple80211_frame_counters *) override;
    void setInfraSpecificFrameStats(apple80211_stat_report *, apple80211_infra_specific_stats *) override;
    SInt64 getWmeTxCounters(unsigned long long *) override;
    void setWoWEnabled(bool) override;
    bool wowEnabled() override;
    void printDataPath(userPrintCtx *) override;
    bool findOrCreateFlowQueue(IO80211FlowQueueHash) override;
    UInt64 findOrCreateFlowQueueWithCache(IO80211FlowQueueHash, bool *) override;
    UInt64 findExistingFlowQueue(IO80211FlowQueueHash) override;
    void removePacketQueue(IO80211FlowQueueHash const *) override;
    void flushPacketQueues() override;
    void cachePeer(ether_addr *, unsigned int *) override;
    bool shouldLog(unsigned long long) override;
    void vlogDebug(unsigned long long, char const *, va_list) override;
    void vlogDebugBPF(unsigned long long, char const *, va_list) override;
    void *getP2PSkywalkPeerMgr() override;

private:
    // Slot-only override for the parent's intentionally opaque slot-410
    // declaration. See the class note above; the native argument is unknown
    // to the current Tahoe base header.
    void __tahoe_slot_cd0() __asm__("__ZN23IO80211VirtualInterface8findPeerER10ether_addr") override;

public:
    int getEventPipeSize() override;
    UInt64 createEventPipe(IO80211APIUserClient *) override;

    // Slots 461–487. Parameters are from exact native vtable target symbols.
    // A slot-only void return below means the linked implementation/callers do
    // not settle a C++ return type; it must not be used as a callable API.
    virtual bool init(IO80211Controller *, ether_addr *, unsigned int, char const *);
    virtual void setLinkState(IO80211LinkState, unsigned int);
    virtual void forwardPacket(IO80211NetworkPacket *); // return ABI unresolved; layout only
    virtual Status32 handleIoctl(__ifnet *, unsigned long, void *);
    virtual void addPeerToCache(unsigned char *); // return ABI unresolved; layout only
    virtual void deletePeerFromCache(unsigned char *); // return ABI unresolved; layout only
    virtual bool handleDebugCmd(apple80211_debug_command *);
    virtual Status32 getPeerSlotDataStats(ether_addr *, bool, peerSlotDataStats *);
    virtual void getPeerDataStats(ether_addr *, bool, packetCounters_t *); // return ABI unresolved; layout only
    virtual void clearPeerDataStats(ether_addr *, bool); // return ABI unresolved; layout only
    virtual void setAwdlCurrentChannelSequenceIndex(unsigned int);
    virtual bool isOutputFlowControlled();
    virtual void setOutputFlowControlled();
    virtual void clearOutputFlowControlled();
    virtual void flushFlowQueues(ether_addr *);
    virtual void configureAQMOutput(); // old header says UInt32; 25G241 callers do not resolve it
    virtual bool attachToBpf();
    virtual bool configureIfnet();
    virtual void reset(); // EAX32 zero is visible; source return type/call contract unresolved
    virtual void dupAndTransmitMcastPacket(IO80211NetworkPacket *, unsigned char *, unsigned char *);
    virtual void freeMulticastPacket(IO80211NetworkPacket *);
    virtual void triggerAWDLMulticastTx(unsigned int, unsigned char);
    virtual unsigned int p2pMulticastTx(IO80211NetworkPacket **, unsigned int);
    virtual void p2pMulticastTx(unsigned int, bool);
    virtual void signalMulticastPackets(unsigned int, unsigned int);
    virtual void sendPendingPacketsToStack(IO80211NetworkPacket **, unsigned int);
    virtual void freePendingPackets(IO80211NetworkPacket **, unsigned int);

    // Concrete Broadcom implementation returns EAX32 and the native caller
    // consumes that value as a status. int32_t preserves the ABI width without
    // claiming the original Apple typedef.
    virtual Status32 setMacAddress(ether_addr &) = 0;

    virtual void _RESERVEDIO80211VirtualInterface0();
    virtual void _RESERVEDIO80211VirtualInterface1();
    virtual void _RESERVEDIO80211VirtualInterface2();
    virtual void _RESERVEDIO80211VirtualInterface3();
    virtual void _RESERVEDIO80211VirtualInterface4();
    virtual void _RESERVEDIO80211VirtualInterface5();
    virtual void _RESERVEDIO80211VirtualInterface6();
    virtual void _RESERVEDIO80211VirtualInterface7();
    virtual void _RESERVEDIO80211VirtualInterface8();
    virtual void _RESERVEDIO80211VirtualInterface9();
    virtual void _RESERVEDIO80211VirtualInterface10();
    virtual void _RESERVEDIO80211VirtualInterface11();
    virtual void _RESERVEDIO80211VirtualInterface12();
    virtual void _RESERVEDIO80211VirtualInterface13();
    virtual void _RESERVEDIO80211VirtualInterface14();
    virtual void _RESERVEDIO80211VirtualInterface15();

private:
    // The pointee and the surrounding private allocation are opaque. The
    // pointer's presence and offset are the only field facts established.
    void *__opaque_private_pointer;
};

class IO80211AWDLProtocol
    : public IO80211VirtualInterface {
public:
    OSDeclareAbstractStructors(IO80211AWDLProtocol)

    // Slots 505-531: native get callbacks.
    virtual Status32 getSSID(apple80211_ssid_data *) = 0;
    virtual Status32 getCHANNEL(apple80211_channel_data *) = 0;
    virtual Status32 getBSSID(apple80211_bssid_data *) = 0;
    virtual Status32 getSTATE(apple80211_state_data *) = 0;
    virtual Status32 getAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *) = 0;
    virtual Status32 getAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *) = 0;
    virtual Status32 getAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(
        apple80211_awdl_extension_state_machine_parameter *) = 0;
    virtual Status32 getAWDL_ELECTION_ID(apple80211_awdl_election_id *) = 0;
    virtual Status32 getAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *) = 0;
    virtual Status32 getAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(
        apple80211_awdl_sync_channel_sequence *) = 0;
    virtual Status32 getPEER_CACHE_MAXIMUM_SIZE(
        apple80211_peer_cache_maximum_size *) = 0;
    virtual Status32 getAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *) = 0;
    virtual Status32 getAWDL_SYNC_STATE(apple80211_awdl_sync_state *) = 0;
    virtual Status32 getAWDL_ELECTION_RSSI_THRESHOLDS(
        apple80211_awdl_election_rssi_thresholds *) = 0;
    virtual Status32 getAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *) = 0;
    virtual Status32 getAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *) = 0;
    virtual Status32 getAWDL_DEVICE_CAPABILITIES(
        apple80211_awdl_device_capabilities *) = 0;
    virtual Status32 getAWDL_SECONDARY_MASTER_CHANNEL(
        apple80211_awdl_secondary_master_channel *) = 0;
    virtual Status32 getAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *) = 0;
    virtual Status32 getAWDL_MIN_RATE(apple80211_awdl_min_rate *) = 0;
    virtual Status32 getAWDL_ENCRYPTION_TYPE(apple80211_encrypt *) = 0;
    virtual Status32 getAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *) = 0;
    virtual Status32 getAWDL_DEV_STATS(apple80211_awdl_dev_stats *) = 0;
    virtual Status32 getAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *) = 0;
    virtual Status32 getAWDL_CCA(apple80211_awdl_cca *) = 0;
    virtual Status32 getAWDL_AF_SECONDARY_PAYLOAD_CAPABILITIES(
        apple80211_awdl_cap *) = 0;
    virtual Status32 getLLW_PARAMS(apple80211_llw_params *) = 0;

    // Slots 532-567: native set callbacks.
    virtual Status32 setSSID(apple80211_ssid_data *) = 0;
    virtual Status32 setCHANNEL(apple80211_channel_data *) = 0;
    virtual Status32 setAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *) = 0;
    virtual Status32 setAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *) = 0;
    virtual Status32 setAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(
        apple80211_awdl_extension_state_machine_parameter *) = 0;
    virtual Status32 setAWDL_ELECTION_ID(apple80211_awdl_election_id *) = 0;
    virtual Status32 setAWDL_BSSID(apple80211_awdl_bssid *) = 0;
    virtual Status32 setAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *) = 0;
    virtual Status32 setAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(
        apple80211_awdl_sync_channel_sequence *) = 0;
    virtual Status32 setAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *) = 0;
    virtual Status32 setAWDL_SYNC_STATE(apple80211_awdl_sync_state *) = 0;
    virtual Status32 setAWDL_ELECTION_RSSI_THRESHOLDS(
        apple80211_awdl_election_rssi_thresholds *) = 0;
    virtual Status32 setAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *) = 0;
    virtual Status32 setPEER_CACHE_CONTROL(apple80211_peer_cache_control *) = 0;
    virtual IOReturn setAWDL_OOB_REQUEST(apple80211_awdl_oob_request *) = 0;
    virtual IOReturn setAWDL_SYNC_FRAME_TEMPLATE(
        apple80211_awdl_sync_frame_template *) = 0;
    virtual Status32 setAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *) = 0;
    virtual Status32 setAWDL_PEER_TRAFFIC_REGISTRATION(
        apple80211_awdl_peer_traffic_registration *) = 0;
    virtual Status32 setAWDL_SECONDARY_MASTER_CHANNEL(
        apple80211_awdl_secondary_master_channel *) = 0;
    virtual Status32 setAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *) = 0;
    virtual Status32 setAWDL_MIN_RATE(apple80211_awdl_min_rate *) = 0;
    virtual Status32 setAWDL_ENCRYPTION_KEYS(apple80211_key *) = 0;
    virtual Status32 setAWDL_ENCRYPTION_TYPE(apple80211_encrypt *) = 0;
    virtual Status32 setAWDL_OOB_AUTO_REQUEST(apple80211_awdl_oob_request *) = 0;
    virtual Status32 setAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *) = 0;
    virtual Status32 setAWDL_AWDL_ADVERTISERS(awdl_peer_advert_add *) = 0;
    virtual Status32 setAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *) = 0;
    virtual Status32 setAWDL_DFSP_UCSA_CONFIG(apple80211_awdl_dfsp_ucsa_config *) = 0;
    virtual Status32 setCOMPANION_SKYWALK_IF_CREATE(
        apple80211_companion_skywalk_if_create *) = 0;
    virtual Status32 setAWDL_OOB_SEC_PAYLOAD_REQUEST(
        apple80211_awdl_af_sec_payload_request *) = 0;
    virtual Status32 setLLW_PARAMS(apple80211_llw_params *) = 0;
    virtual Status32 setTX_RATE(apple80211_tx_rate *) = 0;
    virtual Status32 setP2P_COEX_PROTECTION(apple80211_p2p_coex_protection *) = 0;
    virtual Status32 setPSF_DWELL(apple80211_awdl_psf_dwell_params *) = 0;
    virtual Status32 setAWDL_CONFIG(apple80211_awdl_config_request *) = 0;
    virtual Status32 setAWDL_RTG_PEER_STATS_CONFIG(
        apple80211_rtg_peer_stats_cfg *) = 0;
};

class ItlAwdlNativeConcreteGate25G332 : public IO80211AWDLProtocol {
    // The observation uses this as an abstract-allocator callback parent.
    // The 64 request callbacks remain fail-closed and are never advertised.
#if defined(ITL_AWDL_ALLOCATOR_VARIANT_25G332)
    // The independent allocator gate opts into the SDK's concrete structors.
    // Normal builds retain the abstract, null-allocator behavior below.
    OSDeclareDefaultStructors(ItlAwdlNativeConcreteGate25G332)
#else
    OSDeclareAbstractStructors(ItlAwdlNativeConcreteGate25G332)
#endif
public:
    Status32 setMacAddress(ether_addr &) override;
    Status32 getSSID(apple80211_ssid_data *) override;
    Status32 getCHANNEL(apple80211_channel_data *) override;
    Status32 getBSSID(apple80211_bssid_data *) override;
    Status32 getSTATE(apple80211_state_data *) override;
    Status32 getAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *) override;
    Status32 getAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *) override;
    Status32 getAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(apple80211_awdl_extension_state_machine_parameter *) override;
    Status32 getAWDL_ELECTION_ID(apple80211_awdl_election_id *) override;
    Status32 getAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *) override;
    Status32 getAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(apple80211_awdl_sync_channel_sequence *) override;
    Status32 getPEER_CACHE_MAXIMUM_SIZE(apple80211_peer_cache_maximum_size *) override;
    Status32 getAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *) override;
    Status32 getAWDL_SYNC_STATE(apple80211_awdl_sync_state *) override;
    Status32 getAWDL_ELECTION_RSSI_THRESHOLDS(apple80211_awdl_election_rssi_thresholds *) override;
    Status32 getAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *) override;
    Status32 getAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *) override;
    Status32 getAWDL_DEVICE_CAPABILITIES(apple80211_awdl_device_capabilities *) override;
    Status32 getAWDL_SECONDARY_MASTER_CHANNEL(apple80211_awdl_secondary_master_channel *) override;
    Status32 getAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *) override;
    Status32 getAWDL_MIN_RATE(apple80211_awdl_min_rate *) override;
    Status32 getAWDL_ENCRYPTION_TYPE(apple80211_encrypt *) override;
    Status32 getAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *) override;
    Status32 getAWDL_DEV_STATS(apple80211_awdl_dev_stats *) override;
    Status32 getAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *) override;
    Status32 getAWDL_CCA(apple80211_awdl_cca *) override;
    Status32 getAWDL_AF_SECONDARY_PAYLOAD_CAPABILITIES(apple80211_awdl_cap *) override;
    Status32 getLLW_PARAMS(apple80211_llw_params *) override;
    Status32 setSSID(apple80211_ssid_data *) override;
    Status32 setCHANNEL(apple80211_channel_data *) override;
    Status32 setAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *) override;
    Status32 setAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *) override;
    Status32 setAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(apple80211_awdl_extension_state_machine_parameter *) override;
    Status32 setAWDL_ELECTION_ID(apple80211_awdl_election_id *) override;
    Status32 setAWDL_BSSID(apple80211_awdl_bssid *) override;
    Status32 setAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *) override;
    Status32 setAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(apple80211_awdl_sync_channel_sequence *) override;
    Status32 setAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *) override;
    Status32 setAWDL_SYNC_STATE(apple80211_awdl_sync_state *) override;
    Status32 setAWDL_ELECTION_RSSI_THRESHOLDS(apple80211_awdl_election_rssi_thresholds *) override;
    Status32 setAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *) override;
    Status32 setPEER_CACHE_CONTROL(apple80211_peer_cache_control *) override;
    IOReturn setAWDL_OOB_REQUEST(apple80211_awdl_oob_request *) override;
    IOReturn setAWDL_SYNC_FRAME_TEMPLATE(apple80211_awdl_sync_frame_template *) override;
    Status32 setAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *) override;
    Status32 setAWDL_PEER_TRAFFIC_REGISTRATION(apple80211_awdl_peer_traffic_registration *) override;
    Status32 setAWDL_SECONDARY_MASTER_CHANNEL(apple80211_awdl_secondary_master_channel *) override;
    Status32 setAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *) override;
    Status32 setAWDL_MIN_RATE(apple80211_awdl_min_rate *) override;
    Status32 setAWDL_ENCRYPTION_KEYS(apple80211_key *) override;
    Status32 setAWDL_ENCRYPTION_TYPE(apple80211_encrypt *) override;
    Status32 setAWDL_OOB_AUTO_REQUEST(apple80211_awdl_oob_request *) override;
    Status32 setAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *) override;
    Status32 setAWDL_AWDL_ADVERTISERS(awdl_peer_advert_add *) override;
    Status32 setAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *) override;
    Status32 setAWDL_DFSP_UCSA_CONFIG(apple80211_awdl_dfsp_ucsa_config *) override;
    Status32 setCOMPANION_SKYWALK_IF_CREATE(apple80211_companion_skywalk_if_create *) override;
    Status32 setAWDL_OOB_SEC_PAYLOAD_REQUEST(apple80211_awdl_af_sec_payload_request *) override;
    Status32 setLLW_PARAMS(apple80211_llw_params *) override;
    Status32 setTX_RATE(apple80211_tx_rate *) override;
    Status32 setP2P_COEX_PROTECTION(apple80211_p2p_coex_protection *) override;
    Status32 setPSF_DWELL(apple80211_awdl_psf_dwell_params *) override;
    Status32 setAWDL_CONFIG(apple80211_awdl_config_request *) override;
    Status32 setAWDL_RTG_PEER_STATS_CONFIG(apple80211_rtg_peer_stats_cfg *) override;
};

static_assert(sizeof(void *) == 8, "25G332 ABI gate is x86_64 only");
static_assert(sizeof(IO80211SkywalkInterface) == 0x128,
              "native Skywalk parent must be 0x128 bytes");
static_assert(sizeof(IO80211VirtualInterface) == 0x130,
              "native VIF parent must be 0x130 bytes");
static_assert(sizeof(IO80211AWDLProtocol) == 0x130,
              "native AWDL parent must be 0x130 bytes");
static_assert(sizeof(ItlAwdlNativeConcreteGate25G332) == 0x130,
              "concrete prototype must add no instance state");
static_assert(!__is_abstract(ItlAwdlNativeConcreteGate25G332),
              "all inherited native pure slots must be implemented");
