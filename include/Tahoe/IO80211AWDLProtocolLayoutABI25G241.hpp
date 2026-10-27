// Compile-only AWDLProtocol slot/layout witness for macOS 26.7.1 (25G241).
// This is not an Apple class declaration or a production subclass. It adds no
// object fields, has no method bodies, must not be instantiated, and is not
// linked into the kext. The base is the separate VIF layout witness.
#pragma once

#include <stdint.h>
#include <type_traits>

#include "IO80211VirtualInterfaceABI25G241.hpp"

// These names are present in the native method symbols but are intentionally
// incomplete here. Their pointee layouts and any Apple typedef spellings are
// not established by the vtable evidence.
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

namespace TahoeAwdl25G241AwdlABI {

using Status32 = TahoeAwdl25G241VifABI::Status32;

constexpr unsigned int kFirstAwdlProtocolSlot = 505;
constexpr unsigned int kLastAwdlProtocolSlot = 567;
constexpr unsigned int kAwdlProtocolVtableSlots = 568;
constexpr unsigned int kInheritedSetMacAddressSlot = 488;
constexpr unsigned int kAwdlProtocolAddedPureSlotCount = 63;
constexpr unsigned int kAwdlProtocolTotalPureSlotCount = 64;
constexpr unsigned int kInstanceSize = 0x130;

// The 63 declarations below preserve the observed pure-slot order and
// pointer parameter names from the 25G241 vtable witness. Status32 is only an
// ABI-equivalent 32-bit status type for methods whose callers/concrete
// implementations use EAX32; it does not claim Apple's source typedef.
// Selector 149/151 callbacks use IOReturn because their call paths establish
// that source return type independently.
class IO80211AWDLProtocolLayoutWitness25G241
    : public TahoeAwdl25G241VifABI::IO80211VirtualInterfaceLayoutWitness25G241 {
public:
    ~IO80211AWDLProtocolLayoutWitness25G241() override;
    const OSMetaClass *getMetaClass() const override;

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

static_assert(sizeof(void *) == 8, "25G241 AWDL witness requires x86_64");
static_assert(sizeof(IO80211AWDLProtocolLayoutWitness25G241) == kInstanceSize,
              "AWDL witness must preserve the native 0x130-byte instance size");
static_assert(std::is_abstract<IO80211AWDLProtocolLayoutWitness25G241>::value,
              "AWDL witness must remain abstract and non-instantiable");
static_assert(kFirstAwdlProtocolSlot + kAwdlProtocolAddedPureSlotCount ==
                  kAwdlProtocolVtableSlots,
              "AWDL added slot count changed");
static_assert(kLastAwdlProtocolSlot + 1 == kAwdlProtocolVtableSlots,
              "AWDL final slot boundary changed");
static_assert(kAwdlProtocolTotalPureSlotCount ==
                  1 + kAwdlProtocolAddedPureSlotCount,
              "inherited and added pure slot counts changed");

} // namespace TahoeAwdl25G241AwdlABI
