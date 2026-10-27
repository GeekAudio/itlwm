#if !defined(AIRPORT_TAHOE) || defined(ITL_NATIVE_AWDL_INIT_OBSERVATION_25G332) || defined(ITL_NATIVE_AWDL_LIFECYCLE_25G332)
// Compile/link-only concrete AWDL subclass gate for macOS 26 build 25G332.
// No allocator, controller publication, interface registration, HAL, or RF path
// is called from this translation unit.
#include "awdl_native_concrete_25G332.hpp"

// Keep OSMetaClass inheritance linked against Apple's real IO80211AWDLProtocol.
// The allocator probe is a compile-only opt-in; ordinary builds keep alloc null.
#if defined(ITL_AWDL_ALLOCATOR_VARIANT_25G332)
OSDefineMetaClassAndStructors(ItlAwdlNativeConcreteGate25G332,
                             IO80211AWDLProtocol)
#else
OSDefineMetaClassAndAbstractStructors(ItlAwdlNativeConcreteGate25G332,
                                     IO80211AWDLProtocol)
#endif

Status32 ItlAwdlNativeConcreteGate25G332::setMacAddress(ether_addr &) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getSSID(apple80211_ssid_data *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getCHANNEL(apple80211_channel_data *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getBSSID(apple80211_bssid_data *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getSTATE(apple80211_state_data *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(apple80211_awdl_extension_state_machine_parameter *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_ELECTION_ID(apple80211_awdl_election_id *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(apple80211_awdl_sync_channel_sequence *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getPEER_CACHE_MAXIMUM_SIZE(apple80211_peer_cache_maximum_size *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_SYNC_STATE(apple80211_awdl_sync_state *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_ELECTION_RSSI_THRESHOLDS(apple80211_awdl_election_rssi_thresholds *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_DEVICE_CAPABILITIES(apple80211_awdl_device_capabilities *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_SECONDARY_MASTER_CHANNEL(apple80211_awdl_secondary_master_channel *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_MIN_RATE(apple80211_awdl_min_rate *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_ENCRYPTION_TYPE(apple80211_encrypt *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_DEV_STATS(apple80211_awdl_dev_stats *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_CCA(apple80211_awdl_cca *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getAWDL_AF_SECONDARY_PAYLOAD_CAPABILITIES(apple80211_awdl_cap *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::getLLW_PARAMS(apple80211_llw_params *) {
    return kIOReturnNotReady;
}

Status32 ItlAwdlNativeConcreteGate25G332::setSSID(apple80211_ssid_data *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setCHANNEL(apple80211_channel_data *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(apple80211_awdl_extension_state_machine_parameter *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_ELECTION_ID(apple80211_awdl_election_id *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_BSSID(apple80211_awdl_bssid *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(apple80211_awdl_sync_channel_sequence *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_SYNC_STATE(apple80211_awdl_sync_state *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_ELECTION_RSSI_THRESHOLDS(apple80211_awdl_election_rssi_thresholds *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setPEER_CACHE_CONTROL(apple80211_peer_cache_control *) {
    return kIOReturnUnsupported;
}

IOReturn ItlAwdlNativeConcreteGate25G332::setAWDL_OOB_REQUEST(apple80211_awdl_oob_request *) {
    return kIOReturnUnsupported;
}

IOReturn ItlAwdlNativeConcreteGate25G332::setAWDL_SYNC_FRAME_TEMPLATE(apple80211_awdl_sync_frame_template *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_PEER_TRAFFIC_REGISTRATION(apple80211_awdl_peer_traffic_registration *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_SECONDARY_MASTER_CHANNEL(apple80211_awdl_secondary_master_channel *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_MIN_RATE(apple80211_awdl_min_rate *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_ENCRYPTION_KEYS(apple80211_key *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_ENCRYPTION_TYPE(apple80211_encrypt *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_OOB_AUTO_REQUEST(apple80211_awdl_oob_request *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_AWDL_ADVERTISERS(awdl_peer_advert_add *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_DFSP_UCSA_CONFIG(apple80211_awdl_dfsp_ucsa_config *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setCOMPANION_SKYWALK_IF_CREATE(apple80211_companion_skywalk_if_create *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_OOB_SEC_PAYLOAD_REQUEST(apple80211_awdl_af_sec_payload_request *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setLLW_PARAMS(apple80211_llw_params *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setTX_RATE(apple80211_tx_rate *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setP2P_COEX_PROTECTION(apple80211_p2p_coex_protection *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setPSF_DWELL(apple80211_awdl_psf_dwell_params *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_CONFIG(apple80211_awdl_config_request *) {
    return kIOReturnUnsupported;
}

Status32 ItlAwdlNativeConcreteGate25G332::setAWDL_RTG_PEER_STATS_CONFIG(apple80211_rtg_peer_stats_cfg *) {
    return kIOReturnUnsupported;
}

#endif
