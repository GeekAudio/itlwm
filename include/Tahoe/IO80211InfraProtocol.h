// Independently reconstructed from this machine's Apple25G241 BootKC.
// No third-party port header was copied. See evidence/25G241-native-vtables.json.
#pragma once
#include "Types.h"
#include "IO80211InfraInterface.h"

class IO80211InfraProtocol : public IO80211InfraInterface {
    OSDeclareAbstractStructors(IO80211InfraProtocol)

    // native virtual slot 0xea8
public:
    virtual IOReturn getCHANNEL(apple80211_channel_data*) = 0;

    // native virtual slot 0xeb0
public:
    virtual IOReturn getPOWERSAVE(apple80211_powersave_data*) = 0;

    // native virtual slot 0xeb8
public:
    virtual IOReturn getTXPOWER(apple80211_txpower_data*) = 0;

    // native virtual slot 0xec0
public:
    virtual IOReturn getRATE(apple80211_rate_data*) = 0;

    // native virtual slot 0xec8
public:
    virtual IOReturn getOP_MODE(apple80211_opmode_data*) = 0;

    // native virtual slot 0xed0
public:
    virtual IOReturn getRSSI(apple80211_rssi_data*) = 0;

    // native virtual slot 0xed8
public:
    virtual IOReturn getSUPPORTED_CHANNELS(apple80211_sup_channel_data*) = 0;

    // native virtual slot 0xee0
public:
    virtual IOReturn getGUARD_INTERVAL(apple80211_guard_interval_data*) = 0;

    // native virtual slot 0xee8
public:
    virtual IOReturn getMCS(apple80211_mcs_data*) = 0;

    // native virtual slot 0xef0
public:
    virtual IOReturn getPOWER_DEBUG_INFO(apple80211_power_debug_info*) = 0;

    // native virtual slot 0xef8
public:
    virtual IOReturn getHT_CAPABILITY(apple80211_ht_capability*) = 0;

    // native virtual slot 0xf00
public:
    virtual IOReturn getMCS_VHT(apple80211_mcs_vht_data*) = 0;

    // native virtual slot 0xf08
public:
    virtual IOReturn getCHANNELS_INFO(apple80211_channels_info*) = 0;

    // native virtual slot 0xf10
public:
    virtual IOReturn getVHT_CAPABILITY(apple80211_vht_capability*) = 0;

    // native virtual slot 0xf18
public:
    virtual IOReturn getROAM_PROFILE(apple80211_roam_profile_all_bands*) = 0;

    // native virtual slot 0xf20
public:
    virtual IOReturn getCHIP_COUNTER_STATS(apple80211_chip_stats*) = 0;

    // native virtual slot 0xf28
public:
    virtual IOReturn getDBG_GUARD_TIME_PARAMS(apple80211_dbg_guard_time_params*) = 0;

    // native virtual slot 0xf30
public:
    virtual IOReturn getLEAKY_AP_STATS_MODE(apple80211_leaky_ap_setting*) = 0;

    // native virtual slot 0xf38
public:
    virtual IOReturn getCOUNTRY_CHANNELS(apple80211_country_channel_data*) = 0;

    // native virtual slot 0xf40
public:
    virtual IOReturn getPRIVATE_MAC(apple80211_private_mac_data*) = 0;

    // native virtual slot 0xf48
public:
    virtual IOReturn getRANGING_ENABLE(apple80211_ranging_enable_request_t*) = 0;

    // native virtual slot 0xf50
public:
    virtual IOReturn getRANGING_START(apple80211_ranging_start_request_t*) = 0;

    // native virtual slot 0xf58
public:
    virtual IOReturn getAWDL_RSDB_CAPS(apple80211_rsdb_capability*) = 0;

    // native virtual slot 0xf60
public:
    virtual IOReturn getTKO_PARAMS(apple80211_tko_params*) = 0;

    // native virtual slot 0xf68
public:
    virtual IOReturn getTKO_DUMP(apple80211_tko_dump*) = 0;

    // native virtual slot 0xf70
public:
    virtual IOReturn getHW_SUPPORTED_CHANNELS(apple80211_sup_channel_data*) = 0;

    // native virtual slot 0xf78
public:
    virtual IOReturn getBTCOEX_PROFILE(apple80211_btcoex_profile*) = 0;

    // native virtual slot 0xf80
public:
    virtual IOReturn getBTCOEX_PROFILE_ACTIVE(apple80211_btcoex_profile_active_data*) = 0;

    // native virtual slot 0xf88
public:
    virtual IOReturn getTRAP_INFO(apple80211_trap_info_data*) = 0;

    // native virtual slot 0xf90
public:
    virtual IOReturn getTHERMAL_INDEX(apple80211_thermal_index_t*) = 0;

    // native virtual slot 0xf98
public:
    virtual IOReturn getMAX_NSS_FOR_AP(apple80211_btcoex_max_nss_for_ap_data*) = 0;

    // native virtual slot 0xfa0
public:
    virtual IOReturn getBTCOEX_2G_CHAIN_DISABLE(apple80211_btcoex_2g_chain_disable*) = 0;

    // native virtual slot 0xfa8
public:
    virtual IOReturn getPOWER_BUDGET(apple80211_power_budget_t*) = 0;

    // native virtual slot 0xfb0
public:
    virtual IOReturn getOFFLOAD_TCPKA_ENABLE(apple80211_offload_tcpka_enable_t*) = 0;

    // native virtual slot 0xfb8
public:
    virtual IOReturn getRANGING_CAPS(apple80211_ranging_capabilities_t*) = 0;

    // native virtual slot 0xfc0
public:
    virtual IOReturn getLQM_CONFIG(apple80211_lqm_config_t*) = 0;

    // native virtual slot 0xfc8
public:
    virtual IOReturn getTRAP_CRASHTRACER_MINI_DUMP(apple80211_trap_mini_dump_data*) = 0;

    // native virtual slot 0xfd0
public:
    virtual IOReturn getBEACON_INFO(apple80211_beacon_info_t*) = 0;

    // native virtual slot 0xfd8
public:
    virtual IOReturn getCHIP_POWER_RANGE(apple80211_chip_power_limit*) = 0;

    // native virtual slot 0xfe0
public:
    virtual IOReturn getNSS(apple80211_nss_data*) = 0;

    // native virtual slot 0xfe8
public:
    virtual IOReturn getHW_ADDR(apple80211_hw_mac_address*) = 0;

    // native virtual slot 0xff0
public:
    virtual IOReturn getCHIP_DIAGS(appl80211_chip_diags_data*) = 0;

    // native virtual slot 0xff8
public:
    virtual IOReturn getHP2P_CTRL(apple80211_hp2p_ctrl*) = 0;

    // native virtual slot 0x1000
public:
    virtual IOReturn getBSS_BLACKLIST(bss_blacklist*) = 0;

    // native virtual slot 0x1008
public:
    virtual IOReturn getTXRX_CHAIN_INFO(apple80211_txrx_chain_info*) = 0;

    // native virtual slot 0x1010
public:
    virtual IOReturn getMIMO_STATUS(apple80211_mimo_status*) = 0;

    // native virtual slot 0x1018
public:
    virtual IOReturn getCUR_PMK(apple80211_pmk*) = 0;

    // native virtual slot 0x1020
public:
    virtual IOReturn getDYNSAR_DETAIL(apple80211_dynsar_detail*) = 0;

    // native virtual slot 0x1028
public:
    virtual IOReturn getCOUNTRY_CHANNELS_INFO(apple80211_channels_info*) = 0;

    // native virtual slot 0x1030
public:
    virtual IOReturn getLQM_SUMMARY(apple80211_lqm_summary*) = 0;

    // native virtual slot 0x1038
public:
    virtual IOReturn getSLOW_WIFI_FEATURE_ENABLED(apple80211_slow_wifi_feature_enabled*) = 0;

    // native virtual slot 0x1040
public:
    virtual IOReturn getTIMESYNC_INFO(apple80211_timesync_info*) = 0;

    // native virtual slot 0x1048
public:
    virtual IOReturn getSENSING_DATA(apple80211_sensing_data_t*) = 0;

    // native virtual slot 0x1050
public:
    virtual IOReturn getWCL_FW_HOT_CHANNELS(apple80211_fw_hot_channels*) = 0;

    // native virtual slot 0x1058
public:
    virtual IOReturn getWCL_LOW_LATENCY_INFO(apple80211_low_latency_info*) = 0;

    // native virtual slot 0x1060
public:
    virtual IOReturn getWCL_BSS_INFO(apple80211_beacon_msg*) = 0;

    // native virtual slot 0x1068
public:
    virtual IOReturn getWCL_TRAFFIC_COUNTERS(apple80211_wcl_traffic_counters*) = 0;

    // native virtual slot 0x1070
public:
    virtual IOReturn getWCL_GET_TX_BLANKING_STATUS(unsigned int*) = 0;

    // native virtual slot 0x1078
public:
    virtual IOReturn getHE_COUNTERS(apple80211_he_counters_ctl*) = 0;

    // native virtual slot 0x1080
public:
    virtual IOReturn getWCL_CHANNELS_INFO(apple80211ChannelInfo*) = 0;

    // native virtual slot 0x1088
public:
    virtual IOReturn getRSN_XE(apple80211_rsn_xe_data*) = 0;

    // native virtual slot 0x1090
public:
    virtual IOReturn getSIB_COEX_STATUS(apple80211_sib_coex_status*) = 0;

    // native virtual slot 0x1098
public:
    virtual IOReturn getWCL_EXTENDED_BSS_INFO(apple80211_extended_bss_info*) = 0;

    // native virtual slot 0x10a0
public:
    virtual IOReturn getWCL_LOW_LATENCY_INFO_STATS(apple80211_wcl_low_latency_stats*) = 0;

    // native virtual slot 0x10a8
public:
    virtual IOReturn getWCL_BGSCAN_CACHE_RESULT(apple80211_bgscan_cached_network_data_list*) = 0;

    // native virtual slot 0x10b0
public:
    virtual IOReturn getWCL_WNM_OFFLOAD(apple80211_wcl_wnm_offload_t*) = 0;

    // native virtual slot 0x10b8
public:
    virtual IOReturn getWIFI_NOISE_PER_ANT(apple80211_noise_per_ant_t*) = 0;

    // native virtual slot 0x10c0
public:
    virtual IOReturn getFW_CLOCK_INFO(apple80211_fw_clock_info*) = 0;

    // native virtual slot 0x10c8
public:
    virtual IOReturn getTIMESYNC_STATS(apple80211_timesync_stats*) = 0;

    // native virtual slot 0x10d0
public:
    virtual IOReturn getSYSTEM_SLEEP_CONFIG(apple80211_system_sleep_config*) = 0;

    // native virtual slot 0x10d8
public:
    virtual IOReturn getSMARTCCA_OPMODE(apple80211_smartcca_opmode*) = 0;

    // native virtual slot 0x10e0
public:
    virtual IOReturn getLQM_STATISTICS(apple80211_lqm_statistics*) = 0;

    // native virtual slot 0x10e8
public:
    virtual IOReturn getHE_CAPABILITY(apple80211_he_capability*) = 0;

    // native virtual slot 0x10f0
public:
    virtual IOReturn getDEVICE_ORIENTATION(apple80211_device_orientation*) = 0;

    // native virtual slot 0x10f8
public:
    virtual IOReturn getACCESSORY_STATE(apple80211_device_accessory_info*) = 0;

    // native virtual slot 0x1100
public:
    virtual IOReturn getP2P_DEVICE_CAPABILITY(apple80211_p2p_device_capability*) = 0;

    // native virtual slot 0x1108
public:
    virtual IOReturn getPOWERTABLE_VERSION(apple80211_powertable_version_data*) = 0;

    // native virtual slot 0x1110
public:
    virtual IOReturn setCIPHER_KEY(apple80211_key*) = 0;

    // native virtual slot 0x1118
public:
    virtual IOReturn setCHANNEL(apple80211_channel_data*) = 0;

    // native virtual slot 0x1120
public:
    virtual IOReturn setPOWERSAVE(apple80211_powersave_data*) = 0;

    // native virtual slot 0x1128
public:
    virtual IOReturn setTXPOWER(apple80211_txpower_data*) = 0;

    // native virtual slot 0x1130
public:
    virtual IOReturn setRATE(apple80211_rate_data*) = 0;

    // native virtual slot 0x1138
public:
    virtual IOReturn setIBSS_MODE(apple80211_network_data*) = 0;

    // native virtual slot 0x1140
public:
    virtual IOReturn setAP_MODE(apple80211_apmode_data*) = 0;

    // native virtual slot 0x1148
public:
    virtual IOReturn setIE(apple80211_ie_data*) = 0;

    // native virtual slot 0x1150
public:
    virtual IOReturn setWOW_TEST(apple80211_wow_test_data*) = 0;

    // native virtual slot 0x1158
public:
    virtual IOReturn setCLEAR_PMKSA_CACHE(void*) = 0;

    // native virtual slot 0x1160
public:
    virtual IOReturn setVIRTUAL_IF_CREATE(apple80211_virt_if_create_data*) = 0;

    // native virtual slot 0x1168
public:
    virtual IOReturn setHT_CAPABILITY(apple80211_ht_capability*) = 0;

    // native virtual slot 0x1170
public:
    virtual IOReturn setOFFLOAD_ARP(apple80211_offload_arp_data*) = 0;

    // native virtual slot 0x1178
public:
    virtual IOReturn setOFFLOAD_NDP(apple80211_offload_ndp_data*) = 0;

    // native virtual slot 0x1180
public:
    virtual IOReturn setGAS_REQ(apple80211_gas_query_t*) = 0;

    // native virtual slot 0x1188
public:
    virtual IOReturn setVHT_CAPABILITY(apple80211_vht_capability*) = 0;

    // native virtual slot 0x1190
public:
    virtual IOReturn setROAM_PROFILE(apple80211_roam_profile_all_bands*) = 0;

    // native virtual slot 0x1198
public:
    virtual IOReturn setDBG_GUARD_TIME_PARAMS(apple80211_dbg_guard_time_params*) = 0;

    // native virtual slot 0x11a0
public:
    virtual IOReturn setLEAKY_AP_STATS_MODE(apple80211_leaky_ap_setting*) = 0;

    // native virtual slot 0x11a8
public:
    virtual IOReturn setPRIVATE_MAC(apple80211_private_mac_data*) = 0;

    // native virtual slot 0x11b0
public:
    virtual IOReturn setRESET_CHIP(apple80211_reset_command*) = 0;

    // native virtual slot 0x11b8
public:
    virtual IOReturn setCRASH(apple80211_crash_command*) = 0;

    // native virtual slot 0x11c0
public:
    virtual IOReturn setRANGING_ENABLE(apple80211_ranging_enable_request_t*) = 0;

    // native virtual slot 0x11c8
public:
    virtual IOReturn setRANGING_START(apple80211_ranging_start_request_t*) = 0;

    // native virtual slot 0x11d0
public:
    virtual IOReturn setRANGING_AUTHENTICATE(apple80211_ranging_authenticate_request_t*) = 0;

    // native virtual slot 0x11d8
public:
    virtual IOReturn setTKO_PARAMS(apple80211_tko_params*) = 0;

    // native virtual slot 0x11e0
public:
    virtual IOReturn setBTCOEX_PROFILE(apple80211_btcoex_profile*) = 0;

    // native virtual slot 0x11e8
public:
    virtual IOReturn setBTCOEX_PROFILE_ACTIVE(apple80211_btcoex_profile_active_data*) = 0;

    // native virtual slot 0x11f0
public:
    virtual IOReturn setTHERMAL_INDEX(apple80211_thermal_index_t*) = 0;

    // native virtual slot 0x11f8
public:
    virtual IOReturn setBTCOEX_2G_CHAIN_DISABLE(apple80211_btcoex_2g_chain_disable*) = 0;

    // native virtual slot 0x1200
public:
    virtual IOReturn setPOWER_BUDGET(apple80211_power_budget_t*) = 0;

    // native virtual slot 0x1208
public:
    virtual IOReturn setOFFLOAD_TCPKA_ENABLE(apple80211_offload_tcpka_enable_t*) = 0;

    // native virtual slot 0x1210
public:
    virtual IOReturn setLQM_CONFIG(apple80211_lqm_config_t*) = 0;

    // native virtual slot 0x1218
public:
    virtual IOReturn setDYNAMIC_RSSI_WINDOW_CONFIG(apple80211_dynamic_rssi_window_config*) = 0;

    // native virtual slot 0x1220
public:
    virtual IOReturn setUSB_HOST_NOTIFICATION(apple80211_usb_host_notification_data*) = 0;

    // native virtual slot 0x1228
public:
    virtual IOReturn setHP2P_CTRL(apple80211_hp2p_ctrl*) = 0;

    // native virtual slot 0x1230
public:
    virtual IOReturn setBSS_BLACKLIST(bss_blacklist*) = 0;

    // native virtual slot 0x1238
public:
    virtual IOReturn setSET_PROPERTY(apple80211_set_property_unserialized_data*) = 0;

    // native virtual slot 0x1240
public:
    virtual IOReturn setROAM_CACHE_UPDATE(apple80211_roam_cache_data*) = 0;

    // native virtual slot 0x1248
public:
    virtual IOReturn setPM_MODE(apple80211_pm_mode*) = 0;

    // native virtual slot 0x1250
public:
    virtual IOReturn setSET_WIFI_ASSERTION_STATE(apple80211_wifi_assertion_data*) = 0;

    // native virtual slot 0x1258
public:
    virtual IOReturn setREALTIME_QOS_MSCS(apple80211_state_data*) = 0;

    // native virtual slot 0x1260
public:
    virtual IOReturn setSENSING_ENABLE(apple80211_sensing_enable_t*) = 0;

    // native virtual slot 0x1268
public:
    virtual IOReturn setSENSING_DISABLE(apple80211_sensing_disable_t*) = 0;

    // native virtual slot 0x1270
public:
    virtual IOReturn setWCL_LEAVE_NETWORK(apple80211_leave_network*) = 0;

    // native virtual slot 0x1278
public:
    virtual IOReturn setWCL_REASSOC(apple80211_reassoc*) = 0;

    // native virtual slot 0x1280
public:
    virtual IOReturn setWCL_SET_ROAM_LOCK(apple80211_set_roam_lock*) = 0;

    // native virtual slot 0x1288
public:
    virtual IOReturn setWCL_LEGACY_ROAM_PROFILE_CONFIG(apple80211_legacy_roam_profile_config*) = 0;

    // native virtual slot 0x1290
public:
    virtual IOReturn setWCL_ROAM_PROFILE_CONFIG(apple80211_roam_profile_config*) = 0;

    // native virtual slot 0x1298
public:
    virtual IOReturn setWCL_ROAM_USER_CACHE(apple80211_user_roam_cache*) = 0;

    // native virtual slot 0x12a0
public:
    virtual IOReturn setWCL_SCAN_ABORT(void*) = 0;

    // native virtual slot 0x12a8
public:
    virtual IOReturn setWCL_REAL_TIME_MODE(apple80211_wcl_real_time_mode*) = 0;

    // native virtual slot 0x12b0
public:
    virtual IOReturn setWCL_ARP_MODE(apple80211_wcl_arp_mode*) = 0;

    // native virtual slot 0x12b8
public:
    virtual IOReturn setWCL_JOIN_ABORT(apple80211_wcl_abort_join*) = 0;

    // native virtual slot 0x12c0
public:
    virtual IOReturn setWCL_TRIGGER_CC(triggerCC*) = 0;

    // native virtual slot 0x12c8
public:
    virtual IOReturn setWCL_SCAN_REQ(apple80211ScanRequest*) = 0;

    // native virtual slot 0x12d0
public:
    virtual IOReturn setWCL_ASSOCIATE(apple80211AssocCandidates*) = 0;

    // native virtual slot 0x12d8
public:
    virtual IOReturn setWCL_QOS_PARAMS(apple80211_wcl_qos_params*) = 0;

    // native virtual slot 0x12e0
public:
    virtual IOReturn setWCL_LINK_UP_DONE(void*) = 0;

    // native virtual slot 0x12e8
public:
    virtual IOReturn setWCL_SET_SCAN_HOME_AWAY_TIME(scanHomeAndAwayTime*) = 0;

    // native virtual slot 0x12f0
public:
    virtual IOReturn setVOICE_IND_STATE(apple80211_voice_ind_state*) = 0;

    // native virtual slot 0x12f8
public:
    virtual IOReturn setRSN_XE(apple80211_rsn_xe_data*) = 0;

    // native virtual slot 0x1300
public:
    virtual IOReturn setMWS_ACCESSORY_POWER_LIMIT_WIFI_ENH(apple80211_mws_accessory_power_limit*) = 0;

    // native virtual slot 0x1308
public:
    virtual IOReturn setWCL_ULOFDMA_STATE(apple80211_wcl_ulofdma_state*) = 0;

    // native virtual slot 0x1310
public:
    virtual IOReturn setWCL_ACTION_FRAME(apple80211_wcl_action_frame*) = 0;

    // native virtual slot 0x1318
public:
    virtual IOReturn setGAS_ABORT(void*) = 0;

    // native virtual slot 0x1320
public:
    virtual IOReturn setOS_FEATURE_FLAGS(apple80211_feature_flags*) = 0;

    // native virtual slot 0x1328
public:
    virtual IOReturn setDHCP_RENEWAL_DATA(apple80211_dhcp_renewal_data*) = 0;

    // native virtual slot 0x1330
public:
    virtual IOReturn setBATTERY_POWERSAVE_CONFIG(apple80211_battery_ps_config*) = 0;

    // native virtual slot 0x1338
public:
    virtual IOReturn setMIMO_CONFIG(apple80211_mimo_config*) = 0;

    // native virtual slot 0x1340
public:
    virtual IOReturn setWCL_CONFIG_BG_MOTIONPROFILE(apple80211_bg_motion_profile*) = 0;

    // native virtual slot 0x1348
public:
    virtual IOReturn setWCL_CONFIG_BG_NETWORK(apple80211_bg_network*) = 0;

    // native virtual slot 0x1350
public:
    virtual IOReturn setWCL_CONFIG_BGSCAN(apple80211_bg_scan*) = 0;

    // native virtual slot 0x1358
public:
    virtual IOReturn setWCL_CONFIG_BG_PARAMS(apple80211_bg_params*) = 0;

    // native virtual slot 0x1360
public:
    virtual IOReturn setPOWER_PROFILE(apple80211_power_profile*) = 0;

    // native virtual slot 0x1368
public:
    virtual IOReturn setHEARTBEAT(void*) = 0;

    // native virtual slot 0x1370
public:
    virtual IOReturn setINTERFACE_SETTING(apple80211_interface_setting*) = 0;

    // native virtual slot 0x1378
public:
    virtual IOReturn setBYPASS_TX_POWER_CAP(apple80211_bypass_tx_power_cap*) = 0;

    // native virtual slot 0x1380
public:
    virtual IOReturn setFACETIME_WIFICALLING_PARAMS(apple80211_facetime_wificalling_params*) = 0;

    // native virtual slot 0x1388
public:
    virtual IOReturn setIPV4_PARAMS(apple80211_ipv4_params*) = 0;

    // native virtual slot 0x1390
public:
    virtual IOReturn setWCL_WNM_OPS(apple80211_wcl_wnm_config_t*) = 0;

    // native virtual slot 0x1398
public:
    virtual IOReturn setWCL_WNM_OFFLOAD(apple80211_wcl_wnm_offload_t*) = 0;

    // native virtual slot 0x13a0
public:
    virtual IOReturn setWCL_LIMITED_AGGREGATION(apple80211_limited_aggregation_config*) = 0;

    // native virtual slot 0x13a8
public:
    virtual IOReturn setWCL_BCN_MUTE_CONFIG(apple80211_bcn_mute_config*) = 0;

    // native virtual slot 0x13b0
public:
    virtual IOReturn setEAP_FILTER_CONFIG(apple80211_eap_filter_config*) = 0;

    // native virtual slot 0x13b8
public:
    virtual IOReturn setWOW_LOW_POWER_MODE(apple80211_wow_low_power_mode*) = 0;

    // native virtual slot 0x13c0
public:
    virtual IOReturn setDUAL_POWER_MODE(apple80211_dual_power_mode_params*) = 0;

    // native virtual slot 0x13c8
public:
    virtual IOReturn setWCL_UPDATE_FAST_LANE(apple80211_fastlane*) = 0;

    // native virtual slot 0x13d0
public:
    virtual IOReturn setWCL_ASSOCIATED_SLEEP(apple80211_associated_sleep_config*) = 0;

    // native virtual slot 0x13d8
public:
    virtual IOReturn setCONGESTION_CTRL_IND(apple80211_congestion_control_indication*) = 0;

    // native virtual slot 0x13e0
public:
    virtual IOReturn setSTAND_ALONE_MODE_STATE(apple80211_standalone_state*) = 0;

    // native virtual slot 0x13e8
public:
    virtual IOReturn setIPV6_PARAMS(apple80211_ipv6_params*) = 0;

    // native virtual slot 0x13f0
public:
    virtual IOReturn setINFRA_ENUMERATED(apple80211_infra_enumerated*) = 0;

    // native virtual slot 0x13f8
public:
    virtual IOReturn setLMTPC_CONFIG(apple80211_lmtpc_config*) = 0;

    // native virtual slot 0x1400
public:
    virtual IOReturn setTRAFFIC_ENG_PARAMS(apple80211_traffic_eng_params*) = 0;

    // native virtual slot 0x1408
public:
    virtual IOReturn setLE_SCAN_PARAM(apple80211_le_scan_params*) = 0;

    // native virtual slot 0x1410
public:
    virtual IOReturn setTIMESYNC_GPIO(apple80211_timesync_gpio*) = 0;

    // native virtual slot 0x1418
public:
    virtual IOReturn setHOST_CLOCK_INFO(apple80211_host_clock_info*) = 0;

    // native virtual slot 0x1420
public:
    virtual IOReturn setFW_CLOCK_SOURCE(apple80211_fw_clock_source*) = 0;

    // native virtual slot 0x1428
public:
    virtual IOReturn setTIMESYNC_TX_POLICY(apple80211_timesync_tx_policy*) = 0;

    // native virtual slot 0x1430
public:
    virtual IOReturn setTIMESYNC_RX_POLICY(apple80211_timesync_rx_policy*) = 0;

    // native virtual slot 0x1438
public:
    virtual IOReturn setTIMESTAMPING_EN(apple80211_timestamping_en*) = 0;

    // native virtual slot 0x1440
public:
    virtual IOReturn setWCL_SOI_CONFIG(appl80211_sleep_on_inactivity_config*) = 0;

    // native virtual slot 0x1448
public:
    virtual IOReturn setMWS_TIME_SHARING_WIFI_ENH(apple80211_mws_time_sharing*) = 0;

    // native virtual slot 0x1450
public:
    virtual IOReturn setMWS_WIFI_TYPE_7_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) = 0;

    // native virtual slot 0x1458
public:
    virtual IOReturn setMWS_COEX_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) = 0;

    // native virtual slot 0x1460
public:
    virtual IOReturn setMWS_DISABLE_OCL_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) = 0;

    // native virtual slot 0x1468
public:
    virtual IOReturn setMWS_RFEM_CONFIG_WIFI_ENH(apple80211_mws_rfem_config*) = 0;

    // native virtual slot 0x1470
public:
    virtual IOReturn setMWS_ASSOC_PROTECTION_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) = 0;

    // native virtual slot 0x1478
public:
    virtual IOReturn setMWS_SCAN_FREQ_WIFI_ENH(apple80211_mws_scan_freq*) = 0;

    // native virtual slot 0x1480
public:
    virtual IOReturn setMWS_SCAN_FREQ_MODE_WIFI_ENH(apple80211_mws_scan_freq_mode*) = 0;

    // native virtual slot 0x1488
public:
    virtual IOReturn setMWS_CONDITION_ID_BITMAP_WIFI_ENH(apple80211_mws_condition_id_config*) = 0;

    // native virtual slot 0x1490
public:
    virtual IOReturn setMWS_ANTENNA_SELECTION_WIFI_ENH(apple80211_mws_antenna_selection*) = 0;

    // native virtual slot 0x1498
public:
    virtual IOReturn setNDD_REQ(apple80211_ndd_data*) = 0;

    // native virtual slot 0x14a0
public:
    virtual IOReturn setDBRG_ENTROPY(apple80211_drbg_entropy*) = 0;

    // native virtual slot 0x14a8
public:
    virtual IOReturn setSDB_ENABLE(apple80211_sdb_enable*) = 0;

    // native virtual slot 0x14b0
public:
    virtual IOReturn setBTCOEX_EXT_PROFILE(apple80211_btcoex_ext_profile*) = 0;

    // native virtual slot 0x14b8
public:
    virtual IOReturn setDEVICE_ORIENTATION(apple80211_device_orientation*) = 0;

    // native virtual slot 0x14c0
public:
    virtual IOReturn setACCESSORY_STATE(apple80211_device_accessory_info*) = 0;

    // native virtual slot 0x14c8
public:
    virtual IOReturn setOS_ELIGIBILITY(apple80211_os_eligibility*) = 0;

    // native virtual slot 0x14d0
public:
    virtual IOReturn setTX_MODE_CONFIG(apple80211_tx_mode_config*) = 0;

    // native virtual slot 0x14d8
public:
    virtual IOReturn setMITIGATE_INTERFERENCE(apple80211_mitigate_interference*) = 0;
};
static_assert(sizeof(IO80211InfraProtocol) == 0x130, "25G241 IO80211InfraProtocol size");
