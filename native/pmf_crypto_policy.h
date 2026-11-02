#ifndef ITL_PMF_CRYPTO_POLICY_H
#define ITL_PMF_CRYPTO_POLICY_H

#include <stddef.h>
#include <stdint.h>

/* 802.11 frame-control values used by the PMF decision helpers. */
#define ITL_PMF_FC0_TYPE_MASK       0x0c
#define ITL_PMF_FC0_TYPE_MGMT       0x00
#define ITL_PMF_FC0_SUBTYPE_MASK    0xf0
#define ITL_PMF_FC0_SUBTYPE_DISASSOC 0xa0
#define ITL_PMF_FC0_SUBTYPE_DEAUTH  0xc0
#define ITL_PMF_FC0_SUBTYPE_ACTION  0xd0
#define ITL_PMF_FC1_PROTECTED       0x40

#define ITL_PMF_KEY_SWCRYPTO        0x00000080U
#define ITL_PMF_KEY_FWMFP           0x00000100U
#define ITL_PMF_KEY_FWPENDING       0x00000200U
#define ITL_PMF_KEY_FWACTIVE        0x00000400U

#define ITL_PMF_IGTK_CMD_V1_SIZE    68U
#define ITL_PMF_IGTK_CMD_V2_SIZE    52U
#define ITL_PMF_RESET_RETRY_LIMIT   5U
#define ITL_PMF_RESET_RETRY_DELAY_MS 100U

static inline int
itl_pmf_reset_identity_valid(int requested, uint32_t request_generation,
	    uint32_t current_generation, uint32_t request_epoch,
	    uint32_t current_epoch)
{
	return requested && request_generation == current_generation &&
	    request_epoch == current_epoch;
}

static inline int
itl_pmf_reset_deadline_expired(uint64_t now_ns, uint64_t deadline_ns)
{
	return deadline_ns != 0 && now_ns >= deadline_ns;
}

static inline int
itl_pmf_reset_busy_retry_allowed(uint8_t attempts, uint8_t limit)
{
	return attempts < limit;
}

static inline int
itl_pmf_robust_action_category(uint8_t category)
{
	/* Public, HT, unprotected WNM, self-protected, DMG, VHT, S1G,
	 * and vendor-specific Action frames are not robust MMPDUs. */
	return category != 4 && category != 7 && category != 11 &&
	    category != 15 && category != 20 && category != 21 &&
	    category != 22 && category != 127;
}

static inline int
itl_pmf_is_robust_mgmt_category(uint8_t fc0, int has_action_category,
	    uint8_t category)
{
	uint8_t subtype;

	if ((fc0 & ITL_PMF_FC0_TYPE_MASK) != ITL_PMF_FC0_TYPE_MGMT)
		return 0;
	subtype = fc0 & ITL_PMF_FC0_SUBTYPE_MASK;
	if (subtype == ITL_PMF_FC0_SUBTYPE_DISASSOC ||
	    subtype == ITL_PMF_FC0_SUBTYPE_DEAUTH)
		return 1;
	if (subtype != ITL_PMF_FC0_SUBTYPE_ACTION || !has_action_category)
		return 0;
	return itl_pmf_robust_action_category(category);
}

static inline int
itl_pmf_is_robust_mgmt_rx(uint8_t fc0, uint8_t fc1,
	    int has_action_category, uint8_t category)
{
	if ((fc0 & ITL_PMF_FC0_TYPE_MASK) != ITL_PMF_FC0_TYPE_MGMT)
		return 0;
	if ((fc1 & ITL_PMF_FC1_PROTECTED) != 0 &&
	    (fc0 & ITL_PMF_FC0_SUBTYPE_MASK) == ITL_PMF_FC0_SUBTYPE_ACTION)
		return 1;
	return itl_pmf_is_robust_mgmt_category(fc0, has_action_category,
	    category);
}

static inline int
itl_pmf_use_igtk_tx(int mfp, int multicast, int management,
	    int protected_bit, int robust)
{
	return mfp && multicast && management && protected_bit && robust;
}

static inline int
itl_pmf_group_mgmt_protected_bit_valid(int robust, int multicast,
	    int protected_bit)
{
	return !robust || !multicast || !protected_bit;
}

static inline int
itl_pmf_bip_replay_ok(uint64_t ipn, uint64_t last_ipn)
{
	return ipn > last_ipn;
}

static inline uint64_t
itl_pmf_bip_ipn_high_watermark(uint64_t current, uint64_t observed)
{
	return observed > current ? observed : current;
}

static inline int
itl_pmf_initial_m3_igtk_valid(int mfp, int new_ptk, int has_igtk,
	    int keydata_encrypted)
{
	return !mfp || !new_ptk || (has_igtk && keydata_encrypted);
}

static inline int
itl_pmf_bip_pn_can_advance(uint64_t ipn)
{
	return ipn <= UINT64_C(0x0000ffffffffffff);
}

/* Validate the BIP frame after software encapsulation has cleared the
 * Protected bit. The caller supplies the final 18-byte tail copied from the
 * end of the full mbuf chain. */
static inline int
itl_pmf_bip_tx_frame_valid(int protected_bit, size_t frame_length,
	    size_t header_length, uint16_t selected_key_id,
	    const uint8_t *mmie, size_t mmie_length)
{
	uint16_t mmie_key_id;
	if (protected_bit || frame_length < header_length + 18 ||
	    mmie == NULL || mmie_length != 18 ||
	    (selected_key_id != 4 && selected_key_id != 5) ||
	    mmie[0] != 76 || mmie[1] != 16)
		return 0;
	mmie_key_id = (uint16_t)mmie[2] | ((uint16_t)mmie[3] << 8);
	return mmie_key_id == selected_key_id;
}

static inline void
itl_pmf_bip_mmie_init(uint8_t *mmie, uint8_t element_id, uint16_t key_id,
	    uint64_t ipn)
{
	unsigned int i;
	mmie[0] = element_id;
	mmie[1] = 16;
	mmie[2] = (uint8_t)key_id;
	mmie[3] = (uint8_t)(key_id >> 8);
	for (i = 0; i < 6; i++)
		mmie[4 + i] = (uint8_t)(ipn >> (i * 8));
	for (i = 10; i < 18; i++)
		mmie[i] = 0;
}

static inline int
itl_pmf_should_set_ccmp_mfp(int node_mfp, int group_key)
{
	return node_mfp && !group_key;
}

static inline int
itl_pmf_use_software_crypto(int is_ccmp, uint32_t key_flags)
{
	return !is_ccmp || (key_flags & ITL_PMF_KEY_SWCRYPTO) != 0;
}

static inline int
itl_pmf_should_hw_process_ccmp(int is_ccmp, uint32_t key_flags,
	    int protected_bit)
{
	return is_ccmp && (key_flags & ITL_PMF_KEY_SWCRYPTO) == 0 &&
	    protected_bit;
}

static inline int
itl_pmf_ccmp_hw_status_ok(int ccm_status, int dec_done, int mic_ok)
{
	return ccm_status && dec_done && mic_ok;
}

static inline int
itl_pmf_unicast_mgmt_hw_proof_ok(int protected_bit, int hw_decrypted,
	    int robust_status, int software_key)
{
	if (!protected_bit)
		return 0;
	if (!hw_decrypted)
		return 1;
	return robust_status && !software_key;
}

static inline int
itl_pmf_igtk_material_valid(int igtk_flag, uint8_t key_id, uint32_t key_len)
{
	return igtk_flag && (key_id == 4 || key_id == 5) && key_len == 16;
}

static inline void
itl_pmf_store_le32(uint8_t *dst, uint32_t value)
{
	dst[0] = (uint8_t)value;
	dst[1] = (uint8_t)(value >> 8);
	dst[2] = (uint8_t)(value >> 16);
	dst[3] = (uint8_t)(value >> 24);
}

static inline void
itl_pmf_store_le64(uint8_t *dst, uint64_t value)
{
	unsigned int i;
	for (i = 0; i < 8; i++)
		dst[i] = (uint8_t)(value >> (i * 8));
}

/*
 * Build either legacy 68-byte or new-RX-API 52-byte MGMT_MCAST_KEY payload.
 * Removal payloads deliberately contain no old key material or RSC.
 */
static inline int
itl_pmf_build_igtk_payload(uint8_t *out, size_t out_len, int remove_key,
	    uint32_t not_valid_flag, uint32_t ccm_flag, uint32_t key_id,
	    uint32_t sta_id, const uint8_t *key, uint64_t rsc)
{
	size_t key_id_offset, sta_id_offset, rsc_offset, i;
	uint32_t ctrl_flags;

	if (out == NULL || (out_len != ITL_PMF_IGTK_CMD_V1_SIZE &&
	    out_len != ITL_PMF_IGTK_CMD_V2_SIZE) ||
	    (key_id != 4 && key_id != 5) || (!remove_key && key == NULL))
		return 0;
	for (i = 0; i < out_len; i++)
		out[i] = 0;
	key_id_offset = out_len == ITL_PMF_IGTK_CMD_V2_SIZE ? 36 : 52;
	sta_id_offset = key_id_offset + 4;
	rsc_offset = sta_id_offset + 4;
	ctrl_flags = remove_key ? not_valid_flag : ccm_flag;
	itl_pmf_store_le32(out, ctrl_flags);
	if (!remove_key) {
		for (i = 0; i < 16; i++)
			out[4 + i] = key[i];
	}
	itl_pmf_store_le32(out + key_id_offset, key_id);
	itl_pmf_store_le32(out + sta_id_offset, sta_id);
	if (!remove_key)
		itl_pmf_store_le64(out + rsc_offset, rsc);
	return 1;
}

static inline int
itl_pmf_fw_mfp_key_installed(uint32_t key_flags)
{
	return (key_flags & ITL_PMF_KEY_FWMFP) != 0;
}

static inline int
itl_pmf_key_ack_matches(uint32_t current_generation,
	    uint32_t command_generation, uint32_t current_epoch,
	    uint32_t command_epoch, uint32_t current_incarnation,
	    uint32_t command_incarnation, int command_ok, int timed_out)
{
	return command_ok && !timed_out &&
	    current_generation == command_generation &&
	    current_epoch == command_epoch &&
	    current_incarnation == command_incarnation;
}

/* C++ driver-side helper tested with the same fixed-size slot array used by
 * the iwx STA PMF command path. */
#ifdef __cplusplus
template <typename Pending>
static inline int
itl_pmf_ack_slot_available(const Pending *pending, size_t count,
	    uint8_t key_slot, uint8_t qid, uint8_t index)
{
	size_t i;
	if (pending == NULL || key_slot >= count || pending[key_slot].active)
		return 0;
	for (i = 0; i < count; i++) {
		if (pending[i].active && pending[i].command_qid == qid &&
		    pending[i].command_index == index)
			return 0;
	}
	return 1;
}

template <typename Pending>
static inline int
itl_pmf_ack_find_ring_slot(const Pending *pending, size_t count,
	    uint8_t qid, uint8_t index)
{
	size_t i;
	if (pending == NULL)
		return -1;
	for (i = 0; i < count; i++) {
		if (pending[i].active && pending[i].command_qid == qid &&
		    pending[i].command_index == index)
			return (int)i;
	}
	return -1;
}
#endif

static inline int
itl_pmf_ack_response_matches(uint32_t current_generation,
	    uint32_t command_generation, uint32_t current_epoch,
	    uint32_t command_epoch, uint32_t current_incarnation,
	    uint32_t command_incarnation, uint32_t command_id,
	    uint32_t response_id, int command_ok, int timed_out)
{
	return itl_pmf_key_ack_matches(current_generation, command_generation,
	    current_epoch, command_epoch, current_incarnation,
	    command_incarnation, command_ok && command_id == response_id,
	    timed_out);
}

/* ADD_STA_KEY carries iwl_cmd_response.status; the pinned SO68
 * MGMT_MCAST_KEY reply uses its own identity-gated status contract. Keep the
 * command contracts explicit so malformed replies cannot mark keys active. */
static inline int
itl_pmf_add_sta_key_response_ok(size_t payload_length, uint32_t status,
	    uint32_t success_status, int command_failed)
{
	return !command_failed &&
	    payload_length == sizeof(uint32_t) && status == success_status;
}

/* Exact status-bearing IGTK ACK ABI proven for the pinned SO68 image. */
static inline int
itl_pmf_so68_igtk_status1_firmware_identity(const char *firmware_name,
	    uint32_t firmware_version, uint32_t firmware_build,
	    const uint8_t *human_readable)
{
	static const char expected_name[] = "iwlwifi-so-a0-hr-b0-68.ucode";
	static const char expected_source[] =
	    "release/core66_LinADLPV::01d30b0c";
	size_t i;

	if (firmware_name == NULL || human_readable == NULL ||
	    firmware_version != 68U || firmware_build != 0x01d30b0cU)
		return 0;
	for (i = 0; i < sizeof(expected_name); i++) {
		if (firmware_name[i] != expected_name[i])
			return 0;
	}
	for (i = 0; i < 64; i++) {
		const uint8_t expected = i < sizeof(expected_source) ?
		    (uint8_t)expected_source[i] : 0;
		if (human_readable[i] != expected)
			return 0;
	}
	return 1;
}

static inline int
itl_pmf_igtk_response_ok(size_t payload_length, uint32_t status,
	    uint32_t success_status, int command_failed,
	    int so68_status1_abi)
{
	return so68_status1_abi && !command_failed &&
	    payload_length == sizeof(uint32_t) && status == success_status;
}

static inline int
itl_pmf_key_tx_ready(uint32_t key_flags, int is_igtk, int is_pairwise,
	    int generation_matches, int node_pending, int association_failed)
{
	if (node_pending || association_failed ||
	    (key_flags & ITL_PMF_KEY_FWPENDING) != 0)
		return 0;
	if (is_igtk || is_pairwise)
		return (key_flags & (ITL_PMF_KEY_FWMFP | ITL_PMF_KEY_FWACTIVE)) ==
		    (ITL_PMF_KEY_FWMFP | ITL_PMF_KEY_FWACTIVE) &&
		    generation_matches;
	if (key_flags & ITL_PMF_KEY_SWCRYPTO)
		return 1;
	return (key_flags & ITL_PMF_KEY_FWACTIVE) != 0 &&
	    generation_matches;
}

static inline int
itl_pmf_authorize_port(int batch_ready, int pending_commands,
	    int association_failed, int pairwise_active, int gtk_active,
	    int igtk_active)
{
	return batch_ready && !pending_commands && !association_failed &&
	    pairwise_active && gtk_active && igtk_active;
}

#endif /* ITL_PMF_CRYPTO_POLICY_H */
