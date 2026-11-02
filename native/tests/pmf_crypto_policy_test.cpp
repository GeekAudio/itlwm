#include "../pmf_crypto_policy.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

constexpr uint8_t kDisassoc = ITL_PMF_FC0_SUBTYPE_DISASSOC;
constexpr uint8_t kDeauth = ITL_PMF_FC0_SUBTYPE_DEAUTH;
constexpr uint8_t kAction = ITL_PMF_FC0_SUBTYPE_ACTION;
constexpr uint8_t kProtected = ITL_PMF_FC1_PROTECTED;

void testRobustActionClassification() {
    assert(itl_pmf_is_robust_mgmt_category(kDisassoc, 0, 0));
    assert(itl_pmf_is_robust_mgmt_category(kDeauth, 0, 0));
    assert(itl_pmf_is_robust_mgmt_category(kAction, 1, 8));  // SA Query
    assert(itl_pmf_is_robust_mgmt_category(kAction, 1, 9));  // Protected dual
    assert(itl_pmf_is_robust_mgmt_category(kAction, 1, 126));
    assert(!itl_pmf_is_robust_mgmt_category(kAction, 0, 8));
    assert(!itl_pmf_is_robust_mgmt_category(kAction, 1, 4));
    assert(!itl_pmf_is_robust_mgmt_category(kAction, 1, 7));
    assert(!itl_pmf_is_robust_mgmt_category(kAction, 1, 11));
    assert(!itl_pmf_is_robust_mgmt_category(kAction, 1, 15));
    assert(!itl_pmf_is_robust_mgmt_category(kAction, 1, 20));
    assert(!itl_pmf_is_robust_mgmt_category(kAction, 1, 21));
    assert(!itl_pmf_is_robust_mgmt_category(kAction, 1, 22));
    assert(!itl_pmf_is_robust_mgmt_category(kAction, 1, 127));
    assert(!itl_pmf_is_robust_mgmt_category(0x08, 1, 8)); // data frame

    // A protected action may have an encrypted category. RX may trust the
    // frame-control/status pair until the CCMP MIC and replay checks complete.
    assert(itl_pmf_is_robust_mgmt_rx(kAction, kProtected, 0, 0));
    assert(itl_pmf_is_robust_mgmt_rx(kDeauth, 0, 0, 0));
    assert(!itl_pmf_is_robust_mgmt_rx(0x08, kProtected, 1, 8));
}

void testKeySelectionAndProtectionBit() {
    assert(itl_pmf_use_igtk_tx(1, 1, 1, 1, 1)); // group SA Query action
    assert(!itl_pmf_use_igtk_tx(1, 1, 0, 1, 1)); // multicast DATA uses GTK
    assert(!itl_pmf_use_igtk_tx(1, 0, 1, 1, 1)); // unicast uses pairwise
    assert(!itl_pmf_use_igtk_tx(1, 1, 1, 0, 1));
    assert(!itl_pmf_use_igtk_tx(1, 1, 1, 1, 0)); // public action uses GTK
    assert(!itl_pmf_use_igtk_tx(0, 1, 1, 1, 1));

    assert(itl_pmf_group_mgmt_protected_bit_valid(1, 0, 1));
    assert(itl_pmf_group_mgmt_protected_bit_valid(0, 1, 1));
    assert(!itl_pmf_group_mgmt_protected_bit_valid(1, 1, 1));
    assert(itl_pmf_group_mgmt_protected_bit_valid(1, 1, 0));
}

void testBipReplayAndPnLifetime() {
    assert(itl_pmf_bip_replay_ok(2, 1));
    assert(!itl_pmf_bip_replay_ok(1, 1));
    assert(!itl_pmf_bip_replay_ok(1, 2));
    assert(itl_pmf_bip_pn_can_advance(0));
    assert(itl_pmf_bip_pn_can_advance(UINT64_C(0x0000fffffffffffe)));
    assert(itl_pmf_bip_pn_can_advance(UINT64_C(0x0000ffffffffffff)));
    assert(!itl_pmf_bip_pn_can_advance(UINT64_C(0x0001000000000000)));
    assert(itl_pmf_bip_ipn_high_watermark(9, 4) == 9);
    assert(itl_pmf_bip_ipn_high_watermark(9, 10) == 10);

    uint8_t mmie[18];
    for (uint8_t &byte : mmie)
        byte = 0xaa;
    itl_pmf_bip_mmie_init(mmie, 76, 5,
                          UINT64_C(0x0000a1b2c3d4e5f6));
    const uint8_t expected[18] = {
        76, 16, 5, 0, 0xf6, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1,
        0, 0, 0, 0, 0, 0, 0, 0
    };
    for (size_t i = 0; i < sizeof(mmie); i++)
        assert(mmie[i] == expected[i]);
}

void testBipTxPostEncapsulationGate() {
    constexpr size_t kHeaderLength = 24;
    constexpr size_t kFrameLength = kHeaderLength + 3 + 18;
    constexpr uint32_t kIgtkFlags = ITL_PMF_KEY_SWCRYPTO |
        ITL_PMF_KEY_FWMFP | ITL_PMF_KEY_FWACTIVE;
    uint8_t mmie[18] = {76, 16, 4, 0};

    assert(itl_pmf_bip_tx_frame_valid(0, kFrameLength, kHeaderLength,
                                      4, mmie, sizeof(mmie)));
    mmie[2] = 5;
    assert(!itl_pmf_bip_tx_frame_valid(0, kFrameLength, kHeaderLength,
                                       4, mmie, sizeof(mmie)));
    assert(itl_pmf_bip_tx_frame_valid(0, kFrameLength, kHeaderLength,
                                      5, mmie, sizeof(mmie)));
    assert(!itl_pmf_bip_tx_frame_valid(1, kFrameLength, kHeaderLength,
                                       5, mmie, sizeof(mmie)));
    assert(!itl_pmf_bip_tx_frame_valid(0, kHeaderLength + 17,
                                       kHeaderLength, 5, mmie,
                                       sizeof(mmie)));
    assert(!itl_pmf_bip_tx_frame_valid(0, kFrameLength, kHeaderLength,
                                       5, nullptr, 0));
    mmie[1] = 15;
    assert(!itl_pmf_bip_tx_frame_valid(0, kFrameLength, kHeaderLength,
                                       5, mmie, sizeof(mmie)));
    mmie[1] = 16;
    assert(!itl_pmf_bip_tx_frame_valid(0, kFrameLength, kHeaderLength,
                                       6, mmie, sizeof(mmie)));

    // The pre-encapsulation iwx_tx gate runs while the management Protected
    // bit is still set; after BIP it is clear and the MMIE becomes the proof.
    assert(itl_pmf_key_tx_ready(kIgtkFlags, 1, 0, 1, 0, 0));
    assert(!itl_pmf_key_tx_ready(kIgtkFlags | ITL_PMF_KEY_FWPENDING,
                                 1, 0, 1, 0, 0));
    assert(!itl_pmf_key_tx_ready(kIgtkFlags, 1, 0, 0, 0, 0));
    assert(!itl_pmf_key_tx_ready(kIgtkFlags, 1, 0, 1, 1, 0));
    assert(!itl_pmf_key_tx_ready(kIgtkFlags, 1, 0, 1, 0, 1));
}

struct PendingAck {
    uint8_t active;
    uint8_t command_qid;
    uint8_t command_index;
};

void testInitialM3AndKeyRotationPolicy() {
    assert(itl_pmf_initial_m3_igtk_valid(0, 1, 0, 0));
    assert(itl_pmf_initial_m3_igtk_valid(1, 0, 0, 0));
    assert(itl_pmf_initial_m3_igtk_valid(1, 1, 1, 1));
    assert(!itl_pmf_initial_m3_igtk_valid(1, 1, 0, 1));
    assert(!itl_pmf_initial_m3_igtk_valid(1, 1, 1, 0));

    // Repeated M3 can never move the receive IPN backwards.
    assert(itl_pmf_bip_ipn_high_watermark(20, 17) == 20);
    assert(itl_pmf_bip_ipn_high_watermark(20, 21) == 21);
    assert(!itl_pmf_authorize_port(1, 0, 0, 1, 1, 0));
}

void testAckRingReservationAndStaleResponses() {
    PendingAck pending[7]{};
    assert(itl_pmf_ack_slot_available(pending, 7, 2, 4, 9));
    pending[2] = PendingAck{1, 4, 9};
    assert(!itl_pmf_ack_slot_available(pending, 7, 2, 5, 10));
    assert(!itl_pmf_ack_slot_available(pending, 7, 3, 4, 9));
    assert(itl_pmf_ack_find_ring_slot(pending, 7, 4, 9) == 2);
    assert(itl_pmf_ack_find_ring_slot(pending, 7, 5, 9) == -1);
    assert(itl_pmf_ack_find_ring_slot(pending, 7, 4, 10) == -1);

    // Releasing completion permits key-slot and command-ring reuse.
    pending[2] = PendingAck{};
    assert(itl_pmf_ack_slot_available(pending, 7, 2, 4, 9));
    assert(itl_pmf_ack_slot_available(pending, 7, 3, 4, 9));

    assert(itl_pmf_ack_response_matches(7, 7, 12, 12, 5, 5,
                                        0x17, 0x17, 1, 0));
    assert(!itl_pmf_ack_response_matches(7, 6, 12, 12, 5, 5,
                                         0x17, 0x17, 1, 0));
    assert(!itl_pmf_ack_response_matches(7, 7, 12, 11, 5, 5,
                                         0x17, 0x17, 1, 0));
    assert(!itl_pmf_ack_response_matches(7, 7, 12, 12, 6, 5,
                                         0x17, 0x17, 1, 0));
    assert(!itl_pmf_ack_response_matches(7, 7, 12, 12, 5, 5,
                                         0x17, 0x1f, 1, 0));
    assert(!itl_pmf_ack_response_matches(7, 7, 12, 12, 5, 5,
                                         0x17, 0x17, 1, 1));

    // ADD_STA_KEY reports a four-byte status. The pinned SO68
    // MGMT_MCAST_KEY response also has a strict four-byte status contract.
    constexpr uint32_t kAddStaSuccess = 1;
    assert(itl_pmf_add_sta_key_response_ok(sizeof(uint32_t),
        kAddStaSuccess, kAddStaSuccess, 0));
    assert(!itl_pmf_add_sta_key_response_ok(sizeof(uint32_t), 0,
        kAddStaSuccess, 0));
    assert(!itl_pmf_add_sta_key_response_ok(sizeof(uint32_t) - 1,
        kAddStaSuccess, kAddStaSuccess, 0));
    assert(!itl_pmf_add_sta_key_response_ok(sizeof(uint32_t),
        kAddStaSuccess, kAddStaSuccess, 1));
    assert(itl_pmf_igtk_response_ok(sizeof(uint32_t), 1, 1, 0, 1));
    assert(!itl_pmf_igtk_response_ok(0, 1, 1, 0, 1));
    assert(!itl_pmf_igtk_response_ok(sizeof(uint32_t) - 1, 1, 1, 0, 1));
    assert(!itl_pmf_igtk_response_ok(sizeof(uint32_t) + 1, 1, 1, 0, 1));
    assert(!itl_pmf_igtk_response_ok(sizeof(uint32_t), 0, 1, 0, 1));
    assert(!itl_pmf_igtk_response_ok(sizeof(uint32_t), 1, 1, 1, 1));
    assert(!itl_pmf_igtk_response_ok(sizeof(uint32_t), 1, 1, 0, 0));

    const char firmwareName[] = "iwlwifi-so-a0-hr-b0-68.ucode";
    const char firmwareSource[] = "release/core66_LinADLPV::01d30b0c";
    uint8_t humanReadable[64] = {};
    std::memcpy(humanReadable, firmwareSource, sizeof(firmwareSource));
    assert(itl_pmf_so68_igtk_status1_firmware_identity(
        firmwareName, 68, 0x01d30b0cU, humanReadable));
    assert(!itl_pmf_so68_igtk_status1_firmware_identity(
        firmwareName, 67, 0x01d30b0cU, humanReadable));
    assert(!itl_pmf_so68_igtk_status1_firmware_identity(
        firmwareName, 68, 0x01d30b0dU, humanReadable));
    assert(!itl_pmf_so68_igtk_status1_firmware_identity(
        "iwlwifi-so-a0-gf-a0-68.ucode", 68, 0x01d30b0cU,
        humanReadable));
    humanReadable[sizeof(firmwareSource)] = 'x';
    assert(!itl_pmf_so68_igtk_status1_firmware_identity(
        firmwareName, 68, 0x01d30b0cU, humanReadable));
}

void testHardwareCryptoPolicy() {
    constexpr uint32_t kSwCrypto = ITL_PMF_KEY_SWCRYPTO;
    constexpr uint32_t kFwMfp = ITL_PMF_KEY_FWMFP;

    assert(!itl_pmf_use_software_crypto(1, 0)); // hardware CCMP
    assert(itl_pmf_use_software_crypto(1, kSwCrypto)); // software CCMP
    assert(itl_pmf_use_software_crypto(0, 0)); // BIP and non-CCMP
    assert(itl_pmf_should_hw_process_ccmp(1, 0, 1));
    assert(!itl_pmf_should_hw_process_ccmp(1, kSwCrypto, 1));
    assert(!itl_pmf_should_hw_process_ccmp(1, 0, 0));
    assert(!itl_pmf_should_hw_process_ccmp(0, 0, 1));
    assert(itl_pmf_ccmp_hw_status_ok(1, 1, 1));
    assert(!itl_pmf_ccmp_hw_status_ok(1, 1, 0));
    assert(!itl_pmf_ccmp_hw_status_ok(0, 1, 1));

    assert(itl_pmf_should_set_ccmp_mfp(1, 0));
    assert(!itl_pmf_should_set_ccmp_mfp(1, 1)); // GTK must not get STA_KEY_MFP
    assert(!itl_pmf_should_set_ccmp_mfp(0, 0));
    assert(itl_pmf_unicast_mgmt_hw_proof_ok(1, 1, 1, 0));
    assert(!itl_pmf_unicast_mgmt_hw_proof_ok(1, 1, 0, 0));
    assert(!itl_pmf_unicast_mgmt_hw_proof_ok(1, 1, 1, 1));
    assert(itl_pmf_unicast_mgmt_hw_proof_ok(1, 0, 0, 1));
    assert(!itl_pmf_unicast_mgmt_hw_proof_ok(0, 0, 0, 1));

    assert(itl_pmf_igtk_material_valid(1, 4, 16));
    assert(itl_pmf_igtk_material_valid(1, 5, 16));
    assert(!itl_pmf_igtk_material_valid(1, 3, 16));
    assert(!itl_pmf_igtk_material_valid(1, 4, 32));
    assert(!itl_pmf_igtk_material_valid(0, 4, 16));
    assert(itl_pmf_fw_mfp_key_installed(kFwMfp));
    assert(!itl_pmf_fw_mfp_key_installed(kSwCrypto));
}

void testIgtkCommandLifecycle() {
    constexpr uint32_t kNotValid = 1U << 11;
    constexpr uint32_t kCcm = 2U;
    constexpr uint32_t kStaId = 9;
    constexpr uint32_t kKeyId = 5;
    constexpr uint64_t kRsc = UINT64_C(0x0000a1b2c3d4e5f6);
    const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    uint8_t v2[ITL_PMF_IGTK_CMD_V2_SIZE];
    for (uint8_t &byte : v2)
        byte = 0xcc;
    assert(itl_pmf_build_igtk_payload(v2, sizeof(v2), 0, kNotValid,
                                     kCcm, kKeyId, kStaId, key, kRsc));
    assert(v2[0] == 2 && v2[1] == 0 && v2[2] == 0 && v2[3] == 0);
    for (size_t i = 0; i < sizeof(key); i++)
        assert(v2[4 + i] == key[i]);
    for (size_t i = 20; i < 36; i++)
        assert(v2[i] == 0); // V2 key padding is deterministic.
    assert(v2[36] == 5 && v2[37] == 0 && v2[38] == 0 && v2[39] == 0);
    assert(v2[40] == 9 && v2[41] == 0 && v2[42] == 0 && v2[43] == 0);
    assert(v2[44] == 0xf6 && v2[45] == 0xe5 && v2[46] == 0xd4 &&
           v2[47] == 0xc3 && v2[48] == 0xb2 && v2[49] == 0xa1 &&
           v2[50] == 0 && v2[51] == 0);

    assert(itl_pmf_build_igtk_payload(v2, sizeof(v2), 1, kNotValid,
                                     kCcm, kKeyId, kStaId, key, kRsc));
    assert(v2[0] == 0 && v2[1] == 0x08 && v2[2] == 0 && v2[3] == 0);
    for (size_t i = 4; i < 36; i++)
        assert(v2[i] == 0); // Removal cannot leak old IGTK bytes.
    for (size_t i = 44; i < sizeof(v2); i++)
        assert(v2[i] == 0); // Removal cannot restore an old replay counter.
    assert(v2[36] == 5 && v2[40] == 9);

    uint8_t v1[ITL_PMF_IGTK_CMD_V1_SIZE];
    assert(itl_pmf_build_igtk_payload(v1, sizeof(v1), 0, kNotValid,
                                     kCcm, 4, kStaId, key, kRsc));
    assert(v1[0] == 2 && v1[4] == 0 && v1[19] == 0x0f);
    for (size_t i = 20; i < 52; i++)
        assert(v1[i] == 0); // Legacy K1/K2 fields are zero for BIP-CMAC.
    assert(v1[52] == 4 && v1[56] == 9 && v1[60] == 0xf6);

    assert(!itl_pmf_build_igtk_payload(v1, 53, 0, kNotValid, kCcm,
                                      4, kStaId, key, kRsc));
    assert(!itl_pmf_build_igtk_payload(v1, sizeof(v1), 0, kNotValid,
                                      kCcm, 6, kStaId, key, kRsc));
}

void testPmfResetRetryLifecycle() {
    constexpr uint32_t kGeneration = 19;
    constexpr uint32_t kNodeEpoch = 7;
    constexpr uint64_t kFirstDeadline = UINT64_C(1000000000) +
        uint64_t(ITL_PMF_RESET_RETRY_DELAY_MS) * 1000000ULL;
    uint8_t attempts = 0;
    uint64_t deadline = kFirstDeadline;
    bool requested = true;

    assert(itl_pmf_reset_identity_valid(requested, kGeneration,
        kGeneration, kNodeEpoch, kNodeEpoch));
    assert(!itl_pmf_reset_identity_valid(requested, kGeneration,
        kGeneration + 1, kNodeEpoch, kNodeEpoch));
    assert(!itl_pmf_reset_identity_valid(requested, kGeneration,
        kGeneration, kNodeEpoch, kNodeEpoch + 1));
    assert(!itl_pmf_reset_deadline_expired(kFirstDeadline - 1, deadline));

    // Timer task arrives early: defer to the absolute request deadline.
    assert(!itl_pmf_reset_deadline_expired(kFirstDeadline - 1, deadline));
    assert(itl_pmf_reset_deadline_expired(kFirstDeadline, deadline));
    assert(itl_pmf_reset_busy_retry_allowed(
        attempts, ITL_PMF_RESET_RETRY_LIMIT));
    ++attempts; // The gated reset action authorizes one attempt.

    // EBUSY schedules one bounded 100 ms retry; the next attempt succeeds.
    assert(itl_pmf_reset_busy_retry_allowed(
        attempts, ITL_PMF_RESET_RETRY_LIMIT));
    deadline += uint64_t(ITL_PMF_RESET_RETRY_DELAY_MS) * 1000000ULL;
    assert(!itl_pmf_reset_deadline_expired(deadline - 1, deadline));
    assert(itl_pmf_reset_deadline_expired(deadline, deadline));
    ++attempts;
    requested = false; // Successful stop/invalidate cancels the request.
    assert(!itl_pmf_reset_identity_valid(requested, kGeneration,
        kGeneration, kNodeEpoch, kNodeEpoch));

    // The retry budget is finite and a late request cannot target a new epoch.
    assert(!itl_pmf_reset_busy_retry_allowed(
        ITL_PMF_RESET_RETRY_LIMIT, ITL_PMF_RESET_RETRY_LIMIT));
    assert(!itl_pmf_reset_identity_valid(1, kGeneration,
        kGeneration, kNodeEpoch, kNodeEpoch + 1));
}

} // namespace

int main() {
    testRobustActionClassification();
    testKeySelectionAndProtectionBit();
    testBipReplayAndPnLifetime();
    testBipTxPostEncapsulationGate();
    testInitialM3AndKeyRotationPolicy();
    testAckRingReservationAndStaleResponses();
    testHardwareCryptoPolicy();
    testIgtkCommandLifecycle();
    testPmfResetRetryLifecycle();
    std::puts("PMF crypto policy tests passed");
    return 0;
}
