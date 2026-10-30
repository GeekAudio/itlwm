#include "radiotap_parser.h"

#include <string.h>

#define RADIOTAP_MAX_PRESENT_WORDS 8U
#define RADIOTAP_EXT (UINT32_C(1) << 31)
#define RADIOTAP_VENDOR_NAMESPACE (UINT32_C(1) << 30)
#define RADIOTAP_TLV_INDEX 28U
#define RADIOTAP_TX_FLAGS_INDEX 15U
#define RADIOTAP_DATA_RETRIES_INDEX 17U
#define RADIOTAP_FLAGS_INDEX 1U
#define RADIOTAP_F_FCS 0x10U

struct field_layout {
    uint8_t alignment;
    uint8_t size;
};

static const struct field_layout layouts[28] = {
    {8U, 8U}, /* 0: TSFT */
    {1U, 1U}, /* 1: FLAGS */
    {1U, 1U}, /* 2: RATE */
    {2U, 4U}, /* 3: CHANNEL */
    {2U, 2U}, /* 4: FHSS */
    {1U, 1U}, /* 5: DBM_ANTSIGNAL */
    {1U, 1U}, /* 6: DBM_ANTNOISE */
    {2U, 2U}, /* 7: LOCK_QUALITY */
    {2U, 2U}, /* 8: TX_ATTENUATION */
    {2U, 2U}, /* 9: DB_TX_ATTENUATION */
    {1U, 1U}, /* 10: DBM_TX_POWER */
    {1U, 1U}, /* 11: ANTENNA */
    {1U, 1U}, /* 12: DB_ANTSIGNAL */
    {1U, 1U}, /* 13: DB_ANTNOISE */
    {2U, 2U}, /* 14: RX_FLAGS */
    {2U, 2U}, /* 15: TX_FLAGS */
    {1U, 1U}, /* 16: RTS_RETRIES */
    {1U, 1U}, /* 17: DATA_RETRIES */
    {4U, 8U}, /* 18: XCHANNEL */
    {1U, 3U}, /* 19: MCS */
    {4U, 8U}, /* 20: AMPDU_STATUS */
    {2U, 12U}, /* 21: VHT */
    {8U, 12U}, /* 22: TIMESTAMP */
    {2U, 12U}, /* 23: HE */
    {2U, 12U}, /* 24: HE_MU */
    {2U, 6U}, /* 25: HE_MU_OTHER_USER */
    {1U, 1U}, /* 26: ZERO_LEN_PSDU */
    {2U, 4U}  /* 27: L-SIG */
};

static uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static bool align_offset(size_t *offset, size_t alignment, size_t limit) {
    size_t remainder;
    if (alignment == 0U || offset == NULL) return false;
    remainder = *offset % alignment;
    if (remainder != 0U) {
        size_t addition = alignment - remainder;
        if (*offset > SIZE_MAX - addition) return false;
        *offset += addition;
    }
    return *offset <= limit;
}

static bool fits(size_t offset, size_t amount, size_t limit) {
    return offset <= limit && amount <= limit - offset;
}

static bool is_test_probe(const uint8_t *mpdu, size_t length,
                          const uint8_t sent_mpdu[96],
                          uint16_t *wifi_sequence, uint16_t *awdl_sequence) {
    static const uint8_t marker[8] = {'T', '0', '8', '6', 'R', 'X', '0', '1'};
    if (mpdu == NULL || sent_mpdu == NULL || length != 96U) return false;
    if (memcmp(mpdu, sent_mpdu, 96U) != 0) return false;
    if (wifi_sequence != NULL)
        *wifi_sequence = (uint16_t)(((uint16_t)mpdu[23] << 4) |
                                    ((uint16_t)mpdu[22] >> 4));
    if (awdl_sequence != NULL)
        *awdl_sequence = read_le16(mpdu + 34U);
    return memcmp(mpdu + 88U, marker, sizeof(marker)) == 0;
}

enum t089_parse_result t089_parse_observation(
    const uint8_t *packet, size_t packet_length, unsigned packet_type,
    const uint8_t sent_mpdu[96], struct t089_observation *out) {
    uint32_t present[RADIOTAP_MAX_PRESENT_WORDS] = {0};
    size_t present_words = 0U;
    size_t offset;
    size_t radiotap_length;
    bool more;

    if (packet == NULL || sent_mpdu == NULL || out == NULL ||
        packet_length < 8U || packet[0] != 0U || packet[1] != 0U)
        return T089_PARSE_INVALID;
    memset(out, 0, sizeof(*out));
    radiotap_length = read_le16(packet + 2U);
    if (radiotap_length < 8U || radiotap_length > packet_length)
        return T089_PARSE_INVALID;

    offset = 4U;
    do {
        if (present_words >= RADIOTAP_MAX_PRESENT_WORDS ||
            !fits(offset, 4U, radiotap_length))
            return T089_PARSE_UNSUPPORTED;
        present[present_words] = read_le32(packet + offset);
        more = (present[present_words] & RADIOTAP_EXT) != 0U;
        present_words++;
        offset += 4U;
    } while (more);

    /* Extended field namespaces are deliberately fail-closed. */
    if ((present[0] & RADIOTAP_VENDOR_NAMESPACE) != 0U)
        return T089_PARSE_UNSUPPORTED;
    for (size_t word = 1U; word < present_words; ++word) {
        if ((present[word] & ~RADIOTAP_EXT) != 0U)
            return T089_PARSE_UNSUPPORTED;
    }

    offset = 4U + present_words * 4U;
    for (unsigned index = 0U; index <= 30U; ++index) {
        size_t field_length;
        size_t alignment;
        uint32_t bit = UINT32_C(1) << index;
        if ((present[0] & bit) == 0U) continue;
        if (index == 29U || index == 30U) {
            /* Namespace markers carry no field bytes in this bitmap. */
            continue;
        }
        if (index == RADIOTAP_TLV_INDEX) {
            if (!align_offset(&offset, 4U, radiotap_length) ||
                !fits(offset, 4U, radiotap_length))
                return T089_PARSE_INVALID;
            field_length = (size_t)read_le16(packet + offset + 2U) + 4U;
            if (!fits(offset, field_length, radiotap_length))
                return T089_PARSE_INVALID;
            offset += field_length;
            continue;
        }
        if (index > 27U) return T089_PARSE_UNSUPPORTED;
        alignment = layouts[index].alignment;
        field_length = layouts[index].size;
        if (!align_offset(&offset, alignment, radiotap_length) ||
            !fits(offset, field_length, radiotap_length))
            return T089_PARSE_INVALID;
        if (index == RADIOTAP_TX_FLAGS_INDEX) {
            out->has_tx_flags = true;
            out->tx_flags = read_le16(packet + offset);
        } else if (index == RADIOTAP_FLAGS_INDEX) {
            out->has_radiotap_flags = true;
            out->radiotap_flags = packet[offset];
        } else if (index == RADIOTAP_DATA_RETRIES_INDEX) {
            out->has_data_retries = true;
            out->data_retries = packet[offset];
        }
        offset += field_length;
    }

    if (offset > radiotap_length) return T089_PARSE_INVALID;
    out->radiotap_length = radiotap_length;
    out->mpdu_offset = radiotap_length;
    out->mpdu_length = packet_length - radiotap_length;
    if (out->has_radiotap_flags &&
        (out->radiotap_flags & RADIOTAP_F_FCS) != 0U) {
        if (out->mpdu_length < 4U) return T089_PARSE_INVALID;
        out->mpdu_length -= 4U;
    }
    out->exact_probe_match = is_test_probe(packet + radiotap_length,
                                           out->mpdu_length, sent_mpdu,
                                           &out->wifi_sequence,
                                           &out->awdl_sequence);
    out->is_outgoing_echo = out->exact_probe_match &&
                            packet_type == T089_PACKET_OUTGOING;
    out->is_host_driver_completion_candidate = out->exact_probe_match &&
                                               packet_type == T089_PACKET_OTHERHOST &&
                                               out->has_tx_flags &&
                                               out->has_data_retries;
    out->is_other_matching_packet = out->exact_probe_match &&
                                    !out->is_outgoing_echo &&
                                    !out->is_host_driver_completion_candidate;
    return T089_PARSE_VALID;
}
