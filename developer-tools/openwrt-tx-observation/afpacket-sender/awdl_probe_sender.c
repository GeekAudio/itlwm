#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef SENDER_HOST_TEST
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif

#define MAX_FRAMES 4U
#define MAX_INTERVAL_MS 10U
#define TX_BUDGET_NS UINT64_C(40000000)
#define GO_TIMEOUT_MS 30000
#define IFNAME_MAX_BYTES 15U
#define NONCE_HEX_BYTES 32U
#define MPDU_LENGTH 96U
#define RADIOTAP_LENGTH 10U
#define PACKET_LENGTH (MPDU_LENGTH + RADIOTAP_LENGTH)
#define WIFI_SEQUENCE_BASE 291U
#define AWDL_SEQUENCE_BASE 34305U
#define MAX_CAPTURE_PACKETS 128U
#define MAX_PRE_SEND_DRAIN_PACKETS 256U
#define MAX_CAPTURE_MATCHES 16U
#define MAX_CAPTURE_READ_ATTEMPTS 512U
#define CAPTURE_PACKET_BYTES 4096U
#define MAX_REJECT_SAMPLES 8U
#define MAX_REJECT_PREFIX_BYTES 96U
#define MAX_PRESENT_BITMAP_WORDS 8U
#define PACKET_TYPE_OTHERHOST 3U
#define PACKET_TYPE_OUTGOING 4U
#define EXIT_ARGUMENT 2
#define EXIT_GATE 3
#define EXIT_INTERFACE 4
#define EXIT_SEND 5
#define EXIT_HOST_SEND_DISABLED 6
#define EXIT_ABORT 7

static const uint8_t radiotap_base[RADIOTAP_LENGTH] = {
    0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x00, 0x00, 0x18, 0x00
};

static const uint8_t mpdu_base[MPDU_LENGTH] = {
    0x08, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x02, 0x86,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x25, 0x00, 0xff, 0x94, 0x73, 0x30, 0x12,
    0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2, 0x08, 0x00, 0x03, 0x04, 0x01, 0x86,
    0x00, 0x00, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x01,
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0x00, 0xff,
    0xfe, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc0, 0x00, 0xc0, 0x01,
    0x00, 0x10, 0x73, 0xd0, 0x54, 0x30, 0x38, 0x36, 0x52, 0x58, 0x30, 0x31
};

struct options {
    bool send;
    bool wait_go;
    bool have_interface;
    const char *interface_name;
    const char *nonce;
    bool have_nonce;
    unsigned count;
    unsigned interval_ms;
};

enum radiotap_reject_reason {
    RADIOTAP_REJECT_NONE = 0,
    RADIOTAP_REJECT_SHORT_HEADER,
    RADIOTAP_REJECT_INVALID_VERSION,
    RADIOTAP_REJECT_INVALID_PAD,
    RADIOTAP_REJECT_INVALID_DECLARED_LENGTH,
    RADIOTAP_REJECT_PRESENT_BITMAP_TRUNCATED,
    RADIOTAP_REJECT_PRESENT_BITMAP_CAPACITY_EXCEEDED,
    RADIOTAP_REJECT_VENDOR_NAMESPACE,
    RADIOTAP_REJECT_UNSUPPORTED_NAMESPACE,
    RADIOTAP_REJECT_UNSUPPORTED_FIELD,
    RADIOTAP_REJECT_FIELD_BOUNDS,
    RADIOTAP_REJECT_FCS_BYTES_MISSING,
    RADIOTAP_REJECT_PACKET_TRUNCATED
};

struct radiotap_observation {
    size_t header_length;
    bool version_present;
    uint8_t version;
    bool pad_present;
    uint8_t pad;
    bool declared_header_length_present;
    uint16_t declared_header_length;
    bool present_bitmap_present;
    bool present_bitmap_complete;
    bool present_bitmap_capacity_exceeded;
    unsigned present_word_count;
    uint32_t present_words[MAX_PRESENT_BITMAP_WORDS];
    enum radiotap_reject_reason reject_reason;
    bool has_flags;
    uint8_t flags;
    bool has_tx_flags;
    uint16_t tx_flags;
    bool has_data_retries;
    uint8_t data_retries;
};

struct rejected_radiotap_sample {
    bool packet_type_present;
    unsigned packet_type;
    bool ifindex_present;
    int ifindex;
    unsigned message_flags;
    uint64_t received_len;
    size_t copied_len;
    bool version_present;
    uint8_t version;
    bool pad_present;
    uint8_t pad;
    bool declared_header_length_present;
    uint16_t declared_header_length;
    bool present_bitmap_present;
    bool present_bitmap_complete;
    bool present_bitmap_capacity_exceeded;
    unsigned present_word_count;
    uint32_t present_words[MAX_PRESENT_BITMAP_WORDS];
    enum radiotap_reject_reason reject_reason;
    enum radiotap_reject_reason radiotap_parse_reason;
    bool packet_truncated;
    uint8_t raw_prefix[MAX_REJECT_PREFIX_BYTES];
    size_t raw_prefix_len;
    bool raw_prefix_truncated;
};

enum radiotap_parse_result {
    RADIOTAP_INVALID = 0,
    RADIOTAP_VALID = 1,
    RADIOTAP_UNSUPPORTED = 2
};

struct provenance_observation {
    unsigned ordinal;
    unsigned packet_type;
    unsigned wifi_sequence;
    unsigned awdl_sequence;
    uint64_t observed_ns;
    char mpdu_sha256[65];
    const char *classification;
    bool has_tx_flags;
    uint16_t tx_flags;
    bool has_data_retries;
    uint8_t data_retries;
};

struct provenance_capture {
    int receive_fd;
    bool available;
    bool complete;
    bool limit_reached;
    bool pre_send_queue_empty;
    bool capture_started;
    bool capture_finished;
    bool synthetic_fixture;
    unsigned pre_send_drained_packets;
    unsigned rx_packets;
    unsigned decoded_packets;
    unsigned truncated_packets;
    unsigned invalid_radiotap;
    unsigned unsupported_radiotap;
    unsigned exact_matches;
    unsigned packet_drops;
    unsigned kernel_packets;
    bool kernel_stats_available;
    unsigned rejected_packets;
    unsigned rejected_sample_overflow;
    unsigned rejected_sample_count;
    unsigned fcs_bytes_missing;
    int receive_error;
    int statistics_error;
    uint64_t started_ns;
    uint64_t ended_ns;
    uint64_t actual_finished_ns;
    uint64_t deadline_ns;
    unsigned expected_frames;
    uint8_t expected_mpdus[MAX_FRAMES][MPDU_LENGTH];
    char expected_mpdu_sha256[MAX_FRAMES][65];
    struct provenance_observation observations[MAX_CAPTURE_MATCHES];
    struct rejected_radiotap_sample rejected_samples[MAX_REJECT_SAMPLES];
};

static bool append_exact_observation(
        struct provenance_capture *capture, unsigned ordinal,
        unsigned packet_type, unsigned wifi_sequence,
        unsigned awdl_sequence, uint64_t observed_ns,
        const struct radiotap_observation *radiotap) {
    if (capture == NULL || radiotap == NULL || observed_ns == 0U ||
        ordinal >= MAX_FRAMES || capture->exact_matches >= MAX_CAPTURE_MATCHES)
        return false;

    struct provenance_observation staged;
    memset(&staged, 0, sizeof(staged));
    staged.ordinal = ordinal;
    staged.packet_type = packet_type;
    staged.wifi_sequence = wifi_sequence;
    staged.awdl_sequence = awdl_sequence;
    staged.observed_ns = observed_ns;
    memcpy(staged.mpdu_sha256, capture->expected_mpdu_sha256[ordinal],
           sizeof(staged.mpdu_sha256));
    staged.has_tx_flags = radiotap->has_tx_flags;
    staged.tx_flags = radiotap->tx_flags;
    staged.has_data_retries = radiotap->has_data_retries;
    staged.data_retries = radiotap->data_retries;
    staged.classification = packet_type == PACKET_TYPE_OUTGOING
        ? "packet_outgoing_echo"
        : (packet_type == PACKET_TYPE_OTHERHOST &&
           radiotap->has_tx_flags && radiotap->has_data_retries
           ? "generated_tx_completion_copy_candidate"
           : "exact_frame_match_unclassified");

    capture->observations[capture->exact_matches] = staged;
    capture->exact_matches++;
    return true;
}

static uint64_t monotonic_ns(void);

static bool is_ifname_char(unsigned char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
           (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.';
}

static bool valid_ifname(const char *value) {
    size_t length;
    if (value == NULL) return false;
    length = strlen(value);
    if (length == 0 || length > IFNAME_MAX_BYTES) return false;
    for (size_t i = 0; i < length; ++i) {
        if (!is_ifname_char((unsigned char)value[i])) return false;
    }
    return true;
}

static bool valid_nonce(const char *value) {
    if (value == NULL || strlen(value) != NONCE_HEX_BYTES) return false;
    for (size_t i = 0; i < NONCE_HEX_BYTES; ++i) {
        unsigned char ch = (unsigned char)value[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
    }
    return true;
}

static bool parse_uint(const char *value, unsigned minimum, unsigned maximum,
                       unsigned *result) {
    unsigned parsed = 0;
    if (value == NULL || *value == '\0' || result == NULL) return false;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        unsigned digit = (unsigned)(*p - '0');
        if (parsed > (maximum - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    if (parsed < minimum || parsed > maximum) return false;
    *result = parsed;
    return true;
}

static void usage(FILE *stream, const char *program) {
    (void)fprintf(stream,
        "Usage: %s [--count 1..4] [--interval-ms 0..10] "
        "[--send --interface NAME --nonce 32hex --wait-go]\n"
        "Default: dry-run only. Sending requires explicit --send and gated nonce.\n",
        program);
}

static bool parse_options(int argc, char **argv, struct options *out,
                          bool *help_requested) {
    bool seen_send = false, seen_if = false, seen_count = false, seen_nonce = false;
    bool seen_interval = false, seen_wait = false;
    *out = (struct options){.count = MAX_FRAMES, .interval_ms = 10U};
    *help_requested = false;
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--help") == 0) {
            if (*help_requested) return false;
            *help_requested = true;
            continue;
        }
        if (strcmp(arg, "--send") == 0) {
            if (seen_send) return false;
            seen_send = true;
            out->send = true;
            continue;
        }
        if (strcmp(arg, "--wait-go") == 0) {
            if (seen_wait) return false;
            seen_wait = true;
            out->wait_go = true;
            continue;
        }
        if (strcmp(arg, "--interface") == 0 ||
            strcmp(arg, "--count") == 0 ||
            strcmp(arg, "--interval-ms") == 0 ||
            strcmp(arg, "--nonce") == 0) {
            if (i + 1 >= argc) return false;
            const char *value = argv[++i];
            if (strcmp(arg, "--interface") == 0) {
                if (seen_if || !valid_ifname(value)) return false;
                seen_if = true;
                out->interface_name = value;
                out->have_interface = true;
            } else if (strcmp(arg, "--nonce") == 0) {
                if (seen_nonce || !valid_nonce(value)) return false;
                seen_nonce = true;
                out->nonce = value;
                out->have_nonce = true;
            } else if (strcmp(arg, "--count") == 0) {
                if (seen_count || !parse_uint(value, 1U, MAX_FRAMES, &out->count))
                    return false;
                seen_count = true;
            } else {
                if (seen_interval ||
                    !parse_uint(value, 0U, MAX_INTERVAL_MS, &out->interval_ms))
                    return false;
                seen_interval = true;
            }
            continue;
        }
        return false;
    }
    if (*help_requested && argc != 2) return false;
    if (out->wait_go && !out->send) return false;
    if (out->send && !out->wait_go) return false;
    if (out->send && (!out->have_interface || !out->have_nonce)) return false;
    if (out->have_nonce && !out->send) return false;
    return true;
}

static bool validate_probe_contract(void) {
    static const uint8_t required_radiotap_prefix[8] = {
        0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x00, 0x00
    };
    static const uint8_t multicast_da[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t snap_awdl[10] = {
        0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2, 0x08, 0x00, 0x03, 0x04
    };
    static const uint8_t ipv6_and_udp_marker[MPDU_LENGTH - 40U] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x01, 0xfe, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0x00, 0xff,
        0xfe, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xc0, 0x00, 0xc0, 0x01, 0x00, 0x10, 0x73, 0xd0, 0x54, 0x30,
        0x38, 0x36, 0x52, 0x58, 0x30, 0x31
    };
    return memcmp(radiotap_base, required_radiotap_prefix,
                  sizeof(required_radiotap_prefix)) == 0 &&
           radiotap_base[8] == 0x18 && radiotap_base[9] == 0x00 &&
           mpdu_base[0] == 0x08 && mpdu_base[1] == 0x00 &&
           mpdu_base[2] == 0x00 && mpdu_base[3] == 0x00 &&
           mpdu_base[22] == 0x30 && mpdu_base[23] == 0x12 &&
           mpdu_base[34] == 0x01 && mpdu_base[35] == 0x86 &&
           memcmp(mpdu_base + 4, multicast_da, sizeof(multicast_da)) == 0 &&
           memcmp(mpdu_base + 24, snap_awdl, sizeof(snap_awdl)) == 0 &&
           memcmp(mpdu_base + 40, ipv6_and_udp_marker,
                  sizeof(ipv6_and_udp_marker)) == 0;
}

static void build_packet(uint8_t packet[PACKET_LENGTH], unsigned index,
                         unsigned *wifi_sequence, unsigned *awdl_sequence) {
    uint16_t wifi = (uint16_t)((WIFI_SEQUENCE_BASE + index) & 0x0fffU);
    uint16_t awdl = (uint16_t)((AWDL_SEQUENCE_BASE + index) & 0xffffU);
    memcpy(packet, radiotap_base, RADIOTAP_LENGTH);
    memcpy(packet + RADIOTAP_LENGTH, mpdu_base, MPDU_LENGTH);
    packet[RADIOTAP_LENGTH + 22U] = (uint8_t)((wifi << 4) & 0xffU);
    packet[RADIOTAP_LENGTH + 23U] = (uint8_t)(wifi >> 4);
    packet[RADIOTAP_LENGTH + 34U] = (uint8_t)(awdl & 0xffU);
    packet[RADIOTAP_LENGTH + 35U] = (uint8_t)(awdl >> 8);
    *wifi_sequence = wifi;
    *awdl_sequence = awdl;
}

static uint32_t sha256_rotr(uint32_t value, unsigned count) {
    return (value >> count) | (value << (32U - count));
}

static void mpdu_sha256_hex(const uint8_t *data, size_t length, char output[65]) {
    static const uint32_t k[64] = {
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
    };
    static const char hex[] = "0123456789abcdef";
    uint32_t h[8] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    };
    uint8_t padded[192] = {0};
    const size_t padded_length = ((length + 9U + 63U) / 64U) * 64U;
    if (padded_length > sizeof(padded)) {
        memset(output, '0', 64U);
        output[64] = '\0';
        return;
    }
    memcpy(padded, data, length);
    padded[length] = 0x80U;
    const uint64_t bits = (uint64_t)length * UINT64_C(8);
    for (unsigned index = 0; index < 8U; ++index)
        padded[padded_length - 1U - index] =
            (uint8_t)(bits >> (index * 8U));

    for (size_t offset = 0; offset < padded_length; offset += 64U) {
        uint32_t words[64];
        for (unsigned index = 0; index < 16U; ++index) {
            const size_t base = offset + (size_t)index * 4U;
            words[index] = ((uint32_t)padded[base] << 24) |
                ((uint32_t)padded[base + 1U] << 16) |
                ((uint32_t)padded[base + 2U] << 8) |
                (uint32_t)padded[base + 3U];
        }
        for (unsigned index = 16U; index < 64U; ++index) {
            const uint32_t s0 = sha256_rotr(words[index - 15U], 7U) ^
                sha256_rotr(words[index - 15U], 18U) ^
                (words[index - 15U] >> 3U);
            const uint32_t s1 = sha256_rotr(words[index - 2U], 17U) ^
                sha256_rotr(words[index - 2U], 19U) ^
                (words[index - 2U] >> 10U);
            words[index] = words[index - 16U] + s0 +
                words[index - 7U] + s1;
        }
        uint32_t a=h[0], b=h[1], c=h[2], d=h[3];
        uint32_t e=h[4], f=h[5], g=h[6], q=h[7];
        for (unsigned index = 0; index < 64U; ++index) {
            const uint32_t s1 = sha256_rotr(e, 6U) ^
                sha256_rotr(e, 11U) ^ sha256_rotr(e, 25U);
            const uint32_t choose = (e & f) ^ (~e & g);
            const uint32_t t1 = q + s1 + choose + k[index] + words[index];
            const uint32_t s0 = sha256_rotr(a, 2U) ^
                sha256_rotr(a, 13U) ^ sha256_rotr(a, 22U);
            const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = s0 + majority;
            q=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=q;
    }
    for (unsigned word = 0; word < 8U; ++word) {
        for (unsigned byte = 0; byte < 4U; ++byte) {
            const uint8_t value =
                (uint8_t)(h[word] >> (24U - byte * 8U));
            const size_t index = (size_t)word * 8U + (size_t)byte * 2U;
            output[index] = hex[value >> 4U];
            output[index + 1U] = hex[value & 0x0fU];
        }
    }
    output[64] = '\0';
}

struct radiotap_field_layout { uint8_t alignment; uint8_t size; };

static const struct radiotap_field_layout radiotap_layouts[28] = {
    {8U,8U}, {1U,1U}, {1U,1U}, {2U,4U}, {2U,2U}, {1U,1U}, {1U,1U},
    {2U,2U}, {2U,2U}, {2U,2U}, {1U,1U}, {1U,1U}, {1U,1U}, {1U,1U},
    {2U,2U}, {2U,2U}, {1U,1U}, {1U,1U}, {4U,8U}, {1U,3U}, {4U,8U},
    {2U,12U}, {8U,12U}, {2U,12U}, {2U,12U}, {2U,6U}, {1U,1U}, {2U,4U}
};

static uint16_t read_le16(const uint8_t *bytes) {
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static uint32_t read_le32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static bool buffer_fits(size_t offset, size_t length, size_t limit) {
    return offset <= limit && length <= limit - offset;
}

static bool align_buffer_offset(size_t *offset, size_t alignment,
                                size_t limit) {
    if (offset == NULL || alignment == 0U) return false;
    size_t remainder = *offset % alignment;
    if (remainder != 0U) {
        size_t addition = alignment - remainder;
        if (*offset > SIZE_MAX - addition) return false;
        *offset += addition;
    }
    return *offset <= limit;
}

static void capture_present_bitmap_bytes(
        const uint8_t *packet, size_t packet_length,
        struct radiotap_observation *out) {
    if (packet == NULL || out == NULL || packet_length < 8U) return;
    out->present_bitmap_present = true;
    size_t offset = 4U;
    for (;;) {
        if (out->present_word_count >= MAX_PRESENT_BITMAP_WORDS) {
            out->present_bitmap_capacity_exceeded = true;
            return;
        }
        if (!buffer_fits(offset, 4U, packet_length)) return;
        const uint32_t word = read_le32(packet + offset);
        out->present_words[out->present_word_count++] = word;
        offset += 4U;
        if ((word & UINT32_C(0x80000000)) == 0U) {
            out->present_bitmap_complete = true;
            return;
        }
        if (out->present_word_count == MAX_PRESENT_BITMAP_WORDS) {
            out->present_bitmap_capacity_exceeded = true;
            return;
        }
    }
}

/* Bounded radiotap parser: standard fields 0..28 only; unknown namespaces fail closed. */
static enum radiotap_parse_result parse_radiotap(
        const uint8_t *packet, size_t packet_length,
        struct radiotap_observation *out) {
    uint32_t present[MAX_PRESENT_BITMAP_WORDS] = {0};
    size_t present_words = 0U;
    size_t offset;
    bool extended;
    if (out == NULL) return RADIOTAP_INVALID;
    memset(out, 0, sizeof(*out));

    /* Preserve only header bytes that were actually available, even when the
     * packet is too short to contain a complete radiotap header. */
    if (packet != NULL) {
        if (packet_length >= 1U) {
            out->version_present = true;
            out->version = packet[0];
        }
        if (packet_length >= 2U) {
            out->pad_present = true;
            out->pad = packet[1];
        }
        if (packet_length >= 4U) {
            out->declared_header_length_present = true;
            out->declared_header_length = read_le16(packet + 2U);
        }
        capture_present_bitmap_bytes(packet, packet_length, out);
    }
    if (packet == NULL || packet_length < 8U) {
        out->reject_reason = RADIOTAP_REJECT_SHORT_HEADER;
        return RADIOTAP_INVALID;
    }
    if (out->version != 0U) {
        out->reject_reason = RADIOTAP_REJECT_INVALID_VERSION;
        return RADIOTAP_INVALID;
    }
    if (out->pad != 0U) {
        out->reject_reason = RADIOTAP_REJECT_INVALID_PAD;
        return RADIOTAP_INVALID;
    }

    const size_t header_length = out->declared_header_length;
    if (header_length < 8U || header_length > packet_length) {
        out->reject_reason = RADIOTAP_REJECT_INVALID_DECLARED_LENGTH;
        return RADIOTAP_INVALID;
    }
    offset = 4U;
    do {
        if (present_words >= MAX_PRESENT_BITMAP_WORDS) {
            out->reject_reason =
                RADIOTAP_REJECT_PRESENT_BITMAP_CAPACITY_EXCEEDED;
            return RADIOTAP_UNSUPPORTED;
        }
        if (!buffer_fits(offset, 4U, header_length)) {
            out->reject_reason = RADIOTAP_REJECT_PRESENT_BITMAP_TRUNCATED;
            return RADIOTAP_INVALID;
        }
        present[present_words] = read_le32(packet + offset);
        extended = (present[present_words] & UINT32_C(0x80000000)) != 0U;
        present_words++;
        offset += 4U;
        if (extended && present_words == MAX_PRESENT_BITMAP_WORDS) {
            out->reject_reason =
                RADIOTAP_REJECT_PRESENT_BITMAP_CAPACITY_EXCEEDED;
            return RADIOTAP_UNSUPPORTED;
        }
    } while (extended);

    const uint32_t first = present[0];
    if ((first & UINT32_C(0x40000000)) != 0U) {
        out->reject_reason = RADIOTAP_REJECT_VENDOR_NAMESPACE;
        return RADIOTAP_UNSUPPORTED;
    }
    for (unsigned word = 1U; word < present_words; ++word) {
        if ((present[word] & UINT32_C(0x7fffffff)) != 0U) {
            out->reject_reason = RADIOTAP_REJECT_UNSUPPORTED_NAMESPACE;
            return RADIOTAP_UNSUPPORTED;
        }
    }

    offset = 4U + present_words * 4U;
    for (unsigned index = 0U; index <= 30U; ++index) {
        if ((first & (UINT32_C(1) << index)) == 0U) continue;
        if (index == 29U || index == 30U) continue;
        if (index == 28U) {
            if (!align_buffer_offset(&offset, 4U, header_length) ||
                !buffer_fits(offset, 4U, header_length)) {
                out->reject_reason = RADIOTAP_REJECT_FIELD_BOUNDS;
                return RADIOTAP_INVALID;
            }
            const size_t tlv_length =
                (size_t)read_le16(packet + offset + 2U) + 4U;
            if (!buffer_fits(offset, tlv_length, header_length)) {
                out->reject_reason = RADIOTAP_REJECT_FIELD_BOUNDS;
                return RADIOTAP_INVALID;
            }
            offset += tlv_length;
            continue;
        }
        if (index > 27U) {
            out->reject_reason = RADIOTAP_REJECT_UNSUPPORTED_FIELD;
            return RADIOTAP_UNSUPPORTED;
        }
        const size_t alignment = radiotap_layouts[index].alignment;
        const size_t field_length = radiotap_layouts[index].size;
        if (!align_buffer_offset(&offset, alignment, header_length) ||
            !buffer_fits(offset, field_length, header_length)) {
            out->reject_reason = RADIOTAP_REJECT_FIELD_BOUNDS;
            return RADIOTAP_INVALID;
        }
        if (index == 1U) {
            out->has_flags = true;
            out->flags = packet[offset];
        } else if (index == 15U) {
            out->has_tx_flags = true;
            out->tx_flags = read_le16(packet + offset);
        } else if (index == 17U) {
            out->has_data_retries = true;
            out->data_retries = packet[offset];
        }
        offset += field_length;
    }
    if (offset > header_length) {
        out->reject_reason = RADIOTAP_REJECT_FIELD_BOUNDS;
        return RADIOTAP_INVALID;
    }
    out->header_length = header_length;
    out->reject_reason = RADIOTAP_REJECT_NONE;
    return RADIOTAP_VALID;
}

static const char *radiotap_reject_reason_name(
        enum radiotap_reject_reason reason) {
    switch (reason) {
        case RADIOTAP_REJECT_NONE: return "none";
        case RADIOTAP_REJECT_SHORT_HEADER: return "short_header";
        case RADIOTAP_REJECT_INVALID_VERSION: return "invalid_version";
        case RADIOTAP_REJECT_INVALID_PAD: return "invalid_pad";
        case RADIOTAP_REJECT_INVALID_DECLARED_LENGTH:
            return "invalid_declared_length";
        case RADIOTAP_REJECT_PRESENT_BITMAP_TRUNCATED:
            return "present_bitmap_truncated";
        case RADIOTAP_REJECT_PRESENT_BITMAP_CAPACITY_EXCEEDED:
            return "present_bitmap_capacity_exceeded";
        case RADIOTAP_REJECT_VENDOR_NAMESPACE: return "vendor_namespace";
        case RADIOTAP_REJECT_UNSUPPORTED_NAMESPACE:
            return "unsupported_namespace";
        case RADIOTAP_REJECT_UNSUPPORTED_FIELD:
            return "unsupported_field";
        case RADIOTAP_REJECT_FIELD_BOUNDS: return "field_bounds";
        case RADIOTAP_REJECT_FCS_BYTES_MISSING:
            return "fcs_bytes_missing";
        case RADIOTAP_REJECT_PACKET_TRUNCATED: return "packet_truncated";
    }
    return "unknown";
}

static void record_rejected_radiotap(
        struct provenance_capture *capture, const uint8_t *packet,
        size_t copied_length, uint64_t received_length, unsigned msg_flags,
        bool packet_type_present, unsigned packet_type, bool ifindex_present,
        int ifindex, bool packet_truncated,
        enum radiotap_reject_reason reject_reason,
        const struct radiotap_observation *radiotap) {
    if (capture == NULL) return;
    capture->rejected_packets++;
    if (capture->rejected_sample_count >= MAX_REJECT_SAMPLES) {
        capture->rejected_sample_overflow++;
        return;
    }
    struct rejected_radiotap_sample *sample =
        &capture->rejected_samples[capture->rejected_sample_count++];
    memset(sample, 0, sizeof(*sample));
    sample->packet_type_present = packet_type_present;
    sample->packet_type = packet_type;
    sample->ifindex_present = ifindex_present;
    sample->ifindex = ifindex;
    sample->message_flags = msg_flags;
    sample->received_len = received_length;
    sample->copied_len = copied_length;
    sample->reject_reason = reject_reason;
    sample->packet_truncated = packet_truncated;
    const size_t prefix_length = copied_length < MAX_REJECT_PREFIX_BYTES
        ? copied_length : MAX_REJECT_PREFIX_BYTES;
    sample->raw_prefix_len = prefix_length;
    sample->raw_prefix_truncated = copied_length > prefix_length;
    if (prefix_length > 0U && packet != NULL)
        memcpy(sample->raw_prefix, packet, prefix_length);
    if (radiotap != NULL) {
        sample->version_present = radiotap->version_present;
        sample->version = radiotap->version;
        sample->pad_present = radiotap->pad_present;
        sample->pad = radiotap->pad;
        sample->declared_header_length_present =
            radiotap->declared_header_length_present;
        sample->declared_header_length = radiotap->declared_header_length;
        sample->present_bitmap_present = radiotap->present_bitmap_present;
        sample->present_bitmap_complete = radiotap->present_bitmap_complete;
        sample->present_bitmap_capacity_exceeded =
            radiotap->present_bitmap_capacity_exceeded;
        sample->present_word_count = radiotap->present_word_count;
        memcpy(sample->present_words, radiotap->present_words,
               sizeof(sample->present_words));
        sample->radiotap_parse_reason = radiotap->reject_reason;
    }
}

#ifdef SENDER_TIMING_TEST
static uint64_t test_monotonic_now_ns = UINT64_C(100000000000);
static const char *test_monotonic_stage = "gate";
static bool test_clock_failure_used;

static void set_timing_test_stage(const char *stage) {
    test_monotonic_stage = stage;
}

static uint64_t monotonic_ns(void) {
    const char *fail_stage = getenv("SENDER_TIMING_TEST_CLOCK_FAIL_STAGE");
    if (!test_clock_failure_used && fail_stage != NULL &&
        strcmp(fail_stage, test_monotonic_stage) == 0) {
        test_clock_failure_used = true;
        errno = EIO;
        return 0;
    }
    uint64_t now = test_monotonic_now_ns;
    if (now == 0 || now > UINT64_MAX - UINT64_C(1000)) return 0;
    test_monotonic_now_ns += UINT64_C(1000);
    return now;
}
#else
static uint64_t monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}
#endif

#ifdef SENDER_TIMING_TEST
#define SET_TIMING_TEST_STAGE(stage) set_timing_test_stage(stage)
#else
#define SET_TIMING_TEST_STAGE(stage) ((void)0)
#endif

static bool sleep_until_ns(uint64_t deadline_ns, int *error_code) {
    if (error_code != NULL) *error_code = 0;
#ifdef SENDER_TIMING_TEST
    const char *injected_error = getenv("SENDER_TIMING_TEST_SLEEP_ERROR");
    if (injected_error != NULL) {
        unsigned parsed_error = 0;
        if (!parse_uint(injected_error, 1U, 4095U, &parsed_error)) {
            if (error_code != NULL) *error_code = EINVAL;
            return false;
        }
        if (error_code != NULL) *error_code = (int)parsed_error;
        return false;
    }
    if (deadline_ns <= test_monotonic_now_ns) return true;
    test_monotonic_now_ns = deadline_ns;
    return true;
#else
#ifdef SENDER_HOST_TEST
    for (;;) {
        uint64_t now = monotonic_ns();
        if (now == 0) {
            if (error_code != NULL) *error_code = errno != 0 ? errno : EIO;
            return false;
        }
        if (now >= deadline_ns) return true;
        uint64_t remaining = deadline_ns - now;
        struct timespec relative = {
            .tv_sec = (time_t)(remaining / UINT64_C(1000000000)),
            .tv_nsec = (long)(remaining % UINT64_C(1000000000)),
        };
        if (nanosleep(&relative, NULL) == 0) return true;
        if (errno != EINTR) {
            if (error_code != NULL) *error_code = errno;
            return false;
        }
    }
#else
    struct timespec deadline = {
        .tv_sec = (time_t)(deadline_ns / UINT64_C(1000000000)),
        .tv_nsec = (long)(deadline_ns % UINT64_C(1000000000)),
    };
    int result;
    do {
        result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
    } while (result == EINTR);
    if (result != 0 && error_code != NULL) *error_code = result;
    return result == 0;
#endif
#endif
}

enum gate_result { GATE_GO, GATE_ABORT, GATE_FAILED };

/* Return 1 for a complete line, 0 for timeout, -1 for EOF/error/overlong. */
static int read_line_until(uint64_t deadline_ns, char *line, size_t capacity) {
    size_t used = 0;
    if (capacity < 2U) return -1;
    for (;;) {
        uint64_t now = monotonic_ns();
        if (now == 0 || now >= deadline_ns) return 0;
        uint64_t remaining_ns = deadline_ns - now;
        int timeout_ms = (int)((remaining_ns + UINT64_C(999999)) / UINT64_C(1000000));
        struct pollfd descriptor = {.fd = STDIN_FILENO, .events = POLLIN};
        int ready;
        do {
            ready = poll(&descriptor, 1, timeout_ms);
        } while (ready < 0 && errno == EINTR);
        if (ready <= 0) return ready == 0 ? 0 : -1;
        if (!(descriptor.revents & POLLIN)) return -1;
        char ch;
        ssize_t n;
        do {
            n = read(STDIN_FILENO, &ch, 1);
        } while (n < 0 && errno == EINTR);
        if (n != 1 || used + 1U >= capacity) return -1;
        line[used++] = ch;
        if (ch == '\n') {
            line[used] = '\0';
            return 1;
        }
    }
}

static enum gate_result wait_for_go(const struct options *options,
                                    uint64_t *go_received_ns) {
    uint64_t start = monotonic_ns();
    if (start == 0 || start > UINT64_MAX - (uint64_t)GO_TIMEOUT_MS * UINT64_C(1000000))
        return GATE_FAILED;
    uint64_t deadline = start + (uint64_t)GO_TIMEOUT_MS * UINT64_C(1000000);
    if (printf("READY frames=%u interval_ms=%u mpdu_bytes=%u radiotap_bytes=%u packet_bytes=%u udp_payload_bytes=8 tx_flags=NOACK|NOSEQNO hardware_honoring=unknown\n",
               options->count, options->interval_ms, MPDU_LENGTH,
               RADIOTAP_LENGTH, PACKET_LENGTH) < 0 || fflush(stdout) != 0)
        return GATE_FAILED;
    char expected[NONCE_HEX_BYTES + 5U];
    int expected_length = snprintf(expected, sizeof(expected), "GO %s\n", options->nonce);
    if (expected_length < 0 || (size_t)expected_length >= sizeof(expected))
        return GATE_FAILED;
    for (;;) {
        char line[NONCE_HEX_BYTES + 8U];
        int read_result = read_line_until(deadline, line, sizeof(line));
        if (read_result != 1) return GATE_FAILED;
        if (strcmp(line, "WAIT\n") == 0) continue;
        if (strcmp(line, "ABORT\n") == 0) return GATE_ABORT;
        if (strcmp(line, expected) == 0) {
            uint64_t received = monotonic_ns();
            if (received == 0 || go_received_ns == NULL) return GATE_FAILED;
            *go_received_ns = received;
            return GATE_GO;
        }
        return GATE_FAILED;
    }
}

static bool post_go_control_pending(void) {
    struct pollfd descriptor = {.fd = STDIN_FILENO, .events = POLLIN};
    int result;
    do {
        result = poll(&descriptor, 1, 0);
    } while (result < 0 && errno == EINTR);
    return result > 0 && (descriptor.revents & (POLLIN | POLLHUP | POLLERR));
}

static int dry_run(const struct options *options) {
    if (!validate_probe_contract()) {
        (void)fprintf(stderr, "error=probe_contract_invalid\n");
        return EXIT_ARGUMENT;
    }
    if (printf("mode=dry-run frames=%u interval_ms=%u mpdu_bytes=%u radiotap_bytes=%u tx_flags=NOACK|NOSEQNO hardware_honoring=unknown\n",
               options->count, options->interval_ms, MPDU_LENGTH,
               RADIOTAP_LENGTH) < 0) return EXIT_SEND;
    for (unsigned i = 0; i < options->count; ++i) {
        uint8_t packet[PACKET_LENGTH];
        unsigned wifi_sequence, awdl_sequence;
        build_packet(packet, i, &wifi_sequence, &awdl_sequence);
        struct radiotap_observation parsed;
        if (parse_radiotap(packet, sizeof(packet), &parsed) != RADIOTAP_VALID ||
            !parsed.has_tx_flags || parsed.tx_flags != 0x18U) {
            (void)fprintf(stderr, "error=probe_radiotap_contract_invalid\n");
            return EXIT_ARGUMENT;
        }
        char digest[65];
        mpdu_sha256_hex(packet + RADIOTAP_LENGTH, MPDU_LENGTH, digest);
        if (printf("frame=%u wifi_seq=%u awdl_seq=%u bytes=%u mpdu_sha256=%s\n",
                   i + 1U, wifi_sequence, awdl_sequence,
                   (unsigned)sizeof(packet), digest) < 0) return EXIT_SEND;
    }
    return fflush(stdout) == 0 ? 0 : EXIT_SEND;
}

#ifndef SENDER_HOST_TEST
static bool monitor_interface_index(const char *name, int *ifindex) {
    int control = -1;
    struct ifreq request;
    unsigned index;
    if (!valid_ifname(name) || ifindex == NULL) return false;
    index = if_nametoindex(name);
    if (index == 0 || index > INT_MAX) return false;
    control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (control < 0) return false;
    memset(&request, 0, sizeof(request));
    memcpy(request.ifr_name, name, strlen(name) + 1U);
    if (ioctl(control, SIOCGIFHWADDR, &request) != 0) {
        int saved = errno;
        (void)close(control);
        errno = saved;
        return false;
    }
    if (close(control) != 0) return false;
    if ((unsigned short)request.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_RADIOTAP) {
        errno = EPROTOTYPE;
        return false;
    }
    *ifindex = (int)index;
    return true;
}

static int open_packet_socket(int ifindex) {
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                    htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct sockaddr_ll address;
    memset(&address, 0, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int open_provenance_receive_socket(int ifindex) {
    int fd = open_packet_socket(ifindex);
    if (fd < 0) return -1;
    int receive_buffer = 256 * 1024;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer,
                     sizeof(receive_buffer));
    return fd;
}

static int drain_packet_socket(int fd, struct provenance_capture *capture,
                               bool before_send,
                               unsigned attempted_frames) {
    uint8_t packet[CAPTURE_PACKET_BYTES];
    unsigned drained_this_call = 0U;
    unsigned read_attempts = 0U;
    for (;;) {
        if (++read_attempts > MAX_CAPTURE_READ_ATTEMPTS) {
            if (before_send) capture->pre_send_queue_empty = false;
            else capture->limit_reached = true;
            return 0;
        }
        if (!before_send && capture->capture_started &&
            capture->deadline_ns != 0U) {
            uint64_t now = monotonic_ns();
            if (now == 0U) {
                capture->receive_error = errno != 0 ? errno : EIO;
                capture->complete = false;
                return -1;
            }
            if (now >= capture->deadline_ns) return 0;
        }
        if (before_send && drained_this_call >= MAX_PRE_SEND_DRAIN_PACKETS) {
            capture->pre_send_queue_empty = false;
            return 0;
        }
        if (!before_send && (capture->rx_packets >= MAX_CAPTURE_PACKETS ||
            capture->exact_matches >= MAX_CAPTURE_MATCHES)) {
            capture->limit_reached = true;
            return 0;
        }
        struct sockaddr_ll address;
        struct iovec vector = {.iov_base = packet, .iov_len = sizeof(packet)};
        struct msghdr message;
        memset(&address, 0, sizeof(address));
        memset(&message, 0, sizeof(message));
        message.msg_name = &address;
        message.msg_namelen = sizeof(address);
        message.msg_iov = &vector;
        message.msg_iovlen = 1U;
        ssize_t received = recvmsg(fd, &message, MSG_DONTWAIT | MSG_TRUNC);
        if (received < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (before_send) capture->pre_send_queue_empty = true;
                return 0;
            }
            capture->receive_error = errno;
            capture->complete = false;
            return -1;
        }
        drained_this_call++;
        if (before_send) {
            capture->pre_send_drained_packets++;
            continue; /* discard pre-GO queue; never join stale echoes */
        }
        capture->rx_packets++;
        const uint64_t received_length = (uint64_t)received;
        const size_t copied_length = received_length > sizeof(packet)
            ? sizeof(packet) : (size_t)received_length;
        struct radiotap_observation radiotap;
        const enum radiotap_parse_result parsed = parse_radiotap(
            packet, copied_length, &radiotap);
        const bool packet_truncated = (message.msg_flags & MSG_TRUNC) != 0 ||
            received_length > sizeof(packet);
        if (packet_truncated) {
            capture->truncated_packets++;
            record_rejected_radiotap(
                capture, packet, copied_length, received_length,
                (unsigned)message.msg_flags, true, address.sll_pkttype,
                address.sll_ifindex > 0, address.sll_ifindex, true,
                RADIOTAP_REJECT_PACKET_TRUNCATED, &radiotap);
            continue;
        }
        if (parsed == RADIOTAP_UNSUPPORTED) {
            capture->unsupported_radiotap++;
            record_rejected_radiotap(
                capture, packet, copied_length, received_length,
                (unsigned)message.msg_flags, true, address.sll_pkttype,
                address.sll_ifindex > 0, address.sll_ifindex, false,
                radiotap.reject_reason, &radiotap);
            continue;
        }
        if (parsed != RADIOTAP_VALID) {
            capture->invalid_radiotap++;
            record_rejected_radiotap(
                capture, packet, copied_length, received_length,
                (unsigned)message.msg_flags, true, address.sll_pkttype,
                address.sll_ifindex > 0, address.sll_ifindex, false,
                radiotap.reject_reason, &radiotap);
            continue;
        }
        size_t mpdu_length = copied_length - radiotap.header_length;
        if (radiotap.has_flags && (radiotap.flags & 0x10U) != 0U) {
            if (mpdu_length < 4U) {
                capture->invalid_radiotap++;
                capture->fcs_bytes_missing++;
                record_rejected_radiotap(
                    capture, packet, copied_length, received_length,
                    (unsigned)message.msg_flags, true, address.sll_pkttype,
                    address.sll_ifindex > 0, address.sll_ifindex, false,
                    RADIOTAP_REJECT_FCS_BYTES_MISSING, &radiotap);
                continue;
            }
            mpdu_length -= 4U;
        }
        capture->decoded_packets++;
        unsigned comparable_frames = attempted_frames < capture->expected_frames
            ? attempted_frames : capture->expected_frames;
        for (unsigned ordinal = 0U; ordinal < comparable_frames; ++ordinal) {
            uint16_t wifi_sequence = (uint16_t)((WIFI_SEQUENCE_BASE + ordinal) & 0x0fffU);
            uint16_t awdl_sequence = (uint16_t)((AWDL_SEQUENCE_BASE + ordinal) & 0xffffU);
            if (mpdu_length != MPDU_LENGTH ||
                memcmp(packet + radiotap.header_length,
                       capture->expected_mpdus[ordinal], MPDU_LENGTH) != 0)
                continue;
            const uint64_t observed_ns = monotonic_ns();
            if (observed_ns == 0U) {
                capture->complete = false;
                capture->receive_error = errno != 0 ? errno : EIO;
                return -1;
            }
            if (!append_exact_observation(
                    capture, ordinal, address.sll_pkttype, wifi_sequence,
                    awdl_sequence, observed_ns, &radiotap)) {
                capture->limit_reached = true;
                return 0;
            }
            break;
        }
    }
}

static bool capture_ready_for_sends(struct provenance_capture *capture) {
    if (capture == NULL || !capture->available) return false;
    return drain_packet_socket(capture->receive_fd, capture, true, 0U) == 0;
}

static bool wait_until_with_capture(uint64_t deadline_ns,
                                    struct provenance_capture *capture,
                                    unsigned attempted_frames,
                                    int *error_code) {
    if (error_code != NULL) *error_code = 0;
    for (;;) {
        uint64_t now = monotonic_ns();
        if (now == 0U) {
            if (error_code != NULL) *error_code = errno != 0 ? errno : EIO;
            return false;
        }
        if (now >= deadline_ns) return true;
        uint64_t remaining = deadline_ns - now;
        int timeout_ms = (int)((remaining + UINT64_C(999999)) /
                               UINT64_C(1000000));
        struct pollfd descriptor = {
            .fd = capture->receive_fd, .events = POLLIN
        };
        int polled = poll(&descriptor, 1U, timeout_ms);
        if (polled < 0 && errno == EINTR) continue;
        if (polled < 0) {
            if (error_code != NULL) *error_code = errno;
            return false;
        }
        if (polled == 0) continue; /* Recheck the absolute schedule deadline. */
        if ((descriptor.revents & (POLLERR | POLLNVAL | POLLHUP)) != 0) {
            if (error_code != NULL) *error_code = EIO;
            return false;
        }
        if ((descriptor.revents & POLLIN) != 0 &&
            drain_packet_socket(capture->receive_fd, capture, false,
                                attempted_frames) != 0) {
            if (error_code != NULL) *error_code = capture->receive_error;
            return false;
        }
    }
}

static void capture_nonblocking(struct provenance_capture *capture,
                                unsigned attempted_frames) {
    if (capture == NULL || !capture->available || capture->limit_reached) return;
    (void)drain_packet_socket(capture->receive_fd, capture, false,
                              attempted_frames);
}

static void collect_packet_statistics(struct provenance_capture *capture) {
    if (capture == NULL || capture->receive_fd < 0) return;
    struct tpacket_stats stats;
    socklen_t length = sizeof(stats);
    memset(&stats, 0, sizeof(stats));
    if (getsockopt(capture->receive_fd, SOL_PACKET, PACKET_STATISTICS,
                   &stats, &length) == 0 && length >= sizeof(stats)) {
        capture->kernel_packets = stats.tp_packets;
        capture->packet_drops = stats.tp_drops;
        capture->kernel_stats_available = true;
    } else {
        capture->statistics_error = errno != 0 ? errno : EIO;
    }
}

#endif

struct send_sample {
    unsigned ordinal;
    unsigned ieee80211_sequence;
    unsigned awdl_sequence;
    bool before_time_valid;
    bool after_time_valid;
    uint64_t before_ns;
    uint64_t after_ns;
    ssize_t return_value;
    int send_errno;
    char mpdu_sha256[65];
};

struct send_result {
    unsigned frames_attempted;
    unsigned frames_completed;
    unsigned error_count;
    unsigned frames_requested;
    int last_errno;
    bool deadline_hit;
    bool timing_valid;
    bool finished_time_valid;
    bool elapsed_time_unknown;
    uint64_t elapsed_ns;
    uint64_t go_received_ns;
    uint64_t started_ns;
    uint64_t finished_ns;
    const char *stop_reason;
    struct send_sample samples[MAX_FRAMES];
    struct provenance_capture provenance;
};

static bool emit_sender_started(const struct options *options,
                                uint64_t go_received_ns,
                                uint64_t started_ns) {
    if (printf("{\"event\":\"SENDER_STARTED\",\"timing_schema\":1,\"clock_domain\":\"CLOCK_MONOTONIC\",\"go_received_ns\":%llu,\"started_ns\":%llu,\"frames_requested\":%u,\"interval_ms\":%u,\"send_budget_ns\":%llu}\n",
               (unsigned long long)go_received_ns,
               (unsigned long long)started_ns,
               options->count, options->interval_ms,
               (unsigned long long)TX_BUDGET_NS) < 0)
        return false;
    return fflush(stdout) == 0;
}

static int emit_send_result(const struct send_result *result) {
    uint64_t elapsed_ms = result->elapsed_ns / UINT64_C(1000000);
    const char *status = strcmp(result->stop_reason, "aborted_before_go") == 0
        ? "aborted"
        : (result->error_count == 0 && result->frames_completed > 0
           ? "complete" : "failed");
    if (printf("{\"event\":\"SENDER_RESULT\",\"status\":\"%s\",\"frames_requested\":%u,\"frames_attempted\":%u,\"frames_completed\":%u,\"sent\":%u,\"payload_bytes\":%u,\"mpdu_bytes\":%u,\"radiotap_bytes\":%u,\"packet_bytes\":%u,\"udp_payload_bytes\":8,\"elapsed_ms\":",
               status,
               result->frames_requested, result->frames_attempted,
               result->frames_completed,
               result->frames_completed, MPDU_LENGTH, MPDU_LENGTH,
               RADIOTAP_LENGTH, PACKET_LENGTH) < 0)
        return EXIT_SEND;
    if (result->elapsed_time_unknown) {
        if (printf("null") < 0) return EXIT_SEND;
    } else if (printf("%llu", (unsigned long long)elapsed_ms) < 0) {
        return EXIT_SEND;
    }
    if (printf(",\"deadline_hit\":%s,\"error_count\":%u,\"last_errno\":%d,\"stop_reason\":\"%s\",\"tx_flags_requested\":\"NOACK|NOSEQNO\",\"hardware_honoring\":\"unknown\"",
               result->deadline_hit ? "true" : "false",
               result->error_count, result->last_errno,
               result->stop_reason != NULL ? result->stop_reason : "unknown") < 0)
        return EXIT_SEND;
    if (result->timing_valid &&
        printf(",\"timing_schema\":1,\"clock_domain\":\"CLOCK_MONOTONIC\",\"go_received_ns\":%llu,\"started_ns\":%llu,\"finished_ns\":",
               (unsigned long long)result->go_received_ns,
               (unsigned long long)result->started_ns) < 0)
        return EXIT_SEND;
    if (result->timing_valid) {
        if (result->finished_time_valid) {
            if (printf("%llu", (unsigned long long)result->finished_ns) < 0)
                return EXIT_SEND;
        } else if (printf("null") < 0) {
            return EXIT_SEND;
        }
        if (printf(",\"send_timing\":[") < 0) return EXIT_SEND;
    }
    if (result->frames_requested > MAX_FRAMES ||
        result->frames_attempted > MAX_FRAMES) return EXIT_SEND;
    for (unsigned i = 0; result->timing_valid && i < result->frames_attempted; ++i) {
        const struct send_sample *sample = &result->samples[i];
        if (printf("%s{\"ordinal\":%u,\"ieee80211_sequence\":%u,\"awdl_sequence\":%u,\"mpdu_sha256\":\"%s\",\"before_ns\":",
                   i == 0 ? "" : ",", sample->ordinal,
                   sample->ieee80211_sequence, sample->awdl_sequence,
                   sample->mpdu_sha256) < 0)
            return EXIT_SEND;
        if (sample->before_time_valid) {
            if (printf("%llu", (unsigned long long)sample->before_ns) < 0)
                return EXIT_SEND;
        } else if (printf("null") < 0) {
            return EXIT_SEND;
        }
        if (printf(",\"after_ns\":") < 0) return EXIT_SEND;
        if (sample->after_time_valid) {
            if (printf("%llu", (unsigned long long)sample->after_ns) < 0)
                return EXIT_SEND;
        } else if (printf("null") < 0) {
            return EXIT_SEND;
        }
        if (printf(",\"return_bytes\":%lld,\"errno\":%d}",
                   (long long)sample->return_value, sample->send_errno) < 0) {
            return EXIT_SEND;
        }
    }
    if (result->timing_valid && printf("]") < 0) return EXIT_SEND;
    const struct provenance_capture *capture = &result->provenance;
    const char *capture_status = !capture->available ? "not_run_host_test" :
        (!capture->capture_started ? "not_started" :
         (capture->receive_error != 0 ? "receive_error" :
          (capture->limit_reached ? "bounded_limit_reached" :
           "bounded_during_send_sequence")));
    if (printf(",\"tx_provenance\":{\"schema\":\"openwrt-tx-observation/v1\",\"capture\":{\"status\":\"%s\",\"window\":\"send_sequence_span\",\"budget_ns\":%llu,\"started_ns\":",
               capture_status, (unsigned long long)TX_BUDGET_NS) < 0)
        return EXIT_SEND;
    if (capture->capture_started) {
        if (printf("%llu", (unsigned long long)capture->started_ns) < 0)
            return EXIT_SEND;
    } else if (printf("null") < 0) {
        return EXIT_SEND;
    }
    if (printf(",\"ended_ns\":") < 0) return EXIT_SEND;
    if (capture->capture_started && capture->ended_ns != 0U) {
        if (printf("%llu", (unsigned long long)capture->ended_ns) < 0)
            return EXIT_SEND;
    } else if (printf("null") < 0) {
        return EXIT_SEND;
    }
    const bool capture_finished = capture->available &&
        capture->capture_finished && capture->ended_ns != 0U;
    const bool decoder_coverage_known = capture->rx_packets != 0U;
    const bool decoder_coverage = decoder_coverage_known &&
        capture->decoded_packets == capture->rx_packets &&
        capture->rejected_packets == 0U &&
        capture->rejected_sample_overflow == 0U;
    const bool known_capture_loss =
        (capture->kernel_stats_available && capture->packet_drops != 0U) ||
        capture->truncated_packets != 0U ||
        capture->rejected_sample_overflow != 0U ||
        capture->receive_error != 0 || capture->limit_reached ||
        (capture->capture_started &&
         (!capture->capture_finished || !capture->complete));
    const bool loss_free_known = known_capture_loss ||
        capture->kernel_stats_available;
    const bool loss_free = loss_free_known && !known_capture_loss &&
        capture->kernel_stats_available;
    if (printf(",\"window_cutoff_semantics\":\"min(actual_finished_ns,started_ns+budget_ns)\",\"actual_finished_ns\":") < 0)
        return EXIT_SEND;
    if (capture->capture_finished && capture->actual_finished_ns != 0U) {
        if (printf("%llu", (unsigned long long)capture->actual_finished_ns) < 0)
            return EXIT_SEND;
    } else if (printf("null") < 0) {
        return EXIT_SEND;
    }
    if (printf(",\"schema_contract\":\"capture_finished_is_execution_completion_not_full_budget_coverage\",\"capture_finished\":%s,\"loss_free\":",
               capture_finished ? "true" : "false") < 0)
        return EXIT_SEND;
    if (loss_free_known) {
        if (printf("%s", loss_free ? "true" : "false") < 0)
            return EXIT_SEND;
    } else if (printf("null") < 0) {
        return EXIT_SEND;
    }
    if (printf(",\"decoder_coverage\":") < 0) return EXIT_SEND;
    if (decoder_coverage_known) {
        if (printf("%s", decoder_coverage ? "true" : "false") < 0)
            return EXIT_SEND;
    } else if (printf("null") < 0) {
        return EXIT_SEND;
    }
    if (printf(",\"actual_horizon_ns\":") < 0) return EXIT_SEND;
    if (capture->capture_finished &&
        capture->actual_finished_ns >= capture->started_ns) {
        if (printf("%llu", (unsigned long long)(capture->actual_finished_ns -
                                                  capture->started_ns)) < 0)
            return EXIT_SEND;
    } else if (printf("null") < 0) {
        return EXIT_SEND;
    }
    if (printf(",\"decode_coverage\":{\"packet_received\":%u,\"packet_decoded\":%u,\"invalid_radiotap\":%u,\"unsupported_radiotap\":%u,\"truncated_packets\":%u,\"fcs_bytes_missing\":%u,\"rejected_radiotap_samples_recorded\":%u,\"rejected_radiotap_sample_overflow\":%u,\"kernel_dropped_packets\":",
               capture->rx_packets, capture->decoded_packets,
               capture->invalid_radiotap, capture->unsupported_radiotap,
               capture->truncated_packets, capture->fcs_bytes_missing,
               capture->rejected_sample_count,
               capture->rejected_sample_overflow) < 0)
        return EXIT_SEND;
    if (capture->kernel_stats_available) {
        if (printf("%u", capture->packet_drops) < 0) return EXIT_SEND;
    } else if (printf("null") < 0) {
        return EXIT_SEND;
    }
    if (printf(",\"kernel_stats_available\":%s,\"kernel_packets\":",
               capture->kernel_stats_available ? "true" : "false") < 0)
        return EXIT_SEND;
    if (capture->kernel_stats_available) {
        if (printf("%u", capture->kernel_packets) < 0) return EXIT_SEND;
    } else if (printf("null") < 0) {
        return EXIT_SEND;
    }
    if (printf(",\"kernel_stats_error\":") < 0) return EXIT_SEND;
    if (capture->statistics_error != 0) {
        if (printf("%d", capture->statistics_error) < 0) return EXIT_SEND;
    } else if (printf("null") < 0) {
        return EXIT_SEND;
    }
    if (printf(",\"receive_error\":") < 0) return EXIT_SEND;
    if (capture->receive_error != 0) {
        if (printf("%d", capture->receive_error) < 0) return EXIT_SEND;
    } else if (printf("null") < 0) {
        return EXIT_SEND;
    }
    if (printf(",\"capture_limit_reached\":%s},\"pre_send_drained_packets\":%u,\"pre_send_queue_empty\":%s,\"rejected_radiotap_samples\":[",
               capture->limit_reached ? "true" : "false",
               capture->pre_send_drained_packets,
               capture->pre_send_queue_empty ? "true" : "false") < 0)
        return EXIT_SEND;
    if (capture->rejected_sample_count > MAX_REJECT_SAMPLES) return EXIT_SEND;
    static const char hex[] = "0123456789abcdef";
    for (unsigned index = 0U; index < capture->rejected_sample_count; ++index) {
        const struct rejected_radiotap_sample *sample =
            &capture->rejected_samples[index];
        char prefix_sha256[65];
        mpdu_sha256_hex(sample->raw_prefix, sample->raw_prefix_len,
                        prefix_sha256);
        if (printf("%s{\"packet_type_present\":%s,\"packet_type\":",
                   index == 0U ? "" : ",",
                   sample->packet_type_present ? "true" : "false") < 0)
            return EXIT_SEND;
        if (sample->packet_type_present) {
            if (printf("%u", sample->packet_type) < 0) return EXIT_SEND;
        } else if (printf("null") < 0) {
            return EXIT_SEND;
        }
        if (printf(",\"ifindex_present\":%s,\"ifindex\":",
                   sample->ifindex_present ? "true" : "false") < 0)
            return EXIT_SEND;
        if (sample->ifindex_present) {
            if (printf("%d", sample->ifindex) < 0) return EXIT_SEND;
        } else if (printf("null") < 0) {
            return EXIT_SEND;
        }
        if (printf(",\"msg_flags\":%u,\"received_len\":%llu,\"copied_len\":%zu,\"version_present\":%s,\"version\":",
                   sample->message_flags,
                   (unsigned long long)sample->received_len,
                   sample->copied_len,
                   sample->version_present ? "true" : "false") < 0)
            return EXIT_SEND;
        if (sample->version_present) {
            if (printf("%u", sample->version) < 0) return EXIT_SEND;
        } else if (printf("null") < 0) {
            return EXIT_SEND;
        }
        if (printf(",\"pad_present\":%s,\"pad\":",
                   sample->pad_present ? "true" : "false") < 0)
            return EXIT_SEND;
        if (sample->pad_present) {
            if (printf("%u", sample->pad) < 0) return EXIT_SEND;
        } else if (printf("null") < 0) {
            return EXIT_SEND;
        }
        if (printf(",\"rtap_declared_len_present\":%s,\"rtap_declared_len\":",
                   sample->declared_header_length_present ? "true" : "false") < 0)
            return EXIT_SEND;
        if (sample->declared_header_length_present) {
            if (printf("%u", sample->declared_header_length) < 0)
                return EXIT_SEND;
        } else if (printf("null") < 0) {
            return EXIT_SEND;
        }
        if (printf(",\"present_bitmap_present\":%s,\"present_bitmap_complete\":%s,\"present_bitmap_capacity_exceeded\":%s,\"present_word_count\":%u,\"present_words\":[",
                   sample->present_bitmap_present ? "true" : "false",
                   sample->present_bitmap_complete ? "true" : "false",
                   sample->present_bitmap_capacity_exceeded ? "true" : "false",
                   sample->present_word_count) < 0)
            return EXIT_SEND;
        if (sample->present_word_count > MAX_PRESENT_BITMAP_WORDS)
            return EXIT_SEND;
        for (unsigned word = 0U; word < sample->present_word_count; ++word) {
            if (printf("%s%u", word == 0U ? "" : ",",
                       sample->present_words[word]) < 0)
                return EXIT_SEND;
        }
        if (printf("],\"reject_reason\":\"%s\",\"radiotap_parse_reason\":\"%s\",\"packet_truncated\":%s,\"raw_prefix_hex\":\"",
                   radiotap_reject_reason_name(sample->reject_reason),
                   radiotap_reject_reason_name(sample->radiotap_parse_reason),
                   sample->packet_truncated ? "true" : "false") < 0)
            return EXIT_SEND;
        if (sample->raw_prefix_len > MAX_REJECT_PREFIX_BYTES) return EXIT_SEND;
        for (size_t byte = 0U; byte < sample->raw_prefix_len; ++byte) {
            const uint8_t value = sample->raw_prefix[byte];
            if (putchar(hex[value >> 4U]) == EOF ||
                putchar(hex[value & 0x0fU]) == EOF)
                return EXIT_SEND;
        }
        if (printf("\",\"raw_prefix_len\":%zu,\"raw_prefix_truncated\":%s,\"raw_prefix_sha256\":\"%s\"}",
                   sample->raw_prefix_len,
                   sample->raw_prefix_truncated ? "true" : "false",
                   prefix_sha256) < 0)
            return EXIT_SEND;
    }
    if (printf(" ]},\"observations\":[") < 0) return EXIT_SEND;
    if (capture->exact_matches > MAX_CAPTURE_MATCHES) return EXIT_SEND;
    for (unsigned i = 0U; i < capture->exact_matches; ++i) {
        const struct provenance_observation *row = &capture->observations[i];
        if (printf("%s{\"ordinal\":%u,\"packet_type\":%u,\"invocation_bound\":false,\"exact_mpdu_match\":true,\"mpdu_sha256\":\"%s\",\"wifi_sequence\":%u,\"awdl_sequence\":%u,\"observed_ns\":%llu,\"classification\":\"%s\",\"has_tx_flags\":%s,\"tx_flags\":%u,\"has_data_retries\":%s,\"data_retries\":%u,\"pid_cookie_tx_status_proven\":false,\"rf_transmission_proven\":false}",
                   i == 0U ? "" : ",", row->ordinal, row->packet_type,
                   row->mpdu_sha256, row->wifi_sequence, row->awdl_sequence,
                   (unsigned long long)row->observed_ns,
                   row->classification != NULL ? row->classification : "unknown",
                   row->has_tx_flags ? "true" : "false", row->tx_flags,
                   row->has_data_retries ? "true" : "false", row->data_retries) < 0)
            return EXIT_SEND;
    }
    if (printf("],\"fixture_mode\":%s,\"run_nonce_is_local_only\":true,\"nonce_in_mpdu\":false,\"tx_status_path\":\"not_observed\",\"tx_status_pid\":null,\"tx_status_cookie\":null,\"pid_txs_expectation\":\"unknown\",\"pid_cookie_bound_tx_status\":\"unknown\",\"pid_cookie_status_source_available\":false,\"tx_status_unknown_reason\":\"AF_PACKET monitor capture has no PID-cookie-bound TXS or TXFREE source\",\"rf_transmission_proven\":false,\"peer_receipt_proven\":false,\"ack_proven\":false}}\n",
               capture->synthetic_fixture
                   ? "\"synthetic_host_fixture\"" : "null") < 0)
        return EXIT_SEND;
    return fflush(stdout) == 0 ? 0 : EXIT_SEND;
}

static int send_sequence(const struct options *options, int fd,
                         struct send_result *result,
                         struct provenance_capture *capture,
                         uint64_t go_received_ns) {
    struct provenance_capture initial_capture;
    bool have_capture = capture != NULL;
    if (have_capture) initial_capture = *capture;
    memset(result, 0, sizeof(*result));
    if (have_capture) {
        result->provenance = initial_capture;
        capture = &result->provenance;
    }
    result->frames_requested = options->count;
    if (capture != NULL) {
        capture->expected_frames = options->count;
        for (unsigned ordinal = 0U; ordinal < options->count; ++ordinal) {
            uint8_t expected[PACKET_LENGTH];
            unsigned wifi_sequence, awdl_sequence;
            build_packet(expected, ordinal, &wifi_sequence, &awdl_sequence);
            memcpy(capture->expected_mpdus[ordinal],
                   expected + RADIOTAP_LENGTH, MPDU_LENGTH);
            mpdu_sha256_hex(capture->expected_mpdus[ordinal], MPDU_LENGTH,
                            capture->expected_mpdu_sha256[ordinal]);
        }
    }
    result->stop_reason = "complete";
#ifdef SENDER_HOST_TEST
#ifndef SENDER_TIMING_TEST
    (void)options;
    (void)fd;
    (void)sleep_until_ns(monotonic_ns(), NULL);
    if (post_go_control_pending()) {
        result->error_count = 1U;
        result->stop_reason = "post_go_control_or_stdin_closed";
        return EXIT_SEND;
    }
    result->error_count = 1U;
    result->stop_reason = "host_test_send_disabled";
    return EXIT_HOST_SEND_DISABLED;
#else
    (void)fd;
#endif
#endif
    #ifndef SENDER_HOST_TEST
    /* Remove queued pre-GO monitor traffic so old identical frames are not joined. */
    if (capture != NULL && capture->available) {
        (void)capture_ready_for_sends(capture);
    }
    #endif
    SET_TIMING_TEST_STAGE("start");
    errno = 0;
    uint64_t started = monotonic_ns();
    if (started == 0 || started > UINT64_MAX - TX_BUDGET_NS) {
        result->error_count = 1U;
        result->stop_reason = "monotonic_clock_unavailable";
        result->last_errno = errno != 0 ? errno : EIO;
        return EXIT_SEND;
    }
    result->timing_valid = true;
    result->go_received_ns = go_received_ns;
    result->started_ns = started;
    if (capture != NULL && capture->available) {
        capture->capture_started = true;
        capture->started_ns = started;
        capture->deadline_ns = started + TX_BUDGET_NS;
        capture->complete = capture->receive_error == 0;
    }
    uint64_t deadline = started + TX_BUDGET_NS;
    if (!emit_sender_started(options, go_received_ns, started)) {
        result->error_count++;
        result->stop_reason = "start_event_write_failed";
        SET_TIMING_TEST_STAGE("finish");
        errno = 0;
        uint64_t finished = monotonic_ns();
        if (finished >= started) {
            result->finished_ns = finished;
            result->finished_time_valid = true;
            result->elapsed_ns = finished - started;
        } else {
            result->last_errno = errno != 0 ? errno : EIO;
            result->elapsed_time_unknown = true;
        }
        return EXIT_SEND;
    }
    for (unsigned i = 0; i < options->count; ++i) {
        if (post_go_control_pending()) {
            result->error_count++;
            result->stop_reason = "post_go_control_or_stdin_closed";
            break;
        }
        if (i != 0 && options->interval_ms != 0) {
            uint64_t scheduled = started +
                (uint64_t)i * (uint64_t)options->interval_ms * UINT64_C(1000000);
            if (scheduled >= deadline) {
                result->error_count++;
                result->deadline_hit = true;
                result->stop_reason = "send_budget_expired";
                break;
            }
            int sleep_error = 0;
            SET_TIMING_TEST_STAGE("sleep");
#ifndef SENDER_HOST_TEST
            bool slept = capture != NULL && capture->available
                ? wait_until_with_capture(scheduled, capture,
                                          result->frames_attempted,
                                          &sleep_error)
                : sleep_until_ns(scheduled, &sleep_error);
            if (!slept && capture != NULL && capture->available) {
                capture->complete = false;
                if (capture->receive_error == 0)
                    capture->receive_error = sleep_error != 0 ? sleep_error : EIO;
                int fallback_error = 0;
                slept = sleep_until_ns(scheduled, &fallback_error);
                if (!slept) sleep_error = fallback_error;
            }
#else
            bool slept = sleep_until_ns(scheduled, &sleep_error);
#endif
            if (!slept) {
                result->error_count++;
                result->last_errno = sleep_error != 0 ? sleep_error : EIO;
                result->stop_reason = "schedule_sleep_error";
                break;
            }
        }
        if (post_go_control_pending()) {
            result->error_count++;
            result->stop_reason = "post_go_control_or_stdin_closed";
            break;
        }
        uint8_t packet[PACKET_LENGTH];
        unsigned wifi_sequence, awdl_sequence;
        build_packet(packet, i, &wifi_sequence, &awdl_sequence);
        SET_TIMING_TEST_STAGE("before");
        errno = 0;
        uint64_t before = monotonic_ns();
        if (before == 0) {
            result->error_count++;
            result->last_errno = errno != 0 ? errno : EIO;
            result->stop_reason = "monotonic_clock_before_failed";
            break;
        }
        if (before >= deadline) {
            result->error_count++;
            result->deadline_hit = true;
            result->stop_reason = "send_budget_expired";
            break;
        }
        struct send_sample *sample = &result->samples[i];
        sample->ordinal = i;
        sample->ieee80211_sequence = wifi_sequence;
        sample->awdl_sequence = awdl_sequence;
        if (capture != NULL && i < capture->expected_frames) {
            memcpy(sample->mpdu_sha256,
                   capture->expected_mpdu_sha256[i],
                   sizeof(sample->mpdu_sha256));
        } else {
            mpdu_sha256_hex(packet + RADIOTAP_LENGTH, MPDU_LENGTH,
                            sample->mpdu_sha256);
        }
        sample->before_time_valid = true;
        sample->before_ns = before;
        result->frames_attempted++;
#ifdef SENDER_TIMING_TEST
        const char *fail_at = getenv("SENDER_TIMING_TEST_FAIL_AT");
        unsigned fail_ordinal = 0;
        if (fail_at != NULL && !parse_uint(fail_at, 1U, MAX_FRAMES, &fail_ordinal)) {
            errno = EINVAL;
            fail_ordinal = i + 1U;
        }
        ssize_t sent;
        if (fail_ordinal == i + 1U) {
            errno = EIO;
            sent = -1;
        } else {
            sent = (ssize_t)PACKET_LENGTH;
        }
#elif defined(SENDER_HOST_TEST)
        (void)fd;
        ssize_t sent = -1;
        errno = EIO;
#else
        ssize_t sent = send(fd, packet, sizeof(packet), MSG_DONTWAIT);
#endif
        int saved_errno = sent < 0 ? errno : 0;
        sample->return_value = sent;
        sample->send_errno = saved_errno;
        SET_TIMING_TEST_STAGE("after");
        errno = 0;
        uint64_t after = monotonic_ns();
        int after_clock_error = errno != 0 ? errno : EIO;
        if (after != 0) {
            sample->after_time_valid = true;
            sample->after_ns = after;
        }
        if (sent != (ssize_t)sizeof(packet)) {
            result->error_count++;
            result->last_errno = saved_errno;
            result->stop_reason = sent < 0 ? "send_errno" : "short_write";
            break;
        }
        result->frames_completed++;
        if (after == 0) {
            result->error_count++;
            result->last_errno = after_clock_error;
            result->stop_reason = "monotonic_clock_after_failed";
            break;
        }
        if (after > deadline) {
            result->error_count++;
            result->deadline_hit = true;
            result->stop_reason = "send_completed_after_budget";
            break;
        }
#ifndef SENDER_HOST_TEST
        if (capture != NULL && capture->available)
            capture_nonblocking(capture, result->frames_attempted);
#endif
    }
    SET_TIMING_TEST_STAGE("finish");
    errno = 0;
    uint64_t finished = monotonic_ns();
    if (finished == 0 || finished < started) {
        result->error_count++;
        result->stop_reason = "monotonic_clock_end_failed";
        result->last_errno = errno != 0 ? errno : EIO;
        result->elapsed_ns = TX_BUDGET_NS;
        result->elapsed_time_unknown = true;
    } else {
        result->finished_ns = finished;
        result->finished_time_valid = true;
        result->elapsed_ns = finished - started;
        if (finished > deadline) result->deadline_hit = true;
    }
    if (capture != NULL && capture->available && capture->capture_started) {
        uint64_t observation_end = finished;
        if (capture->deadline_ns != 0U && observation_end > capture->deadline_ns)
            observation_end = capture->deadline_ns;
        capture->ended_ns = observation_end;
        if (result->finished_time_valid && finished >= started) {
            capture->actual_finished_ns = finished;
            capture->capture_finished = true;
        }
    }
    if (result->frames_completed != options->count && result->error_count == 0) {
        result->error_count++;
        result->stop_reason = "partial_sequence";
    }
    return result->error_count == 0 &&
           result->frames_completed == options->count ? 0 : EXIT_SEND;
}

static int finish_send_result(struct send_result *result, int exit_code) {
    int log_result = emit_send_result(result);
    if (log_result != 0) return log_result;
    return exit_code;
}

#ifndef SENDER_UNIT_TEST
int main(int argc, char **argv) {
    struct options options;
    bool help_requested;
    (void)signal(SIGPIPE, SIG_IGN);
    if (!parse_options(argc, argv, &options, &help_requested)) {
        usage(stderr, argv[0]);
        (void)fprintf(stderr, "error=invalid_arguments\n");
        return EXIT_ARGUMENT;
    }
    if (help_requested) {
        usage(stdout, argv[0]);
        return fflush(stdout) == 0 ? 0 : EXIT_SEND;
    }
    if (!validate_probe_contract()) {
        (void)fprintf(stderr, "error=probe_contract_invalid\n");
        return EXIT_ARGUMENT;
    }
    if (!options.send) return dry_run(&options);

#ifndef SENDER_HOST_TEST
    int ifindex = 0;
    if (!monitor_interface_index(options.interface_name, &ifindex)) {
        (void)fprintf(stderr, "error=monitor_radiotap_interface_required errno=%d\n", errno);
        return EXIT_INTERFACE;
    }
    int fd = open_packet_socket(ifindex);
    if (fd < 0) {
        (void)fprintf(stderr, "error=packet_socket_open_or_bind_failed errno=%d\n", errno);
        return EXIT_INTERFACE;
    }
    int receive_fd = open_provenance_receive_socket(ifindex);
    if (receive_fd < 0) {
        int saved = errno;
        (void)close(fd);
        (void)fprintf(stderr, "error=provenance_receive_socket_failed errno=%d\n", saved);
        return EXIT_INTERFACE;
    }
    struct provenance_capture capture;
    memset(&capture, 0, sizeof(capture));
    capture.receive_fd = receive_fd;
    capture.available = true;
    capture.complete = false;
#else
    int fd = -1;
    struct provenance_capture capture;
    memset(&capture, 0, sizeof(capture));
    capture.receive_fd = -1;
#ifdef SENDER_PROVENANCE_ALIAS_TEST
    capture.available = true;
    capture.pre_send_queue_empty = true;
#endif
#endif

    uint64_t go_received_ns = 0;
    enum gate_result gate = wait_for_go(&options, &go_received_ns);
    struct send_result result;
    memset(&result, 0, sizeof(result));
    result.frames_requested = options.count;
    result.provenance = capture;
    int exit_code = 0;
    if (gate == GATE_ABORT) {
        result.stop_reason = "aborted_before_go";
    } else if (gate == GATE_FAILED) {
        result.error_count = 1U;
        result.stop_reason = "gate_eof_timeout_or_invalid_token";
        exit_code = EXIT_GATE;
    } else {
        exit_code = send_sequence(&options, fd, &result,
                                  &result.provenance, go_received_ns);
    }

#ifndef SENDER_HOST_TEST
    collect_packet_statistics(&result.provenance);
    if (close(receive_fd) != 0 && result.provenance.receive_error == 0) {
        result.provenance.receive_error = errno;
        result.provenance.complete = false;
    }
    result.provenance.receive_fd = -1;
    if (close(fd) != 0) {
        result.error_count++;
        result.last_errno = errno;
        result.stop_reason = "socket_close_error";
        if (exit_code == 0) exit_code = EXIT_SEND;
    }
#endif
    return finish_send_result(&result, exit_code);
}
#endif
