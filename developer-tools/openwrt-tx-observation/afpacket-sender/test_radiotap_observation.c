#define SENDER_HOST_TEST 1
#define SENDER_UNIT_TEST 1
#include "awdl_probe_sender.c"

#include <assert.h>

static void put_le16(uint8_t *bytes, uint16_t value) {
    bytes[0] = (uint8_t)(value & 0xffU);
    bytes[1] = (uint8_t)(value >> 8U);
}

static void put_le32(uint8_t *bytes, uint32_t value) {
    bytes[0] = (uint8_t)(value & 0xffU);
    bytes[1] = (uint8_t)((value >> 8U) & 0xffU);
    bytes[2] = (uint8_t)((value >> 16U) & 0xffU);
    bytes[3] = (uint8_t)(value >> 24U);
}

static void test_valid_empty_header_boundary(void) {
    const uint8_t packet[8] = {0, 0, 8, 0, 0, 0, 0, 0};
    struct radiotap_observation parsed;
    assert(parse_radiotap(packet, sizeof(packet), &parsed) == RADIOTAP_VALID);
    assert(parsed.version_present && parsed.version == 0U);
    assert(parsed.pad_present && parsed.pad == 0U);
    assert(parsed.declared_header_length_present &&
           parsed.declared_header_length == 8U);
    assert(parsed.present_bitmap_present && parsed.present_bitmap_complete);
    assert(parsed.present_word_count == 1U && parsed.present_words[0] == 0U);
    assert(parsed.reject_reason == RADIOTAP_REJECT_NONE);
}

static void test_vendor_namespace_is_preserved_as_reject(void) {
    const uint8_t packet[8] = {0, 0, 8, 0, 0, 0, 0, 0};
    uint8_t fixture[sizeof(packet)];
    memcpy(fixture, packet, sizeof(packet));
    put_le32(fixture + 4U, UINT32_C(0x40000000));
    struct radiotap_observation parsed;
    assert(parse_radiotap(fixture, sizeof(fixture), &parsed) ==
           RADIOTAP_UNSUPPORTED);
    assert(parsed.reject_reason == RADIOTAP_REJECT_VENDOR_NAMESPACE);
    assert(parsed.present_bitmap_complete && parsed.present_word_count == 1U);
}

static void test_extended_bitmap_valid_and_unknown_namespace(void) {
    uint8_t valid[12] = {0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    put_le32(valid + 4U, UINT32_C(0x80000000));
    put_le32(valid + 8U, 0U);
    struct radiotap_observation parsed;
    assert(parse_radiotap(valid, sizeof(valid), &parsed) == RADIOTAP_VALID);
    assert(parsed.present_word_count == 2U && parsed.present_bitmap_complete);

    put_le32(valid + 8U, 1U);
    assert(parse_radiotap(valid, sizeof(valid), &parsed) ==
           RADIOTAP_UNSUPPORTED);
    assert(parsed.reject_reason == RADIOTAP_REJECT_UNSUPPORTED_NAMESPACE);
    assert(parsed.present_word_count == 2U && parsed.present_words[1] == 1U);
}

static void test_truncated_bitmap_short_header_and_lengths(void) {
    uint8_t packet[12] = {0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    put_le32(packet + 4U, UINT32_C(0x80000000));
    struct radiotap_observation parsed;
    assert(parse_radiotap(packet, 8U, &parsed) == RADIOTAP_INVALID);
    assert(parsed.reject_reason == RADIOTAP_REJECT_PRESENT_BITMAP_TRUNCATED);
    assert(parsed.present_bitmap_present && !parsed.present_bitmap_complete);

    assert(parse_radiotap(packet, 7U, &parsed) == RADIOTAP_INVALID);
    assert(parsed.reject_reason == RADIOTAP_REJECT_SHORT_HEADER);

    packet[0] = 1U;
    assert(parse_radiotap(packet, 8U, &parsed) == RADIOTAP_INVALID);
    assert(parsed.reject_reason == RADIOTAP_REJECT_INVALID_VERSION);
    packet[0] = 0U;
    packet[1] = 1U;
    assert(parse_radiotap(packet, 8U, &parsed) == RADIOTAP_INVALID);
    assert(parsed.reject_reason == RADIOTAP_REJECT_INVALID_PAD);

    packet[1] = 0U;
    put_le16(packet + 2U, 13U);
    assert(parse_radiotap(packet, 12U, &parsed) == RADIOTAP_INVALID);
    assert(parsed.reject_reason == RADIOTAP_REJECT_INVALID_DECLARED_LENGTH);
}

static void test_short_header_preserves_only_available_fields(void) {
    const uint8_t one_byte[] = {0U};
    const uint8_t three_bytes[] = {0U, 0U, 8U};
    const uint8_t seven_bytes[] = {0U, 0U, 8U, 0U, 0U, 0U, 0U};
    const struct {
        const uint8_t *bytes;
        size_t length;
        bool version_present;
        bool pad_present;
        bool declared_length_present;
    } cases[] = {
        {one_byte, sizeof(one_byte), true, false, false},
        {three_bytes, sizeof(three_bytes), true, true, false},
        {seven_bytes, sizeof(seven_bytes), true, true, true},
    };

    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        struct radiotap_observation parsed;
        assert(parse_radiotap(cases[index].bytes, cases[index].length,
                              &parsed) == RADIOTAP_INVALID);
        assert(parsed.reject_reason == RADIOTAP_REJECT_SHORT_HEADER);
        assert(parsed.version_present == cases[index].version_present);
        assert(parsed.pad_present == cases[index].pad_present);
        assert(parsed.declared_header_length_present ==
               cases[index].declared_length_present);
        assert(!parsed.present_bitmap_present);
        assert(!parsed.present_bitmap_complete);
        assert(!parsed.present_bitmap_capacity_exceeded);
        assert(parsed.present_word_count == 0U);
        if (parsed.version_present) assert(parsed.version == 0U);
        if (parsed.pad_present) assert(parsed.pad == 0U);
        if (parsed.declared_header_length_present)
            assert(parsed.declared_header_length == 8U);
    }
}

static void test_field_bounds_and_present_capacity_overflow(void) {
    uint8_t field_missing[8] = {0, 0, 8, 0, 2, 0, 0, 0};
    struct radiotap_observation parsed;
    assert(parse_radiotap(field_missing, sizeof(field_missing), &parsed) ==
           RADIOTAP_INVALID);
    assert(parsed.reject_reason == RADIOTAP_REJECT_FIELD_BOUNDS);

    uint8_t too_many[4U + MAX_PRESENT_BITMAP_WORDS * 4U] = {0};
    too_many[0] = 0U;
    too_many[1] = 0U;
    put_le16(too_many + 2U, (uint16_t)sizeof(too_many));
    for (unsigned index = 0U; index < MAX_PRESENT_BITMAP_WORDS; ++index)
        put_le32(too_many + 4U + (size_t)index * 4U,
                 UINT32_C(0x80000000));
    assert(parse_radiotap(too_many, sizeof(too_many), &parsed) ==
           RADIOTAP_UNSUPPORTED);
    assert(parsed.reject_reason ==
           RADIOTAP_REJECT_PRESENT_BITMAP_CAPACITY_EXCEEDED);
    assert(parsed.present_bitmap_capacity_exceeded);
    assert(parsed.present_word_count == MAX_PRESENT_BITMAP_WORDS);
}

static void test_rejected_sample_fields_prefix_hash_and_overflow(void) {
    struct provenance_capture capture;
    memset(&capture, 0, sizeof(capture));
    struct radiotap_observation parsed;
    const uint8_t bytes[] = {'a', 'b', 'c'};
    assert(parse_radiotap(bytes, sizeof(bytes), &parsed) == RADIOTAP_INVALID);
    record_rejected_radiotap(&capture, bytes, sizeof(bytes), sizeof(bytes),
        0x20U, true, PACKET_TYPE_OUTGOING, true, 7, false,
        parsed.reject_reason, &parsed);
    assert(capture.rejected_sample_count == 1U);
    const struct rejected_radiotap_sample *sample =
        &capture.rejected_samples[0];
    assert(sample->packet_type_present &&
           sample->packet_type == PACKET_TYPE_OUTGOING);
    assert(sample->ifindex_present && sample->ifindex == 7);
    assert(sample->message_flags == 0x20U);
    assert(sample->received_len == 3U && sample->copied_len == 3U);
    assert(sample->raw_prefix_len == 3U && !sample->raw_prefix_truncated);
    assert(memcmp(sample->raw_prefix, "abc", 3U) == 0);
    char digest[65];
    mpdu_sha256_hex(sample->raw_prefix, sample->raw_prefix_len, digest);
    assert(strcmp(digest,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);

    uint8_t long_packet[120];
    memset(long_packet, 0x5a, sizeof(long_packet));
    for (unsigned index = 0U; index < MAX_REJECT_SAMPLES + 2U; ++index) {
        record_rejected_radiotap(&capture, long_packet, sizeof(long_packet),
            sizeof(long_packet), 0U, false, 0U, false, 0, true,
            RADIOTAP_REJECT_PACKET_TRUNCATED, NULL);
    }
    assert(capture.rejected_sample_count == MAX_REJECT_SAMPLES);
    assert(capture.rejected_sample_overflow == 3U);
    assert(capture.rejected_packets == MAX_REJECT_SAMPLES + 3U);
    sample = &capture.rejected_samples[1];
    assert(sample->received_len == 120U && sample->copied_len == 120U);
    assert(sample->raw_prefix_len == MAX_REJECT_PREFIX_BYTES);
    assert(sample->raw_prefix_truncated);
    assert(sample->packet_truncated);
    for (size_t index = 0U; index < sample->raw_prefix_len; ++index)
        assert(sample->raw_prefix[index] == 0x5aU);
}

static void test_exact_observation_publish_is_atomic_on_clock_failure(void) {
    struct provenance_capture capture;
    memset(&capture, 0, sizeof(capture));
    strcpy(capture.expected_mpdu_sha256[0],
           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    struct radiotap_observation radiotap;
    memset(&radiotap, 0, sizeof(radiotap));
    assert(!append_exact_observation(&capture, 0U, PACKET_TYPE_OUTGOING,
        WIFI_SEQUENCE_BASE, AWDL_SEQUENCE_BASE, 0U, &radiotap));
    assert(capture.exact_matches == 0U);
    assert(capture.observations[0].observed_ns == 0U);
    assert(capture.observations[0].mpdu_sha256[0] == '\0');

    assert(append_exact_observation(&capture, 0U, PACKET_TYPE_OUTGOING,
        WIFI_SEQUENCE_BASE, AWDL_SEQUENCE_BASE, UINT64_C(123456), &radiotap));
    assert(capture.exact_matches == 1U);
    assert(capture.observations[0].observed_ns == UINT64_C(123456));
    assert(strcmp(capture.observations[0].mpdu_sha256,
        capture.expected_mpdu_sha256[0]) == 0);
    assert(strcmp(capture.observations[0].classification,
                  "packet_outgoing_echo") == 0);
}

static int emit_synthetic_result(void) {
    struct send_result result;
    memset(&result, 0, sizeof(result));
    result.frames_requested = 1U;
    result.frames_attempted = 1U;
    result.frames_completed = 1U;
    result.timing_valid = true;
    result.finished_time_valid = true;
    result.go_received_ns = UINT64_C(90000);
    result.started_ns = UINT64_C(100000);
    result.finished_ns = UINT64_C(131000);
    result.elapsed_ns = UINT64_C(31000);
    result.stop_reason = "complete";
    struct send_sample *send = &result.samples[0];
    send->ordinal = 0U;
    send->ieee80211_sequence = WIFI_SEQUENCE_BASE;
    send->awdl_sequence = AWDL_SEQUENCE_BASE;
    send->before_time_valid = true;
    send->after_time_valid = true;
    send->before_ns = UINT64_C(110000);
    send->after_ns = UINT64_C(111000);
    send->return_value = (ssize_t)PACKET_LENGTH;
    mpdu_sha256_hex(mpdu_base, MPDU_LENGTH, send->mpdu_sha256);

    struct provenance_capture *capture = &result.provenance;
    capture->available = true;
    capture->complete = true;
    capture->capture_started = true;
    capture->capture_finished = true;
    capture->synthetic_fixture = true;
    capture->started_ns = UINT64_C(100000);
    capture->ended_ns = UINT64_C(131000);
    capture->actual_finished_ns = UINT64_C(131000);
    capture->deadline_ns = capture->started_ns + TX_BUDGET_NS;
    capture->rx_packets = 2U;
    capture->decoded_packets = 1U;
    capture->unsupported_radiotap = 1U;
    capture->rejected_packets = 1U;
    capture->kernel_stats_available = true;
    capture->kernel_packets = 2U;
    capture->pre_send_queue_empty = true;
    capture->exact_matches = 1U;
    struct provenance_observation *observation = &capture->observations[0];
    observation->ordinal = 0U;
    observation->packet_type = PACKET_TYPE_OUTGOING;
    observation->wifi_sequence = WIFI_SEQUENCE_BASE;
    observation->awdl_sequence = AWDL_SEQUENCE_BASE;
    observation->observed_ns = UINT64_C(120000);
    observation->classification = "packet_outgoing_echo";
    memcpy(observation->mpdu_sha256, send->mpdu_sha256,
           sizeof(observation->mpdu_sha256));

    const uint8_t vendor[8] = {0, 0, 8, 0, 0, 0, 0, 0};
    uint8_t vendor_packet[sizeof(vendor)];
    memcpy(vendor_packet, vendor, sizeof(vendor));
    put_le32(vendor_packet + 4U, UINT32_C(0x40000000));
    struct radiotap_observation parsed;
    const enum radiotap_parse_result parse_result = parse_radiotap(
        vendor_packet, sizeof(vendor_packet), &parsed);
    if (parse_result != RADIOTAP_UNSUPPORTED) return 1;
    record_rejected_radiotap(capture, vendor_packet, sizeof(vendor_packet),
        sizeof(vendor_packet), 0U, true, PACKET_TYPE_OTHERHOST,
        true, 7, false, parsed.reject_reason, &parsed);
    return emit_send_result(&result);
}

static int emit_synthetic_failure_result(void) {
    struct send_result result;
    memset(&result, 0, sizeof(result));
    result.frames_requested = MAX_FRAMES;
    result.error_count = 1U;
    result.last_errno = EIO;
    result.stop_reason = "receive_error";
    result.timing_valid = true;
    result.elapsed_time_unknown = true;
    result.started_ns = UINT64_C(200000);
    result.go_received_ns = UINT64_C(190000);
    struct provenance_capture *capture = &result.provenance;
    capture->available = true;
    capture->capture_started = true;
    capture->synthetic_fixture = true;
    capture->started_ns = UINT64_C(200000);
    capture->receive_error = EIO;
    capture->statistics_error = ENOPROTOOPT;
    return emit_send_result(&result);
}

static int emit_synthetic_short_header_results(void) {
    static const uint8_t one_byte[] = {0U};
    static const uint8_t three_bytes[] = {0U, 0U, 8U};
    static const uint8_t seven_bytes[] = {0U, 0U, 8U, 0U, 0U, 0U, 0U};
    static const struct {
        const uint8_t *bytes;
        size_t length;
    } packets[] = {
        {one_byte, sizeof(one_byte)},
        {three_bytes, sizeof(three_bytes)},
        {seven_bytes, sizeof(seven_bytes)},
    };

    struct send_result result;
    memset(&result, 0, sizeof(result));
    result.frames_requested = 1U;
    result.frames_attempted = 1U;
    result.frames_completed = 1U;
    result.timing_valid = true;
    result.finished_time_valid = true;
    result.go_received_ns = UINT64_C(90000);
    result.started_ns = UINT64_C(100000);
    result.finished_ns = UINT64_C(131000);
    result.elapsed_ns = UINT64_C(31000);
    result.stop_reason = "complete";
    struct send_sample *send = &result.samples[0];
    send->ordinal = 0U;
    send->ieee80211_sequence = WIFI_SEQUENCE_BASE;
    send->awdl_sequence = AWDL_SEQUENCE_BASE;
    send->before_time_valid = true;
    send->after_time_valid = true;
    send->before_ns = UINT64_C(110000);
    send->after_ns = UINT64_C(111000);
    send->return_value = (ssize_t)PACKET_LENGTH;
    mpdu_sha256_hex(mpdu_base, MPDU_LENGTH, send->mpdu_sha256);

    struct provenance_capture *capture = &result.provenance;
    capture->available = true;
    capture->complete = true;
    capture->capture_started = true;
    capture->capture_finished = true;
    capture->synthetic_fixture = true;
    capture->started_ns = UINT64_C(100000);
    capture->ended_ns = UINT64_C(131000);
    capture->actual_finished_ns = UINT64_C(131000);
    capture->deadline_ns = capture->started_ns + TX_BUDGET_NS;
    capture->rx_packets = (unsigned)(sizeof(packets) / sizeof(packets[0]));
    capture->invalid_radiotap = capture->rx_packets;
    capture->rejected_packets = capture->rx_packets;
    capture->kernel_stats_available = true;
    capture->kernel_packets = capture->rx_packets;
    capture->pre_send_queue_empty = true;

    for (size_t index = 0U; index < sizeof(packets) / sizeof(packets[0]); ++index) {
        struct radiotap_observation parsed;
        if (parse_radiotap(packets[index].bytes, packets[index].length,
                           &parsed) != RADIOTAP_INVALID ||
            parsed.reject_reason != RADIOTAP_REJECT_SHORT_HEADER)
            return 1;
        record_rejected_radiotap(capture, packets[index].bytes,
            packets[index].length, packets[index].length, 0U, true,
            PACKET_TYPE_OTHERHOST, true, 7, false,
            parsed.reject_reason, &parsed);
    }
    return emit_send_result(&result);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--emit-synthetic") == 0)
        return emit_synthetic_result();
    if (argc == 2 && strcmp(argv[1], "--emit-synthetic-failure") == 0)
        return emit_synthetic_failure_result();
    if (argc == 2 && strcmp(argv[1], "--emit-short-header-fixtures") == 0)
        return emit_synthetic_short_header_results();
    if (argc != 1) return 2;
    test_valid_empty_header_boundary();
    test_vendor_namespace_is_preserved_as_reject();
    test_extended_bitmap_valid_and_unknown_namespace();
    test_truncated_bitmap_short_header_and_lengths();
    test_short_header_preserves_only_available_fields();
    test_field_bounds_and_present_capacity_overflow();
    test_rejected_sample_fields_prefix_hash_and_overflow();
    test_exact_observation_publish_is_atomic_on_clock_failure();
    puts("radiotap_observation_fixtures=passed");
    return 0;
}
