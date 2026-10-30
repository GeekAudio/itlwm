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

#define MAX_FRAMES 16U
#define MAX_INTERVAL_MS 80U
#define TX_BUDGET_NS UINT64_C(2000000000)
#define GO_TIMEOUT_MS 30000
#define IFNAME_MAX_BYTES 15U
#define NONCE_HEX_BYTES 32U
#define MPDU_LENGTH 96U
#define RADIOTAP_LENGTH 10U
#define PACKET_LENGTH (MPDU_LENGTH + RADIOTAP_LENGTH)
#define WIFI_SEQUENCE_BASE 291U
#define AWDL_SEQUENCE_BASE 34305U
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
        "Usage: %s [--count 1..16] [--interval-ms 0..80] "
        "[--send --interface NAME --nonce 32hex --wait-go]\n"
        "Default: dry-run only. Sending requires explicit --send and gated nonce.\n",
        program);
}

static bool parse_options(int argc, char **argv, struct options *out,
                          bool *help_requested) {
    bool seen_send = false, seen_if = false, seen_count = false, seen_nonce = false;
    bool seen_interval = false, seen_wait = false;
    *out = (struct options){.count = MAX_FRAMES, .interval_ms = 80U};
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

static uint64_t monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static bool sleep_until_ns(uint64_t deadline_ns) {
#ifdef SENDER_HOST_TEST
    for (;;) {
        uint64_t now = monotonic_ns();
        if (now == 0) return false;
        if (now >= deadline_ns) return true;
        uint64_t remaining = deadline_ns - now;
        struct timespec relative = {
            .tv_sec = (time_t)(remaining / UINT64_C(1000000000)),
            .tv_nsec = (long)(remaining % UINT64_C(1000000000)),
        };
        if (nanosleep(&relative, NULL) == 0) return true;
        if (errno != EINTR) return false;
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
    return result == 0;
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

static enum gate_result wait_for_go(const struct options *options) {
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
        if (strcmp(line, expected) == 0) return GATE_GO;
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
        if (printf("frame=%u wifi_seq=%u awdl_seq=%u bytes=%u\n",
                   i + 1U, wifi_sequence, awdl_sequence,
                   (unsigned)sizeof(packet)) < 0) return EXIT_SEND;
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

#endif

struct send_result {
    unsigned frames_attempted;
    unsigned frames_completed;
    unsigned error_count;
    int last_errno;
    bool deadline_hit;
    uint64_t elapsed_ns;
    const char *stop_reason;
};

static int emit_send_result(const struct send_result *result) {
    uint64_t elapsed_ms = result->elapsed_ns / UINT64_C(1000000);
    const char *status = strcmp(result->stop_reason, "aborted_before_go") == 0
        ? "aborted"
        : (result->error_count == 0 && result->frames_completed > 0
           ? "complete" : "failed");
    if (printf("{\"event\":\"SENDER_RESULT\",\"status\":\"%s\",\"frames_attempted\":%u,\"frames_completed\":%u,\"sent\":%u,\"payload_bytes\":%u,\"mpdu_bytes\":%u,\"radiotap_bytes\":%u,\"packet_bytes\":%u,\"udp_payload_bytes\":8,\"elapsed_ms\":%llu,\"deadline_hit\":%s,\"error_count\":%u,\"last_errno\":%d,\"stop_reason\":\"%s\",\"tx_flags_requested\":\"NOACK|NOSEQNO\",\"hardware_honoring\":\"unknown\"}\n",
               status,
               result->frames_attempted, result->frames_completed,
               result->frames_completed, MPDU_LENGTH, MPDU_LENGTH,
               RADIOTAP_LENGTH, PACKET_LENGTH,
               (unsigned long long)elapsed_ms,
               result->deadline_hit ? "true" : "false",
               result->error_count, result->last_errno,
               result->stop_reason != NULL ? result->stop_reason : "unknown") < 0)
        return EXIT_SEND;
    return fflush(stdout) == 0 ? 0 : EXIT_SEND;
}

static int send_sequence(const struct options *options, int fd,
                         struct send_result *result) {
    memset(result, 0, sizeof(*result));
    result->stop_reason = "complete";
#ifdef SENDER_HOST_TEST
    (void)options;
    (void)fd;
    (void)sleep_until_ns(monotonic_ns());
    if (post_go_control_pending()) {
        result->error_count = 1U;
        result->stop_reason = "post_go_control_or_stdin_closed";
        return EXIT_SEND;
    }
    result->error_count = 1U;
    result->stop_reason = "host_test_send_disabled";
    return EXIT_HOST_SEND_DISABLED;
#else
    uint64_t started = monotonic_ns();
    if (started == 0 || started > UINT64_MAX - TX_BUDGET_NS) {
        result->error_count = 1U;
        result->stop_reason = "monotonic_clock_unavailable";
        return EXIT_SEND;
    }
    uint64_t deadline = started + TX_BUDGET_NS;
    for (unsigned i = 0; i < options->count; ++i) {
        if (post_go_control_pending()) {
            result->error_count++;
            result->stop_reason = "post_go_control_or_stdin_closed";
            break;
        }
        if (i != 0 && options->interval_ms != 0) {
            uint64_t scheduled = started +
                (uint64_t)i * (uint64_t)options->interval_ms * UINT64_C(1000000);
            if (scheduled >= deadline || !sleep_until_ns(scheduled)) {
                result->error_count++;
                result->deadline_hit = scheduled >= deadline;
                result->stop_reason = "schedule_or_sleep_failed";
                break;
            }
        }
        if (post_go_control_pending()) {
            result->error_count++;
            result->stop_reason = "post_go_control_or_stdin_closed";
            break;
        }
        uint64_t before = monotonic_ns();
        if (before == 0 || before >= deadline) {
            result->error_count++;
            result->deadline_hit = true;
            result->stop_reason = "send_budget_expired";
            break;
        }
        uint8_t packet[PACKET_LENGTH];
        unsigned wifi_sequence, awdl_sequence;
        build_packet(packet, i, &wifi_sequence, &awdl_sequence);
        result->frames_attempted++;
        ssize_t sent = send(fd, packet, sizeof(packet), MSG_DONTWAIT);
        int saved_errno = sent < 0 ? errno : 0;
        if (sent != (ssize_t)sizeof(packet)) {
            result->error_count++;
            result->last_errno = saved_errno;
            result->stop_reason = sent < 0 ? "send_errno" : "short_write";
            break;
        }
        result->frames_completed++;
        uint64_t after = monotonic_ns();
        if (after == 0 || after > deadline) {
            result->error_count++;
            result->deadline_hit = true;
            result->stop_reason = "send_completed_after_budget";
            break;
        }
    }
    uint64_t finished = monotonic_ns();
    if (finished == 0 || finished < started) {
        result->error_count++;
        result->stop_reason = "monotonic_clock_end_failed";
        result->elapsed_ns = TX_BUDGET_NS;
    } else {
        result->elapsed_ns = finished - started;
        if (finished > deadline) result->deadline_hit = true;
    }
    if (result->frames_completed != options->count && result->error_count == 0) {
        result->error_count++;
        result->stop_reason = "partial_sequence";
    }
    return result->error_count == 0 &&
           result->frames_completed == options->count ? 0 : EXIT_SEND;
#endif
}

static int finish_send_result(struct send_result *result, int exit_code) {
    int log_result = emit_send_result(result);
    if (log_result != 0) return log_result;
    return exit_code;
}

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
#else
    int fd = -1;
#endif

    enum gate_result gate = wait_for_go(&options);
    struct send_result result;
    memset(&result, 0, sizeof(result));
    int exit_code = 0;
    if (gate == GATE_ABORT) {
        result.stop_reason = "aborted_before_go";
    } else if (gate == GATE_FAILED) {
        result.error_count = 1U;
        result.stop_reason = "gate_eof_timeout_or_invalid_token";
        exit_code = EXIT_GATE;
    } else {
        exit_code = send_sequence(&options, fd, &result);
    }

#ifndef SENDER_HOST_TEST
    if (close(fd) != 0) {
        result.error_count++;
        result.last_errno = errno;
        result.stop_reason = "socket_close_error";
        if (exit_code == 0) exit_code = EXIT_SEND;
    }
#endif
    return finish_send_result(&result, exit_code);
}
