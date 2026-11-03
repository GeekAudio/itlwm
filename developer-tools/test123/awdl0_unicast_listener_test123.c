#define _DARWIN_C_SOURCE 1
#define __APPLE_USE_RFC_3542 1
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TEST_PORT 49153
#define EXPECTED_SOURCE_PORT 49152
#define TEST_TIMEOUT_MS 15000
#define MARKER_LENGTH 8
#define SCHEMA "test123-awdl-unicast-listener/v1"

/* XNU's socket-private option; scoped to this listener socket only. */
#ifndef SO_RECV_ANYIF
#define SO_RECV_ANYIF 0x1104
#endif

static int recv_anyif_requested = 0;
static int recv_anyif_set = 0;
static int recv_anyif_errno = 0;
static char run_token[33];
static char expected_nonce_hex[17];
static unsigned char expected_nonce[8];
static char received_payload_hex[17];
static int received_payload_present = 0;
static uint64_t ready_ns = 0, observed_ns = 0, finished_ns = 0;

static uint64_t monotonic_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0 || value.tv_sec < 0) return 0;
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static int parse_nonce(const char *value) {
    unsigned int i, nonzero = 0;
    if (value == NULL || strlen(value) != 16) return 0;
    for (i = 0; i < 8; ++i) {
        unsigned int n, byte = 0;
        for (n = 0; n < 2; ++n) {
            unsigned char c = (unsigned char)value[2 * i + n];
            unsigned int nibble;
            if (c >= '0' && c <= '9') nibble = c - '0';
            else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
            else return 0;
            byte = (byte << 4) | nibble;
        }
        expected_nonce[i] = (unsigned char)byte;
        nonzero |= byte;
    }
    if (!nonzero) return 0;
    memcpy(expected_nonce_hex, value, sizeof(expected_nonce_hex));
    return 1;
}

static int payload_matches_nonce(const unsigned char *payload, size_t length,
                                 int truncated) {
    return payload != NULL && length == sizeof(expected_nonce) && !truncated &&
           memcmp(payload, expected_nonce, sizeof(expected_nonce)) == 0;
}

static void remember_payload(const unsigned char *payload, ssize_t length,
                             int truncated) {
    static const char hex[] = "0123456789abcdef";
    received_payload_present = length == MARKER_LENGTH && !truncated;
    if (!received_payload_present) return;
    for (unsigned int i = 0; i < MARKER_LENGTH; ++i) {
        received_payload_hex[2 * i] = hex[payload[i] >> 4];
        received_payload_hex[2 * i + 1] = hex[payload[i] & 15];
    }
    received_payload_hex[16] = '\0';
}

static long long monotonic_ms(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
    return (long long)value.tv_sec * 1000LL + value.tv_nsec / 1000000LL;
}

static const char *json_bool(int value) {
    return value ? "true" : "false";
}

static void emit_setup_error(const char *step, int error_number) {
    printf("{\"event\":\"LISTENER_RESULT\",\"status\":\"setup_error\","
           "\"step\":\"%s\",\"errno\":%d,"
           "\"recv_anyif_requested\":%s,\"recv_anyif_set\":%s,"
           "\"recv_anyif_errno\":%d,\"run_token\":\"%s\"}\n",
           step, error_number,
           json_bool(recv_anyif_requested), json_bool(recv_anyif_set),
           recv_anyif_errno, run_token);
    fflush(stdout);
}

static int is_hex_token(const char *value) {
    size_t i;
    if (value == NULL || strlen(value) != 32) return 0;
    for (i = 0; i < 32; ++i) {
        const unsigned char c = (unsigned char)value[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static int parse_ifindex(const char *value, unsigned int *result) {
    char *end = NULL;
    unsigned long parsed;
    if (value == NULL || *value == '\0') return 0;
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0 || parsed > INT_MAX) {
        return 0;
    }
    *result = (unsigned int)parsed;
    return 1;
}

static int parse_link_local(const char *value, struct in6_addr *result) {
    if (value == NULL || strchr(value, '%') != NULL ||
        inet_pton(AF_INET6, value, result) != 1) return 0;
    return IN6_IS_ADDR_LINKLOCAL(result) && !IN6_IS_ADDR_UNSPECIFIED(result) &&
           !IN6_IS_ADDR_MULTICAST(result);
}

static uint64_t fnv1a64(const void *data, size_t length) {
    const unsigned char *bytes = (const unsigned char *)data;
    uint64_t value = UINT64_C(0xcbf29ce484222325);
    size_t i;
    for (i = 0; i < length; ++i) {
        value ^= (uint64_t)bytes[i];
        value *= UINT64_C(0x100000001b3);
    }
    return value;
}

static void format_tag(uint64_t value, char output[17]) {
    (void)snprintf(output, 17, "%016llx", (unsigned long long)value);
}

static int address_assigned_to_awdl0(const struct in6_addr *expected) {
    struct ifaddrs *all = NULL;
    struct ifaddrs *item;
    int found = 0;
    if (getifaddrs(&all) != 0) return -1;
    for (item = all; item != NULL; item = item->ifa_next) {
        if (item->ifa_name == NULL || strcmp(item->ifa_name, "awdl0") != 0 ||
            item->ifa_addr == NULL || item->ifa_addr->sa_family != AF_INET6) continue;
        const struct sockaddr_in6 *address =
            (const struct sockaddr_in6 *)item->ifa_addr;
        if (memcmp(&address->sin6_addr, expected, sizeof(*expected)) == 0) {
            found = 1;
            break;
        }
    }
    freeifaddrs(all);
    return found;
}

static void emit_ready(unsigned int ifindex, const char *source_tag,
                       const char *destination_tag) {
    printf("{\"event\":\"LISTENER_READY\",\"schema\":\"%s\","
           "\"interface\":\"awdl0\",\"ifindex\":%u,\"family\":6,"
           "\"port\":%d,\"source_port\":%d,\"hop_limit\":1,"
           "\"payload\":\"%s\",\"timeout_ms\":%d,\"bound_if\":true,"
           "\"destination_assigned\":true,\"pktinfo_enabled\":true,"
           "\"hoplimit_enabled\":true,\"recv_anyif_requested\":%s,"
           "\"recv_anyif_set\":%s,\"recv_anyif_errno\":%d,"
           "\"source_identity_tag_fnv1a64\":\"%s\","
           "\"destination_identity_tag_fnv1a64\":\"%s\","
           "\"peer_address_serialized\":false,\"run_token\":\"%s\","
           "\"wire_nonce_hex\":\"%s\",\"payload_encoding\":\"hex\","
           "\"tool_test\":\"Test123\",\"running_kernel_test\":\"Test122\","
           "\"clock_domain\":\"CLOCK_MONOTONIC\",\"clock_host\":\"mac\","
           "\"ready_ns\":%llu}\n",
           SCHEMA, ifindex, TEST_PORT, EXPECTED_SOURCE_PORT, expected_nonce_hex,
           TEST_TIMEOUT_MS, json_bool(recv_anyif_requested),
           json_bool(recv_anyif_set), recv_anyif_errno, source_tag,
           destination_tag, run_token, expected_nonce_hex,
           (unsigned long long)ready_ns);
    fflush(stdout);
}

static void emit_result(unsigned int ifindex, unsigned int datagrams,
                        int marker_match, int source_address_match,
                        int destination_address_match, int source_port_match,
                        int destination_port_match, int hop_limit_present,
                        int hop_limit_match, int pktinfo_present,
                        int pktinfo_ifindex_match, int payload_length,
                        int payload_match, int payload_truncated,
                        int control_truncated, unsigned int wrong_source,
                        unsigned int wrong_destination, unsigned int other_unmatched,
                        int receive_error, const char *source_tag,
                        const char *destination_tag) {
    const char *status = marker_match ? "marker_received" : "timeout_or_unmatched";
    char source_json[32];
    char destination_json[32];
    char payload_json[32];
    if (received_payload_present)
        (void)snprintf(payload_json, sizeof(payload_json), "\"%s\"", received_payload_hex);
    else
        (void)snprintf(payload_json, sizeof(payload_json), "null");
    if (source_tag != NULL) {
        (void)snprintf(source_json, sizeof(source_json), "\"%s\"", source_tag);
    } else {
        (void)snprintf(source_json, sizeof(source_json), "null");
    }
    if (destination_tag != NULL) {
        (void)snprintf(destination_json, sizeof(destination_json), "\"%s\"", destination_tag);
    } else {
        (void)snprintf(destination_json, sizeof(destination_json), "null");
    }
    printf("{\"event\":\"LISTENER_RESULT\",\"schema\":\"%s\","
           "\"status\":\"%s\",\"interface\":\"awdl0\","
           "\"ifindex\":%u,\"datagrams\":%u,\"marker_match\":%s,"
           "\"source_address_match\":%s,\"destination_address_match\":%s,"
           "\"source_port_match\":%s,\"destination_port_match\":%s,"
           "\"hop_limit_present\":%s,\"hop_limit_match\":%s,"
           "\"pktinfo_present\":%s,\"pktinfo_ifindex_match\":%s,"
           "\"payload_length\":%d,\"payload_match\":%s,"
           "\"payload_truncated\":%s,\"control_truncated\":%s,"
           "\"wrong_source_datagrams\":%u,\"wrong_destination_datagrams\":%u,"
           "\"other_unmatched_datagrams\":%u,\"receive_error\":%d,"
           "\"source_identity_tag_fnv1a64\":%s,"
           "\"destination_identity_tag_fnv1a64\":%s,"
           "\"peer_address_serialized\":false,"
           "\"recv_anyif_requested\":%s,\"recv_anyif_set\":%s,"
           "\"recv_anyif_errno\":%d,\"run_token\":\"%s\","
           "\"wire_nonce_hex\":\"%s\",\"received_payload_hex\":%s,"
           "\"payload_encoding\":\"hex\",\"distinct_ordinals_proven\":false,"
           "\"tool_test\":\"Test123\",\"running_kernel_test\":\"Test122\","
           "\"clock_domain\":\"CLOCK_MONOTONIC\",\"clock_host\":\"mac\","
           "\"time_semantics\":\"userspace_recvmsg_return\","
           "\"ready_ns\":%llu,\"observed_ns\":%llu,\"finished_ns\":%llu}\n",
           SCHEMA, status, ifindex, datagrams, json_bool(marker_match),
           json_bool(source_address_match), json_bool(destination_address_match),
           json_bool(source_port_match), json_bool(destination_port_match),
           json_bool(hop_limit_present), json_bool(hop_limit_match),
           json_bool(pktinfo_present), json_bool(pktinfo_ifindex_match),
           payload_length, json_bool(payload_match), json_bool(payload_truncated),
           json_bool(control_truncated), wrong_source, wrong_destination,
           other_unmatched, receive_error,
           source_json, destination_json, json_bool(recv_anyif_requested),
           json_bool(recv_anyif_set), recv_anyif_errno, run_token,
           expected_nonce_hex, payload_json, (unsigned long long)ready_ns,
           (unsigned long long)observed_ns, (unsigned long long)finished_ns);
    fflush(stdout);
}

int main(int argc, char **argv) {
    int fd = -1;
    int enabled = 1;
    int ifindex_int = 0;
    unsigned int expected_ifindex = 0;
    unsigned int datagrams = 0;
    unsigned int wrong_source = 0;
    unsigned int wrong_destination = 0;
    unsigned int other_unmatched = 0;
    struct in6_addr expected_source;
    struct in6_addr expected_destination;
    struct sockaddr_in6 local;
    struct sockaddr_in6 bound;
    socklen_t bound_length = sizeof(bound);
    char source_tag[17];
    char destination_tag[17];
    char actual_source_tag[17];
    char actual_destination_tag[17];
    const char *source_text = NULL;
    const char *destination_text = NULL;
    const char *ifindex_text = NULL;
    long long deadline;
    long long now;
    int marker_match = 0;
    int source_address_match = 0;
    int destination_address_match = 0;
    int source_port_match = 0;
    int destination_port_match = 0;
    int hop_limit_present = 0;
    int hop_limit_match = 0;
    int pktinfo_present = 0;
    int pktinfo_ifindex_match = 0;
    int payload_length = 0;
    int payload_match = 0;
    int payload_truncated = 0;
    int control_truncated = 0;
    int receive_error = 0;
    int arg = 5;
    int have_source = 0;
    int have_destination = 0;
    int have_ifindex = 0;
    unsigned int live_ifindex;
    int source_tag_observed = 0;
    int destination_tag_observed = 0;

    /* No interface lookup or socket operation before explicit --listen. */
    if (argc < 5 || strcmp(argv[1], "--listen-nonce") != 0 ||
        !parse_nonce(argv[2]) || strcmp(argv[3], "--run-token") != 0 ||
        !is_hex_token(argv[4])) {
        fprintf(stderr,
                "usage: %s --listen-nonce <16-lower-hex-nonzero> --run-token <32-lower-hex> "
                "--expected-source-ipv6 <link-local> "
                "--expected-destination-ipv6 <link-local> "
                "--expected-ifindex <positive-integer> [--recv-anyif]\n",
                argv[0]);
        return 64;
    }
    memcpy(run_token, argv[4], sizeof(run_token));
    while (arg < argc) {
        if (strcmp(argv[arg], "--recv-anyif") == 0) {
            if (recv_anyif_requested) return 64;
            recv_anyif_requested = 1;
            ++arg;
        } else if (strcmp(argv[arg], "--expected-source-ipv6") == 0 &&
                   arg + 1 < argc && !have_source) {
            source_text = argv[arg + 1];
            have_source = 1;
            arg += 2;
        } else if (strcmp(argv[arg], "--expected-destination-ipv6") == 0 &&
                   arg + 1 < argc && !have_destination) {
            destination_text = argv[arg + 1];
            have_destination = 1;
            arg += 2;
        } else if (strcmp(argv[arg], "--expected-ifindex") == 0 &&
                   arg + 1 < argc && !have_ifindex) {
            ifindex_text = argv[arg + 1];
            have_ifindex = 1;
            arg += 2;
        } else {
            fprintf(stderr, "unexpected or duplicate listener argument\n");
            return 64;
        }
    }

    if (!have_source || !have_destination || !have_ifindex) {
        fprintf(stderr, "missing manifest-bound listener identity arguments\n");
        return 64;
    }
    if (!parse_link_local(source_text, &expected_source) ||
        !parse_link_local(destination_text, &expected_destination) ||
        memcmp(&expected_source, &expected_destination, sizeof(expected_source)) == 0 ||
        !parse_ifindex(ifindex_text, &expected_ifindex)) {
        emit_setup_error("expected_identity_environment", EINVAL);
        return 1;
    }
    live_ifindex = if_nametoindex("awdl0");
    if (live_ifindex == 0 || live_ifindex > INT_MAX || live_ifindex != expected_ifindex) {
        emit_setup_error("awdl0_ifindex_binding", errno ? errno : ENXIO);
        return 1;
    }
    int assigned = address_assigned_to_awdl0(&expected_destination);
    if (assigned < 0) {
        emit_setup_error("getifaddrs", errno ? errno : EIO);
        return 1;
    }
    if (assigned == 0) {
        emit_setup_error("destination_not_assigned_to_awdl0", EADDRNOTAVAIL);
        return 1;
    }
    format_tag(fnv1a64(&expected_source, sizeof(expected_source)), source_tag);
    format_tag(fnv1a64(&expected_destination, sizeof(expected_destination)), destination_tag);

    fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        emit_setup_error("socket", errno);
        return 1;
    }
    ifindex_int = (int)live_ifindex;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF,
                   &ifindex_int, sizeof(ifindex_int)) != 0) {
        emit_setup_error("IPV6_BOUND_IF", errno);
        goto cleanup;
    }
    if (recv_anyif_requested) {
        if (setsockopt(fd, SOL_SOCKET, SO_RECV_ANYIF, &enabled, sizeof(enabled)) == 0) {
            recv_anyif_set = 1;
        } else {
            recv_anyif_errno = errno;
            emit_setup_error("SO_RECV_ANYIF", errno);
            goto cleanup;
        }
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                   &enabled, sizeof(enabled)) != 0) {
        emit_setup_error("IPV6_RECVPKTINFO", errno);
        goto cleanup;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
                   &enabled, sizeof(enabled)) != 0) {
        emit_setup_error("IPV6_RECVHOPLIMIT", errno);
        goto cleanup;
    }
    memset(&local, 0, sizeof(local));
    local.sin6_family = AF_INET6;
    local.sin6_port = htons(TEST_PORT);
    local.sin6_addr = in6addr_any;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        emit_setup_error("bind", errno);
        goto cleanup;
    }
    memset(&bound, 0, sizeof(bound));
    if (getsockname(fd, (struct sockaddr *)&bound, &bound_length) != 0 ||
        bound.sin6_family != AF_INET6 || ntohs(bound.sin6_port) != TEST_PORT) {
        emit_setup_error("getsockname", errno ? errno : EPROTO);
        goto cleanup;
    }
    ready_ns = monotonic_ns();
    if (!ready_ns) { emit_setup_error("ready_clock", errno ? errno : EIO); goto cleanup; }
    emit_ready(live_ifindex, source_tag, destination_tag);

    now = monotonic_ms();
    if (now < 0) {
        receive_error = errno ? errno : EIO;
        goto finish;
    }
    deadline = now + TEST_TIMEOUT_MS;
    while (!marker_match) {
        struct pollfd pollfd;
        int remaining;
        int poll_result;
        unsigned char payload[256];
        unsigned char control[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
                              CMSG_SPACE(sizeof(int))];
        struct sockaddr_in6 peer;
        struct iovec iov;
        struct msghdr message;
        struct cmsghdr *cmsg;
        struct in6_pktinfo packet_info;
        int have_pktinfo = 0;
        int observed_hop_limit = -1;
        int have_hop_limit = 0;
        int source_match;
        int destination_match;
        int source_port_ok;
        int destination_port_ok;
        int ifindex_ok;
        int payload_ok;
        int payload_trunc;
        int control_trunc;
        int all_ok;
        ssize_t received;

        now = monotonic_ms();
        if (now < 0) {
            receive_error = errno ? errno : EIO;
            break;
        }
        remaining = (int)(deadline - now);
        if (remaining <= 0) break;
        pollfd.fd = fd;
        pollfd.events = POLLIN;
        pollfd.revents = 0;
        poll_result = poll(&pollfd, 1, remaining);
        if (poll_result == 0) break;
        if (poll_result < 0) {
            if (errno == EINTR) continue;
            receive_error = errno;
            break;
        }
        now = monotonic_ms();
        if (now < 0) {
            receive_error = errno ? errno : EIO;
            break;
        }
        if (now >= deadline) break;
        if ((pollfd.revents & (POLLERR | POLLNVAL)) != 0) {
            receive_error = EIO;
            break;
        }
        if ((pollfd.revents & POLLIN) == 0) continue;

        memset(&peer, 0, sizeof(peer));
        memset(&message, 0, sizeof(message));
        memset(control, 0, sizeof(control));
        iov.iov_base = payload;
        iov.iov_len = sizeof(payload);
        message.msg_name = &peer;
        message.msg_namelen = sizeof(peer);
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        /* On Darwin, passing MSG_TRUNC as an input flag is reflected in
         * msg_flags even when the full datagram fits. Keep it output-only. */
        received = recvmsg(fd, &message, MSG_DONTWAIT);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            receive_error = errno;
            break;
        }
        observed_ns = monotonic_ns();
        if (!observed_ns || observed_ns < ready_ns) { receive_error = EIO; break; }
        datagrams++;
        payload_trunc = ((message.msg_flags & MSG_TRUNC) != 0) ||
                        (size_t)received > sizeof(payload);
        control_trunc = ((message.msg_flags & MSG_CTRUNC) != 0);
        memset(&packet_info, 0, sizeof(packet_info));
        for (cmsg = CMSG_FIRSTHDR(&message); cmsg != NULL;
             cmsg = CMSG_NXTHDR(&message, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                cmsg->cmsg_type == IPV6_PKTINFO &&
                cmsg->cmsg_len >= CMSG_LEN(sizeof(packet_info))) {
                memcpy(&packet_info, CMSG_DATA(cmsg), sizeof(packet_info));
                have_pktinfo = 1;
            } else if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                       cmsg->cmsg_type == IPV6_HOPLIMIT &&
                       cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
                memcpy(&observed_hop_limit, CMSG_DATA(cmsg), sizeof(int));
                have_hop_limit = 1;
            }
        }
        source_match = peer.sin6_family == AF_INET6 &&
            memcmp(&peer.sin6_addr, &expected_source, sizeof(expected_source)) == 0;
        destination_match = have_pktinfo &&
            memcmp(&packet_info.ipi6_addr, &expected_destination,
                   sizeof(expected_destination)) == 0;
        source_port_ok = peer.sin6_family == AF_INET6 &&
            ntohs(peer.sin6_port) == EXPECTED_SOURCE_PORT;
        destination_port_ok = bound.sin6_port == htons(TEST_PORT);
        ifindex_ok = have_pktinfo && packet_info.ipi6_ifindex == live_ifindex;
        hop_limit_match = have_hop_limit && observed_hop_limit == 1;
        payload_length = (received > INT_MAX) ? INT_MAX : (int)received;
        remember_payload(payload, received, payload_trunc);
        payload_ok = payload_matches_nonce(payload, (size_t)received, payload_trunc);
        payload_match = payload_ok;
        hop_limit_present = have_hop_limit;
        pktinfo_present = have_pktinfo;
        pktinfo_ifindex_match = ifindex_ok;
        source_address_match = source_match;
        destination_address_match = destination_match;
        source_port_match = source_port_ok;
        destination_port_match = destination_port_ok;
        payload_truncated = payload_trunc;
        control_truncated = control_trunc;
        if (peer.sin6_family == AF_INET6) {
            format_tag(fnv1a64(&peer.sin6_addr, sizeof(peer.sin6_addr)),
                       actual_source_tag);
            source_tag_observed = 1;
        }
        if (have_pktinfo) {
            format_tag(fnv1a64(&packet_info.ipi6_addr, sizeof(packet_info.ipi6_addr)),
                       actual_destination_tag);
            destination_tag_observed = 1;
        }
        all_ok = source_match && destination_match && source_port_ok &&
                 destination_port_ok && ifindex_ok && have_pktinfo &&
                 have_hop_limit && observed_hop_limit == 1 && payload_ok &&
                 !control_trunc;
        /* A user-space identity recheck is not an atomic HAL/BSD lease read. */
        if (all_ok && (if_nametoindex("awdl0") != live_ifindex ||
                       address_assigned_to_awdl0(&expected_destination) != 1)) {
            receive_error = ENXIO;
            break;
        }
        marker_match = all_ok;
        if (!source_match) wrong_source++;
        if (!destination_match) wrong_destination++;
        if (!all_ok && source_match && destination_match) other_unmatched++;
    }

finish:
    finished_ns = monotonic_ns();
    if (!finished_ns || finished_ns < ready_ns || finished_ns < observed_ns) {
        emit_setup_error("finish_clock", EIO);
        goto cleanup;
    }
    emit_result(live_ifindex, datagrams, marker_match, source_address_match,
                destination_address_match, source_port_match,
                destination_port_match, hop_limit_present, hop_limit_match,
                pktinfo_present, pktinfo_ifindex_match, payload_length,
                payload_match, payload_truncated, control_truncated,
                wrong_source, wrong_destination, other_unmatched, receive_error,
                source_tag_observed ? actual_source_tag : NULL,
                destination_tag_observed ? actual_destination_tag : NULL);
    (void)close(fd);
    return 0;

cleanup:
    if (fd >= 0) (void)close(fd);
    return 1;
}
