#define _DARWIN_C_SOURCE 1
#define __APPLE_USE_RFC_3542 1
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TEST_PORT 49153
#define EXPECTED_SOURCE_PORT 49152
#define TEST_TIMEOUT_MS 15000
#define MARKER "T086RX01"
#define MARKER_LENGTH 8

/*
 * Apple XNU bsd/sys/socket_private.h defines SO_RECV_ANYIF as 0x1104.
 * It is used only when the operator explicitly supplies --recv-anyif. The
 * option applies to this socket; this tool never changes system-wide policy.
 */
#ifndef SO_RECV_ANYIF
#define SO_RECV_ANYIF 0x1104
#endif

static int recv_anyif_requested = 0;
static int recv_anyif_set = 0;
static int recv_anyif_errno = 0;
static char run_token[33];

static long long monotonic_ms(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
    return (long long)value.tv_sec * 1000LL + value.tv_nsec / 1000000LL;
}

static void emit_error(const char *step, int error_number) {
    printf("{\"event\":\"LISTENER_RESULT\",\"status\":\"setup_error\","
           "\"step\":\"%s\",\"errno\":%d,"
           "\"recv_anyif_requested\":%s,\"recv_anyif_set\":%s,"
           "\"recv_anyif_errno\":%d,\"run_token\":\"%s\"}\n",
           step, error_number,
           recv_anyif_requested ? "true" : "false",
           recv_anyif_set ? "true" : "false",
           recv_anyif_errno, run_token);
    fflush(stdout);
}

static int is_hex_token(const char *value) {
    size_t i;
    if (value == NULL || strlen(value) != 32) return 0;
    for (i = 0; i < 32; ++i) {
        const unsigned char c = (unsigned char)value[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv) {
    int fd = -1;
    int joined = 0;
    int ifindex_int = 0;
    unsigned int ifindex;
    int enabled = 1;
    struct ipv6_mreq membership;
    struct sockaddr_in6 local;
    struct in6_addr expected_group;
    long long deadline;
    unsigned int datagrams = 0;
    int marker_received = 0;
    int packet_info_present = 0;
    int ifindex_match = 0;
    int destination_match = 0;
    int source_link_local = 0;
    int source_port_match = 0;
    int payload_length = 0;

    int arg = 3;

    /* No interface lookup, socket call, or bind before the explicit gate. */
    if (argc < 5 || strcmp(argv[1], "--listen") != 0 ||
        strcmp(argv[2], MARKER) != 0 || strcmp(argv[3], "--run-token") != 0 ||
        !is_hex_token(argv[4])) {
        fprintf(stderr,
                "usage: %s --listen T086RX01 --run-token <32-hex> [--recv-anyif]\n",
                argv[0]);
        return 64;
    }
    memcpy(run_token, argv[4], sizeof(run_token));
    arg = 5;
    if (arg < argc && strcmp(argv[arg], "--recv-anyif") == 0) {
        recv_anyif_requested = 1;
        ++arg;
    }
    if (arg != argc) {
        fprintf(stderr,
                "usage: %s --listen T086RX01 --run-token <32-hex> [--recv-anyif]\n",
                argv[0]);
        return 64;
    }

    errno = 0;
    ifindex = if_nametoindex("awdl0");
    if (ifindex == 0 || ifindex > INT_MAX) {
        emit_error("if_nametoindex", errno ? errno : ENXIO);
        return 1;
    }
    ifindex_int = (int)ifindex;

    fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        emit_error("socket", errno);
        return 1;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF,
                   &ifindex_int, sizeof(ifindex_int)) != 0) {
        emit_error("IPV6_BOUND_IF", errno);
        goto cleanup;
    }
    if (recv_anyif_requested) {
        if (setsockopt(fd, SOL_SOCKET, SO_RECV_ANYIF,
                       &enabled, sizeof(enabled)) == 0) {
            recv_anyif_set = 1;
        } else {
            recv_anyif_errno = errno;
            emit_error("SO_RECV_ANYIF", recv_anyif_errno);
            goto cleanup;
        }
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                   &enabled, sizeof(enabled)) != 0) {
        emit_error("IPV6_RECVPKTINFO", errno);
        goto cleanup;
    }

    memset(&membership, 0, sizeof(membership));
    if (inet_pton(AF_INET6, "ff02::1", &membership.ipv6mr_multiaddr) != 1) {
        emit_error("parse_group", EINVAL);
        goto cleanup;
    }
    membership.ipv6mr_interface = ifindex;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                   &membership, sizeof(membership)) != 0) {
        emit_error("IPV6_JOIN_GROUP", errno);
        goto cleanup;
    }
    joined = 1;

    memset(&local, 0, sizeof(local));
    local.sin6_len = sizeof(local);
    local.sin6_family = AF_INET6;
    local.sin6_port = htons(TEST_PORT);
    local.sin6_addr = in6addr_any;
    if (bind(fd, (const struct sockaddr *)&local, sizeof(local)) != 0) {
        emit_error("bind", errno);
        goto cleanup;
    }
    if (inet_pton(AF_INET6, "ff02::1", &expected_group) != 1) {
        emit_error("parse_expected_group", EINVAL);
        goto cleanup;
    }

    printf("{\"event\":\"LISTENER_READY\",\"interface\":\"awdl0\","
           "\"ifindex\":%u,\"family\":6,\"port\":%d,"
           "\"group\":\"ff02::1\",\"timeout_ms\":%d,"
           "\"bound_if\":true,\"pktinfo_enabled\":true,"
           "\"recv_anyif_requested\":%s,\"recv_anyif_set\":%s,"
           "\"recv_anyif_errno\":%d,\"run_token\":\"%s\"}\n",
           ifindex, TEST_PORT, TEST_TIMEOUT_MS,
           recv_anyif_requested ? "true" : "false",
           recv_anyif_set ? "true" : "false", recv_anyif_errno, run_token);
    fflush(stdout);

    deadline = monotonic_ms() + TEST_TIMEOUT_MS;
    while (!marker_received) {
        const long long now = monotonic_ms();
        long long remaining;
        struct pollfd pollfd_value;
        int poll_result;
        uint8_t payload[64];
        struct sockaddr_in6 peer;
        struct iovec iov;
        struct msghdr message;
        union {
            struct cmsghdr alignment;
            unsigned char bytes[CMSG_SPACE(sizeof(struct in6_pktinfo))];
        } control;
        struct in6_pktinfo packet_info;
        int have_packet_info = 0;
        ssize_t received;
        struct cmsghdr *header;

        if (now < 0) {
            emit_error("clock_gettime", errno);
            goto cleanup;
        }
        remaining = deadline - now;
        if (remaining <= 0) break;
        pollfd_value.fd = fd;
        pollfd_value.events = POLLIN;
        pollfd_value.revents = 0;
        poll_result = poll(&pollfd_value, 1,
                           remaining > INT_MAX ? INT_MAX : (int)remaining);
        if (poll_result < 0 && errno == EINTR) continue;
        if (poll_result < 0) {
            emit_error("poll", errno);
            goto cleanup;
        }
        if (poll_result == 0) break;
        if ((pollfd_value.revents & POLLIN) == 0) continue;

        memset(&peer, 0, sizeof(peer));
        memset(&message, 0, sizeof(message));
        memset(&control, 0, sizeof(control));
        memset(&packet_info, 0, sizeof(packet_info));
        iov.iov_base = payload;
        iov.iov_len = sizeof(payload);
        message.msg_name = &peer;
        message.msg_namelen = sizeof(peer);
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control.bytes);
        received = recvmsg(fd, &message, 0);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0) {
            emit_error("recvmsg", errno);
            goto cleanup;
        }
        ++datagrams;
        for (header = CMSG_FIRSTHDR(&message); header != NULL;
             header = CMSG_NXTHDR(&message, header)) {
            if (header->cmsg_level == IPPROTO_IPV6 &&
                header->cmsg_type == IPV6_PKTINFO &&
                header->cmsg_len >= CMSG_LEN(sizeof(packet_info))) {
                memcpy(&packet_info, CMSG_DATA(header), sizeof(packet_info));
                have_packet_info = 1;
                break;
            }
        }
        packet_info_present = have_packet_info;
        if (have_packet_info) {
            ifindex_match = packet_info.ipi6_ifindex == ifindex;
            destination_match =
                memcmp(&packet_info.ipi6_addr, &expected_group,
                       sizeof(expected_group)) == 0;
        }
        source_link_local = IN6_IS_ADDR_LINKLOCAL(&peer.sin6_addr) != 0;
        source_port_match = ntohs(peer.sin6_port) == EXPECTED_SOURCE_PORT;
        payload_length = received > INT_MAX ? INT_MAX : (int)received;
        marker_received = !(message.msg_flags & MSG_TRUNC) &&
            received == MARKER_LENGTH &&
            memcmp(payload, MARKER, MARKER_LENGTH) == 0 &&
            have_packet_info && ifindex_match && destination_match &&
            source_link_local && source_port_match;
    }

    printf("{\"event\":\"LISTENER_RESULT\",\"status\":\"%s\","
           "\"interface\":\"awdl0\",\"ifindex\":%u,"
           "\"datagrams\":%u,\"marker_match\":%s,"
           "\"pktinfo_present\":%s,\"pktinfo_ifindex_match\":%s,"
           "\"destination_group_match\":%s,\"source_link_local\":%s,"
           "\"source_port_match\":%s,\"payload_length\":%d,"
           "\"peer_address_serialized\":false,"
           "\"recv_anyif_requested\":%s,\"recv_anyif_set\":%s,"
           "\"recv_anyif_errno\":%d,\"run_token\":\"%s\"}\n",
           marker_received ? "marker_received" : "timeout_or_unmatched",
           ifindex, datagrams, marker_received ? "true" : "false",
           packet_info_present ? "true" : "false",
           ifindex_match ? "true" : "false",
           destination_match ? "true" : "false",
           source_link_local ? "true" : "false",
           source_port_match ? "true" : "false", payload_length,
           recv_anyif_requested ? "true" : "false",
           recv_anyif_set ? "true" : "false", recv_anyif_errno, run_token);
    fflush(stdout);

cleanup:
    if (fd >= 0) {
        if (joined) (void)setsockopt(fd, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
                                     &membership, sizeof(membership));
        (void)close(fd);
    }
    return marker_received ? 0 : 1;
}
