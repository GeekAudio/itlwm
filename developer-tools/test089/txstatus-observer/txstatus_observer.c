#define _POSIX_C_SOURCE 200809L

#include "probe_frame.h"
#include "radiotap_parser.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef __linux__
#error "txstatus_observer is a Linux AF_PACKET tool"
#endif

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define T089_RX_WINDOW_MS 2000U
#define T089_GO_WINDOW_MS 30000U
#define T089_MAX_RX_PACKETS 4096U
#define T089_MAX_MATCHES 16U
#define T089_IFNAME_MAX_BYTES 15U
#define T089_MAX_LINE 96U
#define T089_NONCE_LENGTH 32U

enum exit_code {
    EXIT_OK = 0,
    EXIT_ARGUMENT = 2,
    EXIT_INTERFACE = 3,
    EXIT_GATE = 4,
    EXIT_SEND = 5,
    EXIT_RECEIVE = 6
};

struct options {
    bool send;
    bool wait_go;
    bool have_interface;
    bool have_nonce;
    char interface_name[T089_IFNAME_MAX_BYTES + 1U];
    char nonce[T089_NONCE_LENGTH + 1U];
};

struct counts {
    unsigned rx_packets;
    unsigned probe_matches;
    unsigned outgoing_echo;
    unsigned host_driver_completion_candidate;
    unsigned other_match;
};

static bool valid_ifname(const char *name) {
    size_t length;
    if (name == NULL) return false;
    length = strlen(name);
    if (length == 0U || length > T089_IFNAME_MAX_BYTES) return false;
    for (size_t i = 0U; i < length; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return false;
    }
    return true;
}

static bool valid_nonce(const char *nonce) {
    if (nonce == NULL || strlen(nonce) != T089_NONCE_LENGTH) return false;
    for (size_t i = 0U; i < T089_NONCE_LENGTH; ++i) {
        char c = nonce[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

static void usage(FILE *stream, const char *program) {
    (void)fprintf(stream,
        "Usage: %s [--send --interface MON --nonce 32hex --wait-go]\n"
        "Default is a dry-run. A send invocation sends exactly one frame, then\n"
        "observes the same socket for at most 2000 ms.\n", program);
}

static void emit_gate_result(const char *status, const char *nonce,
                             bool timeout, bool deadline_reached) {
    (void)printf("{\"event\":\"TEST089_RESULT\",\"status\":\"%s\",\"run_token\":\"%s\",\"send_attempted\":false,\"send_completed\":false,\"setup_error\":0,\"send_errno\":0,\"observation_complete\":false,\"timeout\":%s,\"recv_error\":0,\"deadline_reached\":%s,\"firmware_tx_status_proven\":false,\"airborne_proven\":false,\"rf_delivery_proven\":false,\"acked_proven\":false,\"counts\":{\"rx_packets\":0,\"probe_matches\":0,\"outgoing_echo\":0,\"host_driver_completion_candidate\":0,\"other_match\":0}}\n",
        status, nonce, timeout ? "true" : "false",
        deadline_reached ? "true" : "false");
    (void)fflush(stdout);
}

static bool parse_options(int argc, char **argv, struct options *out) {
    bool seen_send = false, seen_wait = false, seen_if = false, seen_nonce = false;
    memset(out, 0, sizeof(*out));
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--send") == 0) {
            if (seen_send) return false;
            seen_send = true;
            out->send = true;
        } else if (strcmp(arg, "--wait-go") == 0) {
            if (seen_wait) return false;
            seen_wait = true;
            out->wait_go = true;
        } else if (strcmp(arg, "--interface") == 0 ||
                   strcmp(arg, "--nonce") == 0) {
            if (++i >= argc) return false;
            const char *value = argv[i];
            if (strcmp(arg, "--interface") == 0) {
                if (seen_if || !valid_ifname(value)) return false;
                seen_if = true;
                memcpy(out->interface_name, value, strlen(value) + 1U);
                out->have_interface = true;
            } else {
                if (seen_nonce || !valid_nonce(value)) return false;
                seen_nonce = true;
                memcpy(out->nonce, value, T089_NONCE_LENGTH + 1U);
                out->have_nonce = true;
            }
        } else if (strcmp(arg, "--help") == 0 && argc == 2) {
            usage(stdout, argv[0]);
            exit(EXIT_OK);
        } else {
            return false;
        }
    }
    if (!out->send) return !out->wait_go && !out->have_interface && !out->have_nonce;
    return out->wait_go && out->have_interface && out->have_nonce;
}

static uint64_t monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) return 0U;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static bool remaining_poll_ms(uint64_t deadline_ns, int *wait_ms) {
    uint64_t now = monotonic_ns();
    uint64_t remaining;
    if (now == 0U || wait_ms == NULL) return false;
    if (now >= deadline_ns) {
        *wait_ms = 0;
        return true;
    }
    remaining = deadline_ns - now;
    uint64_t milliseconds = (remaining + UINT64_C(999999)) / UINT64_C(1000000);
    *wait_ms = milliseconds > (uint64_t)INT_MAX ? INT_MAX : (int)milliseconds;
    return true;
}

/* Read one bounded control line without allowing an unbounded blocking fgets. */
static int read_control_line(char *line, size_t capacity, uint64_t deadline_ns) {
    size_t used = 0U;
    if (line == NULL || capacity < 2U) return -1;
    for (;;) {
        struct pollfd pfd = {.fd = STDIN_FILENO, .events = POLLIN};
        int wait_ms;
        if (!remaining_poll_ms(deadline_ns, &wait_ms)) return -1;
        if (wait_ms == 0) return 0;
        int polled = poll(&pfd, 1U, wait_ms);
        if (polled < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (polled == 0) return 0;
        if ((pfd.revents & (POLLERR | POLLNVAL)) != 0) return -1;
        char ch;
        ssize_t amount = read(STDIN_FILENO, &ch, 1U);
        if (amount == 0) return -1;
        if (amount < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            return -1;
        }
        if (ch == '\n') {
            line[used] = '\0';
            return 1;
        }
        if (ch == '\r' || used + 1U >= capacity) return -1;
        line[used++] = ch;
    }
}

static int wait_for_go(const char *nonce) {
    uint64_t now = monotonic_ns();
    if (now == 0U || now > UINT64_MAX -
        (uint64_t)T089_GO_WINDOW_MS * UINT64_C(1000000)) return EXIT_GATE;
    uint64_t deadline = now + (uint64_t)T089_GO_WINDOW_MS * UINT64_C(1000000);
    char line[T089_MAX_LINE];
    unsigned waits = 0U;
    for (;;) {
        int result = read_control_line(line, sizeof(line), deadline);
        if (result == 0) {
            emit_gate_result("gate_timeout", nonce, true, true);
            return EXIT_GATE;
        }
        if (result < 0) {
            emit_gate_result("gate_error", nonce, false, false);
            return EXIT_GATE;
        }
        if (strcmp(line, "ABORT") == 0) {
            emit_gate_result("aborted", nonce, false, false);
            return EXIT_OK;
        }
        if (strncmp(line, "GO ", 3U) == 0 && strcmp(line + 3U, nonce) == 0)
            return EXIT_OK + 10; /* Private sentinel: GO accepted. */
        if (strcmp(line, "WAIT") == 0 && waits++ < 32U) continue;
        emit_gate_result("gate_error", nonce, false, false);
        return EXIT_GATE;
    }
}

static bool get_interface_index(const char *name, int *ifindex) {
    int control;
    struct ifreq request;
    unsigned index;
    if (!valid_ifname(name) || ifindex == NULL) return false;
    index = if_nametoindex(name);
    if (index == 0U || index > INT_MAX) return false;
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

static void emit_result(const char *status, const char *nonce,
                        bool send_attempted, bool send_completed,
                        bool observation_complete, bool timeout,
                        int setup_error, int send_errno, int recv_error,
                        bool deadline_reached,
                        unsigned send_bytes, uint64_t elapsed_ns,
                        const struct counts *counts) {
    bool capture_limit_reached = counts->rx_packets >= T089_MAX_RX_PACKETS ||
                                 counts->probe_matches >= T089_MAX_MATCHES;
    (void)printf("{\"event\":\"TEST089_RESULT\",\"status\":\"%s\",\"run_token\":\"%s\",\"send_attempted\":%s,\"send_completed\":%s,\"setup_error\":%d,\"send_errno\":%d,\"send_bytes\":%u,\"observation_complete\":%s,\"timeout\":%s,\"recv_error\":%d,\"deadline_reached\":%s,\"capture_limit_reached\":%s,\"rx_window_ms\":%u,\"elapsed_ms\":%llu,\"tx_flags_requested\":\"NOACK|NOSEQNO\",\"firmware_tx_status_proven\":false,\"airborne_proven\":false,\"rf_delivery_proven\":false,\"acked_proven\":false,\"counts\":{\"rx_packets\":%u,\"probe_matches\":%u,\"outgoing_echo\":%u,\"host_driver_completion_candidate\":%u,\"other_match\":%u}}\n",
        status, nonce, send_attempted ? "true" : "false",
        send_completed ? "true" : "false", setup_error, send_errno, send_bytes,
        observation_complete ? "true" : "false",
        timeout ? "true" : "false",
        recv_error,
        deadline_reached ? "true" : "false",
        capture_limit_reached ? "true" : "false", T089_RX_WINDOW_MS,
        (unsigned long long)(elapsed_ns / UINT64_C(1000000)),
        counts->rx_packets, counts->probe_matches, counts->outgoing_echo,
        counts->host_driver_completion_candidate, counts->other_match);
    (void)fflush(stdout);
}

static int observe_after_send(int fd, const char *nonce,
                              const uint8_t sent_packet[T089_PACKET_LENGTH],
                              uint64_t started_ns) {
    const uint8_t *sent_mpdu = sent_packet + T089_RADIOTAP_LENGTH;
    uint64_t deadline = started_ns +
                        (uint64_t)T089_RX_WINDOW_MS * UINT64_C(1000000);
    struct counts counts = {0};
    bool timed_out = false;
    bool deadline_reached = false;
    int recv_error = 0;
    uint64_t ended_ns;
    uint64_t elapsed_ns;
    uint8_t packet[4096];

    if (deadline < started_ns) {
        recv_error = ERANGE;
        goto finish;
    }

    while (counts.rx_packets < T089_MAX_RX_PACKETS &&
           counts.probe_matches < T089_MAX_MATCHES) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int wait_ms;
        if (!remaining_poll_ms(deadline, &wait_ms)) {
            recv_error = EIO;
            break;
        }
        if (wait_ms == 0) {
            timed_out = true;
            deadline_reached = true;
            break;
        }
        int polled = poll(&pfd, 1U, wait_ms);
        if (polled < 0) {
            if (errno == EINTR) continue;
            recv_error = errno;
            break;
        }
        if (polled == 0) {
            timed_out = true;
            deadline_reached = true;
            break;
        }
        if ((pfd.revents & (POLLERR | POLLNVAL)) != 0) {
            recv_error = EIO;
            break;
        }
        struct sockaddr_ll address;
        struct iovec vector = {.iov_base = packet, .iov_len = sizeof(packet)};
        struct msghdr message;
        memset(&message, 0, sizeof(message));
        memset(&address, 0, sizeof(address));
        message.msg_name = &address;
        message.msg_namelen = sizeof(address);
        message.msg_iov = &vector;
        message.msg_iovlen = 1U;
        ssize_t received = recvmsg(fd, &message, MSG_DONTWAIT);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            recv_error = errno;
            break;
        }
        if ((message.msg_flags & MSG_TRUNC) != 0 ||
            (size_t)received > sizeof(packet)) {
            counts.rx_packets++;
            continue;
        }
        counts.rx_packets++;
        struct t089_observation observation;
        enum t089_parse_result parsed = t089_parse_observation(
            packet, (size_t)received, address.sll_pkttype, sent_mpdu,
            &observation);
        if (parsed != T089_PARSE_VALID || !observation.exact_probe_match) continue;
        counts.probe_matches++;
        const char *kind = "other_matching_packet";
        if (observation.is_outgoing_echo) {
            counts.outgoing_echo++;
            kind = "packet_outgoing_echo";
        } else if (observation.is_host_driver_completion_candidate) {
            counts.host_driver_completion_candidate++;
            kind = "host_driver_completion_candidate";
        } else {
            counts.other_match++;
        }
        (void)printf("{\"event\":\"TEST089_OBSERVATION\",\"run_token\":\"%s\",\"kind\":\"%s\",\"packet_type\":%u,\"exact_mpdu_match\":true,\"wifi_sequence\":%u,\"awdl_sequence\":%u,\"has_tx_flags\":%s,\"tx_flags\":%u,\"has_data_retries\":%s,\"data_retries\":%u,\"firmware_tx_status_proven\":false,\"airborne_proven\":false,\"rf_delivery_proven\":false,\"acked_proven\":false}\n",
            nonce, kind, address.sll_pkttype, observation.wifi_sequence,
            observation.awdl_sequence,
            observation.has_tx_flags ? "true" : "false",
            observation.tx_flags,
            observation.has_data_retries ? "true" : "false",
            observation.data_retries);
        (void)fflush(stdout);
    }
finish:
    ended_ns = monotonic_ns();
    elapsed_ns = ended_ns >= started_ns ? ended_ns - started_ns : 0U;
    bool complete = recv_error == 0 && deadline_reached;
    bool capture_limit_reached = counts.rx_packets >= T089_MAX_RX_PACKETS ||
                                 counts.probe_matches >= T089_MAX_MATCHES;
    const char *status = recv_error != 0 ? "receive_error" :
        (capture_limit_reached ? "capture_limit_reached" :
        (counts.host_driver_completion_candidate > 0U ? "host_driver_completion_candidate_observed" :
         (counts.other_match > 0U ? "no_status_candidate_observed" :
          (counts.outgoing_echo > 0U ? "outgoing_echo_only" : "no_matching_observation"))));
    emit_result(status, nonce, true, true, complete, timed_out, 0, 0,
                recv_error, deadline_reached, T089_PACKET_LENGTH,
                elapsed_ns, &counts);
    return (recv_error != 0 || capture_limit_reached) ? EXIT_RECEIVE : EXIT_OK;
}

int main(int argc, char **argv) {
    struct options options;
    if (!parse_options(argc, argv, &options)) {
        usage(stderr, argv[0]);
        (void)fprintf(stderr, "invalid_arguments\n");
        return EXIT_ARGUMENT;
    }
    uint8_t packet[T089_PACKET_LENGTH];
    t089_build_probe(packet);
    if (!options.send) {
        (void)printf("{\"event\":\"TEST089_PLAN\",\"send_enabled\":false,\"frames\":1,\"packet_bytes\":%u,\"rx_window_ms\":%u,\"tx_flags_requested\":\"NOACK|NOSEQNO\",\"rf_performed\":false}\n",
            T089_PACKET_LENGTH, T089_RX_WINDOW_MS);
        return fflush(stdout) == 0 ? EXIT_OK : EXIT_SEND;
    }

    int ifindex;
    if (!get_interface_index(options.interface_name, &ifindex)) {
        int saved = errno;
        struct counts counts = {0};
        emit_result("interface_rejected", options.nonce, false, false,
                    false, false, saved, 0, 0, false, 0U, 0U, &counts);
        (void)fprintf(stderr, "interface_rejected errno=%d\n", saved);
        return EXIT_INTERFACE;
    }
    int fd = open_packet_socket(ifindex);
    if (fd < 0) {
        int saved = errno;
        struct counts counts = {0};
        emit_result("packet_socket_failed", options.nonce, false, false,
                    false, false, saved, 0, 0, false, 0U, 0U, &counts);
        (void)fprintf(stderr, "packet_socket_failed errno=%d\n", saved);
        return EXIT_INTERFACE;
    }
    (void)printf("READY frames=1 packet_bytes=%u rx_window_ms=%u\n",
                 T089_PACKET_LENGTH, T089_RX_WINDOW_MS);
    (void)fflush(stdout);
    int gate = wait_for_go(options.nonce);
    if (gate != EXIT_OK + 10) {
        (void)close(fd);
        return gate;
    }

    uint64_t started_ns = monotonic_ns();
    if (started_ns == 0U) {
        struct counts counts = {0};
        emit_result("clock_failed", options.nonce, false, false,
                    false, false, errno, 0, 0, false, 0U, 0U, &counts);
        (void)close(fd);
        (void)fprintf(stderr, "clock_failed\n");
        return EXIT_SEND;
    }
    ssize_t sent = send(fd, packet, sizeof(packet), MSG_DONTWAIT);
    uint64_t send_finished_ns = monotonic_ns();
    int send_error = sent < 0 ? errno : (sent == (ssize_t)sizeof(packet) ? 0 : EIO);
    (void)printf("{\"event\":\"TEST089_SEND\",\"run_token\":\"%s\",\"send_attempted\":true,\"send_completed\":%s,\"send_bytes\":%u,\"send_errno\":%d,\"send_started_ns\":%llu,\"send_finished_ns\":%llu,\"firmware_tx_status_proven\":false,\"airborne_proven\":false,\"rf_delivery_proven\":false,\"acked_proven\":false}\n",
        options.nonce, sent == (ssize_t)sizeof(packet) ? "true" : "false",
        sent > 0 ? (unsigned)sent : 0U, send_error,
        (unsigned long long)started_ns,
        (unsigned long long)send_finished_ns);
    (void)fflush(stdout);
    if (sent != (ssize_t)sizeof(packet)) {
        struct counts counts = {0};
        uint64_t ended = monotonic_ns();
        emit_result("send_failed", options.nonce, true, false, false,
                    false, 0, send_error, 0, false,
                    sent > 0 ? (unsigned)sent : 0U,
                    ended >= started_ns ? ended - started_ns : 0U, &counts);
        (void)fprintf(stderr, "send_error errno=%d\n", send_error);
        (void)close(fd);
        return EXIT_SEND;
    }
    if (send_finished_ns == 0U || send_finished_ns < started_ns) {
        struct counts counts = {0};
        emit_result("clock_failed_after_send", options.nonce, true, true,
                    false, false, 0, 0, EIO, false,
                    T089_PACKET_LENGTH, 0U, &counts);
        (void)close(fd);
        return EXIT_RECEIVE;
    }
    int result = observe_after_send(fd, options.nonce, packet, send_finished_ns);
    int close_error = close(fd);
    if (close_error != 0 && result == EXIT_OK) {
        (void)fprintf(stderr, "socket_close_failed errno=%d\n", errno);
        return EXIT_RECEIVE;
    }
    return result;
}
