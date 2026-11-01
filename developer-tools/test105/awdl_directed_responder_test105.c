/* SPDX-License-Identifier: GPL-2.0-only */
#define _DARWIN_C_SOURCE 1
#define __APPLE_USE_RFC_3542 1
#include "awdl_directed_responder_test105.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <netinet6/in6_var.h>
#endif

typedef struct { int fd; } SocketContext;

static int64_t clock_ms(void *unused)
{
    struct timespec ts;
    (void)unused;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int wait_readable(void *opaque, int timeout_ms)
{
    SocketContext *ctx = opaque;
    struct pollfd pfd = { .fd = ctx->fd, .events = POLLIN, .revents = 0 };
    int result = poll(&pfd, 1, timeout_ms);
    if (result <= 0) return result;
    if (pfd.revents & POLLIN) return 1;
    errno = EIO;
    return -1;
}

static ssize_t receive_datagram(void *opaque, T105Datagram *out, int *err)
{
    SocketContext *ctx = opaque;
    struct sockaddr_in6 source;
    struct iovec iov;
    struct msghdr msg;
    union { struct cmsghdr align; uint8_t bytes[128]; } control;
    uint8_t payload[T105_NONCE_BYTES];
    struct cmsghdr *cmsg;
    int have_info = 0, have_hop = 0;
    ssize_t amount;
    memset(&source, 0, sizeof(source));
    memset(&msg, 0, sizeof(msg));
    memset(&control, 0, sizeof(control));
    iov.iov_base = payload;
    iov.iov_len = sizeof(payload);
    msg.msg_name = &source;
    msg.msg_namelen = sizeof(source);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.bytes;
    msg.msg_controllen = sizeof(control.bytes);
    amount = recvmsg(ctx->fd, &msg, MSG_DONTWAIT);
    if (amount < 0) { *err = errno; return -1; }
    if (msg.msg_namelen != sizeof(source) || source.sin6_family != AF_INET6) {
        *err = EPROTO;
        return -1;
    }
    out->payload_length = (size_t)amount;
    if (amount <= (ssize_t)sizeof(out->payload))
        memcpy(out->payload, payload, (size_t)amount);
    memcpy(out->source_ipv6, &source.sin6_addr, 16);
    out->source_port = ntohs(source.sin6_port);
    out->destination_port = T105_REPLY_PORT;
    out->payload_truncated = ((msg.msg_flags & MSG_TRUNC) != 0) ||
        amount > (ssize_t)sizeof(out->payload);
    out->control_truncated = (msg.msg_flags & MSG_CTRUNC) != 0;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level != IPPROTO_IPV6) { *err = EPROTO; return -1; }
#ifdef IPV6_PKTINFO
        if (cmsg->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo info;
            if (have_info || cmsg->cmsg_len != CMSG_LEN(sizeof(info))) {
                *err = EPROTO; return -1;
            }
            memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
            out->ifindex = info.ipi6_ifindex;
            memcpy(out->destination_ipv6, &info.ipi6_addr, 16);
            out->pktinfo_present = 1;
            have_info = 1;
        }
#endif
#ifdef IPV6_HOPLIMIT
        if (cmsg->cmsg_type == IPV6_HOPLIMIT) {
            if (have_hop || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
                *err = EPROTO; return -1;
            }
            memcpy(&out->hop_limit, CMSG_DATA(cmsg), sizeof(int));
            out->hop_limit_present = 1;
            have_hop = 1;
        }
#endif
        if (cmsg->cmsg_type != IPV6_PKTINFO && cmsg->cmsg_type != IPV6_HOPLIMIT) {
            *err = EPROTO;
            return -1;
        }
    }
    if (!have_info || !have_hop ||
        (source.sin6_scope_id != 0 && source.sin6_scope_id != out->ifindex)) {
        *err = EPROTO;
        return -1;
    }
    /* A link-local source with no sockaddr scope inherits the verified ingress
     * interface scope from IPV6_PKTINFO on this interface-bound socket. */
    out->source_scope_id = source.sin6_scope_id ? source.sin6_scope_id : out->ifindex;
    return amount;
}

static ssize_t send_reply(void *opaque, const T105Expected *e,
                          const uint8_t payload[T105_NONCE_BYTES], int *err)
{
    SocketContext *ctx = opaque;
    struct sockaddr_in6 dst;
    struct iovec iov;
    struct msghdr msg;
    union { struct cmsghdr align; uint8_t bytes[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))]; } control;
    struct in6_pktinfo info;
    struct cmsghdr *cmsg;
    int hop = 1;
    ssize_t n;
    memset(&dst, 0, sizeof(dst));
    dst.sin6_len = sizeof(dst);
    dst.sin6_family = AF_INET6;
    dst.sin6_port = htons(T105_REQUEST_PORT);
    dst.sin6_scope_id = e->ifindex;
    memcpy(&dst.sin6_addr, e->peer_ipv6, 16);
    memset(&msg, 0, sizeof(msg));
    memset(&control, 0, sizeof(control));
    memset(&info, 0, sizeof(info));
    info.ipi6_ifindex = e->ifindex;
    memcpy(&info.ipi6_addr, e->local_ipv6, 16);
    iov.iov_base = (void *)payload;
    iov.iov_len = T105_NONCE_BYTES;
    msg.msg_name = &dst;
    msg.msg_namelen = sizeof(dst);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.bytes;
    msg.msg_controllen = sizeof(control.bytes);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(info));
    memcpy(CMSG_DATA(cmsg), &info, sizeof(info));
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    if (cmsg == NULL) { *err = EINVAL; return -1; }
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_HOPLIMIT;
    cmsg->cmsg_len = CMSG_LEN(sizeof(hop));
    memcpy(CMSG_DATA(cmsg), &hop, sizeof(hop));
    n = sendmsg(ctx->fd, &msg, MSG_DONTWAIT);
    if (n < 0) { *err = errno; return -1; }
    if (n != T105_NONCE_BYTES) { *err = EIO; return -1; }
    return n;
}

static int parse_index(const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long n;
    if (!s || !*s) return 0;
    errno = 0;
    n = strtoul(s, &end, 10);
    if (errno || end == s || *end || n == 0 || n > INT_MAX) return 0;
    *out = (uint32_t)n;
    return 1;
}

static int parse_nonce(const char *s, uint8_t out[T105_NONCE_BYTES])
{
    size_t i;
    if (!s || strlen(s) != 16) return 0;
    for (i = 0; i < 8; ++i) {
        char pair[3] = { s[i * 2], s[i * 2 + 1], 0 };
        char *end = NULL;
        unsigned long n;
        if (!((pair[0] >= '0' && pair[0] <= '9') || (pair[0] >= 'a' && pair[0] <= 'f')) ||
            !((pair[1] >= '0' && pair[1] <= '9') || (pair[1] >= 'a' && pair[1] <= 'f')))
            return 0;
        n = strtoul(pair, &end, 16);
        if (end == pair || *end) return 0;
        out[i] = (uint8_t)n;
    }
    return t105_nonce_is_usable(out);
}

static int parse_linklocal(const char *s, uint8_t out[16])
{
    struct in6_addr addr;
    if (!s || strchr(s, '%') || inet_pton(AF_INET6, s, &addr) != 1 ||
        !IN6_IS_ADDR_LINKLOCAL(&addr) || IN6_IS_ADDR_UNSPECIFIED(&addr) ||
        IN6_IS_ADDR_MULTICAST(&addr)) return 0;
    memcpy(out, &addr, 16);
    return 1;
}

static int local_on_awdl0(const uint8_t address[16])
{
    struct ifaddrs *all = NULL, *p;
    int found = 0;
    if (getifaddrs(&all) != 0) return -1;
    for (p = all; p; p = p->ifa_next) {
        const struct sockaddr_in6 *a;
        if (!p->ifa_name || strcmp(p->ifa_name, "awdl0") || !p->ifa_addr || p->ifa_addr->sa_family != AF_INET6)
            continue;
        a = (const struct sockaddr_in6 *)p->ifa_addr;
        if (!memcmp(&a->sin6_addr, address, 16)) { found = 1; break; }
    }
    freeifaddrs(all);
    return found;
}

static void usage(const char *name)
{
    fprintf(stderr, "usage: %s --peer <link-local-IPv6> --local <awdl0-link-local-IPv6> --ifindex <index> --nonce <16-lower-hex> [--timeout-ms 1..60000] [--run]\n", name);
}

static void result(T105Status s, const T105Stats *v, uint32_t idx)
{
    printf("{\"event\":\"T105_REPLY_RESULT\",\"schema\":\"test105-awdl-directed-responder/v1\",\"status\":\"%s\",\"interface\":\"awdl0\",\"ifindex\":%u,\"datagrams_seen\":%u,\"datagrams_rejected\":%u,\"send_attempted\":%s,\"local_send_accepted\":%s,\"neighbor_state\":\"unknown\",\"peer_receipt_proven\":false,\"airdrop_proven\":false,\"send_errno\":%d,\"receive_errno\":%d}\n",
           t105_status_name(s), idx, v->datagrams_seen, v->datagrams_rejected,
           v->send_attempted ? "true" : "false", v->local_send_accepted ? "true" : "false",
           v->send_errno, v->receive_errno);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    const char *peer = NULL, *local = NULL, *nonce_arg = NULL;
    uint32_t idx = 0, live_idx;
    int timeout = 15000, run = 0, fd, one = 1, bound_if, i;
    int file_flags;
    uint8_t nonce[8];
    T105Expected e;
    T105Session session = {0, 0, 0};
    T105Stats stats;
    SocketContext ctx;
    T105Io io = {wait_readable, receive_datagram, send_reply, clock_ms};
    T105Status status;
    struct sockaddr_in6 bind_addr, actual;
    socklen_t actual_len = sizeof(actual);
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--run") && !run) run = 1;
        else if (!strcmp(argv[i], "--peer") && i + 1 < argc && !peer) peer = argv[++i];
        else if (!strcmp(argv[i], "--local") && i + 1 < argc && !local) local = argv[++i];
        else if (!strcmp(argv[i], "--nonce") && i + 1 < argc && !nonce_arg) nonce_arg = argv[++i];
        else if (!strcmp(argv[i], "--ifindex") && i + 1 < argc && !idx) {
            if (!parse_index(argv[++i], &idx)) { usage(argv[0]); return 64; }
        } else if (!strcmp(argv[i], "--timeout-ms") && i + 1 < argc) {
            char *end = NULL; long n = strtol(argv[++i], &end, 10);
            if (!end || *end || n < 1 || n > 60000) { usage(argv[0]); return 64; }
            timeout = (int)n;
        } else { usage(argv[0]); return 64; }
    }
    memset(&e, 0, sizeof(e));
    if (!peer || !local || !idx || !parse_linklocal(peer, e.peer_ipv6) ||
        !parse_linklocal(local, e.local_ipv6) || !memcmp(e.peer_ipv6, e.local_ipv6, 16) ||
        !parse_nonce(nonce_arg, nonce)) { usage(argv[0]); return 64; }
    memcpy(e.nonce, nonce, 8);
    e.ifindex = idx;
    bound_if = (int)idx;
    if (!run) {
        printf("{\"event\":\"T105_REPLY_READY\",\"schema\":\"test105-awdl-directed-responder/v1\",\"status\":\"planned\",\"interface\":\"awdl0\",\"ifindex\":%u,\"request_source_port\":%u,\"request_destination_port\":%u,\"reply_source_port\":%u,\"reply_destination_port\":%u,\"hop_limit\":1,\"payload_bytes\":8,\"timeout_ms\":%d,\"nonce_serialized\":false,\"socket_opened\":false,\"neighbor_state\":\"not_checked\",\"peer_receipt_proven\":false}\n",
               idx, T105_REQUEST_PORT, T105_REPLY_PORT, T105_REPLY_PORT, T105_REQUEST_PORT, timeout);
        return 0;
    }
#if !defined(__APPLE__) || !defined(IPV6_BOUND_IF) || !defined(IPV6_RECVPKTINFO) || !defined(IPV6_RECVHOPLIMIT)
    result(T105_RECEIVE_FAILED, &(T105Stats){.receive_errno = ENOTSUP}, idx);
    return 1;
#else
    live_idx = if_nametoindex("awdl0");
    if (!live_idx || live_idx != idx || local_on_awdl0(e.local_ipv6) != 1) {
        result(T105_RECEIVE_FAILED, &(T105Stats){.receive_errno = ENODEV}, idx);
        return 1;
    }
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) { result(T105_RECEIVE_FAILED, &(T105Stats){.receive_errno = errno}, idx); return 1; }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &bound_if, sizeof(bound_if)) != 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)) != 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one)) != 0 ||
        (file_flags = fcntl(fd, F_GETFL, 0)) < 0 ||
        fcntl(fd, F_SETFL, file_flags | O_NONBLOCK) < 0) {
        int saved = errno; close(fd);
        result(T105_RECEIVE_FAILED, &(T105Stats){.receive_errno = saved}, idx); return 1;
    }
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin6_len = sizeof(bind_addr);
    bind_addr.sin6_family = AF_INET6;
    bind_addr.sin6_port = htons(T105_REPLY_PORT);
    bind_addr.sin6_scope_id = idx;
    memcpy(&bind_addr.sin6_addr, e.local_ipv6, 16);
    if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0 ||
        getsockname(fd, (struct sockaddr *)&actual, &actual_len) != 0 ||
        actual_len != sizeof(actual) || actual.sin6_family != AF_INET6 ||
        actual.sin6_scope_id != idx || ntohs(actual.sin6_port) != T105_REPLY_PORT ||
        memcmp(&actual.sin6_addr, e.local_ipv6, 16) != 0) {
        int saved = errno ? errno : EPROTO; close(fd);
        result(T105_RECEIVE_FAILED, &(T105Stats){.receive_errno = saved}, idx); return 1;
    }
    ctx.fd = fd;
    session.armed = 1;
    printf("{\"event\":\"T105_REPLY_READY\",\"schema\":\"test105-awdl-directed-responder/v1\",\"status\":\"listening\",\"interface\":\"awdl0\",\"ifindex\":%u,\"local_port\":%u,\"peer_port\":%u,\"hop_limit\":1,\"payload_bytes\":8,\"timeout_ms\":%d,\"nonce_serialized\":false}\n",
           idx, T105_REPLY_PORT, T105_REQUEST_PORT, timeout);
    fflush(stdout);
    status = t105_reply_once(&io, &ctx, &e, &session, timeout, &stats);
    close(fd);
    result(status, &stats, idx);
    return status == T105_LOCAL_SEND_ACCEPTED ? 0 : 1;
#endif
}
