/* SPDX-License-Identifier: GPL-2.0-only */
#define _DARWIN_C_SOURCE 1
#define __APPLE_USE_RFC_3542 1
#include "matched_return_test110.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach_time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <netinet6/in6_var.h>
#endif

#define T110_REQUEST_PORT 49152u
#define T110_REPLY_PORT 49153u
#define T110_MAX_DATAGRAMS 16u
#define T110_MAX_TIMEOUT_MS 100u
#define T110_CMSG_ALIGN(length) (((length) + sizeof(uint32_t) - 1u) & \
                                  ~(sizeof(uint32_t) - 1u))

static int64_t t110_uptime_us(void)
{
    static mach_timebase_info_data_t scale;
    static int scale_ready;
    const uint64_t absolute = mach_absolute_time();
    uint64_t nanoseconds;
    uint64_t quotient;
    uint64_t remainder;
    if (!scale_ready) {
        if (mach_timebase_info(&scale) != KERN_SUCCESS ||
            scale.denom == 0 || scale.numer == 0) {
            errno = EIO;
            return -1;
        }
        scale_ready = 1;
    }
    quotient = absolute / scale.denom;
    remainder = absolute % scale.denom;
    if (quotient > UINT64_MAX / scale.numer) {
        errno = EOVERFLOW;
        return -1;
    }
    nanoseconds = quotient * scale.numer +
        (remainder * scale.numer) / scale.denom;
    if (nanoseconds / 1000ULL > INT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    return (int64_t)(nanoseconds / 1000ULL);
}

int t110_current_uptime_us(uint64_t *now_us)
{
    int64_t now;
    if (!now_us) {
        errno = EINVAL;
        return -1;
    }
    now = t110_uptime_us();
    if (now < 0) return -1;
    *now_us = (uint64_t)now;
    return 0;
}

static int t110_nonce_usable(const uint8_t nonce[8])
{
    static const uint8_t old_marker[8] = {'T','0','8','6','R','X','0','1'};
    uint8_t any = 0;
    size_t index;
    if (!nonce) return 0;
    for (index = 0; index < 8; ++index) any |= nonce[index];
    return any != 0 && memcmp(nonce, old_marker, sizeof(old_marker)) != 0;
}

int t110_datagram_matches(const T110Datagram *datagram,
                          const T110Expected *expected)
{
    if (!datagram || !expected || expected->ifindex == 0 ||
        !t110_nonce_usable(expected->nonce)) return 0;
    return datagram->payload_length == sizeof(expected->nonce) &&
        !datagram->payload_truncated && !datagram->control_truncated &&
        datagram->ancillary_valid && datagram->pktinfo_present &&
        datagram->hop_limit_present && datagram->ifindex == expected->ifindex &&
        datagram->source_scope_id == expected->ifindex &&
        datagram->hop_limit == 1 &&
        datagram->source_port == T110_REQUEST_PORT &&
        datagram->destination_port == T110_REPLY_PORT &&
        memcmp(datagram->source_ipv6, expected->peer_ipv6, 16) == 0 &&
        memcmp(datagram->destination_ipv6, expected->local_ipv6, 16) == 0 &&
        memcmp(datagram->payload, expected->nonce, sizeof(expected->nonce)) == 0;
}

int t110_prepare_existing_socket(int fd, const uint8_t local_ipv6[16],
                                 uint32_t ifindex, int *error_number)
{
#if !defined(__APPLE__) || !defined(IPV6_BOUND_IF) || \
    !defined(IPV6_RECVPKTINFO) || !defined(IPV6_RECVHOPLIMIT)
    (void)fd; (void)local_ipv6; (void)ifindex;
    if (error_number) *error_number = ENOTSUP;
    return -1;
#else
    int enabled = 1;
    int bound_if;
    int current_bound_if = 0;
    int current_pktinfo = 0;
    int current_hoplimit = 0;
    int flags;
    socklen_t option_length;
    struct sockaddr_in6 actual;
    socklen_t actual_length = sizeof(actual);
    if (error_number) *error_number = 0;
    if (fd < 0 || !local_ipv6 || !ifindex || ifindex > INT_MAX || !error_number) {
        if (error_number) *error_number = EINVAL;
        return -1;
    }
    bound_if = (int)ifindex;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF,
                   &bound_if, sizeof(bound_if)) != 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                   &enabled, sizeof(enabled)) != 0 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
                   &enabled, sizeof(enabled)) != 0) {
        *error_number = errno;
        return -1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        *error_number = errno;
        return -1;
    }
    memset(&actual, 0, sizeof(actual));
    if (getsockname(fd, (struct sockaddr *)&actual, &actual_length) != 0) {
        *error_number = errno;
        return -1;
    }
    if (actual_length != sizeof(actual) || actual.sin6_family != AF_INET6 ||
        actual.sin6_len != sizeof(actual) ||
        ntohs(actual.sin6_port) != T110_REPLY_PORT ||
        actual.sin6_scope_id != ifindex ||
        memcmp(&actual.sin6_addr, local_ipv6, 16) != 0) {
        *error_number = EPROTO;
        return -1;
    }
    option_length = sizeof(current_bound_if);
    if (getsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF,
                   &current_bound_if, &option_length) != 0) {
        *error_number = errno;
        return -1;
    }
    if (option_length != sizeof(current_bound_if) || current_bound_if != bound_if) {
        *error_number = EPROTO;
        return -1;
    }
    option_length = sizeof(current_pktinfo);
    if (getsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                   &current_pktinfo, &option_length) != 0) {
        *error_number = errno;
        return -1;
    }
    if (option_length != sizeof(current_pktinfo) || current_pktinfo != enabled) {
        *error_number = EPROTO;
        return -1;
    }
    option_length = sizeof(current_hoplimit);
    if (getsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
                   &current_hoplimit, &option_length) != 0) {
        *error_number = errno;
        return -1;
    }
    if (option_length != sizeof(current_hoplimit) || current_hoplimit != enabled) {
        *error_number = EPROTO;
        return -1;
    }
    return 0;
#endif
}

static int t110_decode_ancillary(struct msghdr *message,
                                 T110Datagram *datagram)
{
    uint8_t *bytes;
    size_t total;
    size_t offset = 0;
    int have_pktinfo = 0;
    int have_hoplimit = 0;
    if (!message || !datagram)
        return 0;
    bytes = (uint8_t *)message->msg_control;
    total = message->msg_controllen;
    if ((message->msg_flags & MSG_CTRUNC) != 0 || (total && !bytes))
        return 0;
    while (offset < total) {
        struct cmsghdr *header;
        size_t remaining = total - offset;
        size_t aligned;
        if (remaining < sizeof(struct cmsghdr)) return 0;
        header = (struct cmsghdr *)(bytes + offset);
        if (header->cmsg_len < CMSG_LEN(0) || header->cmsg_len > remaining)
            return 0;
        if (header->cmsg_level != IPPROTO_IPV6) return 0;
        if (header->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo info;
            if (have_pktinfo || header->cmsg_len != CMSG_LEN(sizeof(info)))
                return 0;
            memcpy(&info, CMSG_DATA(header), sizeof(info));
            datagram->ifindex = info.ipi6_ifindex;
            memcpy(datagram->destination_ipv6, &info.ipi6_addr, 16);
            datagram->pktinfo_present = 1;
            have_pktinfo = 1;
        } else if (header->cmsg_type == IPV6_HOPLIMIT) {
            int hop_limit;
            if (have_hoplimit || header->cmsg_len != CMSG_LEN(sizeof(hop_limit)))
                return 0;
            memcpy(&hop_limit, CMSG_DATA(header), sizeof(hop_limit));
            datagram->hop_limit = hop_limit;
            datagram->hop_limit_present = 1;
            have_hoplimit = 1;
        } else {
            return 0;
        }
        aligned = T110_CMSG_ALIGN(header->cmsg_len);
        if (aligned > remaining) return 0;
        offset += aligned;
    }
    return have_pktinfo && have_hoplimit;
}

int t110_wait_for_matching_return(
    int fd, const uint8_t peer_ipv6[16], const uint8_t local_ipv6[16],
    uint32_t ifindex, const uint8_t nonce[8], uint64_t kernel_deadline_us,
    uint32_t timeout_ms,
    uint32_t *datagrams_seen, uint32_t *datagrams_rejected,
    int32_t *receive_error, uint64_t *elapsed_us)
{
    T110Expected expected;
    int64_t now, previous, deadline, started;
    if (datagrams_seen) *datagrams_seen = 0;
    if (datagrams_rejected) *datagrams_rejected = 0;
    if (receive_error) *receive_error = 0;
    if (elapsed_us) *elapsed_us = 0;
    if (fd < 0 || !peer_ipv6 || !local_ipv6 || !nonce || !ifindex ||
        !kernel_deadline_us || kernel_deadline_us > INT64_MAX || timeout_ms == 0 ||
        timeout_ms > T110_MAX_TIMEOUT_MS ||
        !datagrams_seen || !datagrams_rejected || !receive_error || !elapsed_us ||
        !t110_nonce_usable(nonce)) {
        if (receive_error) *receive_error = EINVAL;
        return -1;
    }
    memset(&expected, 0, sizeof(expected));
    memcpy(expected.peer_ipv6, peer_ipv6, 16);
    memcpy(expected.local_ipv6, local_ipv6, 16);
    memcpy(expected.nonce, nonce, 8);
    expected.ifindex = ifindex;
    now = t110_uptime_us();
    if (now < 0 || now > INT64_MAX - (int64_t)timeout_ms * 1000LL) {
        *receive_error = errno ? errno : EIO;
        return -1;
    }
    previous = now;
    started = now;
    if ((uint64_t)now >= kernel_deadline_us)
        return 0;
    deadline = now + (int64_t)timeout_ms * 1000LL;
    if ((uint64_t)deadline > kernel_deadline_us)
        deadline = (int64_t)kernel_deadline_us;
    while (*datagrams_seen < T110_MAX_DATAGRAMS) {
        struct pollfd poll_item;
        struct sockaddr_in6 source;
        struct iovec iov;
        struct msghdr message;
        union {
            struct cmsghdr alignment;
            uint8_t bytes[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
                          CMSG_SPACE(sizeof(int))];
        } control;
        uint8_t payload[9];
        T110Datagram datagram;
        int64_t remaining_us;
        int timeout_remaining_ms;
        int polled;
        ssize_t amount;
        int source_valid = 0;
        int ancillary_valid;

        now = t110_uptime_us();
        if (now < 0 || now < previous) {
            *receive_error = now < 0 ? EIO : ERANGE;
            goto failed;
        }
        previous = now;
        remaining_us = deadline - now;
        if (remaining_us <= 0) goto timed_out;
        timeout_remaining_ms = (int)((remaining_us + 999LL) / 1000LL);
        memset(&poll_item, 0, sizeof(poll_item));
        poll_item.fd = fd;
        poll_item.events = POLLIN;
        do {
            polled = poll(&poll_item, 1, timeout_remaining_ms);
            if (polled < 0 && errno == EINTR) {
                now = t110_uptime_us();
                if (now < 0 || now < previous) {
                    *receive_error = now < 0 ? EIO : ERANGE;
                    goto failed;
                }
                previous = now;
                remaining_us = deadline - now;
                if (remaining_us <= 0) goto timed_out;
                timeout_remaining_ms = (int)((remaining_us + 999LL) / 1000LL);
            }
        } while (polled < 0 && errno == EINTR);
        if (polled == 0) goto timed_out;
        if (polled < 0 || (poll_item.revents & (POLLERR | POLLNVAL)) != 0) {
            *receive_error = polled < 0 ? errno : EIO;
            goto failed;
        }
        now = t110_uptime_us();
        if (now < 0 || now < previous) {
            *receive_error = now < 0 ? EIO : ERANGE;
            goto failed;
        }
        previous = now;
        if (now >= deadline) goto timed_out;
        if ((poll_item.revents & POLLIN) == 0) continue;

        memset(&source, 0, sizeof(source));
        memset(&message, 0, sizeof(message));
        memset(&control, 0, sizeof(control));
        memset(&datagram, 0, sizeof(datagram));
        iov.iov_base = payload;
        iov.iov_len = sizeof(payload);
        message.msg_name = &source;
        message.msg_namelen = sizeof(source);
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control.bytes);
        amount = recvmsg(fd, &message, MSG_DONTWAIT);
        if (amount < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            *receive_error = errno;
            goto failed;
        }
        ++*datagrams_seen;
        datagram.payload_length = amount > UINT32_MAX ? UINT32_MAX :
                                  (uint32_t)amount;
        datagram.payload_truncated = (message.msg_flags & MSG_TRUNC) != 0 ||
                                     amount > (ssize_t)sizeof(payload);
        datagram.control_truncated = (message.msg_flags & MSG_CTRUNC) != 0;
        if (message.msg_namelen == sizeof(source) &&
            source.sin6_len == sizeof(source) &&
            source.sin6_family == AF_INET6) {
            memcpy(datagram.source_ipv6, &source.sin6_addr, 16);
            datagram.source_port = ntohs(source.sin6_port);
            datagram.source_scope_id = source.sin6_scope_id;
            source_valid = 1;
        }
        ancillary_valid = t110_decode_ancillary(&message, &datagram);
        datagram.ancillary_valid = source_valid && ancillary_valid;
        if (datagram.source_scope_id == 0 && datagram.pktinfo_present)
            datagram.source_scope_id = datagram.ifindex;
        datagram.destination_port = T110_REPLY_PORT;
        if (amount >= 0 && amount <= (ssize_t)sizeof(datagram.payload))
            memcpy(datagram.payload, payload, (size_t)amount);
        now = t110_uptime_us();
        if (now < 0 || now < previous) {
            *receive_error = now < 0 ? EIO : ERANGE;
            goto failed;
        }
        previous = now;
        if (now >= deadline) goto timed_out;
        if (t110_datagram_matches(&datagram, &expected)) {
            *elapsed_us = (uint64_t)(now - started);
            return 1;
        }
        ++*datagrams_rejected;
    }
    *receive_error = EOVERFLOW;
    goto failed;

timed_out:
    now = t110_uptime_us();
    if (now < 0 || now < previous) {
        *receive_error = now < 0 ? EIO : ERANGE;
        goto failed;
    }
    *elapsed_us = (uint64_t)(now - started);
    return 0;

failed:
    now = t110_uptime_us();
    if (now >= previous) *elapsed_us = (uint64_t)(now - started);
    return -1;
}
