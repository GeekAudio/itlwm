/* SPDX-License-Identifier: GPL-2.0-only */
/* Offline parser/predicate tests; this translation unit never creates a socket. */
#include "matched_return_test110.c"

#include <assert.h>
#include <stdio.h>

static void set_expected(T110Expected *expected)
{
    memset(expected, 0, sizeof(*expected));
    expected->peer_ipv6[0] = 0xfe;
    expected->peer_ipv6[1] = 0x80;
    expected->peer_ipv6[15] = 2;
    expected->local_ipv6[0] = 0xfe;
    expected->local_ipv6[1] = 0x80;
    expected->local_ipv6[15] = 1;
    expected->nonce[0] = 0x01;
    expected->nonce[7] = 0xa5;
    expected->ifindex = 17;
}

static T110Datagram valid_datagram(const T110Expected *expected)
{
    T110Datagram datagram;
    memset(&datagram, 0, sizeof(datagram));
    memcpy(datagram.payload, expected->nonce, sizeof(datagram.payload));
    datagram.payload_length = sizeof(datagram.payload);
    memcpy(datagram.source_ipv6, expected->peer_ipv6, 16);
    memcpy(datagram.destination_ipv6, expected->local_ipv6, 16);
    datagram.source_scope_id = expected->ifindex;
    datagram.ifindex = expected->ifindex;
    datagram.source_port = T110_REQUEST_PORT;
    datagram.destination_port = T110_REPLY_PORT;
    datagram.hop_limit = 1;
    datagram.pktinfo_present = 1;
    datagram.hop_limit_present = 1;
    datagram.ancillary_valid = 1;
    return datagram;
}

static size_t fill_pktinfo(uint8_t *buffer, size_t offset,
                           const struct in6_addr *destination, uint32_t ifindex)
{
    struct cmsghdr *header = (struct cmsghdr *)(buffer + offset);
    struct in6_pktinfo info;
    memset(&info, 0, sizeof(info));
    info.ipi6_ifindex = ifindex;
    info.ipi6_addr = *destination;
    header->cmsg_level = IPPROTO_IPV6;
    header->cmsg_type = IPV6_PKTINFO;
    header->cmsg_len = CMSG_LEN(sizeof(info));
    memcpy(CMSG_DATA(header), &info, sizeof(info));
    return T110_CMSG_ALIGN(header->cmsg_len);
}

static size_t fill_hoplimit(uint8_t *buffer, size_t offset, int hop)
{
    struct cmsghdr *header = (struct cmsghdr *)(buffer + offset);
    header->cmsg_level = IPPROTO_IPV6;
    header->cmsg_type = IPV6_HOPLIMIT;
    header->cmsg_len = CMSG_LEN(sizeof(hop));
    memcpy(CMSG_DATA(header), &hop, sizeof(hop));
    return T110_CMSG_ALIGN(header->cmsg_len);
}

static int decode_control(int flags, int form)
{
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(sizeof(struct in6_pktinfo)) * 2 +
                      CMSG_SPACE(sizeof(int))];
    } storage;
    struct msghdr message;
    struct in6_addr destination;
    T110Datagram datagram;
    size_t used = 0;
    memset(&storage, 0, sizeof(storage));
    memset(&message, 0, sizeof(message));
    memset(&datagram, 0, sizeof(datagram));
    memset(&destination, 0, sizeof(destination));
    destination.s6_addr[0] = 0xfe;
    destination.s6_addr[1] = 0x80;
    destination.s6_addr[15] = 1;
    if (form == 1) {
        used += fill_pktinfo(storage.bytes, used, &destination, 17);
        used += fill_hoplimit(storage.bytes, used, 1);
    } else if (form == 2) {
        used += fill_pktinfo(storage.bytes, used, &destination, 17);
        used += fill_pktinfo(storage.bytes, used, &destination, 17);
        used += fill_hoplimit(storage.bytes, used, 1);
    } else if (form == 3) {
        struct cmsghdr *header = (struct cmsghdr *)storage.bytes;
        header->cmsg_level = IPPROTO_IPV6;
        header->cmsg_type = IPV6_TCLASS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        used = T110_CMSG_ALIGN(header->cmsg_len);
    } else if (form == 4) {
        used += fill_pktinfo(storage.bytes, used, &destination, 17);
        used += fill_hoplimit(storage.bytes, used, 1);
        ((struct cmsghdr *)(storage.bytes + CMSG_SPACE(sizeof(struct in6_pktinfo))))->cmsg_len =
            CMSG_LEN(sizeof(int)) + 1;
    }
    message.msg_control = storage.bytes;
    message.msg_controllen = used;
    message.msg_flags = flags;
    return t110_decode_ancillary(&message, &datagram);
}

int main(void)
{
    T110Expected expected;
    T110Datagram datagram;
    set_expected(&expected);
    datagram = valid_datagram(&expected);
    assert(t110_datagram_matches(&datagram, &expected));

    datagram.source_ipv6[15] ^= 1;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.destination_ipv6[15] ^= 1;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.source_scope_id++;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.ifindex++;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.source_port++;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.destination_port++;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.hop_limit = 2;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.payload[0] ^= 0x80;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.payload_length--;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.payload_truncated = 1;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.control_truncated = 1;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.ancillary_valid = 0;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.pktinfo_present = 0;
    assert(!t110_datagram_matches(&datagram, &expected));
    datagram = valid_datagram(&expected); datagram.hop_limit_present = 0;
    assert(!t110_datagram_matches(&datagram, &expected));

    assert(decode_control(0, 1));
    assert(!decode_control(MSG_CTRUNC, 1));
    assert(!decode_control(0, 2)); /* duplicate IPV6_PKTINFO */
    assert(!decode_control(0, 3)); /* unsupported ancillary */
    assert(!decode_control(0, 4)); /* malformed ancillary length */

    expected.nonce[0] = 0;
    expected.nonce[7] = 0;
    datagram = valid_datagram(&expected);
    assert(!t110_datagram_matches(&datagram, &expected));
    puts("Test110 matched-return predicate/ancillary cases passed (offline)");
    return 0;
}
