// SPDX-License-Identifier: GPL-2.0-only
// Read the kernel's base wiphy feature flags without changing any interface.
#include "../test110/openwrt_echo_channel.hpp"
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>

namespace {
using namespace Test110Channel;
constexpr uint32_t kFamilySequence = 1;
constexpr uint32_t kWiphySequence = 2;
static_assert(NL80211_FEATURE_ACTIVE_MONITOR == (1u << 17), "wiphy feature ABI");

bool request(int fd, uint32_t port, uint16_t family, uint8_t command,
             uint8_t version, uint32_t sequence, uint16_t attrType,
             const void *value, size_t size, bool splitDump = false)
{
    alignas(nlmsghdr) uint8_t buffer[64]{};
    auto *header = reinterpret_cast<nlmsghdr *>(buffer);
    header->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN;
    header->nlmsg_type = family;
    header->nlmsg_flags = NLM_F_REQUEST | (splitDump ? NLM_F_DUMP : 0);
    header->nlmsg_seq = sequence;
    header->nlmsg_pid = port;
    auto *generic = reinterpret_cast<genlmsghdr *>(buffer + NLMSG_HDRLEN);
    generic->cmd = command;
    generic->version = version;
    auto *attr = reinterpret_cast<nlattr *>(buffer + header->nlmsg_len);
    attr->nla_type = attrType;
    attr->nla_len = NLA_HDRLEN + size;
    memcpy(reinterpret_cast<uint8_t *>(attr) + NLA_HDRLEN, value, size);
    header->nlmsg_len += NLA_ALIGN(attr->nla_len);
    if (splitDump) {
        attr = reinterpret_cast<nlattr *>(buffer + header->nlmsg_len);
        attr->nla_type = NL80211_ATTR_SPLIT_WIPHY_DUMP;
        attr->nla_len = NLA_HDRLEN;
        header->nlmsg_len += NLA_ALIGN(attr->nla_len);
    }
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    return sendto(fd, buffer, header->nlmsg_len, 0,
                  reinterpret_cast<const sockaddr *>(&kernel), sizeof(kernel)) ==
           static_cast<ssize_t>(header->nlmsg_len);
}

ssize_t receiveKernel(int fd, uint8_t *buffer, size_t capacity)
{
    sockaddr_nl sender{};
    iovec vector{buffer, capacity};
    msghdr msg{};
    msg.msg_name = &sender;
    msg.msg_namelen = sizeof(sender);
    msg.msg_iov = &vector;
    msg.msg_iovlen = 1;
    const ssize_t length = recvmsg(fd, &msg, MSG_TRUNC);
    if (length <= 0 || static_cast<size_t>(length) > capacity ||
        (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        msg.msg_namelen != sizeof(sender) || sender.nl_family != AF_NETLINK ||
        sender.nl_pid != 0 || sender.nl_groups != 0)
        return -1;
    return length;
}

struct WiphyReply {
    bool flagsPresent = false;
    bool done = false;
    uint32_t flags = 0;
};

bool consumeWiphy(const uint8_t *buffer, size_t size, uint16_t family,
                  uint32_t port, uint32_t phy, WiphyReply &reply)
{
    while (size >= NLMSG_HDRLEN && !reply.done) {
        const uint32_t length = readLe32(buffer);
        const uint16_t type = readLe16(buffer + 4);
        const uint16_t flags = readLe16(buffer + 6);
        if (length < NLMSG_HDRLEN || length > size ||
            (flags & NLM_F_DUMP_INTR) || readLe32(buffer + 8) != kWiphySequence ||
            readLe32(buffer + 12) != port || !(flags & NLM_F_MULTI))
            return false;
        const size_t step = NLMSG_ALIGN(length);
        if (step > size)
            return false;
        if (type == NLMSG_DONE) {
            // Linux multipart completion carries the signed dump errno.
            if (length < NLMSG_HDRLEN + sizeof(uint32_t) ||
                readLe32(buffer + NLMSG_HDRLEN) != 0)
                return false;
            reply.done = true;
        } else {
            constexpr size_t genericEnd = NLMSG_HDRLEN + GENL_HDRLEN;
            if (type != family || length < genericEnd ||
                buffer[NLMSG_HDRLEN] != NL80211_CMD_NEW_WIPHY ||
                buffer[NLMSG_HDRLEN + 2] || buffer[NLMSG_HDRLEN + 3])
                return false;
            const uint16_t wanted[] = {NL80211_ATTR_WIPHY, NL80211_ATTR_FEATURE_FLAGS};
            Attribute found[2]{};
            if (findAttributes(buffer + genericEnd, length - genericEnd,
                               wanted, 2, found) != Status::kOk ||
                found[0].valueLength != sizeof(uint32_t) ||
                readLe32(found[0].value) != phy)
                return false;
            if (found[1].value) {
                if (reply.flagsPresent || found[1].valueLength != sizeof(uint32_t))
                    return false;
                reply.flags = readLe32(found[1].value);
                reply.flagsPresent = true;
            }
        }
        buffer += step;
        size -= step;
    }
    return size == 0;
}

bool readFeatures(int fd, uint32_t port, uint32_t phy, uint32_t *features)
{
    constexpr char name[] = "nl80211";
    uint8_t buffer[16384]{};
    if (!request(fd, port, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 2,
                 kFamilySequence, CTRL_ATTR_FAMILY_NAME, name, sizeof(name)))
        return false;
    const ssize_t length = receiveKernel(fd, buffer, sizeof(buffer));
    uint16_t family = 0;
    if (length < 0 || parseFamilyReply(buffer, static_cast<size_t>(length), {},
                                       kFamilySequence, port, name, &family) != Status::kOk)
        return false;
    if (!request(fd, port, family, NL80211_CMD_GET_WIPHY, 1, kWiphySequence,
                 NL80211_ATTR_WIPHY, &phy, sizeof(phy), true))
        return false;
    WiphyReply reply{};
    for (unsigned i = 0; i < 64 && !reply.done; ++i) {
        const ssize_t count = receiveKernel(fd, buffer, sizeof(buffer));
        if (count < 0 || !consumeWiphy(buffer, static_cast<size_t>(count),
                                       family, port, phy, reply))
            return false;
    }
    if (!reply.done || !reply.flagsPresent)
        return false;
    *features = reply.flags;
    return true;
}
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2 || !argv[1][0] || strspn(argv[1], "0123456789") != strlen(argv[1])) {
        fputs("usage: openwrt_active_monitor_capability128 <wiphy-number>\n", stderr);
        return 2;
    }
    errno = 0;
    const unsigned long phy = strtoul(argv[1], nullptr, 10);
    if (errno || phy > INT32_MAX)
        return 2;
    const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0)
        return 4;
    timeval timeout{1, 0};
    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    socklen_t addressLength = sizeof(address);
    uint32_t features = 0;
    const bool queried =
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0 &&
        bind(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0 &&
        getsockname(fd, reinterpret_cast<sockaddr *>(&address), &addressLength) == 0 &&
        addressLength == sizeof(address) && address.nl_family == AF_NETLINK &&
        address.nl_pid != 0 && address.nl_groups == 0 &&
        readFeatures(fd, address.nl_pid, static_cast<uint32_t>(phy), &features);
    close(fd);
    if (!queried) {
        fputs("could not read complete nl80211 wiphy feature flags\n", stderr);
        return 4;
    }
    const bool active = (features & NL80211_FEATURE_ACTIVE_MONITOR) != 0;
    printf("{\"wiphy\":%lu,\"feature_flags\":%u,\"active_monitor\":%s}\n",
           phy, features, active ? "true" : "false");
    return active ? 0 : 3;
}
