// SPDX-License-Identifier: GPL-2.0-only
// Offline, single-frame AWDL RX fixture. This program has no RF or socket path.

#include "awdl_data_frame.hpp"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <array>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr uint8_t kSyntheticPeerMac[6] = {0x02, 0x52, 0x58, 0x00, 0x00, 0x01};
constexpr uint8_t kSyntheticIpv6Source[16] = {
    0xfe, 0x80, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0x00, 0x52};
constexpr uint8_t kAllNodesIpv6[16] = {
    0xff, 0x02, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 1};
constexpr uint8_t kMulticastMac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
constexpr char kNonce[] = "IWN-RX-TEST-0001";
constexpr size_t kNonceLength = sizeof(kNonce) - 1;
constexpr size_t kUdpLength = 8 + kNonceLength;
constexpr size_t kIpv6Length = NativeAwdlData::kIpv6HeaderLength + kUdpLength;
constexpr uint16_t kWifiSequence = 0x123;
constexpr uint16_t kAwdlSequence = 0x4a57;

struct Fixture {
    std::array<uint8_t, kIpv6Length> ipv6{};
    std::array<uint8_t, 256> mpdu{};
    size_t mpduLength = 0;
};

void require(bool condition, const char *message)
{
    if (!condition)
        throw std::runtime_error(message);
}

void putBe16(uint8_t *p, uint16_t value)
{
    p[0] = static_cast<uint8_t>(value >> 8);
    p[1] = static_cast<uint8_t>(value);
}

uint16_t getBe16(const uint8_t *p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint16_t getLe16(const uint8_t *p)
{
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t addWords(uint32_t sum, const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i + 1 < length; i += 2)
        sum += (static_cast<uint32_t>(bytes[i]) << 8) | bytes[i + 1];
    if (length & 1)
        sum += static_cast<uint32_t>(bytes[length - 1]) << 8;
    return sum;
}

uint32_t udpPseudoHeaderSum(const uint8_t *ipv6, size_t udpLength)
{
    uint32_t sum = 0;
    sum = addWords(sum, ipv6 + 8, 32);
    const uint8_t suffix[8] = {
        0, 0, static_cast<uint8_t>(udpLength >> 8),
        static_cast<uint8_t>(udpLength), 0, 0, 0, 17};
    return addWords(sum, suffix, sizeof(suffix));
}

uint16_t udpChecksum(const uint8_t *ipv6, const uint8_t *udp,
                     size_t udpLength)
{
    uint32_t sum = udpPseudoHeaderSum(ipv6, udpLength);
    sum = addWords(sum, udp, udpLength);
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    const uint16_t result = static_cast<uint16_t>(~sum);
    return result == 0 ? 0xffff : result;
}

bool validUdpChecksum(const uint8_t *ipv6, size_t ipv6Length)
{
    if (!ipv6 || ipv6Length < NativeAwdlData::kIpv6HeaderLength ||
        ipv6[6] != 17)
        return false;
    const size_t udpLength = getBe16(ipv6 + 4);
    if (udpLength < 8 || ipv6Length != NativeAwdlData::kIpv6HeaderLength + udpLength)
        return false;
    uint32_t sum = udpPseudoHeaderSum(ipv6, udpLength);
    sum = addWords(sum, ipv6 + NativeAwdlData::kIpv6HeaderLength, udpLength);
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return sum == 0xffffu;
}

Fixture buildAndValidateFixture()
{
    Fixture fixture{};
    uint8_t *ip = fixture.ipv6.data();
    ip[0] = 0x60;
    putBe16(ip + 4, static_cast<uint16_t>(kUdpLength));
    ip[6] = 17; // UDP
    ip[7] = 1;  // Link-local multicast scope; this is a fixture, not a send.
    memcpy(ip + 8, kSyntheticIpv6Source, sizeof(kSyntheticIpv6Source));
    memcpy(ip + 24, kAllNodesIpv6, sizeof(kAllNodesIpv6));

    uint8_t *udp = ip + NativeAwdlData::kIpv6HeaderLength;
    putBe16(udp, 49152);
    putBe16(udp + 2, 49153);
    putBe16(udp + 4, static_cast<uint16_t>(kUdpLength));
    putBe16(udp + 6, 0);
    memcpy(udp + 8, kNonce, kNonceLength);
    putBe16(udp + 6, udpChecksum(ip, udp, kUdpLength));

    require(ip[0] == 0x60 && getBe16(ip + 4) == kUdpLength,
            "IPv6 version or payload length mismatch");
    require(ip[6] == 17 && ip[7] == 1, "IPv6 next-header or hop-limit mismatch");
    require(!memcmp(ip + 8, kSyntheticIpv6Source, 16) &&
                !memcmp(ip + 24, kAllNodesIpv6, 16),
            "synthetic IPv6 endpoints mismatch");
    require(getBe16(udp) == 49152 && getBe16(udp + 2) == 49153 &&
                getBe16(udp + 4) == kUdpLength,
            "UDP fixture fields mismatch");
    require(!memcmp(udp + 8, kNonce, kNonceLength), "nonce mismatch");
    require(validUdpChecksum(ip, fixture.ipv6.size()),
            "independent IPv6 UDP checksum verification failed");

    NativeAwdlData::EncodeInput input{};
    memcpy(input.destinationAddress, kMulticastMac, 6);
    memcpy(input.sourceAddress, kSyntheticPeerMac, 6);
    input.wifiSequenceNumber = kWifiSequence;
    input.awdlSequenceNumber = kAwdlSequence;
    input.ipv6Packet = ip;
    input.ipv6Length = fixture.ipv6.size();
    require(NativeAwdlData::encodeIpv6DataMpdu(
                &input, fixture.mpdu.data(), fixture.mpdu.size(),
                &fixture.mpduLength) == NativeAwdlData::Status::Ok,
            "production AWDL frame encoder rejected fixture");

    // Assert the fixed 802.11/AWDL fields independently of the production decoder.
    const uint8_t expectedSnap[8] = {
        0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2, 0x08, 0x00};
    const uint8_t expectedAwdlHeader[8] = {
        0x03, 0x04, 0x57, 0x4a, 0x00, 0x00, 0x86, 0xdd};
    require(fixture.mpduLength == 24 + sizeof(expectedSnap) +
                                      sizeof(expectedAwdlHeader) + kIpv6Length,
            "unexpected MPDU length");
    require(fixture.mpdu[0] == 0x08 && fixture.mpdu[1] == 0x00,
            "fixture is not an unprotected no-DS Data frame");
    require(!memcmp(fixture.mpdu.data() + 4, kMulticastMac, 6) &&
                !memcmp(fixture.mpdu.data() + 10, kSyntheticPeerMac, 6) &&
                !memcmp(fixture.mpdu.data() + 16,
                        NativeAwdlData::kAwdlBssid, 6),
            "802.11 addresses do not match the synthetic fixture");
    require(getLe16(fixture.mpdu.data() + 22) == (kWifiSequence << 4),
            "802.11 sequence control mismatch");
    require(!memcmp(fixture.mpdu.data() + 24, expectedSnap,
                    sizeof(expectedSnap)) &&
                !memcmp(fixture.mpdu.data() + 32, expectedAwdlHeader,
                        sizeof(expectedAwdlHeader)),
            "SNAP or AWDL data header mismatch");
    require(NativeAwdlData::isAwdlDataCandidate(
                fixture.mpdu.data(), fixture.mpduLength),
            "production header classifier rejected fixture");

    NativeAwdlData::DecodedFrame decoded{};
    require(NativeAwdlData::decodeIpv6DataMpdu(
                fixture.mpdu.data(), fixture.mpduLength,
                &decoded) == NativeAwdlData::Status::Ok,
            "production AWDL frame decoder rejected fixture");
    require(decoded.packetCount == 1 && decoded.wifiSequenceNumber == kWifiSequence &&
                decoded.packets[0].awdlSequenceNumber == kAwdlSequence,
            "production decoder returned unexpected sequence or packet count");
    require(!memcmp(decoded.destinationAddress, kMulticastMac, 6) &&
                !memcmp(decoded.sourceAddress, kSyntheticPeerMac, 6) &&
                decoded.packets[0].ipv6Length == fixture.ipv6.size() &&
                !memcmp(decoded.packets[0].ipv6Packet, ip, fixture.ipv6.size()),
            "production decoder changed fixture contents");
    return fixture;
}

void appendLe16(std::vector<uint8_t> &bytes, uint16_t value)
{
    bytes.push_back(static_cast<uint8_t>(value));
    bytes.push_back(static_cast<uint8_t>(value >> 8));
}

void appendLe32(std::vector<uint8_t> &bytes, uint32_t value)
{
    bytes.push_back(static_cast<uint8_t>(value));
    bytes.push_back(static_cast<uint8_t>(value >> 8));
    bytes.push_back(static_cast<uint8_t>(value >> 16));
    bytes.push_back(static_cast<uint8_t>(value >> 24));
}

std::vector<uint8_t> makePcap(const Fixture &fixture)
{
    std::vector<uint8_t> bytes;
    const uint8_t radiotap[8] = {0, 0, 8, 0, 0, 0, 0, 0};
    const uint32_t packetLength = static_cast<uint32_t>(sizeof(radiotap) +
                                                       fixture.mpduLength);
    appendLe32(bytes, 0xa1b2c3d4u);
    appendLe16(bytes, 2);
    appendLe16(bytes, 4);
    appendLe32(bytes, 0);
    appendLe32(bytes, 0);
    appendLe32(bytes, 4096);
    appendLe32(bytes, 127); // DLT_IEEE802_11_RADIO
    appendLe32(bytes, 0);   // Deterministic synthetic timestamp.
    appendLe32(bytes, 0);
    appendLe32(bytes, packetLength);
    appendLe32(bytes, packetLength);
    bytes.insert(bytes.end(), radiotap, radiotap + sizeof(radiotap));
    bytes.insert(bytes.end(), fixture.mpdu.begin(),
                 fixture.mpdu.begin() + fixture.mpduLength);
    return bytes;
}

std::vector<uint8_t> makeHex(const Fixture &fixture)
{
    static const char digits[] = "0123456789abcdef";
    std::vector<uint8_t> bytes;
    bytes.reserve(fixture.mpduLength * 3 + 1);
    for (size_t i = 0; i < fixture.mpduLength; ++i) {
        if (i)
            bytes.push_back(' ');
        bytes.push_back(static_cast<uint8_t>(digits[fixture.mpdu[i] >> 4]));
        bytes.push_back(static_cast<uint8_t>(digits[fixture.mpdu[i] & 0x0f]));
    }
    bytes.push_back('\n');
    return bytes;
}

bool isSafeTemporaryPath(const std::string &path)
{
    const std::string tmpPrefix = "/tmp/";
    const std::string privateTmpPrefix = "/private/tmp/";
    size_t prefixLength = 0;
    if (path.compare(0, tmpPrefix.size(), tmpPrefix) == 0)
        prefixLength = tmpPrefix.size();
    else if (path.compare(0, privateTmpPrefix.size(), privateTmpPrefix) == 0)
        prefixLength = privateTmpPrefix.size();
    else
        return false;
    const std::string name = path.substr(prefixLength);
    if (name.empty() || name.find('/') != std::string::npos ||
        name == "." || name == "..")
        return false;
    for (const char c : name) {
        const bool valid = (c >= 'a' && c <= 'z') ||
                           (c >= 'A' && c <= 'Z') ||
                           (c >= '0' && c <= '9') || c == '.' ||
                           c == '_' || c == '-';
        if (!valid)
            return false;
    }
    return true;
}

void writeNewFile(const std::string &path, const std::vector<uint8_t> &bytes)
{
    require(isSafeTemporaryPath(path),
            "--output must be one filename directly under /tmp");
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    require(fd >= 0, errno == EEXIST ? "output exists; refusing to overwrite"
                                    : "could not create output file");
    size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t count = write(fd, bytes.data() + offset,
                                    bytes.size() - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            close(fd);
            unlink(path.c_str());
            throw std::runtime_error("failed while writing fixture output");
        }
        offset += static_cast<size_t>(count);
    }
    require(close(fd) == 0, "failed to close fixture output");
}

void printUsage(const char *program)
{
    printf("Usage: %s [--output /tmp/name.pcap|/tmp/name.hex]\n", program);
    printf("Default: validate one synthetic frame in memory; never transmits.\n");
}

} // namespace

int main(int argc, char **argv)
{
    try {
        if (argc == 2 && !strcmp(argv[1], "--help")) {
            printUsage(argv[0]);
            return 0;
        }
        if (argc != 1 && argc != 3) {
            printUsage(argv[0]);
            return 2;
        }
        if (argc == 3 && strcmp(argv[1], "--output")) {
            printUsage(argv[0]);
            return 2;
        }

        const Fixture fixture = buildAndValidateFixture();
        const char *artifactKind = "none";
        if (argc == 3) {
            const std::string path(argv[2]);
            std::vector<uint8_t> output;
            if (path.size() >= 5 && path.compare(path.size() - 5, 5, ".pcap") == 0) {
                output = makePcap(fixture);
                artifactKind = "pcap";
            } else if (path.size() >= 4 &&
                       path.compare(path.size() - 4, 4, ".hex") == 0) {
                output = makeHex(fixture);
                artifactKind = "hex";
            } else {
                throw std::runtime_error("output extension must be .pcap or .hex");
            }
            writeNewFile(path, output);
        }

        printf("offline_fixture=passed\n");
        printf("production_encode_decode=passed\n");
        printf("independent_udp_checksum=valid\n");
        printf("fixed_awdl_fields=passed\n");
        printf("nonce=%s\n", kNonce);
        printf("mpdu_bytes=%zu\n", fixture.mpduLength);
        printf("output=%s\n", artifactKind);
        printf("rf_transmission=not_attempted\n");
        return 0;
    } catch (const std::exception &error) {
        fprintf(stderr, "fixture_error=%s\n", error.what());
        return 1;
    }
}
