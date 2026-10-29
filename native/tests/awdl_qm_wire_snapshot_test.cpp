// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_qm_wire_snapshot.hpp"

#include <assert.h>
#include <string.h>

int main()
{
    using namespace NativeAwdlQmWireSnapshot;
    const uint8_t own[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t bssid[6] = {0x00, 0x25, 0x00, 0xff, 0x94, 0x73};
    const uint8_t groupMac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0xfb};
    const uint8_t groupIp[16] = {
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb
    };
    uint8_t header[24] = {};
    header[0] = 0x08; // Non-QoS Data, no DS bits.
    memcpy(header + 4, groupMac, sizeof(groupMac));
    memcpy(header + 10, own, sizeof(own));
    memcpy(header + 16, bssid, sizeof(bssid));
    header[22] = 0x20; // sequence control 32 (sequence 2, fragment 0).

    const HeaderSnapshot qm = inspectHeader(
        header, sizeof(header), 125, own, bssid, true);
    assert(qm.valid);
    assert(qm.frameControl == 0x0008);
    assert(qm.sequenceControl == 32);
    assert(qm.mpduLength == 125);
    assert(qm.headerLength == 24);
    assert(qm.dsBits == 0);
    assert((qm.roleFlags & (kHeaderValid | kNoDs |
        kAddress1Multicast | kAddress2MatchesLocal |
        kAddress3MatchesAwdlBssid |
        kAddress1MatchesAirdropMdnsMapping |
        kIpv6DestinationIsAirdropMdnsGroup)) ==
        (kHeaderValid | kNoDs | kAddress1Multicast |
         kAddress2MatchesLocal | kAddress3MatchesAwdlBssid |
         kAddress1MatchesAirdropMdnsMapping |
         kIpv6DestinationIsAirdropMdnsGroup));
    assert((qm.roleFlags & kAddress1Broadcast) == 0);

    // The role snapshot exposes only booleans and numeric header fields.
    assert(sizeof(qm) < 32);

    header[1] = 0x01; // ToDS set.
    const HeaderSnapshot toDs = inspectHeader(
        header, sizeof(header), 125, own, bssid, true);
    assert(toDs.valid && toDs.dsBits == 1);
    assert((toDs.roleFlags & kNoDs) == 0);

    header[1] = 0;
    header[10] ^= 0x02;
    const HeaderSnapshot wrongSource = inspectHeader(
        header, sizeof(header), 125, own, bssid, true);
    assert(wrongSource.valid);
    assert((wrongSource.roleFlags & kAddress2MatchesLocal) == 0);
    assert((wrongSource.roleFlags & kAddress3MatchesAwdlBssid) != 0);

    assert((wrongSource.roleFlags & kAddress1MatchesAirdropMdnsMapping) != 0);

    // The bool is extracted while the IPv6 bytes are live. Later matching is
    // against the exact ff02::fb IPv6-to-Ethernet mapping constant.
    assert(isAirdropMdnsGroupDestination(groupIp));
    uint8_t otherGroupIp[16];
    memcpy(otherGroupIp, groupIp, sizeof(otherGroupIp));
    otherGroupIp[15] = 0xfc;
    assert(!isAirdropMdnsGroupDestination(otherGroupIp));
    const HeaderSnapshot nonMdns = inspectHeader(
        header, sizeof(header), 125, own, bssid, false);
    assert((nonMdns.roleFlags & kIpv6DestinationIsAirdropMdnsGroup) == 0);
    assert((nonMdns.roleFlags & kAddress1MatchesAirdropMdnsMapping) == 0);

    assert(!inspectHeader(header, 23, 125, own, bssid, true).valid);
    assert(!inspectHeader(header, 24, 23, own, bssid, true).valid);
    assert(!inspectHeader(header, 24, 65536, own, bssid, true).valid);

    Record record{};
    record.header = qm;
    record.token = 45;
    record.contextGeneration = 7;
    record.powerGeneration = 8;
    record.stationGeneration = 9;
    record.rocToken = 10;
    record.stationId = 3;
    record.queueId = 4;
    record.ringSize = 256;
    record.descriptorIndex = 2;
    record.frameType = 1;
    record.txLayout = 2;
    record.txCommandApi = 9;
    record.txNotificationApi = 9;
    record.txFlags = 0x123;
    record.rateNFlags = 0x456;
    record.offloadAssist = 0;
    record.mhSizeWords = 12;
    record.tfdCount = 2;
    record.firstTbBytes = 64;
    record.commandTailBytes = 4;
    record.payloadSegmentCount = 1;
    record.payloadBytes = 85;
    record.channel = 6;
    record.frequencyMhz = 2437;
    record.hostPreDoorbellUs = 0x0102030405060708ULL;
    record.estimatedNotBeforeUs = 100;
    record.estimatedDeadlineUs = 200;
    const EncodedSnapshot encoded = encode(record);
    assert(sizeof(encoded.bytes) == kSerializedSize);
    assert(readLe64(encoded.bytes + kSchemaVersion * 8) ==
           kSchemaVersionValue);
    assert(readLe64(encoded.bytes + kToken * 8) == 45);
    assert(readLe64(encoded.bytes + kSequenceControl * 8) == 32);
    assert(readLe64(encoded.bytes + kMpduLength * 8) == 125);
    assert(readLe64(encoded.bytes + kQueueId * 8) == 4);
    assert(readLe64(encoded.bytes + kChannel * 8) == 6);
    assert(readLe64(encoded.bytes + kCurrentGp2Valid * 8) == 0);
    return 0;
}
