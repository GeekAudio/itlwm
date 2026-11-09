// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_qm_wire_snapshot.hpp"

#include <assert.h>
#include <string.h>

namespace QmRaw = NativeAwdlQmWireSnapshot::Raw;

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

    static_assert(QmRaw::kHeaderSize == 112, "raw QWR1 header changed");
    static_assert(QmRaw::kSerializedSize == 2224, "raw QWR1 size changed");
    static_assert(QmRaw::kStatusSerializedSize == 56, "QWS1 status size changed");

    QmRaw::Record raw{};
    raw.identity = {45, 7, 8, 9, 10};
    raw.stationId = 3;
    raw.queueId = 4;
    raw.ringSize = 256;
    raw.descriptorIndex = 2;
    raw.sequenceControl = 32;
    raw.frameControl = 8;
    uint8_t command[56];
    uint8_t mpduHeader[24];
    uint8_t payload[101];
    for (size_t i = 0; i < sizeof(command); ++i)
        command[i] = static_cast<uint8_t>(i + 1);
    for (size_t i = 0; i < sizeof(mpduHeader); ++i)
        mpduHeader[i] = static_cast<uint8_t>(0x40 + i);
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(0x80 + i);
    assert(QmRaw::captureBytes(&raw, command, sizeof(command), mpduHeader,
                        sizeof(mpduHeader), payload, sizeof(payload), 0));
    assert(raw.stage == QmRaw::Stage::kCapturedAwaitingFinish);
    assert(raw.commandActualLength == sizeof(command));
    assert(raw.commandCopiedLength == sizeof(command));
    assert(raw.mpduActualLength == sizeof(mpduHeader) + sizeof(payload));
    assert(raw.mpduCopiedLength == raw.mpduActualLength);
    assert(raw.flags & QmRaw::kCandidate);
    assert(raw.flags & QmRaw::kCommandCaptured);
    assert(raw.flags & QmRaw::kMpduCaptured);
    raw.doorbellUs = 500;
    raw.finishUs = 525;
    raw.stage = QmRaw::Stage::kStagedAwaitingPublish;
    raw.flags |= QmRaw::kStageAccepted;
    const QmRaw::EncodedSnapshot rawEncoded = QmRaw::encode(raw);
    assert(QmRaw::readLe32(rawEncoded.bytes) == QmRaw::kMagic);
    assert(readLe16(rawEncoded.bytes + 4) == QmRaw::kSchemaVersion);
    assert(readLe16(rawEncoded.bytes + 6) == QmRaw::kHeaderSize);
    assert(QmRaw::readLe32(rawEncoded.bytes + 8) == QmRaw::kSerializedSize);
    assert(readLe64(rawEncoded.bytes + 16) == 45);
    assert(readLe64(rawEncoded.bytes + 24) == 7);
    assert(readLe64(rawEncoded.bytes + 32) == 8);
    assert(readLe64(rawEncoded.bytes + 40) == 9);
    assert(readLe64(rawEncoded.bytes + 48) == 10);
    assert(readLe16(rawEncoded.bytes + 56) == 3);
    assert(readLe16(rawEncoded.bytes + 58) == 4);
    assert(QmRaw::readLe32(rawEncoded.bytes + 68) == sizeof(command));
    assert(QmRaw::readLe32(rawEncoded.bytes + 72) == sizeof(command));
    assert(QmRaw::readLe32(rawEncoded.bytes + 76) == 125);
    assert(QmRaw::readLe32(rawEncoded.bytes + 80) == 125);
    assert(readLe64(rawEncoded.bytes + 96) == 500);
    assert(readLe64(rawEncoded.bytes + 104) == 525);
    assert(memcmp(rawEncoded.bytes + QmRaw::kCommandOffset, command,
                  sizeof(command)) == 0);
    assert(memcmp(rawEncoded.bytes + QmRaw::kMpduOffset, mpduHeader,
                  sizeof(mpduHeader)) == 0);
    assert(memcmp(rawEncoded.bytes + QmRaw::kMpduOffset + sizeof(mpduHeader), payload,
                  sizeof(payload)) == 0);

    QmRaw::StatusRecord publishedStatus{};
    publishedStatus.stage = QmRaw::Stage::kPublished;
    publishedStatus.identity = raw.identity;
    const QmRaw::EncodedStatus statusEncoded = QmRaw::encodeStatus(publishedStatus);
    assert(QmRaw::readLe32(statusEncoded.bytes) == QmRaw::kStatusMagic);
    assert(readLe16(statusEncoded.bytes + 4) == QmRaw::kSchemaVersion);
    assert(readLe16(statusEncoded.bytes + 6) == QmRaw::kStatusSerializedSize);
    assert(QmRaw::readLe32(statusEncoded.bytes + 8) ==
           static_cast<uint32_t>(QmRaw::Stage::kPublished));
    const QmRaw::Identity legacyIdentity = {45, 7, 8, 9, 10};
    assert(QmRaw::sameIdentity(legacyIdentity, raw.identity));
    QmRaw::Identity staleIdentity = legacyIdentity;
    ++staleIdentity.token;
    assert(!QmRaw::sameIdentity(staleIdentity, raw.identity));
    staleIdentity = legacyIdentity;
    ++staleIdentity.contextGeneration;
    assert(!QmRaw::sameIdentity(staleIdentity, raw.identity));
    staleIdentity = legacyIdentity;
    ++staleIdentity.powerGeneration;
    assert(!QmRaw::sameIdentity(staleIdentity, raw.identity));
    staleIdentity = legacyIdentity;
    ++staleIdentity.stationGeneration;
    assert(!QmRaw::sameIdentity(staleIdentity, raw.identity));
    staleIdentity = legacyIdentity;
    ++staleIdentity.rocToken;
    assert(!QmRaw::sameIdentity(staleIdentity, raw.identity));

    // A later eligible packet cannot replace the first staged identity.
    uint32_t oneShotState = 0;
    QmRaw::Identity firstIdentity = raw.identity;
    assert(QmRaw::claimFirstSlot(&oneShotState));
    const QmRaw::Identity retainedIdentity = firstIdentity;
    assert(!QmRaw::claimFirstSlot(&oneShotState));
    assert(QmRaw::sameIdentity(firstIdentity, retainedIdentity));

    // Oversize input is bounded, explicitly truncated, and never marked as a
    // complete command or MPDU capture.
    QmRaw::Record truncated{};
    uint8_t longCommand[70]{};
    uint8_t longPayload[2025]{};
    assert(!QmRaw::captureBytes(&truncated, longCommand, sizeof(longCommand),
        mpduHeader, sizeof(mpduHeader), longPayload, sizeof(longPayload), 0));
    assert(truncated.commandActualLength == 70);
    assert(truncated.commandCopiedLength == QmRaw::kCommandCapacity);
    assert(truncated.flags & QmRaw::kCommandTruncated);
    assert(!(truncated.flags & QmRaw::kCommandCaptured));
    assert(truncated.mpduActualLength == 2049);
    assert(truncated.mpduCopiedLength == QmRaw::kMpduCapacity);
    assert(truncated.flags & QmRaw::kMpduTruncated);
    assert(!(truncated.flags & QmRaw::kMpduCaptured));
    assert(truncated.stage == QmRaw::Stage::kHeaderOrCopyRejected);

    QmRaw::Record payloadReadFailed{};
    assert(!QmRaw::captureBytes(&payloadReadFailed, command, sizeof(command),
        mpduHeader, sizeof(mpduHeader), payload, sizeof(payload), 5));
    assert(payloadReadFailed.commandCopiedLength == sizeof(command));
    assert(payloadReadFailed.mpduCopiedLength == sizeof(mpduHeader));
    assert(payloadReadFailed.mpduCopyResult == 5);
    assert(!(payloadReadFailed.flags & QmRaw::kMpduCaptured));
    assert(payloadReadFailed.stage == QmRaw::Stage::kHeaderOrCopyRejected);
    return 0;
}
