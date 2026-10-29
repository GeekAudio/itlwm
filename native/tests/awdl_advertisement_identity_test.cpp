// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_action_encode.hpp"
#include "../awdl_advertisement_identity.hpp"
#include "../awdl_mif_encode.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

namespace {
NativeAwdl::PsfInput validInput(bool advertise)
{
    NativeAwdl::PsfInput input{};
    const uint8_t source[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t master[6] = {0x02, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4};
    const uint8_t sync[6] = {0x02, 0xf1, 0xe2, 0xd3, 0xc4, 0xb5};
    const uint8_t slots[16] = {
        6, 6, 6, 6, 44, 44, 44, 44, 149, 149, 149, 149, 0, 0, 0, 0
    };
    memcpy(input.sourceAddress, source, sizeof(source));
    memcpy(input.masterAddress, master, sizeof(master));
    memcpy(input.syncAddress, sync, sizeof(sync));
    memcpy(input.channelSlots, slots, sizeof(slots));
    input.sequenceNumber = 0x123;
    input.phyTxTimestampUs = 0x12345678;
    input.targetTxTimestampUs = 0x90abcdef;
    input.nextAwChannel = 6;
    input.txDownCounterTu = 37;
    input.masterChannel = 6;
    input.remainingAwLengthTu = 5;
    input.nextAwSequenceNumber = 0x2345;
    input.apAlignment = 0x6789;
    input.masterCounter = 0x11223344;
    input.distanceToMaster = 7;
    input.masterMetric = 60;
    input.ownMetric = 60;
    input.ownCounter = 0x55667788;
    input.htCapabilityInfo = 0x1234;
    input.ampduParameters = 0x56;
    input.rxMcsMask[0] = 0x3f;
    input.rxMcsLength = 1;
    input.awdlVersion = 0x34;
    input.deviceClass = 1;
    input.advertiseAwdlAddress = advertise;
    return input;
}

size_t dataPathOffset(const uint8_t *frame, size_t length)
{
    size_t offset = NativeAwdl::kActionMacHeaderLength +
        NativeAwdl::kAwdlActionHeaderLength;
    while (offset + 3 <= length) {
        const size_t valueLength = static_cast<uint16_t>(frame[offset + 1]) |
            (static_cast<uint16_t>(frame[offset + 2]) << 8);
        if (valueLength > length - offset - 3)
            return length;
        if (frame[offset] == 12)
            return offset;
        offset += 3 + valueLength;
    }
    return length;
}

void encodePsf(bool advertise, uint8_t *frame, size_t *length)
{
    const auto input = validInput(advertise);
    assert(NativeAwdl::encodePsf(&input, frame,
        NativeAwdl::kMaximumEncodedPsfLength, length) ==
        NativeAwdl::EncodeStatus::Ok);
}

void encodeMif(bool advertise, uint8_t *frame, size_t *length)
{
    const char hostname[] = "identity-host";
    NativeAwdl::MifInput input{validInput(advertise), hostname,
                               sizeof(hostname) - 1};
    assert(NativeAwdl::encodeMif(&input, frame,
        NativeAwdl::kMaximumEncodedMifLength, length) ==
        NativeAwdl::MifEncodeStatus::Ok);
}

void checkEncodedFrame(bool mif)
{
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength + 4]{};
    size_t length = 0;
    if (mif)
        encodeMif(true, frame, &length);
    else
        encodePsf(true, frame, &length);
    const auto input = validInput(true);
    assert(length > NativeAwdl::kActionMacHeaderLength +
                    NativeAwdl::kAwdlActionHeaderLength);
    assert(frame[32] != 0 || frame[33] != 0 || frame[34] != 0 || frame[35] != 0);
    assert(NativeAwdl::actionFrameAdvertisesAddress(
        frame, length, input.sourceAddress));

    uint8_t wrongAddress[6];
    memcpy(wrongAddress, input.sourceAddress, sizeof(wrongAddress));
    wrongAddress[5] ^= 1;
    assert(!NativeAwdl::actionFrameAdvertisesAddress(
        frame, length, wrongAddress));

    const size_t dataPath = dataPathOffset(frame, length);
    assert(dataPath < length && frame[dataPath] == 12 && frame[dataPath + 1] == 8);
    uint8_t changed[sizeof(frame)];
    memcpy(changed, frame, length);
    changed[dataPath + 5] ^= 1; // advertised MAC differs from Addr2
    assert(!NativeAwdl::actionFrameAdvertisesAddress(
        changed, length, input.sourceAddress));

    memcpy(changed, frame, length);
    changed[15] ^= 1; // Addr2 differs from the Data Path State address
    assert(!NativeAwdl::actionFrameAdvertisesAddress(
        changed, length, input.sourceAddress));

    assert(!NativeAwdl::actionFrameAdvertisesAddress(
        frame, length - 1, input.sourceAddress));

    memcpy(changed, frame, length);
    changed[length] = 0;
    assert(NativeAwdl::actionFrameAdvertisesAddress(
        changed, length + 1, input.sourceAddress));
    changed[length + 1] = 0;
    assert(NativeAwdl::actionFrameAdvertisesAddress(
        changed, length + 2, input.sourceAddress));
    changed[length + 1] = 1;
    assert(!NativeAwdl::actionFrameAdvertisesAddress(
        changed, length + 2, input.sourceAddress));

    // Exercise the optional HT Control offset while preserving the valid
    // nonzero AWDL timestamps and generated PSF/MIF bytes.
    memcpy(changed, frame, length);
    memmove(changed + NativeAwdl::kActionMacHeaderLength +
                NativeAwdl::kActionHtControlLength,
            changed + NativeAwdl::kActionMacHeaderLength,
            length - NativeAwdl::kActionMacHeaderLength);
    memset(changed + NativeAwdl::kActionMacHeaderLength, 0x5a,
           NativeAwdl::kActionHtControlLength);
    changed[1] |= 0x80;
    assert(NativeAwdl::actionFrameAdvertisesAddress(
        changed, length + NativeAwdl::kActionHtControlLength,
        input.sourceAddress));
}

void checkLegacyNoAdvertisement(bool mif)
{
    uint8_t frame[NativeAwdl::kMaximumEncodedMifLength]{};
    size_t length = 0;
    if (mif)
        encodeMif(false, frame, &length);
    else
        encodePsf(false, frame, &length);
    const auto input = validInput(false);
    assert(!NativeAwdl::actionFrameAdvertisesAddress(
        frame, length, input.sourceAddress));
}
} // namespace

int main()
{
    checkEncodedFrame(false); // real PSF encoder, flags=0x0004
    checkEncodedFrame(true);  // real MIF encoder, flags=0x0004
    checkLegacyNoAdvertisement(false); // real PSF encoder, flags=0
    checkLegacyNoAdvertisement(true);  // real MIF encoder, flags=0
}
