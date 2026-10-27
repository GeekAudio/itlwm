// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_peer_election.hpp"

#include <string.h>

namespace IntelAwdlElection {
namespace {

constexpr size_t kMacHeaderLength = 24;
constexpr size_t kActionHeaderLength = 16;
constexpr size_t kTlvStart = kMacHeaderLength + kActionHeaderLength;
constexpr size_t kSourceAddressOffset = 10;
// AWDL readers need offsets 0..30. Offset 31 begins AP alignment, and the
// optional copied channel sequence begins at offset 33.
constexpr size_t kSyncRequiredPrefixLength = 31;
constexpr size_t kSyncEmbeddedSequenceOffset = 33;
constexpr size_t kElectionV1Length = 21;
constexpr size_t kElectionV2Length = 40;

uint16_t readLe16(const uint8_t *p)
{
    return static_cast<uint16_t>(p[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(p[1]) << 8);
}

uint32_t readLe32(const uint8_t *p)
{
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

bool isUnicastNonzero(const Address &address)
{
    uint8_t any = 0;
    for (size_t i = 0; i < kAddressLength; ++i)
        any |= address.bytes[i];
    return any != 0 && (address.bytes[0] & 1) == 0;
}

bool equalAddress(const Address &a, const Address &b)
{
    return memcmp(a.bytes, b.bytes, kAddressLength) == 0;
}

int compareAddress(const Address &a, const Address &b)
{
    const int result = memcmp(a.bytes, b.bytes, kAddressLength);
    return result < 0 ? -1 : result > 0 ? 1 : 0;
}

void copyAddress(Address *out, const uint8_t *in)
{
    memcpy(out->bytes, in, kAddressLength);
}

bool allZero(const uint8_t *bytes, size_t length)
{
    uint8_t any = 0;
    for (size_t i = 0; i < length; ++i)
        any |= bytes[i];
    return any == 0;
}

bool decodeChannelSequence(const uint8_t *value, size_t length,
                           size_t paddingLength, uint8_t channels[16])
{
    if (!value || !channels || length < 6 + paddingLength ||
        value[0] != 15 || value[2] != 0 || value[3] != 3 ||
        readLe16(value + 4) != 0xffff)
        return false;

    const uint8_t encoding = value[1];
    if (encoding != 0 && encoding != 1 && encoding != 3)
        return false;
    const size_t bytesPerSlot = encoding == 0 ? 1 : 2;
    const size_t expectedLength = 6 + 16 * bytesPerSlot + paddingLength;
    if (length != expectedLength ||
        !allZero(value + length - paddingLength, paddingLength))
        return false;
    if (encoding == 0) {
        memcpy(channels, value + 6, 16);
    } else {
        // Legacy entries are flags/channel; opclass entries are
        // channel/opclass. The first field is not a channel in encoding 1.
        for (size_t i = 0; i < 16; ++i)
            channels[i] = value[6 + i * 2 + (encoding == 1 ? 1 : 0)];
    }
    return true;
}

uint32_t narrowSize(size_t value)
{
    return value > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(value);
}

void noteReject(DecodeDiagnostics *diagnostics,
                MifDecodeRejectStage stage, uint8_t type, size_t tlvOffset,
                size_t declaredLength, size_t availableLength)
{
    if (!diagnostics)
        return;
    diagnostics->rejectStage = stage;
    diagnostics->offendingTlvType = type;
    diagnostics->tlvOffset = narrowSize(tlvOffset);
    diagnostics->declaredLength = narrowSize(declaredLength);
    diagnostics->availableLength = narrowSize(availableLength);
}

bool recognizableChannelSequenceHeader(const uint8_t *value, size_t length)
{
    if (!value || length < 6 || value[0] != 15 || value[2] != 0 ||
        value[3] != 3 || readLe16(value + 4) != 0xffff)
        return false;
    return value[1] == 0 || value[1] == 1 || value[1] == 3;
}

bool decodeEmbeddedSequence(const uint8_t *value, size_t length,
                            uint8_t channels[16], bool *present,
                            bool *recognized)
{
    if (!value || !channels || !present || !recognized)
        return false;
    *present = length != 0;
    *recognized = false;
    if (length == 0)
        return true;

    if (!recognizableChannelSequenceHeader(value, length))
        return true; // bounded, unknown tail; the independent type 18 is used

    *recognized = true;
    const size_t bytesPerSlot = value[1] == 0 ? 1 : 2;
    const size_t expectedLength = 6 + 16 * bytesPerSlot + 2;
    if (length < expectedLength)
        return false; // a recognized header with a truncated known block
    return decodeChannelSequence(value, expectedLength, 2, channels);
}

} // namespace

static DecodeStatus decodeAdvertisement(const uint8_t *frame, size_t length,
                                        uint8_t expectedSubtype,
                                        Advertisement *output,
                                        DecodeDiagnostics *diagnostics)
{
    if (diagnostics)
        *diagnostics = DecodeDiagnostics{};
    if (!frame || !output)
        return DecodeStatus::InvalidArgument;

    NativeAwdl::ActionFrameInfo parsed{};
    if (NativeAwdl::parseActionFrame(frame, length, &parsed) !=
            NativeAwdl::ParseStatus::Ok)
        return DecodeStatus::InvalidFrame;
    if (parsed.subtype != expectedSubtype)
        return expectedSubtype == 3 ? DecodeStatus::NotMif
                                    : DecodeStatus::NotPsf;

    Advertisement result{};
    copyAddress(&result.peer, frame + kSourceAddressOffset);
    result.phyTxTimestampUs = parsed.phyTx;
    result.targetTxTimestampUs = parsed.targetTx;
    if (!isUnicastNonzero(result.peer))
        return DecodeStatus::InvalidPeerAddress;

    bool haveSync = false;
    bool haveV1 = false;
    bool haveV2 = false;
    bool haveVersion = false;
    Address syncMaster{};
    uint8_t embeddedSlots[16]{};
    uint8_t explicitSlots[16]{};
    bool haveExplicitSlots = false;
    bool embeddedSequencePresent = false;
    bool embeddedSequenceRecognized = false;
    bool embeddedSequenceVerified = false;
    Advertisement v1{};
    Advertisement v2{};
    uint8_t version = 0;
    uint8_t deviceClass = 0;
    size_t offset = kTlvStart;
    while (offset < length) {
        const size_t remaining = length - offset;
        if (remaining < 3) {
            if (allZero(frame + offset, remaining))
                break;
            return DecodeStatus::InvalidFrame;
        }
        const uint8_t type = frame[offset];
        const size_t valueLength = readLe16(frame + offset + 1);
        const size_t valueOffset = offset + 3;
        if (valueLength > length - valueOffset)
            return DecodeStatus::InvalidFrame;
        const uint8_t *value = frame + valueOffset;

        if (type == 4) {
            if (haveSync) {
                noteReject(diagnostics, MifDecodeRejectStage::kDuplicateSyncTlv,
                           type, offset, valueLength, length - valueOffset);
                return DecodeStatus::InvalidSync;
            }
            result.syncParameterLength = static_cast<uint16_t>(valueLength);
            result.syncTailLength = valueLength > kSyncEmbeddedSequenceOffset
                ? static_cast<uint16_t>(valueLength -
                                        kSyncEmbeddedSequenceOffset)
                : 0;
            result.embeddedSequencePresent = result.syncTailLength != 0;
            if (diagnostics) {
                diagnostics->syncParameterLength = result.syncParameterLength;
                diagnostics->syncTailLength = result.syncTailLength;
                diagnostics->embeddedSequencePresent =
                    result.embeddedSequencePresent;
            }
            if (valueLength < kSyncRequiredPrefixLength) {
                noteReject(diagnostics, MifDecodeRejectStage::kShortSyncPrefix,
                           type, offset, valueLength, length - valueOffset);
                return DecodeStatus::InvalidSync;
            }
            copyAddress(&syncMaster, value + 21);
            result.nextAwChannel = value[0];
            result.txDownCounterTu = readLe16(value + 1);
            result.awPeriodTu = readLe16(value + 5);
            result.actionFramePeriodTu = readLe16(value + 7);
            result.nextAwSequence = readLe16(value + 29);
            uint16_t apAlignment = 0;
            if (valueLength >= kSyncEmbeddedSequenceOffset)
                apAlignment = readLe16(value + 31);
            if (diagnostics) {
                diagnostics->nextAwChannel = result.nextAwChannel;
                diagnostics->masterChannel = value[3];
                diagnostics->txDownCounterTu = result.txDownCounterTu;
                diagnostics->awPeriodTu = result.awPeriodTu;
                diagnostics->actionFramePeriodTu = result.actionFramePeriodTu;
                diagnostics->nextAwSequence = result.nextAwSequence;
                diagnostics->apAlignment = apAlignment;
                diagnostics->presenceMode = value[27];
            }
            if (valueLength > kSyncEmbeddedSequenceOffset &&
                !decodeEmbeddedSequence(value + kSyncEmbeddedSequenceOffset,
                    valueLength - kSyncEmbeddedSequenceOffset,
                    embeddedSlots, &embeddedSequencePresent,
                    &embeddedSequenceRecognized)) {
                if (diagnostics) {
                    diagnostics->embeddedSequencePresent = 1;
                    diagnostics->embeddedSequenceRecognized = 1;
                }
                noteReject(diagnostics,
                           MifDecodeRejectStage::kEmbeddedSequenceMalformed,
                           type, offset, valueLength, length - valueOffset);
                return DecodeStatus::InvalidSync;
            }
            result.embeddedSequencePresent = embeddedSequencePresent;
            result.embeddedSequenceRecognized = embeddedSequenceRecognized;
            if (diagnostics) {
                diagnostics->embeddedSequencePresent =
                    embeddedSequencePresent;
                diagnostics->embeddedSequenceRecognized =
                    embeddedSequenceRecognized;
            }
            if (result.txDownCounterTu > 64) {
                noteReject(diagnostics,
                           MifDecodeRejectStage::kSyncCounterOutOfRange,
                           type, offset, valueLength, length - valueOffset);
                return DecodeStatus::InvalidSync;
            }
            if (result.awPeriodTu != 16) {
                noteReject(diagnostics,
                           MifDecodeRejectStage::kSyncAwPeriodInvalid,
                           type, offset, valueLength, length - valueOffset);
                return DecodeStatus::InvalidSync;
            }
            if (value[27] != 4) {
                noteReject(diagnostics,
                           MifDecodeRejectStage::kSyncPresenceModeInvalid,
                           type, offset, valueLength, length - valueOffset);
                return DecodeStatus::InvalidSync;
            }
            if (!isUnicastNonzero(syncMaster)) {
                noteReject(diagnostics,
                           MifDecodeRejectStage::kSyncMasterAddressInvalid,
                           type, offset, valueLength, length - valueOffset);
                return DecodeStatus::InvalidSync;
            }
            haveSync = true;
        } else if (type == 5) {
            if (haveV1 || valueLength != kElectionV1Length || value[0] != 0 ||
                readLe16(value + 1) != 0 || value[4] != 0 ||
                !allZero(value + 19, 2))
                return DecodeStatus::InvalidElection;
            v1.height = value[3];
            copyAddress(&v1.master, value + 5);
            v1.masterMetric = readLe32(value + 11);
            v1.ownMetric = readLe32(value + 15);
            // Version 1 has no sync address or counters; the peer follows
            // the node it advertises as its master.
            v1.sync = result.peer;
            v1.masterCounter = 0;
            v1.ownCounter = 0;
            v1.electionV2 = false;
            haveV1 = true;
        } else if (type == 24) {
            if (haveV2 || valueLength != kElectionV2Length ||
                !allZero(value + 28, 8))
                return DecodeStatus::InvalidElection;
            copyAddress(&v2.master, value);
            copyAddress(&v2.sync, value + 6);
            v2.masterCounter = readLe32(value + 12);
            v2.height = readLe32(value + 16);
            v2.masterMetric = readLe32(value + 20);
            v2.ownMetric = readLe32(value + 24);
            v2.ownCounter = readLe32(value + 36);
            v2.electionV2 = true;
            if (!isUnicastNonzero(v2.master) || !isUnicastNonzero(v2.sync))
                return DecodeStatus::InvalidElection;
            haveV2 = true;
        } else if (type == 18) {
            if (haveExplicitSlots) {
                noteReject(diagnostics,
                           MifDecodeRejectStage::kDuplicateChannelSequenceTlv,
                           type, offset, valueLength, length - valueOffset);
                return DecodeStatus::InvalidSync;
            }
            if (!decodeChannelSequence(value, valueLength, 3, explicitSlots)) {
                noteReject(diagnostics,
                           MifDecodeRejectStage::kChannelSequenceMalformed,
                           type, offset, valueLength, length - valueOffset);
                return DecodeStatus::InvalidSync;
            }
            haveExplicitSlots = true;
        } else if (type == 21) {
            if (haveVersion || valueLength != 2)
                return DecodeStatus::InvalidVersion;
            version = value[0];
            deviceClass = value[1];
            haveVersion = true;
        }
        offset = valueOffset + valueLength;
    }

    if (!haveSync || !haveExplicitSlots || (!haveV1 && !haveV2))
        return DecodeStatus::InvalidElection;
    if (embeddedSequenceRecognized) {
        for (size_t slot = 0; slot < sizeof(embeddedSlots); ++slot) {
            if (embeddedSlots[slot] == explicitSlots[slot])
                continue;
            result.embeddedSequenceMismatch = true;
            result.embeddedMismatchIndex =
                static_cast<uint8_t>(slot);
            result.embeddedMismatchChannel =
                embeddedSlots[slot];
            result.canonicalMismatchChannel =
                explicitSlots[slot];
            if (diagnostics) {
                diagnostics->embeddedSequenceMismatch = 1;
                diagnostics->embeddedMismatchIndex =
                    static_cast<uint8_t>(slot);
                diagnostics->embeddedMismatchChannel =
                    embeddedSlots[slot];
                diagnostics->canonicalMismatchChannel =
                    explicitSlots[slot];
            }
            break;
        }
        if (!result.embeddedSequenceMismatch) {
            embeddedSequenceVerified = true;
            if (diagnostics)
                diagnostics->embeddedSequenceVerified = 1;
        }
    }
    if (!haveVersion || version == 0 || deviceClass == 0)
        return DecodeStatus::InvalidVersion;

    // Type 24 is the authoritative record when present. Sync TLV and election
    // TLV must identify the same master before its timing can be considered.
    const Advertisement &chosen = haveV2 ? v2 : v1;
    if (!equalAddress(syncMaster, chosen.master))
        return DecodeStatus::MasterMismatch;
    result.master = chosen.master;
    result.sync = chosen.sync;
    memcpy(result.channelSlots, explicitSlots, sizeof(result.channelSlots));
    result.height = chosen.height;
    result.masterMetric = chosen.masterMetric;
    result.masterCounter = chosen.masterCounter;
    result.ownMetric = chosen.ownMetric;
    result.ownCounter = chosen.ownCounter;
    result.version = version;
    result.deviceClass = deviceClass;
    result.electionV2 = chosen.electionV2;
    result.syncConsistent = true;
    result.embeddedSequenceVerified = embeddedSequenceVerified;
    if (diagnostics) {
        diagnostics->syncParameterLength = result.syncParameterLength;
        diagnostics->syncTailLength = result.syncTailLength;
        diagnostics->embeddedSequencePresent =
            result.embeddedSequencePresent;
        diagnostics->embeddedSequenceRecognized =
            result.embeddedSequenceRecognized;
        diagnostics->embeddedSequenceVerified =
            result.embeddedSequenceVerified;
        diagnostics->embeddedSequenceMismatch =
            result.embeddedSequenceMismatch;
        diagnostics->embeddedMismatchIndex =
            result.embeddedMismatchIndex;
        diagnostics->embeddedMismatchChannel =
            result.embeddedMismatchChannel;
        diagnostics->canonicalMismatchChannel =
            result.canonicalMismatchChannel;
    }
    *output = result;
    return DecodeStatus::Ok;
}

DecodeStatus decodeMif(const uint8_t *frame, size_t length,
                       Advertisement *output,
                       DecodeDiagnostics *diagnostics)
{
    return decodeAdvertisement(frame, length, 3, output, diagnostics);
}

DecodeStatus decodePsf(const uint8_t *frame, size_t length,
                       Advertisement *output,
                       DecodeDiagnostics *diagnostics)
{
    return decodeAdvertisement(frame, length, 0, output, diagnostics);
}

bool selectMaster(const LocalState *local, const Advertisement *peers,
                  size_t peerCount, Ranking ranking, Selection *output)
{
    if (!local || !output || (peerCount != 0 && !peers) ||
        peerCount > kMaximumPeers || !isUnicastNonzero(local->own))
        return false;

    Selection best{};
    best.master = local->own;
    best.sync = local->own;
    best.height = 0;
    best.masterMetric = local->ownMetric;
    best.masterCounter = local->ownCounter;
    best.followsPeer = false;
    Address bestNode = local->own;

    for (size_t i = 0; i < peerCount; ++i) {
        const Advertisement &peer = peers[i];
        if (!peer.syncConsistent || !isUnicastNonzero(peer.peer) ||
            !isUnicastNonzero(peer.master) || !isUnicastNonzero(peer.sync) ||
            peer.height >= kMaximumFollowedHeight ||
            equalAddress(peer.sync, local->own))
            continue;

        const uint32_t peerMetric = peer.masterMetric;
        const uint32_t peerCounter = peer.masterCounter;
        const uint32_t bestMetric = best.masterMetric;
        const uint32_t bestCounter = best.masterCounter;
        int rank = 0;
        if (ranking == Ranking::MetricFirst) {
            rank = peerMetric < bestMetric ? -1 : peerMetric > bestMetric ? 1 :
                peerCounter < bestCounter ? -1 : peerCounter > bestCounter ? 1 : 0;
        } else {
            rank = peerCounter < bestCounter ? -1 : peerCounter > bestCounter ? 1 :
                peerMetric < bestMetric ? -1 : peerMetric > bestMetric ? 1 : 0;
        }
        if (rank < 0 || (rank == 0 && peer.height > best.height) ||
            (rank == 0 && peer.height == best.height &&
             compareAddress(peer.peer, bestNode) <= 0))
            continue;

        best.master = peer.master;
        best.sync = peer.peer;
        best.height = peer.height + 1;
        best.masterMetric = peer.masterMetric;
        best.masterCounter = peer.masterCounter;
        best.followsPeer = true;
        bestNode = peer.peer;
    }
    *output = best;
    return true;
}

} // namespace IntelAwdlElection
