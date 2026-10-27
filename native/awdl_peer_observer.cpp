// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_peer_observer.hpp"

#include <string.h>

namespace IntelAwdlPeer {
namespace {

constexpr size_t kMacHeaderLength = 24;
constexpr size_t kHtControlLength = 4;
constexpr size_t kAwdlActionHeaderLength = 16;
constexpr size_t kSyncParamsMinimumLength = 31;
constexpr size_t kSourceAddressOffset = 10;

uint16_t readLe16(const uint8_t *p)
{
    return static_cast<uint16_t>(p[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(p[1]) << 8);
}

bool allZero(const uint8_t *p, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        if (p[i] != 0)
            return false;
    }
    return true;
}

bool sameEpochs(const RuntimeEpochs &a, const RuntimeEpochs &b)
{
    return a.contextGeneration == b.contextGeneration &&
           a.powerGeneration == b.powerGeneration &&
           a.stationGeneration == b.stationGeneration &&
           a.active == b.active;
}

bool recordMatchesEpochs(const IntelP2PRx::ActionFrameRecord &record,
                         const RuntimeEpochs &current)
{
    return record.generation == current.contextGeneration &&
           record.powerGeneration == current.powerGeneration &&
           record.stationGeneration == current.stationGeneration;
}

bool validSourceAddress(const uint8_t *address)
{
    // Addr2 in a management MPDU is the transmitter identity. Accept locally
    // administered unicast addresses, but not multicast or all-zero values.
    if (address[0] & 0x01)
        return false;
    return !allZero(address, 6);
}

bool sameAddress(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

bool sameParsedInfo(const NativeAwdl::ActionFrameInfo &a,
                    const NativeAwdl::ActionFrameInfo &b)
{
    return a.frameControl == b.frameControl && a.phyTx == b.phyTx &&
           a.targetTx == b.targetTx && a.subtype == b.subtype &&
           a.version == b.version && a.tlvCount == b.tlvCount;
}

} // namespace

Observer::Observer()
    : current_{}, haveCurrent_(false), candidateFramesTotal_(0),
      psfFramesTotal_(0), mifFramesTotal_(0), admittedFramesTotal_(0),
      updatedFramesTotal_(0), lastAdmittedContextGeneration_(0),
      activeWindowPeakValidPeerCount_(0),
      activeWindowPeakContextGeneration_(0)
{
    clearSlots();
}

void Observer::clearSlots()
{
    memset(peers_, 0, sizeof(peers_));
}

void Observer::reset()
{
    clearSlots();
    current_ = RuntimeEpochs{};
    haveCurrent_ = false;
    candidateFramesTotal_ = 0;
    psfFramesTotal_ = 0;
    mifFramesTotal_ = 0;
    admittedFramesTotal_ = 0;
    updatedFramesTotal_ = 0;
    lastAdmittedContextGeneration_ = 0;
    activeWindowPeakValidPeerCount_ = 0;
    activeWindowPeakContextGeneration_ = 0;
}

void Observer::synchronizeEpochs(const RuntimeEpochs &current)
{
    if (!haveCurrent_ || !sameEpochs(current_, current)) {
        const bool enteringActiveWindow = current.active &&
            (!haveCurrent_ || !current_.active ||
             current_.contextGeneration != current.contextGeneration ||
             current_.powerGeneration != current.powerGeneration ||
             current_.stationGeneration != current.stationGeneration);
        clearSlots();
        if (enteringActiveWindow) {
            activeWindowPeakValidPeerCount_ = 0;
            activeWindowPeakContextGeneration_ = current.contextGeneration;
        }
        current_ = current;
        haveCurrent_ = true;
    }
    if (!current.active)
        clearSlots();
}

void Observer::expire(uint64_t nowMonotonicUs)
{
    for (size_t i = 0; i < kPeerCapacity; ++i) {
        PeerSlot &peer = peers_[i];
        if (!peer.used)
            continue;
        if (nowMonotonicUs < peer.lastSeenUs ||
            nowMonotonicUs - peer.lastSeenUs > kPeerTtlUs)
            memset(&peer, 0, sizeof(peer));
    }
}

bool Observer::extractEvidence(
    const IntelP2PRx::ActionFrameRecord &record, uint8_t *sourceAddress,
    SyncEvidence *sync, uint8_t *version, uint8_t *deviceClass)
{
    if (!sourceAddress || !sync || !version || !deviceClass ||
        record.length > IntelP2PRx::kMaxActionFrameBytes)
        return false;

    NativeAwdl::ActionFrameInfo parsed{};
    if (NativeAwdl::parseActionFrame(record.bytes, record.length, &parsed) !=
            NativeAwdl::ParseStatus::Ok ||
        !sameParsedInfo(parsed, record.awdl))
        return false;

    const uint16_t frameControl = parsed.frameControl;
    const size_t macHeaderLength = kMacHeaderLength +
        ((frameControl & 0x8000) ? kHtControlLength : 0);
    if (record.length < macHeaderLength + kAwdlActionHeaderLength)
        return false;

    memcpy(sourceAddress, record.bytes + kSourceAddressOffset, 6);

    bool haveSync = false;
    bool haveVersion = false;
    size_t offset = macHeaderLength + kAwdlActionHeaderLength;
    while (offset < record.length) {
        const size_t remaining = record.length - offset;
        if (remaining < 3) {
            return allZero(record.bytes + offset, remaining) &&
                   haveSync && haveVersion;
        }

        const uint8_t type = record.bytes[offset];
        const size_t valueLength = readLe16(record.bytes + offset + 1);
        const size_t valueOffset = offset + 3;
        if (valueLength > record.length - valueOffset)
            return false;
        const uint8_t *value = record.bytes + valueOffset;

        if (type == 4) {
            if (haveSync || valueLength < kSyncParamsMinimumLength)
                return false;
            sync->nextAwChannel = value[0];
            sync->nextSlotTu = readLe16(value + 1);
            sync->masterChannel = value[3];
            sync->awPeriodTu = readLe16(value + 5);
            sync->actionFramePeriodTu = readLe16(value + 7);
            sync->presenceMode = value[27];
            sync->nextAwSequence = readLe16(value + 29);

            // These are the fixed schedule values described by the pinned
            // AWDL field reference. This is a field sanity bit, not proof of
            // clock alignment or interoperable AWDL timing.
            sync->valid = sync->nextSlotTu <= 64 &&
                          sync->awPeriodTu == 16 &&
                          sync->presenceMode == 4;
            haveSync = true;
        } else if (type == 21) {
            if (haveVersion || valueLength != 2)
                return false;
            *version = value[0];
            *deviceClass = value[1];
            haveVersion = true;
        }

        offset = valueOffset + valueLength;
    }

    return haveSync && haveVersion;
}

bool Observer::isValidPeer(const PeerSlot &peer)
{
    // Owly's peer model considers a peer valid after a MIF and nonzero
    // version/device-class fields; no peer identity is exposed by this model.
    return peer.sawMif && peer.version != 0 && peer.deviceClass != 0;
}

ObserveResult Observer::observe(const IntelP2PRx::ActionFrameRecord &record,
                               const RuntimeEpochs &current,
                               uint64_t nowMonotonicUs)
{
    synchronizeEpochs(current);
    if (!current.active)
        return ObserveResult::kInactive;
    if (nowMonotonicUs == 0)
        return ObserveResult::kInvalidTimestamp;
    expire(nowMonotonicUs);
    if (!recordMatchesEpochs(record, current))
        return ObserveResult::kStaleGeneration;
    if (record.rxMonotonicUs == 0 || record.rxMonotonicUs > nowMonotonicUs)
        return ObserveResult::kInvalidTimestamp;
    if (nowMonotonicUs - record.rxMonotonicUs > kPeerTtlUs)
        return ObserveResult::kExpiredFrame;

    uint8_t sourceAddress[6]{};
    uint8_t version = 0;
    uint8_t deviceClass = 0;
    SyncEvidence sync{};
    if (!extractEvidence(record, sourceAddress, &sync, &version, &deviceClass))
        return ObserveResult::kInvalidFrame;
    if (!validSourceAddress(sourceAddress))
        return ObserveResult::kInvalidSourceAddress;

    if (record.awdl.subtype == 0)
        ++psfFramesTotal_;
    else if (record.awdl.subtype == 3)
        ++mifFramesTotal_;

    PeerSlot *slot = nullptr;
    PeerSlot *oldest = nullptr;
    bool existed = false;
    for (size_t i = 0; i < kPeerCapacity; ++i) {
        PeerSlot &candidate = peers_[i];
        if (candidate.used && sameAddress(candidate.sourceAddress, sourceAddress)) {
            slot = &candidate;
            existed = true;
            break;
        }
        if (!candidate.used && !slot)
            slot = &candidate;
        if (candidate.used && (!oldest || candidate.lastSeenUs < oldest->lastSeenUs))
            oldest = &candidate;
    }
    if (!slot)
        slot = oldest;
    if (!slot) {
        ++candidateFramesTotal_;
        return ObserveResult::kCandidateOnly;
    }

    if (existed && record.rxMonotonicUs < slot->lastSeenUs)
        return ObserveResult::kOutOfOrderFrame;

    const bool wasValid = existed && isValidPeer(*slot);
    if (!existed) {
        memset(slot, 0, sizeof(*slot));
        slot->used = true;
        memcpy(slot->sourceAddress, sourceAddress, sizeof(slot->sourceAddress));
    }

    slot->lastSeenUs = record.rxMonotonicUs;
    slot->rxChannelIndex = record.channel;
    slot->version = version;
    slot->deviceClass = deviceClass;
    slot->sync = sync;
    if (record.awdl.subtype == 3)
        slot->sawMif = true;

    if (!isValidPeer(*slot)) {
        ++candidateFramesTotal_;
        return ObserveResult::kCandidateOnly;
    }

    uint32_t validPeerCount = 0;
    for (size_t i = 0; i < kPeerCapacity; ++i) {
        if (peers_[i].used && isValidPeer(peers_[i]))
            ++validPeerCount;
    }
    if (validPeerCount > activeWindowPeakValidPeerCount_) {
        activeWindowPeakValidPeerCount_ = validPeerCount;
        activeWindowPeakContextGeneration_ = current.contextGeneration;
    }

    if (wasValid) {
        ++updatedFramesTotal_;
        return ObserveResult::kUpdatedPeer;
    }
    ++admittedFramesTotal_;
    lastAdmittedContextGeneration_ = current.contextGeneration;
    return ObserveResult::kAdmittedPeer;
}

Snapshot Observer::snapshot(const RuntimeEpochs &current,
                            uint64_t nowMonotonicUs)
{
    Snapshot out{};
    synchronizeEpochs(current);
    out.candidateFramesTotal = candidateFramesTotal_;
    out.psfFramesTotal = psfFramesTotal_;
    out.mifFramesTotal = mifFramesTotal_;
    out.admittedFramesTotal = admittedFramesTotal_;
    out.updatedFramesTotal = updatedFramesTotal_;
    out.lastAdmittedContextGeneration = lastAdmittedContextGeneration_;
    out.activeWindowPeakValidPeerCount = activeWindowPeakValidPeerCount_;
    out.activeWindowPeakContextGeneration = activeWindowPeakContextGeneration_;
    if (!current.active || nowMonotonicUs == 0)
        return out;

    expire(nowMonotonicUs);
    const PeerSlot *latest = nullptr;
    for (size_t i = 0; i < kPeerCapacity; ++i) {
        const PeerSlot &peer = peers_[i];
        if (!peer.used || !isValidPeer(peer))
            continue;
        ++out.validPeerCount;
        if (!latest || peer.lastSeenUs > latest->lastSeenUs)
            latest = &peer;
    }
    if (out.validPeerCount > activeWindowPeakValidPeerCount_) {
        activeWindowPeakValidPeerCount_ = out.validPeerCount;
        activeWindowPeakContextGeneration_ = current.contextGeneration;
        out.activeWindowPeakValidPeerCount = activeWindowPeakValidPeerCount_;
        out.activeWindowPeakContextGeneration = activeWindowPeakContextGeneration_;
    }
    if (!latest)
        return out;

    out.hasLatestPeer = true;
    out.syncFieldsValid = latest->sync.valid;
    out.rxChannelIndex = latest->rxChannelIndex;
    out.nextAwChannel = latest->sync.nextAwChannel;
    out.masterChannel = latest->sync.masterChannel;
    out.nextSlotTu = latest->sync.nextSlotTu;
    out.awPeriodTu = latest->sync.awPeriodTu;
    out.actionFramePeriodTu = latest->sync.actionFramePeriodTu;
    out.presenceMode = latest->sync.presenceMode;
    out.nextAwSequence = latest->sync.nextAwSequence;
    out.latestPeerAgeUs = nowMonotonicUs - latest->lastSeenUs;
    return out;
}

} // namespace IntelAwdlPeer
