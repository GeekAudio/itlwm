// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_peer_runtime_table.hpp"

#include <string.h>

namespace IntelAwdlPeerRuntime {
namespace {

bool sameEpochs(const IntelAwdlPeer::RuntimeEpochs &a,
                const IntelAwdlPeer::RuntimeEpochs &b)
{
    return a.contextGeneration == b.contextGeneration &&
           a.powerGeneration == b.powerGeneration &&
           a.stationGeneration == b.stationGeneration && a.active == b.active;
}

bool sameAddress(const IntelAwdlElection::Address &a,
                 const IntelAwdlElection::Address &b)
{
    return memcmp(a.bytes, b.bytes, sizeof(a.bytes)) == 0;
}

bool sameParsedInfo(const NativeAwdl::ActionFrameInfo &a,
                    const NativeAwdl::ActionFrameInfo &b)
{
    return a.frameControl == b.frameControl && a.phyTx == b.phyTx &&
           a.targetTx == b.targetTx && a.subtype == b.subtype &&
           a.version == b.version && a.tlvCount == b.tlvCount;
}

void increment(uint32_t *counter)
{
    if (counter && *counter != UINT32_MAX)
        ++*counter;
}

} // namespace

Table::Table()
    : current_{}, lastNowUs_(0), lastAdmittedContextGeneration_(0),
      admittedTotal_(0), updatedTotal_(0), candidateFrameTotal_(0),
      mifFrameTotal_(0), acceptedPsfTotal_(0), rejectedTotal_(0),
      rejectedMifTotal_(0), rejectedPsfTotal_(0),
      lastRejectedContext_(0),
      lastRejectedResult_(static_cast<uint8_t>(Result::kNone)),
      lastMifDecodeStatus_(0xff), lastMifRejectDiagnostics_{},
      lastPsfDecodeStatus_(0xff), lastPsfRejectDiagnostics_{},
      haveCurrent_(false)
{
    clearEntries();
}

void Table::clearEntries()
{
    memset(entries_, 0, sizeof(entries_));
}

void Table::reset()
{
    clearEntries();
    current_ = IntelAwdlPeer::RuntimeEpochs{};
    lastNowUs_ = 0;
    lastAdmittedContextGeneration_ = 0;
    admittedTotal_ = 0;
    updatedTotal_ = 0;
    candidateFrameTotal_ = 0;
    mifFrameTotal_ = 0;
    acceptedPsfTotal_ = 0;
    rejectedTotal_ = 0;
    rejectedMifTotal_ = 0;
    rejectedPsfTotal_ = 0;
    lastRejectedContext_ = 0;
    lastRejectedResult_ = static_cast<uint8_t>(Result::kNone);
    lastMifDecodeStatus_ = 0xff;
    lastMifRejectDiagnostics_ = IntelAwdlElection::DecodeDiagnostics{};
    lastPsfDecodeStatus_ = 0xff;
    lastPsfRejectDiagnostics_ = IntelAwdlElection::DecodeDiagnostics{};
    haveCurrent_ = false;
}

void Table::synchronizeEpochs(const IntelAwdlPeer::RuntimeEpochs &current)
{
    if (!haveCurrent_ || !sameEpochs(current_, current)) {
        clearEntries();
        lastNowUs_ = 0;
        current_ = current;
        haveCurrent_ = true;
    }
    if (!current.active)
        clearEntries();
}

void Table::expire(uint64_t nowMonotonicUs)
{
    for (size_t i = 0; i < kPeerCapacity; ++i) {
        Entry &entry = entries_[i];
        if (!entry.used)
            continue;
        if (nowMonotonicUs < entry.lastFrameUs ||
            nowMonotonicUs - entry.lastFrameUs > kCandidateTtlUs)
            memset(&entry, 0, sizeof(entry));
    }
}

void Table::noteRejected(Result result, uint64_t contextGeneration,
                         bool rejectedMif, bool rejectedPsf)
{
    increment(&rejectedTotal_);
    if (rejectedMif)
        increment(&rejectedMifTotal_);
    if (rejectedPsf)
        increment(&rejectedPsfTotal_);
    lastRejectedResult_ = static_cast<uint8_t>(result);
    lastRejectedContext_ = contextGeneration;
}

bool Table::validAddress(const IntelAwdlElection::Address &address)
{
    uint8_t any = 0;
    for (uint8_t byte : address.bytes)
        any |= byte;
    return any != 0 && (address.bytes[0] & 1) == 0;
}

bool Table::recordMatchesEpochs(
    const IntelP2PRx::ActionFrameRecord &record,
    const IntelAwdlPeer::RuntimeEpochs &current)
{
    return record.generation == current.contextGeneration &&
           record.powerGeneration == current.powerGeneration &&
           record.stationGeneration == current.stationGeneration;
}

Result Table::observe(const IntelP2PRx::ActionFrameRecord &record,
                      const IntelAwdlPeer::RuntimeEpochs &current,
                      uint64_t nowMonotonicUs)
{
    const bool recordMif = record.awdl.subtype == 3;
    const bool recordPsf = record.awdl.subtype == 0;
    synchronizeEpochs(current);
    if (!current.active)
        return Result::kInactive;
    if (nowMonotonicUs == 0) {
        noteRejected(Result::kInvalidTimestamp, current.contextGeneration,
                     recordMif, recordPsf);
        return Result::kInvalidTimestamp;
    }
    if (lastNowUs_ != 0 && nowMonotonicUs < lastNowUs_) {
        clearEntries();
        lastNowUs_ = nowMonotonicUs;
        noteRejected(Result::kClockRegression, current.contextGeneration,
                     recordMif, recordPsf);
        return Result::kClockRegression;
    }
    lastNowUs_ = nowMonotonicUs;
    expire(nowMonotonicUs);

    if (!recordMatchesEpochs(record, current)) {
        noteRejected(Result::kStaleGeneration, current.contextGeneration,
                     recordMif, recordPsf);
        return Result::kStaleGeneration;
    }
    // Use the RX tap's event time for age/order. `nowMonotonicUs` is only a
    // freshness bound and never substitutes for the event timestamp.
    if (record.rxMonotonicUs == 0 ||
        record.rxMonotonicUs > nowMonotonicUs) {
        noteRejected(Result::kInvalidTimestamp, current.contextGeneration,
                     recordMif, recordPsf);
        return Result::kInvalidTimestamp;
    }
    if (nowMonotonicUs - record.rxMonotonicUs > kCandidateTtlUs) {
        noteRejected(Result::kExpiredFrame, current.contextGeneration,
                     recordMif, recordPsf);
        return Result::kExpiredFrame;
    }
    if (record.length > IntelP2PRx::kMaxActionFrameBytes) {
        noteRejected(Result::kInvalidFrame, current.contextGeneration,
                     recordMif, recordPsf);
        return Result::kInvalidFrame;
    }

    NativeAwdl::ActionFrameInfo parsed{};
    if ((record.awdl.subtype != 0 && record.awdl.subtype != 3) ||
        NativeAwdl::parseActionFrame(record.bytes, record.length, &parsed) !=
            NativeAwdl::ParseStatus::Ok ||
        !sameParsedInfo(parsed, record.awdl) ||
        parsed.subtype != record.awdl.subtype) {
        noteRejected(Result::kInvalidFrame, current.contextGeneration,
                     recordMif, recordPsf);
        return Result::kInvalidFrame;
    }

    IntelAwdlElection::Address source{};
    memcpy(source.bytes, record.bytes + 10, sizeof(source.bytes));
    if (!validAddress(source)) {
        noteRejected(Result::kInvalidSourceAddress, current.contextGeneration,
                     parsed.subtype == 3, parsed.subtype == 0);
        return Result::kInvalidSourceAddress;
    }
    const bool isMif = parsed.subtype == 3;
    const bool isPsf = parsed.subtype == 0;
    IntelAwdlElection::Advertisement advertisement{};
    if (isMif) {
        IntelAwdlElection::DecodeDiagnostics decodeDiagnostics{};
        const auto decode = IntelAwdlElection::decodeMif(
            record.bytes, record.length, &advertisement, &decodeDiagnostics);
        lastMifDecodeStatus_ = static_cast<uint8_t>(decode);
        lastMifRejectDiagnostics_ = decodeDiagnostics;
        if (decode != IntelAwdlElection::DecodeStatus::Ok ||
            !sameAddress(advertisement.peer, source) ||
            !advertisement.syncConsistent) {
            noteRejected(Result::kInvalidMif, current.contextGeneration,
                         true, false);
            return Result::kInvalidMif;
        }
    } else if (isPsf) {
        IntelAwdlElection::DecodeDiagnostics decodeDiagnostics{};
        const auto decode = IntelAwdlElection::decodePsf(
            record.bytes, record.length, &advertisement, &decodeDiagnostics);
        lastPsfDecodeStatus_ = static_cast<uint8_t>(decode);
        lastPsfRejectDiagnostics_ = decodeDiagnostics;
        if (decode != IntelAwdlElection::DecodeStatus::Ok ||
            !sameAddress(advertisement.peer, source) ||
            !advertisement.syncConsistent) {
            noteRejected(Result::kInvalidPsf, current.contextGeneration,
                         false, true);
            return Result::kInvalidPsf;
        }
    }

    Entry *slot = nullptr;
    Entry *oldest = nullptr;
    bool existed = false;
    for (size_t i = 0; i < kPeerCapacity; ++i) {
        Entry &candidate = entries_[i];
        if (candidate.used && memcmp(candidate.sourceAddress, source.bytes,
                                     sizeof(candidate.sourceAddress)) == 0) {
            slot = &candidate;
            existed = true;
            break;
        }
        if (!candidate.used && !slot)
            slot = &candidate;
        if (candidate.used &&
            (!oldest || candidate.lastFrameUs < oldest->lastFrameUs))
            oldest = &candidate;
    }
    if (!slot)
        slot = oldest;
    if (!slot) {
        noteRejected(Result::kInvalidFrame, current.contextGeneration,
                     isMif, isPsf);
        return Result::kInvalidFrame;
    }
    const bool hadMif = existed && slot->hasMif;
    if (existed && record.rxMonotonicUs < slot->lastFrameUs) {
        noteRejected(Result::kOutOfOrderFrame, current.contextGeneration,
                     isMif, isPsf);
        return Result::kOutOfOrderFrame;
    }

    Entry next = existed ? *slot : Entry{};
    if (!existed) {
        memcpy(next.sourceAddress, source.bytes, sizeof(next.sourceAddress));
        next.contextGeneration = current.contextGeneration;
        next.powerGeneration = current.powerGeneration;
        next.stationGeneration = current.stationGeneration;
        next.used = true;
    }
    next.lastFrameUs = record.rxMonotonicUs;
    if (isMif) {
        next.mifAdvertisement = advertisement;
        next.lastMifUs = record.rxMonotonicUs;
        next.mifRxGp2TimestampUs = record.rxGp2TimestampPresent
            ? record.rxGp2TimestampUs : 0;
        next.mifRxGp2TimestampPresent = record.rxGp2TimestampPresent;
        next.rxChannel = record.channel;
        next.hasMif = true;
        increment(&mifFrameTotal_);
    } else if (isPsf) {
        next.psfAdvertisement = advertisement;
        next.lastPsfUs = record.rxMonotonicUs;
        next.psfRxGp2TimestampUs = record.rxGp2TimestampPresent
            ? record.rxGp2TimestampUs : 0;
        next.psfRxGp2TimestampPresent = record.rxGp2TimestampPresent;
        next.psfRxChannel = record.channel;
        next.hasPsf = true;
        increment(&candidateFrameTotal_);
        increment(&acceptedPsfTotal_);
    }

    // The last three validated observations remain source-tagged. A duplicate
    // tap timestamp does not fabricate another relative-clock sample.
    if (next.timingCount == 0 ||
        record.rxMonotonicUs >
            next.timing[(next.timingNext + kTimingSampleCapacity - 1) %
                        kTimingSampleCapacity].rxMonotonicUs) {
        TimingSample &sample = next.timing[next.timingNext];
        sample.rxMonotonicUs = record.rxMonotonicUs;
        sample.rxGp2TimestampUs = record.rxGp2TimestampPresent
            ? record.rxGp2TimestampUs : 0;
        sample.peerPhyTxTimestampUs = parsed.phyTx;
        sample.subtype = parsed.subtype;
        sample.rxGp2TimestampPresent = record.rxGp2TimestampPresent;
        next.timingNext = static_cast<uint8_t>(
            (next.timingNext + 1) % kTimingSampleCapacity);
        if (next.timingCount < kTimingSampleCapacity)
            ++next.timingCount;
    }
    *slot = next;

    if (isPsf)
        return Result::kCandidate;
    if (hadMif) {
        increment(&updatedTotal_);
        return Result::kUpdated;
    }
    increment(&admittedTotal_);
    lastAdmittedContextGeneration_ = current.contextGeneration;
    return Result::kAdmitted;
}


Snapshot Table::snapshot(const IntelAwdlPeer::RuntimeEpochs &current,
                         uint64_t nowMonotonicUs)
{
    Snapshot out{};
    out.latestFreshMifSlot = 0xff;
    out.latestFreshPsfSlot = 0xff;
    synchronizeEpochs(current);
    out.admittedTotal = admittedTotal_;
    out.updatedTotal = updatedTotal_;
    out.candidateFrameTotal = candidateFrameTotal_;
    out.mifFrameTotal = mifFrameTotal_;
    out.acceptedPsfTotal = acceptedPsfTotal_;
    out.rejectedTotal = rejectedTotal_;
    out.rejectedMifTotal = rejectedMifTotal_;
    out.rejectedPsfTotal = rejectedPsfTotal_;
    out.lastAdmittedContextGeneration = lastAdmittedContextGeneration_;
    out.lastRejectedContext = lastRejectedContext_;
    out.lastRejectedResult = lastRejectedResult_;
    out.lastMifDecodeStatus = lastMifDecodeStatus_;
    out.lastMifRejectDiagnostics = lastMifRejectDiagnostics_;
    out.lastPsfDecodeStatus = lastPsfDecodeStatus_;
    out.lastPsfRejectDiagnostics = lastPsfRejectDiagnostics_;
    if (!current.active || nowMonotonicUs == 0)
        return out;
    if (lastNowUs_ != 0 && nowMonotonicUs < lastNowUs_) {
        clearEntries();
        lastNowUs_ = nowMonotonicUs;
        return out;
    }
    lastNowUs_ = nowMonotonicUs;
    expire(nowMonotonicUs);

    uint64_t newestMifUs = 0;
    uint64_t newestPsfUs = 0;
    for (size_t i = 0; i < kPeerCapacity; ++i) {
        const Entry &entry = entries_[i];
        if (!entry.used ||
            entry.contextGeneration != current.contextGeneration ||
            entry.powerGeneration != current.powerGeneration ||
            entry.stationGeneration != current.stationGeneration)
            continue;

        PeerSnapshot &peer = out.peers[i];
        peer.tracked = true;
        peer.contextGeneration = entry.contextGeneration;
        peer.powerGeneration = entry.powerGeneration;
        peer.stationGeneration = entry.stationGeneration;
        peer.frameAgeUs = nowMonotonicUs - entry.lastFrameUs;
        peer.hasMif = entry.hasMif;
        peer.timingSampleCount = entry.timingCount;

        for (size_t sampleIndex = 0; sampleIndex < entry.timingCount;
             ++sampleIndex) {
            const size_t oldest = entry.timingCount < kTimingSampleCapacity
                ? 0 : entry.timingNext;
            const size_t ringIndex = (oldest + sampleIndex) %
                                     kTimingSampleCapacity;
            peer.timingSamples[sampleIndex] = entry.timing[ringIndex];
        }
        ++out.trackedPeerCount;

        if (entry.hasPsf) {
            const uint64_t psfAgeUs = nowMonotonicUs - entry.lastPsfUs;
            const bool psfFresh = psfAgeUs <= kPsfLeaseTtlUs &&
                entry.psfAdvertisement.syncConsistent;
            if (psfFresh) {
                ++out.freshPsfPeerCount;
                if (entry.lastPsfUs > newestPsfUs) {
                    newestPsfUs = entry.lastPsfUs;
                    out.latestFreshPsfSlot = static_cast<uint8_t>(i);
                }
            }
        }

        if (entry.hasMif) {
            peer.mifAgeUs = nowMonotonicUs - entry.lastMifUs;
            peer.mifRxMonotonicUs = entry.lastMifUs;
            peer.mifRxGp2TimestampUs = entry.mifRxGp2TimestampUs;
            peer.mifRxGp2TimestampPresent = entry.mifRxGp2TimestampPresent;
            peer.mifFresh = peer.mifAgeUs <= kMifLeaseTtlUs &&
                            entry.mifAdvertisement.syncConsistent;
            peer.syncConsistent = entry.mifAdvertisement.syncConsistent;
            peer.rxChannel = entry.rxChannel;

            const auto &ad = entry.mifAdvertisement;
            peer.phyTxTimestampUs = ad.phyTxTimestampUs;
            peer.targetTxTimestampUs = ad.targetTxTimestampUs;
            peer.masterMetric = ad.masterMetric;
            peer.masterCounter = ad.masterCounter;
            peer.ownMetric = ad.ownMetric;
            peer.ownCounter = ad.ownCounter;
            peer.height = ad.height;
            peer.txDownCounterTu = ad.txDownCounterTu;
            peer.awPeriodTu = ad.awPeriodTu;
            peer.actionFramePeriodTu = ad.actionFramePeriodTu;
            peer.nextAwSequence = ad.nextAwSequence;
            peer.syncParameterLength = ad.syncParameterLength;
            peer.syncTailLength = ad.syncTailLength;
            peer.nextAwChannel = ad.nextAwChannel;
            peer.embeddedSequencePresent = ad.embeddedSequencePresent;
            peer.embeddedSequenceRecognized = ad.embeddedSequenceRecognized;
            peer.embeddedSequenceVerified = ad.embeddedSequenceVerified;
            peer.embeddedSequenceMismatch = ad.embeddedSequenceMismatch;
            peer.embeddedMismatchIndex =
                ad.embeddedMismatchIndex;
            peer.embeddedMismatchChannel =
                ad.embeddedMismatchChannel;
            peer.canonicalMismatchChannel =
                ad.canonicalMismatchChannel;
            memcpy(peer.channelSlots, ad.channelSlots,
                   sizeof(peer.channelSlots));
            peer.version = ad.version;
            peer.deviceClass = ad.deviceClass;
            peer.electionV2 = ad.electionV2;

            if (peer.mifFresh) {
                ++out.freshMifPeerCount;
                if (entry.lastMifUs > newestMifUs) {
                    newestMifUs = entry.lastMifUs;
                    out.latestFreshMifSlot = static_cast<uint8_t>(i);
                }
            }
        }
    }
    return out;
}

bool Table::getPsfSnapshot(
    uint8_t slot, const IntelAwdlPeer::RuntimeEpochs &current,
    uint64_t nowMonotonicUs, PsfPeerSnapshot *output)
{
    if (!output)
        return false;
    *output = PsfPeerSnapshot{};
    synchronizeEpochs(current);
    if (!current.active || nowMonotonicUs == 0)
        return false;
    if (lastNowUs_ != 0 && nowMonotonicUs < lastNowUs_) {
        clearEntries();
        lastNowUs_ = nowMonotonicUs;
        return false;
    }
    lastNowUs_ = nowMonotonicUs;
    expire(nowMonotonicUs);
    if (slot >= kPeerCapacity)
        return false;

    const Entry &entry = entries_[slot];
    if (!entry.used ||
        entry.contextGeneration != current.contextGeneration ||
        entry.powerGeneration != current.powerGeneration ||
        entry.stationGeneration != current.stationGeneration ||
        !entry.hasPsf)
        return false;

    output->tracked = true;
    output->hasPsf = entry.hasPsf;
    output->contextGeneration = entry.contextGeneration;
    output->powerGeneration = entry.powerGeneration;
    output->stationGeneration = entry.stationGeneration;
    output->psfAgeUs = nowMonotonicUs - entry.lastPsfUs;
    output->psfRxMonotonicUs = entry.lastPsfUs;
    output->psfRxGp2TimestampUs = entry.psfRxGp2TimestampUs;
    output->psfRxGp2TimestampPresent = entry.psfRxGp2TimestampPresent;
    output->rxChannel = entry.psfRxChannel;
    output->psfFresh = output->psfAgeUs <= kPsfLeaseTtlUs &&
                       entry.psfAdvertisement.syncConsistent;

    const auto &ad = entry.psfAdvertisement;
    output->phyTxTimestampUs = ad.phyTxTimestampUs;
    output->targetTxTimestampUs = ad.targetTxTimestampUs;
    output->height = ad.height;
    output->masterMetric = ad.masterMetric;
    output->masterCounter = ad.masterCounter;
    output->ownMetric = ad.ownMetric;
    output->ownCounter = ad.ownCounter;
    output->nextAwChannel = ad.nextAwChannel;
    output->txDownCounterTu = ad.txDownCounterTu;
    output->awPeriodTu = ad.awPeriodTu;
    output->actionFramePeriodTu = ad.actionFramePeriodTu;
    output->nextAwSequence = ad.nextAwSequence;
    output->syncParameterLength = ad.syncParameterLength;
    output->syncTailLength = ad.syncTailLength;
    output->embeddedSequencePresent = ad.embeddedSequencePresent;
    output->embeddedSequenceRecognized = ad.embeddedSequenceRecognized;
    output->embeddedSequenceVerified = ad.embeddedSequenceVerified;
    output->embeddedSequenceMismatch = ad.embeddedSequenceMismatch;
    output->embeddedMismatchIndex =
        ad.embeddedMismatchIndex;
    output->embeddedMismatchChannel =
        ad.embeddedMismatchChannel;
    output->canonicalMismatchChannel =
        ad.canonicalMismatchChannel;
    memcpy(output->channelSlots, ad.channelSlots, sizeof(output->channelSlots));
    output->version = ad.version;
    output->deviceClass = ad.deviceClass;
    output->syncConsistent = ad.syncConsistent;
    output->electionV2 = ad.electionV2;
    return true;
}

bool Table::selectMaster(const IntelAwdlPeer::RuntimeEpochs &current,
                         uint64_t nowMonotonicUs,
                         const IntelAwdlElection::LocalState &local,
                         IntelAwdlElection::Ranking ranking,
                         SelectionSummary *output)
{
    if (!output)
        return false;
    *output = SelectionSummary{};
    output->selectedSlot = 0xff;
    synchronizeEpochs(current);
    if (!current.active || nowMonotonicUs == 0 ||
        (lastNowUs_ != 0 && nowMonotonicUs < lastNowUs_)) {
        clearEntries();
        lastNowUs_ = nowMonotonicUs;
        return false;
    }
    lastNowUs_ = nowMonotonicUs;
    expire(nowMonotonicUs);

    IntelAwdlElection::Advertisement candidates[kPeerCapacity]{};
    uint8_t candidateSlots[kPeerCapacity]{};
    size_t count = 0;
    for (size_t i = 0; i < kPeerCapacity; ++i) {
        const Entry &entry = entries_[i];
        if (!entry.used || !entry.hasMif ||
            nowMonotonicUs < entry.lastMifUs ||
            nowMonotonicUs - entry.lastMifUs > kMifLeaseTtlUs ||
            !entry.mifAdvertisement.syncConsistent ||
            entry.contextGeneration != current.contextGeneration ||
            entry.powerGeneration != current.powerGeneration ||
            entry.stationGeneration != current.stationGeneration)
            continue;
        candidates[count] = entry.mifAdvertisement;
        candidateSlots[count] = static_cast<uint8_t>(i);
        ++count;
    }

    IntelAwdlElection::Selection selected{};
    if (!IntelAwdlElection::selectMaster(&local, candidates, count, ranking,
                                         &selected))
        return false;
    output->height = selected.height;
    output->masterMetric = selected.masterMetric;
    output->masterCounter = selected.masterCounter;
    output->followsPeer = selected.followsPeer;
    if (selected.followsPeer) {
        for (size_t i = 0; i < count; ++i) {
            if (sameAddress(candidates[i].peer, selected.sync)) {
                output->selectedSlot = candidateSlots[i];
                return true;
            }
        }
        *output = SelectionSummary{};
        output->selectedSlot = 0xff;
        return false;
    }
    return true;
}

} // namespace IntelAwdlPeerRuntime
