// SPDX-License-Identifier: GPL-2.0-only
#include "p2p_tx_resources.hpp"

#include <string.h>

namespace IntelP2PTx {
namespace {

constexpr uint16_t kP2pDeviceStaticQueue = 2;
constexpr uint8_t kManagementFrameType = 0;
constexpr uint8_t kActionFrameSubtype = 0xD0;
constexpr size_t kManagementHeaderLength = 24;
constexpr size_t kManagementHeaderWithHtControlLength = 28;
constexpr uint8_t kMaxManagementTid = 8;

bool validMac(const uint8_t *address, bool permitGroup)
{
    uint8_t any = 0;
    for (size_t i = 0; i < 6; ++i)
        any |= address[i];
    return any != 0 && (permitGroup || (address[0] & 1U) == 0);
}

} // namespace

StationRegistry::StationRegistry() : count_(0), generation_(0)
{
    for (Owner &owner : owners_)
        owner = Owner::kFree;
}

Result StationRegistry::initialize(uint8_t count,
                                   uint32_t generation,
                                   bool staInstalled, bool auxInstalled,
                                   bool monitorInstalled)
{
    // Initial role discovery must happen exactly once. Replacing a live
    // bitmap here could free an ID after an ambiguous firmware ADD_STA.
    if (generation_ != 0 || count_ != 0)
        return Result::kBusy;
    return setRoles(count, generation, staInstalled, auxInstalled,
                    monitorInstalled);
}

Result StationRegistry::setRoles(uint8_t count,
                                 uint32_t generation,
                                 bool staInstalled, bool auxInstalled,
                                 bool monitorInstalled)
{
    if (count == 0 || count > 32 || generation == 0 ||
        (staInstalled && count < 1) || (auxInstalled && count < 2) ||
        (monitorInstalled && count < 3))
        return Result::kInvalid;

    count_ = count;
    generation_ = generation;
    for (Owner &owner : owners_)
        owner = Owner::kFree;
    if (staInstalled)
        owners_[0] = Owner::kInfrastructureSta;
    if (auxInstalled)
        owners_[1] = Owner::kAuxiliary;
    if (monitorInstalled)
        owners_[2] = Owner::kMonitor;
    return Result::kSuccess;
}

Result StationRegistry::reserveP2p(uint32_t generation,
                                   uint8_t *stationId)
{
    if (!stationId || count_ == 0)
        return Result::kInvalid;
    if (generation != generation_)
        return Result::kStale;
    for (uint8_t id = 0; id < count_; ++id) {
        if (owners_[id] == Owner::kFree) {
            owners_[id] = Owner::kP2pPending;
            *stationId = id;
            return Result::kSuccess;
        }
    }
    return Result::kNoCapacity;
}

Result StationRegistry::mark(uint32_t generation,
                             uint8_t stationId,
                             Owner expected, Owner next)
{
    if (generation != generation_)
        return Result::kStale;
    if (stationId >= count_ || owners_[stationId] != expected)
        return Result::kInvalid;
    owners_[stationId] = next;
    return Result::kSuccess;
}

Result StationRegistry::addAcknowledged(uint32_t generation,
                                        uint8_t stationId)
{
    return mark(generation, stationId, Owner::kP2pPending,
                Owner::kP2pBroadcast);
}

Result StationRegistry::addOutcomeUnknown(uint32_t generation,
                                          uint8_t stationId)
{
    return mark(generation, stationId, Owner::kP2pPending, Owner::kUnknown);
}

Result StationRegistry::removeAcknowledged(uint32_t generation,
                                           uint8_t stationId)
{
    return mark(generation, stationId, Owner::kP2pBroadcast, Owner::kFree);
}

Result StationRegistry::releaseKnownAbsent(uint32_t generation,
                                           uint8_t stationId)
{
    return mark(generation, stationId, Owner::kP2pPending, Owner::kFree);
}

Result StationRegistry::resetAfterFirmwareDrain(uint32_t newGeneration,
                                                uint8_t count,
                                                bool staInstalled,
                                                bool auxInstalled,
                                                bool monitorInstalled)
{
    // Firmware reset invalidates every old lease. The caller must pass the
    // newly observed role set rather than inheriting old station IDs.
    if (newGeneration == 0 || newGeneration == generation_)
        return Result::kInvalid;
    return setRoles(count, newGeneration, staInstalled, auxInstalled,
                    monitorInstalled);
}

StationSnapshot StationRegistry::snapshot() const
{
    StationSnapshot result{};
    result.count = count_;
    result.generation = generation_;
    for (size_t i = 0; i < 32; ++i)
        result.owners[i] = owners_[i];
    return result;
}

bool noP2pResourcesRetained(const StationSnapshot &stations,
                           const QueueSnapshot &queue)
{
    if (stations.count > 32 || queue.state != QueueState::kAbsent ||
        queue.outstandingTx != 0 || queue.ringMustRemainOwned)
        return false;

    for (uint8_t i = 0; i < stations.count; ++i) {
        const Owner owner = stations.owners[i];
        if (owner == Owner::kP2pPending || owner == Owner::kP2pBroadcast ||
            owner == Owner::kUnknown)
            return false;
    }
    return true;
}

QueueLease::QueueLease()
    : state_(QueueState::kAbsent), api_(QueueApi::kTvqmDynamic), queueId_(0),
      stationId_(0), generation_(0), outstandingTx_(0),
      completionObserved_(false), ringMustRemainOwned_(false),
      removeAcked_(false), drained_(false)
{
}

Result QueueLease::begin(const QueueAdmission &admission)
{
    if (state_ != QueueState::kAbsent)
        return Result::kBusy;
    if (admission.queueCapacity == 0 || admission.generation == 0 ||
        admission.stationId >= 32 ||
        !admission.stationActive || !admission.p2pMacActive ||
        !admission.p2pBindingActive || !admission.phyLeased)
        return Result::kInvalid;
    if (admission.api == QueueApi::kLegacyStaticDqa &&
        !admission.firmwareDqa)
        return Result::kInvalid;
    if (admission.api == QueueApi::kLegacyStaticDqa &&
        admission.monitorInjectionQueueInUse)
        return Result::kBusy;

    api_ = admission.api;
    stationId_ = admission.stationId;
    generation_ = admission.generation;
    queueId_ = 0;
    outstandingTx_ = 0;
    completionObserved_ = false;
    removeAcked_ = false;
    drained_ = false;
    // As soon as queue setup is submitted, its DMA backing must remain alive
    // until firmware absence or a physical drain is proved.
    ringMustRemainOwned_ = true;
    state_ = QueueState::kAllocationPending;
    return Result::kSuccess;
}

Result QueueLease::tvqmAssigned(uint32_t generation,
                                uint8_t stationId,
                                uint16_t queueId,
                                uint16_t queueCapacity,
                                bool queueSlotAvailable)
{
    if (generation != generation_ || stationId != stationId_)
        return Result::kStale;
    if (state_ != QueueState::kAllocationPending ||
        api_ != QueueApi::kTvqmDynamic)
        return Result::kInvalid;
    if (queueCapacity == 0 || queueId >= queueCapacity ||
        !queueSlotAvailable) {
        state_ = QueueState::kUnknown;
        ringMustRemainOwned_ = true;
        return Result::kNeedsReset;
    }
    queueId_ = queueId;
    state_ = QueueState::kActive;
    return Result::kSuccess;
}

Result QueueLease::legacyDqaAssigned(uint32_t generation,
                                     uint8_t stationId,
                                     uint16_t queueId,
                                     uint16_t queueCapacity,
                                     bool queueSlotAvailable)
{
    if (generation != generation_ || stationId != stationId_)
        return Result::kStale;
    if (state_ != QueueState::kAllocationPending ||
        api_ != QueueApi::kLegacyDynamicDqa)
        return Result::kInvalid;
    if (queueCapacity == 0 || queueId >= queueCapacity ||
        !queueSlotAvailable) {
        state_ = QueueState::kUnknown;
        ringMustRemainOwned_ = true;
        return Result::kNeedsReset;
    }
    queueId_ = queueId;
    state_ = QueueState::kActive;
    return Result::kSuccess;
}

Result QueueLease::staticQueueConfigured(uint32_t generation,
                                         uint8_t stationId,
                                         bool queueTwoAvailable)
{
    if (generation != generation_ || stationId != stationId_)
        return Result::kStale;
    if (state_ != QueueState::kAllocationPending ||
        api_ != QueueApi::kLegacyStaticDqa)
        return Result::kInvalid;
    if (!queueTwoAvailable) {
        state_ = QueueState::kUnknown;
        ringMustRemainOwned_ = true;
        return Result::kNeedsReset;
    }
    queueId_ = kP2pDeviceStaticQueue;
    state_ = QueueState::kActive;
    return Result::kSuccess;
}

Result QueueLease::allocationOutcomeUnknown(uint32_t generation,
                                            uint8_t stationId)
{
    if (generation != generation_ || stationId != stationId_)
        return Result::kStale;
    if (state_ != QueueState::kAllocationPending)
        return Result::kInvalid;
    state_ = QueueState::kUnknown;
    ringMustRemainOwned_ = true;
    return Result::kNeedsReset;
}

Result QueueLease::allocationRejected(uint32_t generation,
                                      uint8_t stationId)
{
    if (generation != generation_ || stationId != stationId_)
        return Result::kStale;
    if (state_ != QueueState::kAllocationPending)
        return Result::kInvalid;
    state_ = QueueState::kAbsent;
    queueId_ = 0;
    outstandingTx_ = 0;
    ringMustRemainOwned_ = false;
    removeAcked_ = false;
    drained_ = false;
    return Result::kSuccess;
}

Result QueueLease::txSubmitted(uint32_t generation,
                               uint16_t queueId)
{
    if (generation != generation_ || queueId != queueId_)
        return Result::kStale;
    if (state_ != QueueState::kActive || outstandingTx_ == UINT32_MAX)
        return Result::kBusy;
    ++outstandingTx_;
    return Result::kSuccess;
}

Result QueueLease::txCompleted(uint32_t generation,
                               uint16_t queueId)
{
    if (generation != generation_ || queueId != queueId_)
        return Result::kStale;
    if ((state_ != QueueState::kActive && state_ != QueueState::kRemoving &&
         state_ != QueueState::kUnknown) ||
        outstandingTx_ == 0)
        return Result::kInvalid;
    completionObserved_ = true;
    --outstandingTx_;
    if (state_ == QueueState::kRemoving && removeAcked_ && drained_ &&
        outstandingTx_ == 0) {
        state_ = QueueState::kAbsent;
        ringMustRemainOwned_ = false;
    }
    return Result::kSuccess;
}

Result QueueLease::txCancelled(uint32_t generation,
                               uint16_t queueId)
{
    if (generation != generation_ || queueId != queueId_)
        return Result::kStale;
    if (state_ != QueueState::kActive || outstandingTx_ == 0)
        return Result::kInvalid;
    --outstandingTx_;
    return Result::kSuccess;
}

Result QueueLease::beginRemoval(uint32_t generation,
                                uint16_t queueId)
{
    if (generation != generation_ || queueId != queueId_)
        return Result::kStale;
    if (state_ != QueueState::kActive)
        return Result::kInvalid;
    state_ = QueueState::kRemoving;
    removeAcked_ = false;
    drained_ = false;
    return Result::kSuccess;
}

Result QueueLease::removeAcknowledged(uint32_t generation,
                                      uint16_t queueId)
{
    if (generation != generation_ || queueId != queueId_)
        return Result::kStale;
    if (state_ != QueueState::kRemoving ||
        api_ != QueueApi::kTvqmDynamic)
        return Result::kInvalid;
    removeAcked_ = true;
    return Result::kSuccess;
}

Result QueueLease::stationRemovalAcknowledged(uint32_t generation,
                                              uint16_t queueId)
{
    if (generation != generation_ || queueId != queueId_)
        return Result::kStale;
    if (state_ != QueueState::kRemoving ||
        api_ != QueueApi::kLegacyDynamicDqa)
        return Result::kInvalid;
    // Legacy SCD_QUEUE_CFG v2 has no operation-aware queue REMOVE. A
    // successful REMOVE_STA ACK is the firmware-side lifetime boundary for
    // its station-owned queue, after TXPATH_FLUSH has drained that station.
    removeAcked_ = true;
    return Result::kSuccess;
}

Result QueueLease::neverSubmittedQueueReleasedAfterStationRemoval(
    uint32_t generation, uint16_t queueId)
{
    if (generation != generation_ || queueId != queueId_)
        return Result::kStale;
    if (state_ != QueueState::kRemoving ||
        api_ != QueueApi::kLegacyDynamicDqa || !removeAcked_ ||
        outstandingTx_ != 0 || completionObserved_ || drained_ ||
        !ringMustRemainOwned_)
        return Result::kInvalid;

    // This is a distinct proof path from queueDrained(): only a current
    // station-removal ACK plus the HAL's monotonic never-doorbelled proof can
    // release this legacy queue. Never relax the completion path.
    state_ = QueueState::kAbsent;
    queueId_ = 0;
    outstandingTx_ = 0;
    ringMustRemainOwned_ = false;
    removeAcked_ = false;
    drained_ = false;
    return Result::kSuccess;
}

Result QueueLease::removeOutcomeUnknown(uint32_t generation,
                                        uint16_t queueId)
{
    if (generation != generation_ || queueId != queueId_)
        return Result::kStale;
    if (state_ != QueueState::kRemoving)
        return Result::kInvalid;
    state_ = QueueState::kUnknown;
    ringMustRemainOwned_ = true;
    return Result::kNeedsReset;
}

Result QueueLease::queueDrained(uint32_t generation,
                                uint16_t queueId)
{
    if (generation != generation_ || queueId != queueId_)
        return Result::kStale;
    if (state_ != QueueState::kRemoving || !removeAcked_ ||
        !completionObserved_)
        return Result::kInvalid;
    drained_ = true;
    if (outstandingTx_ == 0) {
        state_ = QueueState::kAbsent;
        ringMustRemainOwned_ = false;
    }
    return Result::kSuccess;
}

Result QueueLease::resetAfterFirmwareDrain(uint32_t newGeneration)
{
    if (newGeneration == 0 || newGeneration == generation_)
        return Result::kInvalid;
    state_ = QueueState::kAbsent;
    queueId_ = 0;
    stationId_ = 0;
    generation_ = newGeneration;
    outstandingTx_ = 0;
    completionObserved_ = false;
    ringMustRemainOwned_ = false;
    removeAcked_ = false;
    drained_ = false;
    return Result::kSuccess;
}

QueueSnapshot QueueLease::snapshot() const
{
    return {state_, api_, queueId_, stationId_, generation_, outstandingTx_,
            completionObserved_, ringMustRemainOwned_};
}

bool parseActionFrame(const uint8_t *frame, size_t length,
                      ActionFrameInfo *info)
{
    if (!frame || !info || length < kManagementHeaderLength)
        return false;
    const uint8_t type = static_cast<uint8_t>((frame[0] >> 2) & 0x3);
    const uint8_t subtype = static_cast<uint8_t>(frame[0] & 0xf0);
    const uint8_t version = static_cast<uint8_t>(frame[0] & 0x3);
    const size_t headerLength = (frame[1] & 0x80U)
        ? kManagementHeaderWithHtControlLength : kManagementHeaderLength;
    if (version != 0 || type != kManagementFrameType ||
        subtype != kActionFrameSubtype)
        return false;
    if (length < headerLength)
        return false;

    if (!validMac(frame + 10, false) || !validMac(frame + 4, true))
        return false;
    info->type = type;
    info->subtype = subtype;
    info->headerLength = static_cast<uint16_t>(headerLength);
    memcpy(info->destination, frame + 4, 6);
    memcpy(info->source, frame + 10, 6);
    memcpy(info->bssid, frame + 16, 6);
    return true;
}

bool encodeTvqmAddCommand(const TvqmAddFields &fields,
                          uint8_t output[36])
{
    if (!output || fields.stationId >= 32 || fields.tid > kMaxManagementTid ||
        (fields.flags & 0xfffcU) != 0 || (fields.flags & 1U) != 0 ||
        fields.circularBufferSizeCode > 5 ||
        fields.byteCountAddress == 0 || fields.descriptorAddress == 0)
        return false;
    // TX_QUEUE_CFG_CMD_API_S_VER_3: operation=ADD, station mask, TID,
    // reserved, flags, circular buffer size, byte-count IOVA, TFDQ IOVA.
    output[0] = 0;
    output[1] = 0;
    output[2] = 0;
    output[3] = 0;
    const uint32_t stationMask = uint32_t{1} << fields.stationId;
    for (unsigned i = 0; i < 4; ++i)
        output[4 + i] = static_cast<uint8_t>(stationMask >> (8 * i));
    output[8] = fields.tid;
    output[9] = output[10] = output[11] = 0;
    const uint32_t flags = fields.flags;
    const uint32_t cbSize = fields.circularBufferSizeCode;
    for (unsigned i = 0; i < 4; ++i) {
        output[12 + i] = static_cast<uint8_t>(flags >> (8 * i));
        output[16 + i] = static_cast<uint8_t>(cbSize >> (8 * i));
    }
    for (unsigned i = 0; i < 8; ++i) {
        output[20 + i] = static_cast<uint8_t>(fields.byteCountAddress >> (8 * i));
        output[28 + i] = static_cast<uint8_t>(fields.descriptorAddress >> (8 * i));
    }
    return true;
}

bool encodeTvqmRemoveCommand(uint8_t stationId, uint8_t tid,
                             uint8_t output[12])
{
    if (!output || stationId >= 32 || tid > kMaxManagementTid)
        return false;
    // TX_QUEUE_CFG_CMD_API_S_VER_3: operation=REMOVE, station mask, TID.
    output[0] = 1;
    output[1] = output[2] = output[3] = 0;
    const uint32_t stationMask = uint32_t{1} << stationId;
    const uint32_t fwTid = tid;
    for (unsigned i = 0; i < 4; ++i) {
        output[4 + i] = static_cast<uint8_t>(stationMask >> (8 * i));
        output[8 + i] = static_cast<uint8_t>(fwTid >> (8 * i));
    }
    return true;
}

} // namespace IntelP2PTx

