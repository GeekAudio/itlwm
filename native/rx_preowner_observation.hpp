// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_RX_PREOWNER_OBSERVATION_HPP
#define NATIVE_RX_PREOWNER_OBSERVATION_HPP

#include <stddef.h>
#include <stdint.h>

// A bounded, read-only observation of the RX dispatch path before its existing
// owner/admission gate. This header intentionally stores numeric metadata only.
namespace NativeRxPreOwner {

constexpr uint32_t kSchemaVersion = 1;
constexpr uint64_t kWindowUs = 4000000ULL;
constexpr uint64_t kCaptureSerial = 1ULL;
constexpr uint32_t kWitnessBankCapacity = 8;
constexpr uint32_t kWitnessCapacity = kWitnessBankCapacity * 2;

// Marks the entire stop operation, including nested stop-device calls.
// A fresh ARM must not infer idleness from an unchanged stop serial.
class StopActivity {
public:
    explicit StopActivity(uint32_t *depth) noexcept : depth_(depth)
    {
        (void)__atomic_fetch_add(depth_, 1u, __ATOMIC_ACQ_REL);
    }
    ~StopActivity()
    {
        (void)__atomic_fetch_sub(depth_, 1u, __ATOMIC_RELEASE);
    }
    StopActivity(const StopActivity &) = delete;
    StopActivity &operator=(const StopActivity &) = delete;
private:
    uint32_t *depth_;
};

enum class EventKind : uint32_t {
    Irq = 0,
    Drain = 1,
    Slot = 2,
    NotificationSeen = 3,
    HeaderRejected = 4,
    LengthRejected = 5,
    NotificationValidated = 6,
    MpduDispatch = 7,
    AddbufFailed = 8,
    CopyFailed = 9,
    MpduEntry = 10,
    OwnerRecorderAccepted = 11,
    OwnerRecorderRejected = 12,
    Count = 13
};
constexpr uint32_t kEventKindCount =
    static_cast<uint32_t>(EventKind::Count);

enum class RxClass : uint32_t {
    Unknown = 0,
    Sta = 1,
    Channel149 = 2,
    Other = 3,
    Count = 4
};
constexpr uint32_t kRxClassCount = static_cast<uint32_t>(RxClass::Count);

enum class IrqSource : uint32_t {
    None = 0,
    Legacy = 1,
    Msix = 2,
    Count = 3
};

// Stable numeric ABI shared with the production owner predicate. Values 1..21
// correspond to its original short-circuit failure order.
enum class OwnerReason : uint32_t {
    Qualified = 0,
    InvalidInput = 1,
    MainGate = 2,
    LeaseInactive = 3,
    LeaseContextZero = 4,
    LeasePowerZero = 5,
    LeaseStationZero = 6,
    LeaseContextMismatchCurrent = 7,
    LeaseContextMismatchProbe = 8,
    LeasePowerMismatchLeaseCurrent = 9,
    LeaseStationMismatchLeaseCurrent = 10,
    PowerMismatchScGeneration = 11,
    PowerMismatchFwGeneration = 12,
    StationMismatchScGeneration = 13,
    RocMissing = 14,
    RocGenerationMismatchLease = 15,
    RocGenerationMismatchCurrent = 16,
    RocCommandPending = 17,
    RocCommandFailed = 18,
    RocWindowNotQualified = 19,
    RocTokenMismatch = 20,
    RocPhaseNotAcked = 21,
    Unknown = 22,
    Count = 23
};
constexpr uint32_t kOwnerReasonCount =
    static_cast<uint32_t>(OwnerReason::Count);

enum class CloseReason : uint32_t {
    None = 0,
    Deadline = 1,
    Explicit = 2,
    Stop = 3,
    GenerationChanged = 4,
    Count = 5
};

// Every field is scalar numeric metadata. Presence flags are 0/1; an absent
// field must carry a zero value. `physicalRing/physicalSlot` are not the
// transport notification qid/index namespace.
struct Event {
    uint64_t nowUs;
    uint32_t generation;
    EventKind kind;
    RxClass rxClass;
    OwnerReason ownerReason;
    IrqSource irqSource;
    uint32_t irqCause; // Raw RX cause; not a ring, qid, or PHY identifier.
    uint32_t notificationCode; // group<<8 | command for notification kinds.
    uint32_t physicalRingPresent;
    uint32_t physicalRing;
    uint32_t physicalSlotPresent;
    uint32_t physicalSlot;
    uint32_t notificationQidPresent;
    uint32_t notificationQid;
    uint32_t notificationIndexPresent;
    uint32_t notificationIndex;
    uint32_t payloadLen;
    uint32_t descSize;
    uint32_t mpduLengthPresent;
    uint32_t mpduLength;
    uint32_t rawStatusPresent;
    uint32_t rawStatus;
    uint32_t rawMacPhyIndexPresent;
    uint32_t rawMacPhyIndex;
    uint32_t macPhyDecodeModePresent;
    uint32_t macPhyDecodeMode;
    uint32_t channelPresent;
    uint32_t channel;
    uint32_t macIndexPresent;
    uint32_t macIndex;
    uint32_t frameControlPresent;
    uint32_t frameControl;
    uint32_t sequenceControlPresent;
    uint32_t sequenceControl;
    uint32_t gp2OnAirRisePresent;
    uint32_t gp2OnAirRiseRaw;
    uint32_t tsfOnAirRisePresent;
    uint64_t tsfOnAirRiseRaw;
    uint32_t awdlCandidate;
};

struct Witness {
    uint32_t present;
    Event event;
};

struct Snapshot {
    uint32_t schemaVersion;
    uint64_t captureSerial;
    uint32_t driverGeneration;
    uint64_t beginUs;
    uint64_t endUs; // zero while active
    uint64_t deadlineUs;
    uint64_t snapshotUs;
    uint32_t active;
    uint32_t closed;
    CloseReason closeReason;
    uint32_t totalEvents;
    uint32_t kindCounts[kEventKindCount];
    uint32_t rxClassCounts[kRxClassCount];
    uint32_t dispatchCount; // EventKind::MpduDispatch
    uint32_t mpduEntryCount;
    uint32_t awdlCandidateCount; // MpduEntry events only
    uint32_t ownerQualifiedCount;
    uint32_t ownerFailedCount;
    uint32_t ownerReasonCounts[kOwnerReasonCount];
    uint32_t lockContentionLoss;
    uint32_t invalidSampleLoss;
    uint32_t generationMismatchLoss;
    uint32_t deadlineRejectCount;
    uint32_t clockReversalLoss;
    uint32_t witness149Overflow;
    uint32_t witnessNon149Overflow;
    uint32_t lossCount;
    uint32_t overflow;
    uint32_t counterOverflow;
    uint32_t witness149Count;
    uint32_t witnessNon149Count;
    Witness channel149Witnesses[kWitnessBankCapacity];
    Witness non149Witnesses[kWitnessBankCapacity];
};

inline bool isOne(uint32_t value) { return value <= 1; }

inline bool validEvent(const Event &event)
{
    if (static_cast<uint32_t>(event.kind) >= kEventKindCount ||
        static_cast<uint32_t>(event.rxClass) >= kRxClassCount ||
        static_cast<uint32_t>(event.ownerReason) >= kOwnerReasonCount ||
        static_cast<uint32_t>(event.irqSource) >=
            static_cast<uint32_t>(IrqSource::Count) ||
        !isOne(event.physicalRingPresent) ||
        !isOne(event.physicalSlotPresent) ||
        !isOne(event.notificationQidPresent) ||
        !isOne(event.notificationIndexPresent) ||
        !isOne(event.mpduLengthPresent) ||
        !isOne(event.rawStatusPresent) || !isOne(event.channelPresent) ||
        !isOne(event.rawMacPhyIndexPresent) ||
        !isOne(event.macPhyDecodeModePresent) ||
        !isOne(event.macIndexPresent) ||
        !isOne(event.frameControlPresent) ||
        !isOne(event.sequenceControlPresent) ||
        !isOne(event.gp2OnAirRisePresent) ||
        !isOne(event.tsfOnAirRisePresent) ||
        !isOne(event.awdlCandidate))
        return false;

    const bool notificationKind =
        event.kind == EventKind::NotificationSeen ||
        event.kind == EventKind::HeaderRejected ||
        event.kind == EventKind::LengthRejected ||
        event.kind == EventKind::NotificationValidated;
    if ((!notificationKind && event.notificationCode != 0) ||
        (notificationKind && event.notificationCode > 0xffffu) ||
        (event.irqSource == IrqSource::None && event.irqCause != 0))
        return false;

    if ((!event.physicalRingPresent && event.physicalRing != 0) ||
        (!event.physicalSlotPresent && event.physicalSlot != 0) ||
        (!event.notificationQidPresent && event.notificationQid != 0) ||
        (!event.notificationIndexPresent && event.notificationIndex != 0) ||
        (!event.mpduLengthPresent && event.mpduLength != 0) ||
        (!event.rawStatusPresent && event.rawStatus != 0) ||
        (!event.rawMacPhyIndexPresent && event.rawMacPhyIndex != 0) ||
        (!event.macPhyDecodeModePresent && event.macPhyDecodeMode != 0) ||
        (!event.channelPresent && event.channel != 0) ||
        (!event.macIndexPresent && event.macIndex != 0) ||
        (!event.frameControlPresent && event.frameControl != 0) ||
        (!event.sequenceControlPresent && event.sequenceControl != 0) ||
        (!event.gp2OnAirRisePresent && event.gp2OnAirRiseRaw != 0) ||
        (!event.tsfOnAirRisePresent && event.tsfOnAirRiseRaw != 0))
        return false;

    if ((event.frameControlPresent && event.frameControl > 0xffffu) ||
        (event.sequenceControlPresent && event.sequenceControl > 0xffffu) ||
        (event.rawMacPhyIndexPresent && event.rawMacPhyIndex > 0xffu) ||
        (event.macPhyDecodeModePresent && event.macPhyDecodeMode > 2u))
        return false;
    if (event.rxClass == RxClass::Channel149 &&
        (!event.channelPresent || event.channel != 149))
        return false;
    return true;
}

inline uint32_t saturatingAdd(uint32_t left, uint32_t right)
{
    return UINT32_MAX - left < right ? UINT32_MAX : left + right;
}

inline uint32_t saturatingAddTracked(uint32_t left, uint32_t right,
                                     bool *overflow)
{
    if (UINT32_MAX - left < right) {
        if (overflow)
            *overflow = true;
        return UINT32_MAX;
    }
    return left + right;
}

inline bool validWitness(const Witness &witness, bool channel149,
                         uint64_t beginUs, uint64_t deadlineUs,
                         uint32_t generation)
{
    if (witness.present > 1)
        return false;
    if (!witness.present)
        return true;
    if (!validEvent(witness.event) ||
        witness.event.kind != EventKind::MpduEntry ||
        witness.event.generation != generation ||
        witness.event.nowUs < beginUs || witness.event.nowUs >= deadlineUs)
        return false;
    const bool isChannel149 = witness.event.channelPresent &&
        witness.event.channel == 149;
    return isChannel149 == channel149;
}

inline bool validateSnapshot(const Snapshot &snapshot)
{
    if (snapshot.schemaVersion != kSchemaVersion ||
        snapshot.captureSerial != kCaptureSerial ||
        snapshot.active > 1 || snapshot.closed > 1 ||
        snapshot.active == snapshot.closed ||
        static_cast<uint32_t>(snapshot.closeReason) >=
            static_cast<uint32_t>(CloseReason::Count) ||
        snapshot.overflow > 1 || snapshot.counterOverflow > 1 ||
        snapshot.deadlineUs < snapshot.beginUs ||
        snapshot.deadlineUs - snapshot.beginUs != kWindowUs ||
        snapshot.witness149Count > kWitnessBankCapacity ||
        snapshot.witnessNon149Count > kWitnessBankCapacity)
        return false;

    if (snapshot.active) {
        if (snapshot.endUs != 0 || snapshot.closeReason != CloseReason::None ||
            snapshot.snapshotUs < snapshot.beginUs)
            return false;
    } else if (snapshot.endUs < snapshot.beginUs ||
               snapshot.endUs > snapshot.deadlineUs ||
               snapshot.closeReason == CloseReason::None ||
               (snapshot.closeReason == CloseReason::Deadline &&
                snapshot.endUs != snapshot.deadlineUs)) {
        return false;
    }
    if (snapshot.snapshotUs < snapshot.beginUs)
        return false;

    uint32_t kindTotal = 0;
    for (uint32_t i = 0; i < kEventKindCount; ++i)
        kindTotal = saturatingAdd(kindTotal, snapshot.kindCounts[i]);
    uint32_t classTotal = 0;
    for (uint32_t i = 0; i < kRxClassCount; ++i)
        classTotal = saturatingAdd(classTotal, snapshot.rxClassCounts[i]);
    if (!snapshot.counterOverflow &&
        (kindTotal != snapshot.totalEvents ||
         classTotal != snapshot.totalEvents ||
         snapshot.dispatchCount != snapshot.kindCounts[
             static_cast<uint32_t>(EventKind::MpduDispatch)] ||
         snapshot.mpduEntryCount != snapshot.kindCounts[
             static_cast<uint32_t>(EventKind::MpduEntry)] ||
        saturatingAdd(snapshot.ownerQualifiedCount,
                      snapshot.ownerFailedCount) !=
             snapshot.mpduEntryCount))
        return false;

    if (!snapshot.counterOverflow &&
        (snapshot.ownerQualifiedCount > snapshot.mpduEntryCount ||
         snapshot.ownerFailedCount > snapshot.mpduEntryCount ||
         snapshot.awdlCandidateCount > snapshot.mpduEntryCount))
        return false;

    uint32_t reasonsTotal = 0;
    for (uint32_t i = 0; i < kOwnerReasonCount; ++i)
        reasonsTotal = saturatingAdd(reasonsTotal,
                                     snapshot.ownerReasonCounts[i]);
    if (!snapshot.counterOverflow && reasonsTotal != snapshot.mpduEntryCount)
        return false;
    if (!snapshot.counterOverflow &&
        (snapshot.ownerReasonCounts[
             static_cast<uint32_t>(OwnerReason::Qualified)] !=
             snapshot.ownerQualifiedCount ||
         saturatingAdd(snapshot.ownerReasonCounts[
                           static_cast<uint32_t>(OwnerReason::Qualified)],
                       snapshot.ownerFailedCount) != snapshot.mpduEntryCount))
        return false;

    if ((snapshot.witness149Overflow &&
         snapshot.witness149Count != kWitnessBankCapacity) ||
        (snapshot.witnessNon149Overflow &&
         snapshot.witnessNon149Count != kWitnessBankCapacity) ||
        ((snapshot.witness149Overflow || snapshot.witnessNon149Overflow ||
          snapshot.counterOverflow) && !snapshot.overflow))
        return false;

    for (uint32_t i = 0; i < kWitnessBankCapacity; ++i) {
        const bool should149 = i < snapshot.witness149Count;
        const bool shouldOther = i < snapshot.witnessNon149Count;
        if (snapshot.channel149Witnesses[i].present !=
                static_cast<uint32_t>(should149) ||
            snapshot.non149Witnesses[i].present !=
                static_cast<uint32_t>(shouldOther) ||
            !validWitness(snapshot.channel149Witnesses[i], true,
                          snapshot.beginUs, snapshot.deadlineUs,
                          snapshot.driverGeneration) ||
            !validWitness(snapshot.non149Witnesses[i], false,
                          snapshot.beginUs, snapshot.deadlineUs,
                          snapshot.driverGeneration))
            return false;
    }

    bool lossOverflow = false;
    uint32_t expectedLoss = snapshot.lockContentionLoss;
    expectedLoss = saturatingAddTracked(expectedLoss,
                                        snapshot.invalidSampleLoss,
                                        &lossOverflow);
    expectedLoss = saturatingAddTracked(expectedLoss,
                                        snapshot.generationMismatchLoss,
                                        &lossOverflow);
    expectedLoss = saturatingAddTracked(expectedLoss,
                                        snapshot.deadlineRejectCount,
                                        &lossOverflow);
    expectedLoss = saturatingAddTracked(expectedLoss,
                                        snapshot.clockReversalLoss,
                                        &lossOverflow);
    expectedLoss = saturatingAddTracked(expectedLoss,
                                        snapshot.witness149Overflow,
                                        &lossOverflow);
    expectedLoss = saturatingAddTracked(expectedLoss,
                                        snapshot.witnessNon149Overflow,
                                        &lossOverflow);
    if (snapshot.lossCount != expectedLoss ||
        (lossOverflow && !snapshot.overflow))
        return false;
    return true;
}

class Observer {
public:
    Observer() noexcept
        : lock_(0), begun_(0), active_(0), pendingCloseState_(0),
          pendingCloseReason_(0), pendingCloseUs_(0), driverGeneration_(0),
          beginUs_(0), endUs_(0), deadlineUs_(0), lastEventUs_(0),
          closeReason_(CloseReason::None), totalEvents_(0), dispatchCount_(0),
          mpduEntryCount_(0), awdlCandidateCount_(0),
          ownerQualifiedCount_(0), ownerFailedCount_(0),
          invalidSampleLoss_(0), generationMismatchLoss_(0),
          deadlineRejectCount_(0), clockReversalLoss_(0),
          witness149Overflow_(0), witnessNon149Overflow_(0),
          witness149Count_(0), witnessNon149Count_(0), overflow_(0),
          counterOverflow_(0), lockContentionLoss_(0)
    {
        zeroCounters();
        zeroWitnesses();
    }

    Observer(const Observer &) = delete;
    Observer &operator=(const Observer &) = delete;

    // A failed attempt (including lock contention or overflowing the time
    // domain) does not consume the one permitted successful begin.
    bool begin(uint64_t nowUs, uint32_t driverGeneration) noexcept
    {
        if (UINT64_MAX - nowUs < kWindowUs)
            return false;
        if (!tryLock()) {
            noteLockContention();
            return false;
        }
        if (begun_) {
            unlock();
            return false;
        }
        begun_ = 1;
        driverGeneration_ = driverGeneration;
        beginUs_ = nowUs;
        endUs_ = 0;
        deadlineUs_ = nowUs + kWindowUs;
        lastEventUs_ = nowUs;
        closeReason_ = CloseReason::None;
        __atomic_store_n(&pendingCloseState_, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&active_, 1u, __ATOMIC_RELEASE);
        unlock();
        return true;
    }

    // No timestamp read is required for the common disabled path.
    bool enabled() const noexcept
    {
        return __atomic_load_n(&active_, __ATOMIC_ACQUIRE) != 0 &&
            __atomic_load_n(&pendingCloseState_, __ATOMIC_ACQUIRE) == 0;
    }

    bool isActive() const noexcept { return enabled(); }

    // Returns true when the event was accepted into aggregate counters. A full
    // witness bank does not reject the event; it increments visible loss.
    bool record(const Event &event) noexcept
    {
        if (!enabled())
            return false;
        if (!tryLock()) {
            noteLockContention();
            return false;
        }
        applyPendingCloseLocked();
        if (!begun_ || !active_) {
            unlock();
            return false;
        }
        if (event.nowUs < beginUs_ || event.nowUs < lastEventUs_) {
            increment(clockReversalLoss_);
            unlock();
            return false;
        }
        if (event.nowUs >= deadlineUs_) {
            closeLocked(deadlineUs_, CloseReason::Deadline);
            increment(deadlineRejectCount_);
            unlock();
            return false;
        }
        if (event.generation != driverGeneration_) {
            increment(generationMismatchLoss_);
            closeLocked(event.nowUs, CloseReason::GenerationChanged);
            unlock();
            return false;
        }
        if (!validEvent(event)) {
            increment(invalidSampleLoss_);
            unlock();
            return false;
        }

        increment(totalEvents_);
        increment(kindCounts_[static_cast<uint32_t>(event.kind)]);
        increment(rxClassCounts_[static_cast<uint32_t>(event.rxClass)]);
        if (event.kind == EventKind::MpduDispatch)
            increment(dispatchCount_);
        if (event.kind == EventKind::MpduEntry)
            recordMpduEntryLocked(event);
        lastEventUs_ = event.nowUs;
        unlock();
        return true;
    }

    // If the lock is busy, publish a pending close request atomically. The
    // active fast flag is then false immediately; the next writer/snapshot
    // finalizes the close under the lock before copying state.
    bool close(uint64_t nowUs,
               CloseReason reason = CloseReason::Explicit) noexcept
    {
        if (reason == CloseReason::None || reason == CloseReason::Deadline ||
            static_cast<uint32_t>(reason) >=
                static_cast<uint32_t>(CloseReason::Count))
            return false;
        if (!tryLock()) {
            requestPendingClose(nowUs, reason);
            return true;
        }
        applyPendingCloseLocked();
        if (!begun_ || !active_) {
            unlock();
            return false;
        }
        if (nowUs >= deadlineUs_) {
            closeLocked(deadlineUs_, CloseReason::Deadline);
        } else {
            closeLocked(nowUs, reason);
        }
        unlock();
        return true;
    }

    // The snapshot is copied under one nonblocking try-lock. An active
    // snapshot has endUs==0 and must not be published as final evidence.
    bool snapshot(uint64_t nowUs, Snapshot *out) noexcept
    {
        if (!out)
            return false;
        if (!tryLock()) {
            noteLockContention();
            return false;
        }
        applyPendingCloseLocked();
        if (!begun_) {
            unlock();
            return false;
        }
        if (active_ && nowUs >= deadlineUs_)
            closeLocked(deadlineUs_, CloseReason::Deadline);

        uint64_t snapshotUs = nowUs;
        if (snapshotUs < beginUs_) {
            increment(clockReversalLoss_);
            snapshotUs = beginUs_;
        } else if (snapshotUs < lastEventUs_) {
            increment(clockReversalLoss_);
            snapshotUs = lastEventUs_;
        }
        fillSnapshotLocked(snapshotUs, out);
        // A close can race the first copy while the lock is held. Re-copy once
        // if a pending request arrived during the first copy.
        if (__atomic_load_n(&pendingCloseState_, __ATOMIC_ACQUIRE) == 2u) {
            applyPendingCloseLocked();
            fillSnapshotLocked(snapshotUs, out);
        }
        unlock();
        return validateSnapshot(*out);
    }

private:
    bool tryLock() noexcept
    {
        return __atomic_exchange_n(&lock_, 1u, __ATOMIC_ACQUIRE) == 0;
    }

    void unlock() noexcept
    {
        __atomic_store_n(&lock_, 0u, __ATOMIC_RELEASE);
    }

    void setOverflow() noexcept
    {
        __atomic_store_n(&overflow_, 1u, __ATOMIC_RELEASE);
    }

    void increment(uint32_t &value) noexcept
    {
        if (value == UINT32_MAX) {
            __atomic_store_n(&counterOverflow_, 1u, __ATOMIC_RELEASE);
            setOverflow();
            return;
        }
        ++value;
    }

    void noteLockContention() noexcept
    {
        // A native-width atomic increment avoids a retry loop on the failed
        // try-lock path. Snapshot saturates this wider counter into its ABI.
        (void)__atomic_fetch_add(&lockContentionLoss_, uint64_t(1),
                                 __ATOMIC_RELAXED);
    }

    void requestPendingClose(uint64_t nowUs, CloseReason reason) noexcept
    {
        uint32_t expected = 0;
        if (__atomic_compare_exchange_n(&pendingCloseState_, &expected, 1u,
                                        false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE)) {
            __atomic_store_n(&pendingCloseUs_, nowUs, __ATOMIC_RELAXED);
            __atomic_store_n(&pendingCloseReason_,
                             static_cast<uint32_t>(reason),
                             __ATOMIC_RELAXED);
            __atomic_store_n(&pendingCloseState_, 2u, __ATOMIC_RELEASE);
        }
    }

    void applyPendingCloseLocked() noexcept
    {
        if (__atomic_load_n(&pendingCloseState_, __ATOMIC_ACQUIRE) != 2u ||
            !begun_ || !active_)
            return;
        const uint64_t requestedUs =
            __atomic_load_n(&pendingCloseUs_, __ATOMIC_RELAXED);
        const uint32_t rawReason =
            __atomic_load_n(&pendingCloseReason_, __ATOMIC_RELAXED);
        CloseReason reason = static_cast<CloseReason>(rawReason);
        if (nowExpired(requestedUs)) {
            closeLocked(deadlineUs_, CloseReason::Deadline);
        } else {
            closeLocked(requestedUs, reason);
        }
        __atomic_store_n(&pendingCloseState_, 0u, __ATOMIC_RELEASE);
    }

    bool nowExpired(uint64_t nowUs) const noexcept
    {
        return nowUs >= deadlineUs_;
    }

    void closeLocked(uint64_t nowUs, CloseReason reason) noexcept
    {
        uint64_t effectiveUs = nowUs;
        if (effectiveUs < beginUs_) {
            increment(clockReversalLoss_);
            effectiveUs = beginUs_;
        } else if (effectiveUs < lastEventUs_) {
            increment(clockReversalLoss_);
            effectiveUs = lastEventUs_;
        }
        if (effectiveUs > deadlineUs_)
            effectiveUs = deadlineUs_;
        if (effectiveUs == deadlineUs_)
            reason = CloseReason::Deadline;
        endUs_ = effectiveUs;
        closeReason_ = reason;
        __atomic_store_n(&active_, 0u, __ATOMIC_RELEASE);
    }

    void recordMpduEntryLocked(const Event &event) noexcept
    {
        increment(mpduEntryCount_);
        if (event.awdlCandidate)
            increment(awdlCandidateCount_);
        const uint32_t reason = static_cast<uint32_t>(event.ownerReason);
        increment(ownerReasonCounts_[reason]);
        if (event.ownerReason == OwnerReason::Qualified)
            increment(ownerQualifiedCount_);
        else
            increment(ownerFailedCount_);

        const bool is149 = event.channelPresent && event.channel == 149;
        Witness *bank = is149 ? channel149Witnesses_ : non149Witnesses_;
        uint32_t &count = is149 ? witness149Count_ : witnessNon149Count_;
        uint32_t &overflow = is149 ? witness149Overflow_ : witnessNon149Overflow_;
        if (count == kWitnessBankCapacity) {
            increment(overflow);
            setOverflow();
            return;
        }
        bank[count].present = 1;
        bank[count].event = event;
        ++count;
    }

    void fillSnapshotLocked(uint64_t snapshotUs, Snapshot *out) const noexcept
    {
        // The caller owns preallocated storage. Zero and fill it in place to
        // avoid a multi-kilobyte Snapshot temporary on the watchdog stack.
        __builtin_memset(out, 0, sizeof(*out));
        out->schemaVersion = kSchemaVersion;
        out->captureSerial = kCaptureSerial;
        out->driverGeneration = driverGeneration_;
        out->beginUs = beginUs_;
        out->endUs = endUs_;
        out->deadlineUs = deadlineUs_;
        out->snapshotUs = snapshotUs;
        out->active = __atomic_load_n(&active_, __ATOMIC_ACQUIRE);
        out->closed = out->active ? 0u : 1u;
        out->closeReason = closeReason_;
        out->totalEvents = totalEvents_;
        for (uint32_t i = 0; i < kEventKindCount; ++i)
            out->kindCounts[i] = kindCounts_[i];
        for (uint32_t i = 0; i < kRxClassCount; ++i)
            out->rxClassCounts[i] = rxClassCounts_[i];
        out->dispatchCount = dispatchCount_;
        out->mpduEntryCount = mpduEntryCount_;
        out->awdlCandidateCount = awdlCandidateCount_;
        out->ownerQualifiedCount = ownerQualifiedCount_;
        out->ownerFailedCount = ownerFailedCount_;
        for (uint32_t i = 0; i < kOwnerReasonCount; ++i)
            out->ownerReasonCounts[i] = ownerReasonCounts_[i];
        const uint64_t lockLoss =
            __atomic_load_n(&lockContentionLoss_, __ATOMIC_RELAXED);
        out->lockContentionLoss = lockLoss > UINT32_MAX ? UINT32_MAX :
            static_cast<uint32_t>(lockLoss);
        out->invalidSampleLoss = invalidSampleLoss_;
        out->generationMismatchLoss = generationMismatchLoss_;
        out->deadlineRejectCount = deadlineRejectCount_;
        out->clockReversalLoss = clockReversalLoss_;
        out->witness149Overflow = witness149Overflow_;
        out->witnessNon149Overflow = witnessNon149Overflow_;
        out->overflow = __atomic_load_n(&overflow_, __ATOMIC_ACQUIRE);
        out->counterOverflow =
            __atomic_load_n(&counterOverflow_, __ATOMIC_ACQUIRE);
        if (lockLoss > UINT32_MAX) {
            out->overflow = 1;
            out->counterOverflow = 1;
        }
        bool lossOverflow = false;
        out->lossCount = out->lockContentionLoss;
        out->lossCount = saturatingAddTracked(out->lossCount,
                                               out->invalidSampleLoss,
                                               &lossOverflow);
        out->lossCount = saturatingAddTracked(out->lossCount,
                                               out->generationMismatchLoss,
                                               &lossOverflow);
        out->lossCount = saturatingAddTracked(out->lossCount,
                                               out->deadlineRejectCount,
                                               &lossOverflow);
        out->lossCount = saturatingAddTracked(out->lossCount,
                                               out->clockReversalLoss,
                                               &lossOverflow);
        out->lossCount = saturatingAddTracked(out->lossCount,
                                               out->witness149Overflow,
                                               &lossOverflow);
        out->lossCount = saturatingAddTracked(out->lossCount,
                                               out->witnessNon149Overflow,
                                               &lossOverflow);
        if (lossOverflow)
            out->overflow = 1;
        out->witness149Count = witness149Count_;
        out->witnessNon149Count = witnessNon149Count_;
        for (uint32_t i = 0; i < kWitnessBankCapacity; ++i) {
            out->channel149Witnesses[i] = channel149Witnesses_[i];
            out->non149Witnesses[i] = non149Witnesses_[i];
        }
    }

    void zeroCounters() noexcept
    {
        for (uint32_t i = 0; i < kEventKindCount; ++i)
            kindCounts_[i] = 0;
        for (uint32_t i = 0; i < kRxClassCount; ++i)
            rxClassCounts_[i] = 0;
        for (uint32_t i = 0; i < kOwnerReasonCount; ++i)
            ownerReasonCounts_[i] = 0;
    }

    void zeroWitnesses() noexcept
    {
        for (uint32_t i = 0; i < kWitnessBankCapacity; ++i) {
            channel149Witnesses_[i] = Witness{};
            non149Witnesses_[i] = Witness{};
        }
    }

    volatile uint32_t lock_;
    uint32_t begun_;
    volatile uint32_t active_;
    volatile uint32_t pendingCloseState_; // 0 none, 1 reserved, 2 ready
    volatile uint32_t pendingCloseReason_;
    volatile uint64_t pendingCloseUs_;
    uint32_t driverGeneration_;
    uint64_t beginUs_;
    uint64_t endUs_;
    uint64_t deadlineUs_;
    uint64_t lastEventUs_;
    CloseReason closeReason_;
    uint32_t totalEvents_;
    uint32_t kindCounts_[kEventKindCount];
    uint32_t rxClassCounts_[kRxClassCount];
    uint32_t dispatchCount_;
    uint32_t mpduEntryCount_;
    uint32_t awdlCandidateCount_;
    uint32_t ownerQualifiedCount_;
    uint32_t ownerFailedCount_;
    uint32_t ownerReasonCounts_[kOwnerReasonCount];
    uint32_t invalidSampleLoss_;
    uint32_t generationMismatchLoss_;
    uint32_t deadlineRejectCount_;
    uint32_t clockReversalLoss_;
    uint32_t witness149Overflow_;
    uint32_t witnessNon149Overflow_;
    uint32_t witness149Count_;
    uint32_t witnessNon149Count_;
    Witness channel149Witnesses_[kWitnessBankCapacity];
    Witness non149Witnesses_[kWitnessBankCapacity];
    volatile uint32_t overflow_;
    volatile uint32_t counterOverflow_;
    volatile uint64_t lockContentionLoss_;
};

} // namespace NativeRxPreOwner

#endif // NATIVE_RX_PREOWNER_OBSERVATION_HPP
