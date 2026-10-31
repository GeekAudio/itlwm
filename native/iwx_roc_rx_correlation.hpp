// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_IWX_ROC_RX_CORRELATION_HPP
#define NATIVE_IWX_ROC_RX_CORRELATION_HPP

#include <stddef.h>
#include <stdint.h>

#include "iwx_completion_observer.hpp"

// Bounded host-side correlation for one manually armed, actual ROC window.
// The caller serializes every method on its existing main command gate. This
// type owns no locks, DMA mappings, mbufs, or pointers into receive storage.
namespace NativeIwxRocRxCorrelation {

static const uint32_t kCapacity = 64;
static const uint32_t kNotificationsPerSlot = 4;
static const size_t kHeaderBytes = 128;
static const size_t kRecordBytes = 192;
static const size_t kWireBytes = kHeaderBytes + kCapacity * kRecordBytes;
static const uint32_t kSchemaVersion = 1;
static const uint32_t kNotificationOverflowFlag = 1u << 2;
static const uint32_t kMpduPresentFlag = 1u << 3;

enum class State : uint32_t {
    kDisabled = 0,
    kArmed = 1,
    kActive = 2,
    kClosed = 3
};

enum class CloseReason : uint32_t {
    kNone = 0,
    kNoStart = 1,
    kEnd = 2,
    kDeadline = 3,
    kStop = 4,
    kGenerationChanged = 5,
    kInvalidBoundary = 6
};

enum class NotificationOutcome : uint8_t {
    kSeen = 1,
    kHeaderRejected = 2,
    kLengthRejected = 3,
    kValidated = 4,
    kMpduDispatch = 5,
    kNonMpdu = 6,
    kAddbufFailed = 7,
    kCopyFailed = 8,
    kNoPacket = 9
};

enum SlotParseFlag : uint8_t {
    kParseHeaderRejected = 1u << 0,
    kParseLengthRejected = 1u << 1,
    kParseValidated = 1u << 2,
    kParseNonMpdu = 1u << 3
};

enum MpduPresenceFlag : uint32_t {
    kChannelPresent = 1u << 0,
    kRawMacPhyPresent = 1u << 1,
    kDecodeModePresent = 1u << 2,
    kFrameControlPresent = 1u << 3,
    kSequenceControlPresent = 1u << 4,
    kRawStatusPresent = 1u << 5,
    kMpduLengthPresent = 1u << 6,
    kDescriptorSizePresent = 1u << 7,
    kPacketOffsetPresent = 1u << 8,
    kHostTimePresent = 1u << 9
};

struct RocEpoch {
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
    uint32_t rocGeneration;
    uint64_t sessionToken;

    RocEpoch()
        : contextGeneration(0), powerGeneration(0), stationGeneration(0),
          rocGeneration(0), sessionToken(0) {}
};

struct Token {
    uint64_t recorderCookie;
    uint64_t sequence;
    uint32_t recordIndex;
    uint8_t valid;

    Token() : recorderCookie(0), sequence(0), recordIndex(0), valid(0) {}
};

struct Notification {
    uint32_t code;
    uint16_t packetOffset;
    uint16_t payloadLength;
    uint16_t packetLength;
    uint8_t qid;
    uint8_t index;
    uint8_t outcome;
    uint8_t flags;

    Notification()
        : code(0), packetOffset(0), payloadLength(0), packetLength(0),
          qid(0), index(0), outcome(0), flags(0) {}
};

struct Mpdu {
    uint32_t presence;
    uint32_t rawStatus;
    uint64_t hostRxMonotonicUs;
    uint16_t sequenceControl;
    uint16_t mpduLength;
    uint16_t descriptorSize;
    uint16_t packetOffset;
    uint8_t channel;
    uint8_t rawMacPhyIndex;
    uint8_t decodeMode;
    uint16_t frameControl;
    uint8_t qid;
    uint8_t index;

    Mpdu()
        : presence(0), rawStatus(0), hostRxMonotonicUs(0),
          sequenceControl(0), mpduLength(0), descriptorSize(0),
          packetOffset(0), channel(0), rawMacPhyIndex(0), decodeMode(0),
          frameControl(0), qid(0), index(0) {}
};

struct SlotInput {
    uint32_t captureSerial;
    uint32_t driverGeneration;
    uint32_t ring;
    uint32_t slot;
    uint32_t head;
    uint64_t copyTimeUs;
    uint32_t copySequence;
    RocEpoch epoch;

    SlotInput()
        : captureSerial(0), driverGeneration(0), ring(0), slot(0), head(0),
          copyTimeUs(0), copySequence(0), epoch() {}
};

class Recorder {
public:
    Recorder() : state_(State::kDisabled), closeReason_(CloseReason::kNone),
        captureSerial_(0), driverGeneration_(0), contextGeneration_(0),
        powerGeneration_(0), stationGeneration_(0), rocGeneration_(0),
        sessionToken_(0), armUs_(0), startUs_(0), deadlineUs_(0), closedUs_(0),
        nextSequence_(0), fullSlots_(0), retained_(0), overflow_(0),
        copySkips_(0), invalid_(0), unfinished_(0), cookie_(1),
        coverageComplete_(false), everStarted_(false), hasLastCopyTime_(false),
        lastCopyTimeUs_(0)
    {
        cookie_ = static_cast<uint64_t>(
            reinterpret_cast<uintptr_t>(this));
        if (cookie_ == 0)
            cookie_ = 1;
        clearRecords();
    }

    Recorder(const Recorder &) = delete;
    Recorder &operator=(const Recorder &) = delete;

    // The first call consumes this recorder even when its arguments are bad.
    // A new ROC epoch can never reuse stale records from an earlier window.
    bool arm(uint32_t captureSerial, uint32_t driverGeneration,
             uint64_t armUs)
    {
        if (state_ != State::kDisabled)
            return false;
        captureSerial_ = captureSerial;
        driverGeneration_ = driverGeneration;
        armUs_ = armUs;
        state_ = State::kArmed;
        if (captureSerial == 0 || driverGeneration == 0 || armUs == 0) {
            invalidate(armUs, CloseReason::kInvalidBoundary);
            return false;
        }
        return true;
    }

    bool beginRoc(const RocEpoch &epoch, uint64_t startUs,
                  uint64_t deadlineUs)
    {
        if (state_ != State::kArmed)
            return rejectMutation();
        if (!validEpoch(epoch) || startUs <= armUs_ ||
            deadlineUs <= startUs) {
            invalidate(startUs, CloseReason::kInvalidBoundary);
            return false;
        }
        setEpoch(epoch);
        startUs_ = startUs;
        deadlineUs_ = deadlineUs;
        everStarted_ = true;
        state_ = State::kActive;
        coverageComplete_ = true;
        return true;
    }

    // Capture the exact CopyResult from this slot iteration. Copy bytes are
    // copied into bounded value storage only when the registry reports kCopied.
    Token beginSlot(const SlotInput &input,
                    const NativeIwxCompletionObserver::CopyResult &copy)
    {
        Token none;
        if (state_ != State::kActive) {
            rejectMutation();
            return none;
        }
        if (input.captureSerial != captureSerial_ ||
            input.driverGeneration != driverGeneration_ ||
            !sameEpoch(input)) {
            invalidate(input.copyTimeUs, CloseReason::kGenerationChanged);
            return none;
        }
        if (input.ring != 0 || input.slot >= 512 || input.head >= 512 ||
            input.copyTimeUs < startUs_ || input.copyTimeUs < armUs_) {
            invalidate(input.copyTimeUs, CloseReason::kInvalidBoundary);
            return none;
        }
        if (input.copyTimeUs >= deadlineUs_) {
            closeAt(CloseReason::kDeadline, input.copyTimeUs);
            return none;
        }
        if (hasLastCopyTime_ && input.copyTimeUs < lastCopyTimeUs_) {
            invalidate(input.copyTimeUs, CloseReason::kInvalidBoundary);
            return none;
        }
        lastCopyTimeUs_ = input.copyTimeUs;
        hasLastCopyTime_ = true;
        increment(fullSlots_);
        if (copy.status != NativeIwxCompletionObserver::CopyStatus::kCopied) {
            increment(copySkips_);
            coverageComplete_ = false;
        }
        if (retained_ >= kCapacity) {
            increment(overflow_);
            coverageComplete_ = false;
            return none;
        }

        const uint32_t index = retained_++;
        Record &record = records_[index];
        record.sequence = ++nextSequence_;
        record.captureSerial = captureSerial_;
        record.driverGeneration = driverGeneration_;
        record.ring = static_cast<uint16_t>(input.ring);
        record.slot = static_cast<uint16_t>(input.slot);
        record.head = static_cast<uint16_t>(input.head);
        record.copyTimeUs = input.copyTimeUs;
        record.copySequence = input.copySequence;
        record.copyStatus = static_cast<uint32_t>(copy.status);
        if (input.copySequence == 0) {
            increment(invalid_);
            coverageComplete_ = false;
        }
        if (copy.status == NativeIwxCompletionObserver::CopyStatus::kCopied) {
            record.copyValid = 1;
            record.mappingIncarnation = copy.snapshot.incarnation;
            for (size_t i = 0;
                 i < NativeIwxCompletionObserver::kCompletionBytes; ++i)
                record.completionBytes[i] = copy.snapshot.bytes[i];
        }
        ++unfinished_;
        none.recorderCookie = cookie_;
        none.sequence = record.sequence;
        none.recordIndex = index;
        none.valid = 1;
        return none;
    }

    bool recordNotification(const Token &token, const Notification &value)
    {
        Record *record = findMutable(token);
        if (!record)
            return false;
        if (value.outcome < static_cast<uint8_t>(NotificationOutcome::kSeen) ||
            value.outcome > static_cast<uint8_t>(NotificationOutcome::kNoPacket)) {
            increment(invalid_);
            coverageComplete_ = false;
            return false;
        }
        if (record->notificationCount >= kNotificationsPerSlot) {
            record->notificationOverflow = 1;
            increment(overflow_);
            coverageComplete_ = false;
            return false;
        }
        record->notifications[record->notificationCount++] = value;
        return true;
    }

    bool recordMpdu(const Token &token, const Mpdu &value)
    {
        Record *record = findMutable(token);
        if (!record)
            return false;
        if (record->mpduPresent) {
            increment(invalid_);
            coverageComplete_ = false;
            return false;
        }
        record->mpdu = value;
        record->mpduPresent = 1;
        return true;
    }

    bool setParseFlags(const Token &token, uint8_t flags)
    {
        const uint8_t allowed = kParseHeaderRejected | kParseLengthRejected |
            kParseValidated | kParseNonMpdu;
        Record *record = findMutable(token);
        if (!record)
            return false;
        if (flags & ~allowed) {
            increment(invalid_);
            coverageComplete_ = false;
            return false;
        }
        record->parseFlags |= flags;
        return true;
    }

    bool finishSlot(const Token &token)
    {
        if (!tokenMatches(token))
            return rejectMutation();
        Record &record = records_[token.recordIndex];
        if (record.finalized)
            return false;
        record.finalized = 1;
        if (unfinished_ != 0)
            --unfinished_;
        return true;
    }

    bool endRoc(const RocEpoch &epoch, uint64_t endUs)
    {
        if (state_ != State::kActive && state_ != State::kArmed)
            return rejectMutation();
        if (!sameEpoch(epoch)) {
            invalidate(endUs, CloseReason::kGenerationChanged);
            return false;
        }
        if (endUs < startUs_ || endUs < armUs_ || endUs < lastCopyTimeUs_ ||
            endUs > deadlineUs_) {
            invalidate(endUs, CloseReason::kInvalidBoundary);
            return false;
        }
        closeAt(CloseReason::kEnd, endUs);
        return true;
    }

    bool closeNoStart(uint64_t nowUs)
    {
        if (state_ != State::kArmed)
            return rejectMutation();
        if (nowUs < armUs_) {
            invalidate(nowUs, CloseReason::kInvalidBoundary);
            return false;
        }
        closeAt(CloseReason::kNoStart, nowUs);
        coverageComplete_ = false;
        return true;
    }

    bool close(CloseReason reason, uint64_t nowUs)
    {
        if (state_ != State::kActive && state_ != State::kArmed)
            return rejectMutation();
        if (reason != CloseReason::kDeadline && reason != CloseReason::kStop &&
            reason != CloseReason::kGenerationChanged &&
            reason != CloseReason::kInvalidBoundary) {
            invalidate(nowUs, CloseReason::kInvalidBoundary);
            return false;
        }
        if ((state_ == State::kActive && nowUs < startUs_) ||
            (state_ == State::kArmed && nowUs < armUs_)) {
            invalidate(nowUs, CloseReason::kInvalidBoundary);
            return false;
        }
        if ((state_ == State::kArmed && reason == CloseReason::kDeadline) ||
            (reason == CloseReason::kDeadline && nowUs < deadlineUs_)) {
            invalidate(nowUs, CloseReason::kInvalidBoundary);
            return false;
        }
        closeAt(reason, nowUs);
        return true;
    }

    // A closed snapshot is stable after all in-flight slot tokens finalize.
    // The one existing token may finish after End; no new content can append.
    bool encode(uint8_t *output, size_t outputBytes) const
    {
        if (!output || outputBytes < kWireBytes || state_ != State::kClosed ||
            unfinished_ != 0)
            return false;
        for (size_t i = 0; i < kWireBytes; ++i)
            output[i] = 0;

        const uint8_t magic[8] = {'I', 'R', 'X', 'R', 'O', 'C', '0', '1'};
        for (size_t i = 0; i < sizeof(magic); ++i)
            output[i] = magic[i];
        put32(output, 8, kSchemaVersion);
        put32(output, 12, static_cast<uint32_t>(kHeaderBytes));
        put32(output, 16, static_cast<uint32_t>(kRecordBytes));
        put32(output, 20, kCapacity);
        put32(output, 24, static_cast<uint32_t>(state_));
        put32(output, 28, static_cast<uint32_t>(closeReason_));
        put32(output, 32, captureSerial_);
        put32(output, 36, driverGeneration_);
        put32(output, 40, contextGeneration_);
        put32(output, 44, powerGeneration_);
        put32(output, 48, stationGeneration_);
        put32(output, 52, rocGeneration_);
        put64(output, 56, sessionToken_);
        put64(output, 64, armUs_);
        put64(output, 72, startUs_);
        put64(output, 80, deadlineUs_);
        put64(output, 88, closedUs_);
        put32(output, 96, fullSlots_);
        put32(output, 100, retained_);
        put32(output, 104, overflow_);
        put32(output, 108, copySkips_);
        put32(output, 112, invalid_);
        put32(output, 116, unfinished_);
        put32(output, 120, coverageComplete() ? 1u : 0u);
        put32(output, 124, retained_);

        for (uint32_t i = 0; i < retained_; ++i)
            encodeRecord(records_[i], output + kHeaderBytes + i * kRecordBytes);
        return true;
    }

    State state() const { return state_; }
    CloseReason closeReason() const { return closeReason_; }
    uint32_t fullSlots() const { return fullSlots_; }
    uint32_t retained() const { return retained_; }
    uint32_t overflow() const { return overflow_; }
    uint32_t copySkips() const { return copySkips_; }
    uint32_t invalid() const { return invalid_; }
    uint32_t unfinished() const { return unfinished_; }
    bool coverageComplete() const
    {
        return coverageComplete_ && state_ == State::kClosed &&
            closeReason_ == CloseReason::kEnd && unfinished_ == 0;
    }
    bool hasStarted() const { return everStarted_; }
    bool readyToEncode() const
    {
        return state_ == State::kClosed && unfinished_ == 0;
    }

private:
    struct Record {
        uint64_t sequence;
        uint64_t copyTimeUs;
        uint64_t mappingIncarnation;
        uint32_t captureSerial;
        uint32_t driverGeneration;
        uint32_t head;
        uint32_t copyStatus;
        uint16_t ring;
        uint16_t slot;
        uint8_t copyValid;
        uint8_t finalized;
        uint8_t notificationCount;
        uint8_t notificationOverflow;
        uint8_t parseFlags;
        uint8_t mpduPresent;
        uint8_t completionBytes[NativeIwxCompletionObserver::kCompletionBytes];
        uint32_t copySequence;
        Notification notifications[kNotificationsPerSlot];
        Mpdu mpdu;
    };

    static void increment(uint32_t &value)
    {
        if (value != UINT32_MAX)
            ++value;
    }

    static void put16(uint8_t *bytes, size_t offset, uint16_t value)
    {
        bytes[offset] = static_cast<uint8_t>(value);
        bytes[offset + 1] = static_cast<uint8_t>(value >> 8);
    }

    static void put32(uint8_t *bytes, size_t offset, uint32_t value)
    {
        for (unsigned i = 0; i < 4; ++i)
            bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
    }

    static void put64(uint8_t *bytes, size_t offset, uint64_t value)
    {
        for (unsigned i = 0; i < 8; ++i)
            bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
    }

    static bool validEpoch(const RocEpoch &epoch)
    {
        return epoch.contextGeneration != 0 && epoch.powerGeneration != 0 &&
            epoch.stationGeneration != 0 && epoch.rocGeneration != 0 &&
            epoch.sessionToken != 0;
    }

    bool sameEpoch(const RocEpoch &epoch) const
    {
        return epoch.contextGeneration == contextGeneration_ &&
            epoch.powerGeneration == powerGeneration_ &&
            epoch.stationGeneration == stationGeneration_ &&
            epoch.rocGeneration == rocGeneration_ &&
            epoch.sessionToken == sessionToken_;
    }

    bool sameEpoch(const SlotInput &input) const
    {
        return input.captureSerial == captureSerial_ &&
            input.driverGeneration == driverGeneration_ &&
            sameEpoch(input.epoch);
    }

    void setEpoch(const RocEpoch &epoch)
    {
        contextGeneration_ = epoch.contextGeneration;
        powerGeneration_ = epoch.powerGeneration;
        stationGeneration_ = epoch.stationGeneration;
        rocGeneration_ = epoch.rocGeneration;
        sessionToken_ = epoch.sessionToken;
    }

    void clearRecords()
    {
        for (uint32_t i = 0; i < kCapacity; ++i)
            records_[i] = Record{};
    }

    void closeAt(CloseReason reason, uint64_t nowUs)
    {
        closeReason_ = reason;
        closedUs_ = nowUs;
        state_ = State::kClosed;
        if (reason != CloseReason::kEnd)
            coverageComplete_ = false;
    }

    void invalidate(uint64_t nowUs, CloseReason reason)
    {
        increment(invalid_);
        coverageComplete_ = false;
        if (state_ != State::kClosed)
            closeAt(reason, nowUs);
    }

    bool rejectMutation()
    {
        // Published/closed records remain immutable. The caller gets a false
        // return, while the already closed snapshot stays byte-for-byte stable.
        if (state_ != State::kClosed) {
            increment(invalid_);
            coverageComplete_ = false;
        }
        return false;
    }

    bool tokenMatches(const Token &token) const
    {
        return token.valid && token.recorderCookie == cookie_ &&
            token.recordIndex < retained_ &&
            records_[token.recordIndex].sequence == token.sequence;
    }

    Record *findMutable(const Token &token)
    {
        if (!tokenMatches(token)) {
            rejectMutation();
            return nullptr;
        }
        if (records_[token.recordIndex].finalized) {
            rejectMutation();
            return nullptr;
        }
        if (state_ != State::kActive && state_ != State::kClosed)
            return nullptr;
        // A closed window accepts no late parsing mutations. finishSlot is
        // the sole operation allowed to settle a token that was already open.
        // Record the rejected late write while that token remains in flight,
        // then leave the terminal snapshot frozen after finishSlot.
        if (state_ == State::kClosed) {
            if (unfinished_ != 0) {
                increment(invalid_);
                coverageComplete_ = false;
            }
            return nullptr;
        }
        return &records_[token.recordIndex];
    }

    void encodeRecord(const Record &record, uint8_t *out) const
    {
        put64(out, 0, record.sequence);
        put64(out, 8, record.copyTimeUs);
        put64(out, 16, record.mappingIncarnation);
        put32(out, 24, record.captureSerial);
        put32(out, 28, record.driverGeneration);
        put16(out, 32, record.ring);
        put16(out, 34, record.slot);
        put16(out, 36, static_cast<uint16_t>(record.head));
        uint16_t recordFlags = 0;
        if (record.finalized)
            recordFlags |= 1u << 0;
        if (record.copyValid)
            recordFlags |= 1u << 1;
        if (record.notificationOverflow)
            recordFlags |= kNotificationOverflowFlag;
        if (record.mpduPresent)
            recordFlags |= kMpduPresentFlag;
        put16(out, 38, recordFlags);
        put32(out, 40, record.copyStatus);
        for (size_t i = 0;
             i < NativeIwxCompletionObserver::kCompletionBytes; ++i)
            out[44 + i] = record.copyValid ? record.completionBytes[i] : 0;
        out[52] = record.notificationCount;
        out[53] = record.notificationOverflow;
        out[54] = record.parseFlags;
        out[55] = 0;

        for (uint32_t i = 0; i < record.notificationCount; ++i) {
            const Notification &note = record.notifications[i];
            const size_t offset = 56 + i * 16;
            out[offset] = note.qid;
            out[offset + 1] = note.index;
            out[offset + 2] = note.outcome;
            out[offset + 3] = note.flags;
            put32(out, offset + 4, note.code);
            put16(out, offset + 8, note.packetOffset);
            put16(out, offset + 10, note.payloadLength);
            put16(out, offset + 12, note.packetLength);
            put16(out, offset + 14, 0);
        }

        const Mpdu &mpdu = record.mpdu;
        if (record.mpduPresent) {
            put32(out, 120, mpdu.presence);
            out[124] = mpdu.channel;
            out[125] = mpdu.rawMacPhyIndex;
            out[126] = mpdu.decodeMode;
            put16(out, 128, mpdu.frameControl);
            put16(out, 130, mpdu.sequenceControl);
            put16(out, 132, mpdu.mpduLength);
            put16(out, 134, mpdu.descriptorSize);
            put16(out, 136, mpdu.packetOffset);
            out[138] = mpdu.qid;
            out[139] = mpdu.index;
            put32(out, 140, mpdu.rawStatus);
            put64(out, 144, mpdu.hostRxMonotonicUs);
        }
        put32(out, 152, record.copySequence);
        // Bytes 156..191 remain zero for versioned future use.
    }

    State state_;
    CloseReason closeReason_;
    uint32_t captureSerial_;
    uint32_t driverGeneration_;
    uint32_t contextGeneration_;
    uint32_t powerGeneration_;
    uint32_t stationGeneration_;
    uint32_t rocGeneration_;
    uint64_t sessionToken_;
    uint64_t armUs_;
    uint64_t startUs_;
    uint64_t deadlineUs_;
    uint64_t closedUs_;
    uint64_t nextSequence_;
    uint32_t fullSlots_;
    uint32_t retained_;
    uint32_t overflow_;
    uint32_t copySkips_;
    uint32_t invalid_;
    uint32_t unfinished_;
    uint64_t cookie_;
    bool coverageComplete_;
    bool everStarted_;
    bool hasLastCopyTime_;
    uint64_t lastCopyTimeUs_;
    Record records_[kCapacity];
};

} // namespace NativeIwxRocRxCorrelation

#endif // NATIVE_IWX_ROC_RX_CORRELATION_HPP
