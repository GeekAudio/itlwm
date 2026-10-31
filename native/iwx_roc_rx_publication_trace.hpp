// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_IWX_ROC_RX_PUBLICATION_TRACE_HPP
#define NATIVE_IWX_ROC_RX_PUBLICATION_TRACE_HPP

#include <stdint.h>

// Scalar diagnostics for the bounded ROC correlation publisher. This is not
// part of the RX admission path: gateAttempt()/noteGateResult() are called by
// the watchdog immediately around its synchronous attemptAction(), and every
// other field is only updated from the corresponding main-gate action.
namespace NativeIwxRocRxPublicationTrace {

static const uint32_t kSchemaVersion = 1;

enum class Stage : uint32_t {
    kUnobserved = 0,
    kGateUnavailable = 1,
    kRecorderNotReady = 2,
    kEncodeFailed = 3,
    kAllocationFailed = 4,
    kPropertyWriteFailed = 5,
    kPublished = 6,
    kRetryExhausted = 7
};

struct Snapshot {
    uint32_t stage;
    uint32_t recorderState;
    uint32_t closeReason;
    uint32_t unfinished;
    uint32_t readyToEncode;
    uint32_t encodeSucceeded;
    uint32_t allocationSucceeded;
    uint32_t propertyWriteSucceeded;
    uint32_t published;
    uint32_t payloadAttempts;
    uint32_t gateAttempts;
    uint32_t gateEntries;
    uint32_t gateResult;
    uint32_t gateResultValid;
    uint32_t captureSerial;
    uint32_t driverGeneration;
    uint64_t armUs;

    Snapshot()
        : stage(static_cast<uint32_t>(Stage::kUnobserved)), recorderState(0),
          closeReason(0), unfinished(0), readyToEncode(0),
          encodeSucceeded(0), allocationSucceeded(0),
          propertyWriteSucceeded(0), published(0), payloadAttempts(0),
          gateAttempts(0), gateEntries(0), gateResult(0),
          gateResultValid(0), captureSerial(0), driverGeneration(0),
          armUs(0) {}

    static uint32_t saturate8(uint32_t value)
    {
        return value > 0xffu ? 0xffu : value;
    }

    // Packed scalar layout, low to high:
    // schema[0:7], stage[8:15], recorder[16:17], close[18:21],
    // unfinished[22:29], ready[30], encoded[31], allocated[32],
    // property-write[33], published[34], payload-attempts[35:36],
    // gate-attempts[37:44], gate-entries[45:52], gate-result-valid[53].
    // The exact IOReturn and capture identity are exported separately.
    uint64_t packed() const
    {
        uint64_t value = uint64_t(kSchemaVersion) |
            (uint64_t(stage & 0xffu) << 8) |
            (uint64_t(recorderState & 0x3u) << 16) |
            (uint64_t(closeReason & 0xfu) << 18) |
            (uint64_t(saturate8(unfinished)) << 22) |
            (uint64_t(readyToEncode != 0) << 30) |
            (uint64_t(encodeSucceeded != 0) << 31) |
            (uint64_t(allocationSucceeded != 0) << 32) |
            (uint64_t(propertyWriteSucceeded != 0) << 33) |
            (uint64_t(published != 0) << 34) |
            (uint64_t(payloadAttempts > 3u ? 3u : payloadAttempts) << 35) |
            (uint64_t(saturate8(gateAttempts)) << 37) |
            (uint64_t(saturate8(gateEntries)) << 45) |
            (uint64_t(gateResultValid != 0) << 53);
        return value;
    }

    uint64_t identity() const
    {
        return (uint64_t(driverGeneration) << 32) | uint64_t(captureSerial);
    }
};

inline void incrementSaturated(uint32_t &value)
{
    if (value != UINT32_MAX)
        ++value;
}

} // namespace NativeIwxRocRxPublicationTrace

#endif // NATIVE_IWX_ROC_RX_PUBLICATION_TRACE_HPP
