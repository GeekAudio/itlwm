// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_INTEL_GP2_CLOCK_HPP
#define NATIVE_INTEL_GP2_CLOCK_HPP

#include <stdint.h>

namespace IntelGp2Clock {

constexpr uint32_t kHalfRangeUs = 0x80000000u;
constexpr uint64_t kPpmScale = 1000000ULL;

// These limits are supplied by the caller only after their provenance has
// been established. The type deliberately has no default constructor: a
// mapper must never silently claim a hardware drift or uncertainty bound.
struct MappingLimits {
    MappingLimits(uint64_t maxBracketUs,
                  uint64_t maxSampleAgeUs,
                  uint64_t maxUncertaintyUs,
                  uint32_t driftBoundPpm,
                  bool driftBoundVerified);

    uint64_t maxBracketUs;
    uint64_t maxSampleAgeUs;
    uint64_t maxUncertaintyUs;
    uint32_t driftBoundPpm;
    bool driftBoundVerified;
};

enum class SampleOrigin : uint8_t {
    kUnknown = 0,
    // Host monotonic timestamps bracketed the actual GP2 read while the
    // caller held the NIC lock. No implementation of that hardware read is
    // provided here; this is a contract token for a future caller.
    kDirectGp2ReadBracket = 1,
    // A host timestamp taken after descriptor/RX processing is not a clock
    // witness and is rejected by Observe().
    kLateRxHostTimestamp = 2,
};

struct BracketedSample {
    uint32_t gp2Us;
    uint64_t hostBeforeUs;
    uint64_t hostAfterUs;
    uint64_t generation;
    SampleOrigin origin;
    bool nicLockHeldAtRead;
};

struct HostInterval {
    uint64_t earliestUs;
    uint64_t latestUs;
};

enum class Status : uint8_t {
    kOk = 0,
    kInvalidArgument,
    kInvalidLimits,
    kNoGeneration,
    kGenerationOrder,
    kGenerationMismatch,
    kInvalidWitness,
    kInvalidBracket,
    kBracketTooWide,
    kHostOrderViolation,
    kGp2OrderViolation,
    kAmbiguousGp2Delta,
    kSampleTooStale,
    kDriftBoundViolation,
    kTooUncertain,
    kArithmeticOverflow,
};

enum class InvalidationReason : uint8_t {
    kSleep = 0,
    kFirmwareReset,
    kDriverReset,
    kPowerTransition,
    kExplicit,
};

class Mapper {
public:
    explicit Mapper(const MappingLimits& limits);
    Mapper() = delete;

    // Every sleep/reset/power epoch must start with a strictly newer,
    // nonzero generation. Starting a generation clears any previous map.
    Status beginGeneration(uint64_t generation);
    void invalidate(InvalidationReason reason);

    // Accepts only a direct-read host bracket with an explicit witness.
    // Rejected ordering/reset evidence invalidates the current generation.
    Status observe(const BracketedSample& sample);

    // Maps a forward GP2 counter value from the newest accepted sample into
    // a host monotonic interval. output is cleared on failure.
    Status map(uint32_t gp2Us,
               uint64_t hostNowUs,
               uint64_t generation,
               HostInterval* output) const;

    bool hasAnchor() const;
    bool hasGeneration() const;
    uint64_t activeGeneration() const;

private:
    bool limitsValid() const;
    void clearActiveGeneration();

    MappingLimits limits_;
    BracketedSample anchor_;
    uint64_t activeGeneration_;
    uint64_t lastGeneration_;
    bool hasAnchor_;
    bool hasGeneration_;
    bool hasLastGeneration_;
};

} // namespace IntelGp2Clock

#endif // NATIVE_INTEL_GP2_CLOCK_HPP
