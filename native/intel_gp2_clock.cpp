// SPDX-License-Identifier: GPL-2.0-only
#include "intel_gp2_clock.hpp"

namespace IntelGp2Clock {
namespace {

bool ScaleElapsedUs(uint32_t gp2DeltaUs,
                    uint32_t driftBoundPpm,
                    uint64_t* earliestHostDeltaUs,
                    uint64_t* latestHostDeltaUs)
{
    if (!earliestHostDeltaUs || !latestHostDeltaUs ||
        driftBoundPpm >= kPpmScale)
        return false;

    // MappingLimits caps the GP2 horizon below half range, so this product
    // remains below 2^31 * 10^6 and is representable in uint64_t.
    const uint64_t numerator =
        static_cast<uint64_t>(gp2DeltaUs) * kPpmScale;
    const uint64_t fastDenominator = kPpmScale + driftBoundPpm;
    const uint64_t slowDenominator = kPpmScale - driftBoundPpm;

    *earliestHostDeltaUs = numerator / fastDenominator;

    // Round the upper bound outward. numerator + denominator - 1 is safe
    // under the same half-range cap used by limitsValid().
    *latestHostDeltaUs =
        (numerator + slowDenominator - 1) / slowDenominator;
    return true;
}

bool AddChecked(uint64_t a, uint64_t b, uint64_t* sum)
{
    if (!sum || a > UINT64_MAX - b)
        return false;
    *sum = a + b;
    return true;
}

bool IntervalWidth(const HostInterval& interval, uint64_t* width)
{
    if (!width || interval.latestUs < interval.earliestUs)
        return false;
    *width = interval.latestUs - interval.earliestUs;
    return true;
}

} // namespace

MappingLimits::MappingLimits(uint64_t maxBracket,
                             uint64_t maxAge,
                             uint64_t maxUncertainty,
                             uint32_t driftPpm,
                             bool verified)
    : maxBracketUs(maxBracket),
      maxSampleAgeUs(maxAge),
      maxUncertaintyUs(maxUncertainty),
      driftBoundPpm(driftPpm),
      driftBoundVerified(verified)
{
}

Mapper::Mapper(const MappingLimits& limits)
    : limits_(limits),
      anchor_{},
      activeGeneration_(0),
      lastGeneration_(0),
      hasAnchor_(false),
      hasGeneration_(false),
      hasLastGeneration_(false)
{
}

bool Mapper::limitsValid() const
{
    return limits_.driftBoundVerified &&
           limits_.maxBracketUs > 0 &&
           limits_.maxSampleAgeUs > 0 &&
           limits_.maxSampleAgeUs < kHalfRangeUs &&
           limits_.maxUncertaintyUs > 0 &&
           limits_.maxBracketUs <= limits_.maxUncertaintyUs &&
           limits_.driftBoundPpm < kPpmScale;
}

void Mapper::clearActiveGeneration()
{
    if (hasGeneration_) {
        lastGeneration_ = activeGeneration_;
        hasLastGeneration_ = true;
    }
    activeGeneration_ = 0;
    hasGeneration_ = false;
    hasAnchor_ = false;
    anchor_ = {};
}

Status Mapper::beginGeneration(uint64_t generation)
{
    clearActiveGeneration();

    if (!generation ||
        (hasLastGeneration_ && generation <= lastGeneration_))
        return Status::kGenerationOrder;

    activeGeneration_ = generation;
    hasGeneration_ = true;
    return Status::kOk;
}

void Mapper::invalidate(InvalidationReason reason)
{
    (void)reason;
    clearActiveGeneration();
}

Status Mapper::observe(const BracketedSample& sample)
{
    if (!limitsValid())
        return Status::kInvalidLimits;
    if (!hasGeneration_)
        return Status::kNoGeneration;
    if (sample.generation != activeGeneration_) {
        clearActiveGeneration();
        return Status::kGenerationMismatch;
    }
    if (sample.origin != SampleOrigin::kDirectGp2ReadBracket ||
        !sample.nicLockHeldAtRead) {
        clearActiveGeneration();
        return Status::kInvalidWitness;
    }
    if (sample.hostAfterUs < sample.hostBeforeUs) {
        clearActiveGeneration();
        return Status::kInvalidBracket;
    }

    const uint64_t bracketUs = sample.hostAfterUs - sample.hostBeforeUs;
    if (bracketUs > limits_.maxBracketUs) {
        clearActiveGeneration();
        return Status::kBracketTooWide;
    }

    if (!hasAnchor_) {
        anchor_ = sample;
        hasAnchor_ = true;
        return Status::kOk;
    }

    if (sample.hostBeforeUs <= anchor_.hostAfterUs) {
        clearActiveGeneration();
        return Status::kHostOrderViolation;
    }

    const uint32_t gp2Delta = sample.gp2Us - anchor_.gp2Us;
    if (gp2Delta == 0) {
        clearActiveGeneration();
        return Status::kGp2OrderViolation;
    }
    if (gp2Delta >= kHalfRangeUs) {
        clearActiveGeneration();
        return Status::kAmbiguousGp2Delta;
    }

    // Both host brackets are treated as intervals. The possible time between
    // their GP2 read instants is [next.before - prev.after,
    // next.after - prev.before].
    const uint64_t observedHostMin =
        sample.hostBeforeUs - anchor_.hostAfterUs;
    const uint64_t observedHostMax =
        sample.hostAfterUs - anchor_.hostBeforeUs;
    if (gp2Delta > limits_.maxSampleAgeUs ||
        observedHostMax > limits_.maxSampleAgeUs) {
        clearActiveGeneration();
        return Status::kSampleTooStale;
    }

    uint64_t expectedHostMin = 0;
    uint64_t expectedHostMax = 0;
    if (!ScaleElapsedUs(gp2Delta, limits_.driftBoundPpm,
                        &expectedHostMin, &expectedHostMax)) {
        clearActiveGeneration();
        return Status::kInvalidLimits;
    }
    if (observedHostMax < expectedHostMin ||
        observedHostMin > expectedHostMax) {
        clearActiveGeneration();
        return Status::kDriftBoundViolation;
    }

    anchor_ = sample;
    hasAnchor_ = true;
    return Status::kOk;
}

Status Mapper::map(uint32_t gp2Us,
                   uint64_t hostNowUs,
                   uint64_t generation,
                   HostInterval* output) const
{
    if (!output)
        return Status::kInvalidArgument;
    *output = {};

    if (!limitsValid())
        return Status::kInvalidLimits;
    if (!hasGeneration_ || !hasAnchor_)
        return Status::kNoGeneration;
    if (generation != activeGeneration_)
        return Status::kGenerationMismatch;
    if (hostNowUs < anchor_.hostAfterUs)
        return Status::kHostOrderViolation;

    const uint64_t anchorAgeUs = hostNowUs - anchor_.hostAfterUs;
    if (anchorAgeUs > limits_.maxSampleAgeUs)
        return Status::kSampleTooStale;

    const uint32_t gp2Delta = gp2Us - anchor_.gp2Us;
    if (gp2Delta >= kHalfRangeUs)
        return Status::kAmbiguousGp2Delta;
    if (gp2Delta > limits_.maxSampleAgeUs)
        return Status::kSampleTooStale;

    uint64_t elapsedMinUs = 0;
    uint64_t elapsedMaxUs = 0;
    if (!ScaleElapsedUs(gp2Delta, limits_.driftBoundPpm,
                        &elapsedMinUs, &elapsedMaxUs))
        return Status::kInvalidLimits;

    HostInterval mapped{};
    if (!AddChecked(anchor_.hostBeforeUs, elapsedMinUs,
                    &mapped.earliestUs) ||
        !AddChecked(anchor_.hostAfterUs, elapsedMaxUs,
                    &mapped.latestUs))
        return Status::kArithmeticOverflow;

    uint64_t uncertaintyUs = 0;
    if (!IntervalWidth(mapped, &uncertaintyUs))
        return Status::kArithmeticOverflow;
    if (uncertaintyUs > limits_.maxUncertaintyUs)
        return Status::kTooUncertain;

    if (hostNowUs > mapped.latestUs &&
        hostNowUs - mapped.latestUs > limits_.maxSampleAgeUs)
        return Status::kSampleTooStale;

    *output = mapped;
    return Status::kOk;
}

bool Mapper::hasAnchor() const
{
    return hasAnchor_;
}

bool Mapper::hasGeneration() const
{
    return hasGeneration_;
}

uint64_t Mapper::activeGeneration() const
{
    return activeGeneration_;
}

} // namespace IntelGp2Clock
