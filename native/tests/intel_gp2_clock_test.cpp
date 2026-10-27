// SPDX-License-Identifier: GPL-2.0-only
#include "../intel_gp2_clock.hpp"

#include <cassert>
#include <cstdint>
#include <limits>

using namespace IntelGp2Clock;

static MappingLimits Limits(uint64_t maxBracket = 20,
                            uint64_t maxAge = 1000000,
                            uint64_t maxUncertainty = 10000,
                            uint32_t driftPpm = 100,
                            bool verified = true)
{
    return MappingLimits(maxBracket, maxAge, maxUncertainty,
                         driftPpm, verified);
}

static BracketedSample DirectSample(uint32_t gp2,
                                    uint64_t before,
                                    uint64_t after,
                                    uint64_t generation = 1)
{
    BracketedSample sample{};
    sample.gp2Us = gp2;
    sample.hostBeforeUs = before;
    sample.hostAfterUs = after;
    sample.generation = generation;
    sample.origin = SampleOrigin::kDirectGp2ReadBracket;
    sample.nicLockHeldAtRead = true;
    return sample;
}

static void TestBracketAndDriftBounds()
{
    Mapper mapper(Limits());
    assert(mapper.beginGeneration(1) == Status::kOk);
    assert(mapper.observe(DirectSample(1000, 5000, 5004)) == Status::kOk);

    HostInterval interval{};
    assert(mapper.map(1000, 5004, 1, &interval) == Status::kOk);
    assert(interval.earliestUs == 5000);
    assert(interval.latestUs == 5004);

    assert(mapper.map(1001000, 6000, 1, &interval) == Status::kOk);
    assert(interval.earliestUs == 1004900);
    assert(interval.latestUs == 1005105);
}

static void TestModuloWrapAndHalfRange()
{
    Mapper mapper(Limits(10, 1000, 100, 0));
    assert(mapper.beginGeneration(1) == Status::kOk);
    assert(mapper.observe(DirectSample(0xfffffff0u, 100, 102)) == Status::kOk);

    HostInterval interval{};
    assert(mapper.map(0x00000010u, 102, 1, &interval) == Status::kOk);
    assert(interval.earliestUs == 132);
    assert(interval.latestUs == 134);

    assert(mapper.map(0x7ffffff0u, 102, 1, &interval) ==
           Status::kAmbiguousGp2Delta);
    assert(interval.earliestUs == 0 && interval.latestUs == 0);
}

static void TestMissingOrLateWitnessFailsClosed()
{
    Mapper mapper(Limits());
    assert(mapper.beginGeneration(1) == Status::kOk);

    BracketedSample sample = DirectSample(10, 100, 101);
    sample.origin = SampleOrigin::kUnknown;
    assert(mapper.observe(sample) == Status::kInvalidWitness);
    assert(!mapper.hasAnchor());
    assert(!mapper.hasGeneration());

    assert(mapper.beginGeneration(2) == Status::kOk);
    sample = DirectSample(10, 100, 101, 2);
    sample.origin = SampleOrigin::kLateRxHostTimestamp;
    assert(mapper.observe(sample) == Status::kInvalidWitness);
    assert(!mapper.hasAnchor());

    assert(mapper.beginGeneration(3) == Status::kOk);
    sample = DirectSample(10, 100, 101, 3);
    sample.nicLockHeldAtRead = false;
    assert(mapper.observe(sample) == Status::kInvalidWitness);
    assert(!mapper.hasAnchor());
}

static void TestLimitsAreExplicitAndBounded()
{
    Mapper unverified(Limits(20, 1000, 1000, 50, false));
    assert(unverified.beginGeneration(1) == Status::kOk);
    assert(unverified.observe(DirectSample(10, 100, 101)) ==
           Status::kInvalidLimits);

    Mapper halfRangeAge(Limits(20, kHalfRangeUs, 1000, 50, true));
    assert(halfRangeAge.beginGeneration(1) == Status::kOk);
    assert(halfRangeAge.observe(DirectSample(10, 100, 101)) ==
           Status::kInvalidLimits);

    Mapper ppmOutOfRange(Limits(20, 1000, 1000, 1000000, true));
    assert(ppmOutOfRange.beginGeneration(1) == Status::kOk);
    assert(ppmOutOfRange.observe(DirectSample(10, 100, 101)) ==
           Status::kInvalidLimits);

    Mapper bracketExceedsUncertainty(Limits(21, 1000, 20, 50, true));
    assert(bracketExceedsUncertainty.beginGeneration(1) == Status::kOk);
    assert(bracketExceedsUncertainty.observe(DirectSample(10, 100, 101)) ==
           Status::kInvalidLimits);
}

static void TestBracketAndOrderFaultsInvalidate()
{
    Mapper wide(Limits(2, 1000, 1000, 0));
    assert(wide.beginGeneration(1) == Status::kOk);
    assert(wide.observe(DirectSample(10, 100, 103)) ==
           Status::kBracketTooWide);
    assert(!wide.hasGeneration());

    Mapper overlap(Limits(10, 1000, 1000, 0));
    assert(overlap.beginGeneration(1) == Status::kOk);
    assert(overlap.observe(DirectSample(10, 100, 102)) == Status::kOk);
    assert(overlap.observe(DirectSample(20, 102, 103)) ==
           Status::kHostOrderViolation);
    assert(!overlap.hasAnchor());

    Mapper counterBackwards(Limits(10, 1000, 1000, 0));
    assert(counterBackwards.beginGeneration(1) == Status::kOk);
    assert(counterBackwards.observe(DirectSample(100, 100, 102)) ==
           Status::kOk);
    assert(counterBackwards.observe(DirectSample(99, 103, 104)) ==
           Status::kAmbiguousGp2Delta);
    assert(!counterBackwards.hasGeneration());
}

static void TestVerifiedDriftBoundAndStaleness()
{
    Mapper mismatch(Limits(10, 100000, 1000, 0));
    assert(mismatch.beginGeneration(1) == Status::kOk);
    assert(mismatch.observe(DirectSample(100, 1000, 1001)) == Status::kOk);
    // With a verified 0 ppm bound, one GP2 usec cannot cover a 100 us host gap.
    assert(mismatch.observe(DirectSample(101, 1101, 1102)) ==
           Status::kDriftBoundViolation);
    assert(!mismatch.hasGeneration());

    Mapper stale(Limits(10, 100, 1000, 100));
    assert(stale.beginGeneration(1) == Status::kOk);
    assert(stale.observe(DirectSample(100, 1000, 1001)) == Status::kOk);
    HostInterval interval{};
    assert(stale.map(101, 1101, 1, &interval) == Status::kOk);
    assert(stale.map(101, 1101, 2, &interval) ==
           Status::kGenerationMismatch);
    assert(stale.map(101, 1200, 1, &interval) == Status::kSampleTooStale);
}

static void TestUncertaintyCapAndArithmeticOverflow()
{
    Mapper uncertain(Limits(10, 1000000, 100, 1000));
    assert(uncertain.beginGeneration(1) == Status::kOk);
    assert(uncertain.observe(DirectSample(0, 100, 110)) == Status::kOk);
    HostInterval interval{};
    assert(uncertain.map(1000000, 110, 1, &interval) ==
           Status::kTooUncertain);
    assert(interval.earliestUs == 0 && interval.latestUs == 0);

    Mapper overflow(Limits(10, 1000, 1000, 0));
    assert(overflow.beginGeneration(1) == Status::kOk);
    const uint64_t max = std::numeric_limits<uint64_t>::max();
    assert(overflow.observe(DirectSample(10, max - 10, max - 9)) ==
           Status::kOk);
    assert(overflow.map(20, max, 1, &interval) ==
           Status::kArithmeticOverflow);
    assert(interval.earliestUs == 0 && interval.latestUs == 0);
}

static void TestSleepResetGenerationInvalidation()
{
    Mapper mapper(Limits());
    assert(mapper.beginGeneration(5) == Status::kOk);
    assert(mapper.observe(DirectSample(10, 100, 101, 5)) == Status::kOk);
    mapper.invalidate(InvalidationReason::kSleep);
    assert(!mapper.hasAnchor());
    assert(!mapper.hasGeneration());

    HostInterval interval{};
    assert(mapper.map(11, 102, 5, &interval) == Status::kNoGeneration);
    assert(mapper.beginGeneration(5) == Status::kGenerationOrder);
    assert(mapper.beginGeneration(6) == Status::kOk);
    assert(mapper.observe(DirectSample(11, 200, 201, 5)) ==
           Status::kGenerationMismatch);
    assert(mapper.beginGeneration(7) == Status::kOk);
    assert(mapper.observe(DirectSample(11, 200, 201, 7)) == Status::kOk);
}

int main()
{
    TestBracketAndDriftBounds();
    TestModuloWrapAndHalfRange();
    TestMissingOrLateWitnessFailsClosed();
    TestLimitsAreExplicitAndBounded();
    TestBracketAndOrderFaultsInvalidate();
    TestVerifiedDriftBoundAndStaleness();
    TestUncertaintyCapAndArithmeticOverflow();
    TestSleepResetGenerationInvalidation();
    return 0;
}
