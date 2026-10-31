#include "../rx149_live_start_snapshot.hpp"

#include <assert.h>
#include <string.h>

using namespace NativeRx149LiveStart;

static Snapshot validSnapshot()
{
    Snapshot value{};
    value.magic = kMagic;
    value.schemaVersion = kSchemaVersion;
    value.revision = 2;
    value.valid = 1;
    for (size_t index = 0; index < kRunTokenBytes; ++index)
        value.runToken[index] = static_cast<uint8_t>(index + 1);
    value.profileMode = kRx149ArmMode;
    value.channel = kChannel;
    value.durationMs = kDurationMs;
    value.configuration = kDeviceDiscoveryConfiguration;
    value.commandResult = 0;
    value.startSeen = 1;
    value.startStatus = 1;
    value.ownerSerial = 17;
    value.contextGeneration = 21;
    value.powerGeneration = 22;
    value.stationGeneration = 23;
    value.rocGeneration = 21;
    value.startObservedUs = 1000000;
    value.hardDeadlineUs = value.startObservedUs + kDurationUs;
    value.publishedUs = value.startObservedUs + 1000;
    return value;
}

int main()
{
    auto value = validSnapshot();
    assert(currentStarted(value, 1010000, 50000));
    assert(!currentStarted(value, 1010000, 90001));
    assert(!currentStarted(value, 1000500, 0)); // publication cannot precede START
    assert(!currentStarted(value, value.hardDeadlineUs, 0));

    uint8_t bytes[kWireBytes]{};
    assert(encode(value, bytes, sizeof(bytes)));
    Snapshot decoded{};
    assert(decode(bytes, sizeof(bytes), &decoded));
    assert(decoded.revision == value.revision);
    assert(decoded.ownerSerial == value.ownerSerial);
    assert(decoded.startObservedUs == value.startObservedUs);
    assert(decoded.hardDeadlineUs == value.hardDeadlineUs);
    assert(memcmp(decoded.runToken, value.runToken, kRunTokenBytes) == 0);
    assert(currentStarted(decoded, 1010000, 50000));
    assert(!decode(bytes, sizeof(bytes) - 1, &decoded));

    auto stale = value;
    stale.revision = 3;
    assert(!currentStarted(stale, 1010000, 0));
    stale = value;
    stale.rocGeneration++;
    assert(!currentStarted(stale, 1010000, 0));
    stale = value;
    stale.endSeen = 1;
    assert(!currentStarted(stale, 1010000, 0));
    stale = value;
    stale.outcomeUnknown = 1;
    assert(!currentStarted(stale, 1010000, 0));
    stale = value;
    stale.configuration++;
    assert(!currentStarted(stale, 1010000, 0));
    stale = value;
    stale.powerGeneration = 0;
    assert(!currentStarted(stale, 1010000, 0));
    stale = value;
    stale.startObservedUs = UINT64_MAX - 10;
    stale.hardDeadlineUs = UINT64_MAX;
    assert(!currentStarted(stale, 1010000, 0));
    stale = value;
    stale.publishedUs = stale.startObservedUs - 1;
    assert(!currentStarted(stale, 1010000, 0));

    value.valid = 0;
    assert(!currentStarted(value, 1010000, 0));
    return 0;
}
