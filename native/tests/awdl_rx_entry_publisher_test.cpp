#include "../awdl_rx_entry_publisher.hpp"

#include <assert.h>
#include <map>
#include <string>

struct Snapshot {
    uint32_t schema {1};
    uint32_t context {0};
    uint32_t count {0};
};

static bool same(const Snapshot &a, const Snapshot &b)
{
    return a.schema == b.schema && a.context == b.context && a.count == b.count;
}

struct FakeRegistry {
    explicit FakeRegistry(unsigned failCall = 0) : failCall(failCall) {}

    bool write(const char *key, uint32_t value)
    {
        ++calls;
        if (calls == failCall)
            return false;
        values[key] = value;
        return true;
    }

    unsigned failCall {0};
    unsigned calls {0};
    std::map<std::string, uint32_t> values;
};

static bool writeBody(FakeRegistry &registry, const Snapshot &snapshot)
{
    if (!registry.write("NativeP2PRxEntrySchema", snapshot.schema))
        return false;
    if (!registry.write("NativeP2PRxEntryContextGeneration", snapshot.context))
        return false;
    if (!registry.write("NativeP2PRxEntryCountOwnerGateEntries", snapshot.count))
        return false;
    return true;
}

static bool publish(uint32_t &attemptVersion, uint32_t &publishedVersion,
                    bool &publishedOnce, Snapshot &published,
                    const Snapshot &current, FakeRegistry &registry)
{
    auto write = [&registry](const char *key, uint32_t value) {
        return registry.write(key, value);
    };
    auto body = [&]() { return writeBody(registry, current); };
    return NativeAwdlRxEntryPublisher::publish(
        attemptVersion, publishedVersion, publishedOnce, published, current,
        write, body);
}

static void test_failed_attempt_does_not_publish_state(unsigned failCall)
{
    uint32_t attemptVersion = 2;
    uint32_t publishedVersion = 2;
    bool publishedOnce = true;
    Snapshot published{1, 10, 100};
    const Snapshot oldPublished = published;
    const Snapshot current{1, 20, 200};
    FakeRegistry registry(failCall);
    registry.values[NativeAwdlRxEntryPublisher::kSnapshotBegin] = 2;
    registry.values[NativeAwdlRxEntryPublisher::kSnapshotEnd] = 2;
    registry.values["NativeP2PRxEntrySchema"] = 1;
    registry.values["NativeP2PRxEntryContextGeneration"] = 10;
    registry.values["NativeP2PRxEntryCountOwnerGateEntries"] = 100;

    assert(!publish(attemptVersion, publishedVersion, publishedOnce,
                    published, current, registry));
    assert(attemptVersion == 4);
    assert(publishedVersion == 2);
    assert(publishedOnce);
    assert(same(published, oldPublished));
    assert(registry.calls == failCall);

    const auto begin = registry.values[NativeAwdlRxEntryPublisher::kSnapshotBegin];
    const auto end = registry.values[NativeAwdlRxEntryPublisher::kSnapshotEnd];
    if (failCall == 1) {
        // A failed Begin writes no body and preserves the old complete view.
        assert(begin == 2 && end == 2);
        assert(registry.values["NativeP2PRxEntryContextGeneration"] == 10);
    } else {
        // A body or End failure leaves a mismatched version; no End is written
        // after a body failure.
        assert(begin == 4 && end == 2);
    }
    if (failCall == 3)
        assert(registry.calls == 3); // Schema, then failed context; no End.
    if (failCall == 5)
        assert(registry.calls == 5); // End was attempted after full body.

    registry.failCall = 0;
    registry.calls = 0;
    assert(publish(attemptVersion, publishedVersion, publishedOnce,
                   published, current, registry));
    assert(attemptVersion == 6 && publishedVersion == 6);
    assert(publishedOnce && same(published, current));
    assert(registry.values[NativeAwdlRxEntryPublisher::kSnapshotBegin] == 6);
    assert(registry.values[NativeAwdlRxEntryPublisher::kSnapshotEnd] == 6);
    assert(registry.values["NativeP2PRxEntryContextGeneration"] == 20);
    assert(registry.values["NativeP2PRxEntryCountOwnerGateEntries"] == 200);
}

static void test_first_begin_failure_then_retry()
{
    uint32_t attemptVersion = 0;
    uint32_t publishedVersion = 0;
    bool publishedOnce = false;
    Snapshot published{};
    const Snapshot current{1, 7, 9};
    FakeRegistry registry(1);
    assert(!publish(attemptVersion, publishedVersion, publishedOnce,
                    published, current, registry));
    assert(registry.calls == 1 && registry.values.empty());
    assert(attemptVersion == 2 && publishedVersion == 0 && !publishedOnce);
    assert(same(published, Snapshot{}));

    registry.failCall = 0;
    registry.calls = 0;
    assert(publish(attemptVersion, publishedVersion, publishedOnce,
                   published, current, registry));
    assert(registry.values[NativeAwdlRxEntryPublisher::kSnapshotBegin] == 4);
    assert(registry.values[NativeAwdlRxEntryPublisher::kSnapshotEnd] == 4);
    assert(publishedVersion == 4 && publishedOnce && same(published, current));
}

int main()
{
    test_failed_attempt_does_not_publish_state(1); // Begin failure.
    test_failed_attempt_does_not_publish_state(3); // Middle body failure.
    test_failed_attempt_does_not_publish_state(5); // End failure.
    test_first_begin_failure_then_retry();
}
