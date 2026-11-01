#include "../iwx_live_key_publish.hpp"
#include <cassert>
#include <atomic>
#include <map>
#include <string>
#include <thread>
#include <cstdio>
using namespace IwxFirmwareDiagnostics;

static Entry key(bool response, unsigned marker) {
    Entry e{};
    e.phase = static_cast<uint32_t>(response ? Phase::RxResponseNoBuffer : Phase::CommandSubmitted);
    e.source = static_cast<uint32_t>(response ? Source::CommandResponseQueue : Source::HostCommand);
    e.command_id = 0x17; e.qid = 0; e.index = marker % 256;
    e.header_sequence = e.index; e.monotonic_ns = marker;
    e.driver_generation = marker; e.firmware_generation = marker;
    e.payload_length = marker; e.flags = response ? kFirmwareStatusPresent : kHeaderFieldsPresent;
    return e;
}
struct Controller {
    std::map<std::string, uint64_t> fields;
    unsigned calls=0, failAt=0;
    bool setProperty(const char *name, uint64_t value, unsigned bits) {
        assert(bits == 32 || bits == 64);
        if (++calls == failAt) return false;
        fields[name] = value; return true;
    }
};
int main() {
    TraceRing ring{}; initialize(&ring);
    auto sample = IwxLiveKey::snapshot(ring);
    assert(sample.submit.stable && !sample.submit.present);
    assert(sample.response.stable && !sample.response.present);
    record(&ring, key(true, 10)); record(&ring, key(false, 20));
    TraceSnapshot sealed{}; assert(snapshot(&ring, &sealed));
    const auto sealedResponse = sealed.latest_add_sta_key_response.serial;
    // A new submit does not manufacture a new response; unrelated ring wrap
    // cannot erase the retained key metadata or rewrite the sealed cut.
    for (unsigned i=0; i<500; ++i) { Entry other{}; other.command_id=0x44; record(&ring, other); }
    sample = IwxLiveKey::snapshot(ring);
    assert(sample.submit.present && sample.response.present);
    assert(sample.submit.entry.monotonic_ns == 20 && sample.response.entry.monotonic_ns == 10);
    assert(sample.response.entry.serial < sample.submit.entry.serial);
    record(&ring, key(true, 21));
    sample = IwxLiveKey::snapshot(ring);
    assert(sample.response.entry.monotonic_ns == 21);
    assert(sealed.latest_add_sta_key_response.serial == sealedResponse);
    // A busy sticky slot yields no usable record. A lost event is visible.
    __atomic_store_n(&ring.latest_add_sta_key_submit.writer, 1U, __ATOMIC_RELEASE);
    record(&ring, key(false, 22));
    auto busy = IwxLiveKey::snapshot(ring);
    assert(!busy.submit.present && !busy.submit.stable && busy.submit.dropped == 1);
    __atomic_store_n(&ring.latest_add_sta_key_submit.writer, 0U, __ATOMIC_RELEASE);
    Controller controller;
    uint32_t revision = 0;
    assert(IwxLiveKey::publish(&controller, sample, 100, 20, 18, true, true, true, revision));
    assert(revision == 2 && controller.fields["NativeKeyLiveHctxFrozen"] == 1);
    assert(controller.fields["NativeKeyLiveResponseMonotonicNs"] == 21);
    assert(controller.fields["NativeKeyLiveOwnerOutputEpoch"] == 18);
    assert(controller.fields["NativeKeyLiveOwnerContextStable"] == 1);
    controller.failAt = controller.calls + 7;
    assert(!IwxLiveKey::publish(&controller, sample, 200, 20, 18, false, false, false, revision));
    assert(revision == 2 && (controller.fields["NativeKeyLiveRevisionBegin"] & 1));
    controller.failAt = 0;
    assert(IwxLiveKey::publish(&controller, sample, 300, 20, 18, true, false, false, revision));
    assert(revision == 4 && controller.fields["NativeKeyLiveRevisionBegin"] == controller.fields["NativeKeyLiveRevisionEnd"]);
    revision = UINT32_MAX - 1;
    assert(!IwxLiveKey::publish(&controller, sample, 400, 20, 18, true, false, false, revision));
    // Real concurrent writers and snapshot reader. Every accepted record must
    // be coherent even when the ring wraps, sticky contention drops a writer,
    // or submission and response happen independently.
    TraceRing concurrent{}; initialize(&concurrent);
    std::atomic<bool> start{false};
    auto writer = [&](bool response) {
        while (!start.load(std::memory_order_acquire)) {}
        for (unsigned i=1; i<10000; ++i) record(&concurrent, key(response, i));
    };
    std::thread a(writer, false), b(writer, true), c(writer, true);
    start.store(true, std::memory_order_release);
    for (unsigned i=0; i<10000; ++i) {
        auto s = IwxLiveKey::snapshot(concurrent);
        for (const auto *o : {&s.submit, &s.response}) if (o->present) {
            assert(o->stable && o->entry.serial);
            assert(o->entry.monotonic_ns == o->entry.driver_generation);
            assert(o->entry.monotonic_ns == o->entry.firmware_generation);
            assert(o->entry.monotonic_ns == o->entry.payload_length);
            assert(o->entry.index == o->entry.monotonic_ns % 256);
        }
    }
    a.join(); b.join(); c.join();
    puts("Test105 live key publication and concurrent retained metadata PASS");
}
