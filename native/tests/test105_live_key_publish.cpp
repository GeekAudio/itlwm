#include "../iwx_live_key_publish.hpp"
#include "../iwx_sta_auth_trace.h"
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
static Entry keySequence(IwxFirmwareDiagnostics::Phase phase,
                         uint64_t marker, uint64_t submitSerial,
                         uint32_t generation = 3U,
                         uint32_t maximumTid = 15U) {
    Entry e{};
    e.phase = static_cast<uint32_t>(phase);
    e.source = static_cast<uint32_t>(Source::HostCommand);
    e.command_id = 0x17; e.group_id = 1; e.version = 3;
    e.qid = 0; e.index = static_cast<uint32_t>(marker % 256U);
    e.header_sequence = e.index; e.monotonic_ns = marker;
    e.driver_generation = generation; e.firmware_generation = generation;
    e.flags = kHeaderFieldsPresent | kKeySequenceApiVersionPresent |
        kOriginGenerationPresent | kOriginSubmitSerialPresent;
    e.packet_length = static_cast<uint32_t>(submitSerial >> 32);
    e.payload_length = static_cast<uint32_t>(submitSerial);
    if (phase == IwxFirmwareDiagnostics::Phase::KeyRxSequenceSubmitted)
        e.flags |= kKeySequenceValuePresent | kKeySequenceMaxTidPresent |
            (maximumTid << kKeySequenceMaxTidShift);
    else if (phase == IwxFirmwareDiagnostics::Phase::KeyTxSequenceSubmitted)
        e.flags |= kKeySequenceValuePresent;
    e.result = static_cast<uint32_t>(marker);
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

    // Sequence metadata has independent sticky slots and a non-reusable
    // origin ID. A normal HCTX wrap cannot erase the PN rows.
    TraceRing sequenceRing{}; initialize(&sequenceRing);
    __atomic_store_n(&sequenceRing.next_serial, 0x100000000ULL,
                     __ATOMIC_RELEASE);
    const uint64_t submitA = record(&sequenceRing, key(false, 24));
    assert(submitA == 0x100000001ULL); // Return width is a full 64-bit serial.
    Entry rxA = keySequence(Phase::KeyRxSequenceSubmitted, 25, submitA);
    Entry txA = keySequence(Phase::KeyTxSequenceSubmitted, 26, submitA);
    assert((rxA.flags & kKeySequenceMaxTidMask) == (15U << 20));
    assert((rxA.flags & kOriginGenerationPresent) != 0U);
    assert((rxA.flags & kOriginSubmitSerialPresent) != 0U);
    const Entry rxTid13 = keySequence(
        Phase::KeyRxSequenceSubmitted, 25, submitA, 3U, 13U);
    assert((rxTid13.flags & kKeySequenceMaxTidMask) == (13U << 20));
    assert((rxTid13.flags & kOriginGenerationPresent) != 0U);
    assert((rxTid13.flags & kOriginGenerationChangedBeforeRecord) == 0U);
    assert((rxTid13.flags & kOriginSubmitSerialPresent) != 0U);
    assert(record(&sequenceRing, rxA) == 0x100000002ULL);
    assert(record(&sequenceRing, txA) == 0x100000003ULL);
    const uint64_t submitB = record(&sequenceRing, key(false, 27));
    Entry rxB = keySequence(Phase::KeyRxSequenceSubmitted, 28, submitB);
    assert(record(&sequenceRing, rxB) == submitB + 1U);
    const uint64_t submitC = record(&sequenceRing, key(false, 29));
    Entry unavailable = keySequence(
        Phase::KeySequenceUnavailable, 30, submitC);
    unavailable.version = 99U; // Driver's IWX_FW_CMD_VER_UNKNOWN sentinel.
    unavailable.result = IWX_STA_KEY_SEQUENCE_UNSUPPORTED_API;
    assert(record(&sequenceRing, unavailable) == submitC + 1U);
    for (unsigned i = 0; i < 500; ++i) {
        Entry other{}; other.command_id = 0x44; record(&sequenceRing, other);
    }
    auto sequenceSample = IwxLiveKey::snapshot(sequenceRing);
    assert(sequenceSample.rxSequence.present && sequenceSample.rxSequence.stable);
    assert(sequenceSample.txSequence.present && sequenceSample.txSequence.stable);
    assert(sequenceSample.sequenceUnavailable.present &&
           sequenceSample.sequenceUnavailable.stable);
    assert(sequenceSample.rxSequence.originSubmitSerial == submitB);
    assert(sequenceSample.txSequence.originSubmitSerial == submitA);
    assert(sequenceSample.sequenceUnavailable.originSubmitSerial == submitC);
    assert(sequenceSample.rxSequence.originSubmitSerial !=
           sequenceSample.txSequence.originSubmitSerial);
    Controller sequenceController;
    uint32_t sequenceRevision = 0;
    assert(IwxLiveKey::publish(&sequenceController, sequenceSample, 1000,
        3, 7, true, false, false, sequenceRevision));
    assert(sequenceController.fields["NativeKeyLiveSchema"] == 2);
    assert(sequenceController.fields["NativeKeyLiveRxSequenceOriginSubmitSerial"] ==
           submitB);
    assert(sequenceController.fields["NativeKeyLiveTxSequenceOriginSubmitSerial"] ==
           submitA);

    // Busy sequence sticky slots fail closed and record a bounded drop
    // receipt, without borrowing or rewriting the Submit/Response slots.
    TraceRing droppedSequence{}; initialize(&droppedSequence);
    __atomic_store_n(&droppedSequence.latest_key_rx_sequence.writer, 1U,
                     __ATOMIC_RELEASE);
    const Entry droppedRx = keySequence(
        Phase::KeyRxSequenceSubmitted, 31, 77U);
    assert(record(&droppedSequence, droppedRx) != 0U);
    assert(__atomic_load_n(&droppedSequence.latest_key_rx_sequence_dropped_count,
                           __ATOMIC_ACQUIRE) == 1U);
    __atomic_store_n(&droppedSequence.latest_key_rx_sequence.writer, 0U,
                     __ATOMIC_RELEASE);
    const auto afterDrop = IwxLiveKey::snapshot(droppedSequence);
    assert(afterDrop.rxSequence.stable && !afterDrop.rxSequence.present);
    assert(afterDrop.rxSequence.dropped == 1U);
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
    auto sequenceWriter = [&](Phase phase) {
        while (!start.load(std::memory_order_acquire)) {}
        for (unsigned i=1; i<10000; ++i)
            record(&concurrent, keySequence(phase, i, 1000U + i));
    };
    std::thread a(writer, false), b(writer, true), c(writer, true),
        d(sequenceWriter, Phase::KeyRxSequenceSubmitted),
        e(sequenceWriter, Phase::KeyTxSequenceSubmitted),
        f(sequenceWriter, Phase::KeySequenceUnavailable);
    start.store(true, std::memory_order_release);
    for (unsigned i=0; i<10000; ++i) {
        auto s = IwxLiveKey::snapshot(concurrent);
        for (const auto *o : {&s.submit, &s.response, &s.rxSequence,
                              &s.txSequence, &s.sequenceUnavailable}) if (o->present) {
            assert(o->stable && o->entry.serial);
            assert(o->entry.monotonic_ns == o->entry.driver_generation ||
                   o->originSubmitSerial != 0U);
            if (o->originSubmitSerial) {
                assert(o->originSubmitSerial ==
                    ((uint64_t(o->entry.packet_length) << 32) |
                     o->entry.payload_length));
            }
            assert(o->entry.index == o->entry.monotonic_ns % 256);
        }
    }
    a.join(); b.join(); c.join(); d.join(); e.join(); f.join();
    puts("Test105 live key publication and concurrent retained metadata PASS");
}
