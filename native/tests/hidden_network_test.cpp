// SPDX-License-Identifier: GPL-2.0-only
#include "../wcl_backend.hpp"
#include <cassert>
#include <cstring>
#include <vector>

using namespace NativeWifi;

static std::vector<uint8_t> scan(unsigned count, bool passive = false) {
    std::vector<uint8_t> wire(ScanWireSize);
    write32(wire.data(), 17);
    write32(wire.data() + 0x40, passive ? 2 : 1);
    write32(wire.data() + 0x1318, count);
    return wire;
}
static void target(std::vector<uint8_t> &wire, unsigned i,
                   const uint8_t *ssid, size_t length) {
    assert(i < 10 && length <= 32);
    uint8_t *p = wire.data() + 0x131c + i * 56;
    write32(p, 1); write32(p + 4, uint32_t(length));
    if (length) memcpy(p + 8, ssid, length);
}
static std::vector<uint8_t> join(const uint8_t *ssid, size_t length) {
    std::vector<uint8_t> wire(JoinWireSize);
    write16(wire.data() + 0xc, 2); write32(wire.data() + 0x10, 1);
    write32(wire.data() + 0x1c, uint32_t(length));
    memcpy(wire.data() + 0x20, ssid, length);
    write32(wire.data() + 0x214, 1);
    wire[0x21c] = 2; wire[0x221] = 1;
    return wire;
}
struct Radio {
    Backend backend;
    unsigned scans{}, joins{}, leaves{}, linkUps{}, connections{}, clearCalls{};
    ScanPlan captured{};
    bool busyJoin{};
    static Status scanOp(void *raw, const ScanPlan &p) {
        auto &r = *static_cast<Radio *>(raw); ++r.scans; r.captured = p;
        return Status::Ok;
    }
    static Status joinOp(void *raw, const JoinPlan &) {
        auto &r = *static_cast<Radio *>(raw); ++r.joins;
        return r.busyJoin ? Status::Busy : Status::Ok;
    }
    static void leaveOp(void *raw) { ++static_cast<Radio *>(raw)->leaves; }
    static void clearOp(void *raw) { ++static_cast<Radio *>(raw)->clearCalls; }
    static Status cancel(void *) { return Status::Ok; }
    static void emit(void *raw, uint32_t kind, const void *p, size_t n) {
        auto &r = *static_cast<Radio *>(raw);
        if (kind == Link && n == LinkEventSize &&
            static_cast<const uint8_t *>(p)[6]) ++r.linkUps;
        if (kind == Connection) ++r.connections;
    }
    Radio() {
        Operations ops{};
        ops.context = this; ops.scan = scanOp; ops.join = joinOp;
        ops.leave = leaveOp; ops.emit = emit; ops.cancelScan = cancel;
        ops.clearCredentials = clearOp;
        backend.initialize(ops); backend.driverState(true);
    }
};

int main() {
    // Binary SSIDs remain length-delimited, including leading NUL and UTF-8.
    const uint8_t hidden[] = {0, 0xe9, 0x9a, 0x90, ' ', 'x'};
    ScanPlan p{};
    auto wire = scan(2);
    target(wire, 0, hidden, sizeof(hidden)); // Producer's final slot is zero-filled.
    assert(decodeScan(wire.data(), wire.size(), p) == DecodeResult::Ok);
    assert(p.targets.count == 2 && p.targets.entries[0].length == sizeof(hidden));
    assert(!memcmp(p.targets.entries[0].bytes, hidden, sizeof(hidden)));
    assert(p.targets.entries[1].length == 0 && itl_scan_targets_bitmap(&p.targets) == 3);
    assert(itl_scan_targets_directed(&p.targets));
    for (unsigned n = 1; n <= 10; ++n) {
        auto list = scan(n);
        for (unsigned i = 0; i < n; ++i) target(list, i, hidden, sizeof(hidden));
        assert(decodeScan(list.data(), list.size(), p) == DecodeResult::Ok);
        assert(p.targets.count == n && itl_scan_targets_bitmap(&p.targets) == (1u << n) - 1);
        // Duplicate targets are retained in order; no replacement or truncation.
        for (unsigned i = 0; i < n; ++i)
            assert(!memcmp(p.targets.entries[i].bytes, hidden, sizeof(hidden)));
    }
    uint8_t full[32]; for (unsigned i = 0; i < 32; ++i) full[i] = uint8_t(i);
    auto fullWire = scan(1); target(fullWire, 0, full, sizeof(full));
    assert(decodeScan(fullWire.data(), fullWire.size(), p) == DecodeResult::Ok);
    assert(p.targets.entries[0].length == 32 && !memcmp(p.targets.entries[0].bytes, full, 32));
    uint32_t field = 0;
    auto reject = [&](std::vector<uint8_t> bad, DecodeResult result, uint32_t offset) {
        assert(decodeScan(bad.data(), bad.size(), p, &field) == result && field == offset);
        const ScanPlan zero{}; assert(!memcmp(&p, &zero, sizeof(p)));
    };
    reject(scan(11), DecodeResult::Malformed, 0x1318);
    auto bad = wire; write32(bad.data() + 0x1320, 33);
    reject(bad, DecodeResult::Malformed, 0x1320);
    bad = wire; write32(bad.data() + 0x131c, 2);
    reject(bad, DecodeResult::Unsupported, 0x131c);
    bad = wire; bad[0x131c + 40] = 1;
    reject(bad, DecodeResult::Unsupported, 0x131c + 40);
    bad = wire; write32(bad.data() + 0x1c, 1); bad[0x20] = 'x';
    reject(bad, DecodeResult::Unsupported, 0x1c);
    auto passive = scan(2, true); target(passive, 0, hidden, sizeof(hidden));
    assert(decodeScan(passive.data(), passive.size(), p) == DecodeResult::Ok && p.type == 2);

    // No BSS cache or synthetic candidate is installed before discovery.
    Radio r;
    assert(r.backend.scanRequest(wire.data(), wire.size()) == Status::Ok);
    memset(wire.data(), 0xff, wire.size()); // Radio owns a value copy.
    assert(r.captured.targets.entries[0].length == sizeof(hidden));
    auto j = join(hidden, sizeof(hidden));
    assert(r.backend.joinRequest(j.data(), j.size()) == Status::Busy);
    r.backend.observeScanComplete(r.captured.identifier + 1, 1); // Foreign terminal.
    assert(r.backend.scanning() && !r.joins);
    r.backend.observeScanComplete(r.captured.identifier, 1);
    assert(r.backend.joinRequest(j.data(), j.size()) == Status::Ok);
    assert(r.joins == 1 && !r.linkUps && !r.connections);
    uint8_t bssid[] = {2,0,0,0,0,1}, other[] = {2,0,0,0,0,2};
    assert(!r.backend.observeAssociation(0, other));
    assert(r.backend.observeAssociation(0, bssid));
    uint8_t frame[38] = {0x80}, ies[2] = {0,0};
    Beacon b{hidden,bssid,ies,frame,sizeof(hidden),sizeof(ies),sizeof(frame),
             0x1006,100,0,6,-45,-95,50};
    r.backend.observeBeacon(b);
    assert(!r.linkUps && !r.connections); // Discovery/association is not authorization.
    r.backend.observeAuthorization(true);
    assert(r.linkUps == 1 && r.connections == 1);
    assert(r.backend.leave(false) == Status::Ok);
    r.backend.observeAuthorization(false); // Real HAL port-down before saved-network retry.
    r.busyJoin = true;
    assert(r.backend.joinRequest(j.data(), j.size()) == Status::Ok); // Bounded deferred retry.
    r.backend.observeAuthorization(true); // Prior association cannot authorize a deferred join.
    assert(r.linkUps == 1);
    r.busyJoin = false; r.backend.tick(1);
    assert(r.backend.joining());
    assert(r.backend.observeAssociation(0, bssid));
    r.backend.observeBeacon(b);
    assert(r.linkUps == 1);
    r.backend.observeAuthorization(true);
    assert(r.linkUps == 2 && r.connections == 2);
    auto missingCandidate = j; write32(missingCandidate.data() + 0x214, 0);
    JoinPlan jp{};
    assert(decodeJoin(missingCandidate.data(), missingCandidate.size(), jp) == DecodeResult::Malformed);
    r.backend.stop();
    assert(r.backend.scanRequest(passive.data(), passive.size()) == Status::NotReady);
    assert(r.backend.joinRequest(j.data(), j.size()) == Status::NotReady);
}
