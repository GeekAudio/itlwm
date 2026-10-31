// SPDX-License-Identifier: GPL-2.0-only
#include "../wcl_backend.hpp"
#include "../native_power_trace.hpp"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace NativeWifi;

static_assert(offsetof(ScanTraceSnapshot, version) == 0, "snapshot version offset");
static_assert(offsetof(ScanTraceSnapshot, count) == 4, "snapshot count offset");
static_assert(offsetof(ScanTraceSnapshot, requestCount) == 8, "snapshot counters offset");
static_assert(offsetof(ScanTraceSnapshot, records) == 40, "snapshot records offset");
static_assert(offsetof(ScanTraceRecord, native237EmitCallCount) == 44, "record emit count offset");
static_assert(offsetof(ScanTraceRecord, requestMonotonicNs) == 48, "record clocks offset");
static_assert(offsetof(ScanTraceRecord, lastBusyReasonCode) == 112, "record detail offset");
static_assert(offsetof(ScanTraceRecord, lastAdmissionStatus) == 116, "record status offset");
static_assert(offsetof(ScanTraceRecord, lastBusyClass) == 120, "record enum offset");
static_assert(offsetof(ScanTraceRecord, valid) == 123, "record flags offset");
static_assert(sizeof(ScanTraceRecord) == 136, "record size");
static_assert(sizeof(ScanTraceSnapshot) == 2216, "snapshot size");
static_assert(sizeof(NativePowerTrace::Entry) == 56, "power entry size");
static_assert(sizeof(NativePowerTrace::Snapshot) == 1808, "power snapshot size");

static bool writeBytes(const char *path, const void *bytes, size_t length)
{
    FILE *file = std::fopen(path, "wb");
    if (!file) return false;
    const bool wrote = std::fwrite(bytes, 1, length, file) == length;
    const int closeStatus = std::fclose(file);
    return wrote && closeStatus == 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;

    ScanTraceSnapshot scan;
    std::memset(&scan, 0, sizeof(scan));
    scan.version = ScanTraceSchemaVersion;
    scan.count = 1;
    scan.requestCount = 1;
    scan.replacementCount = 1;
    scan.overwriteCount = 0;
    scan.staleTerminalCount = 1;
    ScanTraceRecord &record = scan.records[0];
    record.requestSerial = 7;
    record.generation = 42;
    record.replacesSerial = 6;
    record.replacedBySerial = 0;
    record.admissionAttempts = 3;
    record.radioAttempts = 2;
    record.busyAttempts = 1;
    record.event201Count = 2;
    record.staleTerminals = 1;
    record.firmwareStatus = 1;
    record.native237Status = 0;
    record.native237EmitCallCount = 1;
    record.requestMonotonicNs = 100;
    record.firstRadioAttemptMonotonicNs = 110;
    record.lastRadioAttemptMonotonicNs = 130;
    record.acceptedMonotonicNs = 140;
    record.first201MonotonicNs = 120;
    record.last201MonotonicNs = 125;
    record.firmwareTerminalConsumedMonotonicNs = 150;
    record.native237EmitCallMonotonicNs = 151;
    record.lastBusyReasonCode = 4;
    record.lastAdmissionStatus = Status::Ok;
    record.lastBusyClass = ScanBusyClass::RadioReported;
    record.nativeTerminalSource = ScanTerminalSource::FirmwareComplete;
    record.clockSource = ScanTraceClock::MonotonicCallback;
    record.valid = true;
    record.hasFirst201 = true;
    record.hasFirmwareTerminal = true;
    record.hasNative237 = true;
    record.native237EmitCalled = true;
    record.hasFirstRadioAttempt = true;
    record.hasAccepted = true;
    if (!writeBytes(argv[1], &scan, sizeof(scan))) return 3;

    NativePowerTrace::Ledger ledger;
    const uint32_t call = ledger.begin(
        NativePowerTrace::Operation::kPowerSet,
        NativePowerTrace::Phase::kCallBegin,
        100, 7, 3, 3, 9, 0, -1);
    ledger.record(call, NativePowerTrace::Operation::kPowerSet,
        NativePowerTrace::Phase::kCallEnd, 200, 7, 3, 3, 9, 0, 0);
    NativePowerTrace::Snapshot power{};
    ledger.snapshot(&power);
    if (!writeBytes(argv[2], &power, sizeof(power))) return 4;
    return 0;
}
