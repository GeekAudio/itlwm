#!/usr/bin/env python3
"""Execute the actual Tahoe init-trigger recorder with host-only shims."""
from pathlib import Path
import hashlib
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
marker = "uint32_t ItlIwx::tahoeRecordInitTaskTrigger("
start = source.index(marker)
opening = source.index("{", start)
depth = 1
end = opening + 1
while depth:
    depth += (source[end] == "{") - (source[end] == "}")
    end += 1
method = source[start:end]

program = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include "native/iwx_init_dispatch.hpp"
#include "native/iwx_reset_trace.hpp"

class ItlIwx {
public:
    IwxResetTrace::Trace nativeResetTrace_;
    uint32_t nativePowerFaultSerial_ {0};
    uint32_t nativeInitTaskFaultSerial_ {0};
    uint32_t tahoeRecordInitTaskTrigger(IwxResetTrace::InitTaskTrigger);
};
''' + method + r'''

int main() {
    ItlIwx driver;
    using Trigger = IwxResetTrace::InitTaskTrigger;
    uint32_t expectedFaults = 0;
    uint32_t expectedDispatchFaults = 0;
    const Trigger schedulingOnly[] = {
        Trigger::kWakeupDeferred,
        Trigger::kLifecycleFenceRetry,
    };
    for (Trigger trigger : schedulingOnly) {
        const uint32_t previousPowerFaults = driver.nativePowerFaultSerial_;
        const uint32_t serial = driver.tahoeRecordInitTaskTrigger(trigger);
        ++expectedDispatchFaults;
        assert(driver.nativeInitTaskFaultSerial_ == expectedDispatchFaults);
        assert(serial == expectedDispatchFaults);
        assert(driver.nativePowerFaultSerial_ == previousPowerFaults);
    }

    for (uint32_t value = static_cast<uint32_t>(Trigger::kNewStateError);
         value <= static_cast<uint32_t>(Trigger::kMsixHardwareError); ++value) {
        const uint32_t serial = driver.tahoeRecordInitTaskTrigger(
            static_cast<Trigger>(value));
        ++expectedFaults;
        ++expectedDispatchFaults;
        assert(driver.nativePowerFaultSerial_ == expectedFaults);
        assert(driver.nativeInitTaskFaultSerial_ == expectedDispatchFaults);
        assert(serial == expectedDispatchFaults);
    }

    // Unknown trigger values fail closed and advance the independent fault id.
    driver.tahoeRecordInitTaskTrigger(static_cast<Trigger>(0x7fffffffU));
    ++expectedFaults;
    ++expectedDispatchFaults;
    assert(driver.nativePowerFaultSerial_ == expectedFaults);
    assert(driver.nativeInitTaskFaultSerial_ == expectedDispatchFaults);

    // Keep zero reserved on both serials after wrap.
    driver.nativePowerFaultSerial_ = UINT32_MAX;
    driver.tahoeRecordInitTaskTrigger(Trigger::kNewStateError);
    assert(driver.nativePowerFaultSerial_ == 1);

    std::puts("{\"trigger_fault_cases\":10,\"scheduling_only_cases\":2,\"unknown_fails_closed\":true,\"wrap_skips_zero\":true}");
}
'''

with tempfile.TemporaryDirectory(prefix="native-power-fault-serial-") as temp:
    cpp = Path(temp) / "test.cpp"
    exe = Path(temp) / "test"
    cpp.write_text(program)
    subprocess.run([
        "xcrun", "clang++", "-std=c++17", "-O1", "-g",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(ROOT), str(cpp), "-o", str(exe)
    ], check=True)
    print(subprocess.check_output([str(exe)], text=True), end="")
print("source_sha256=" + hashlib.sha256(source.encode()).hexdigest())
