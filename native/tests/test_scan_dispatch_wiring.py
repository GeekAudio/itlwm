#!/usr/bin/env python3
"""Small source contract for the Tahoe scan-dispatch trace wiring."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CPP = (ROOT / "AirportItlwm" / "AirportItlwmSkywalkInterface.cpp").read_text()
HPP = (ROOT / "AirportItlwm" / "AirportItlwmSkywalkInterface.hpp").read_text()
TRACE = (ROOT / "native" / "scan_dispatch_trace.hpp").read_text()


def body_after(signature: str) -> str:
    start = CPP.index(signature)
    opening = CPP.index("{", start)
    depth = 0
    for index in range(opening, len(CPP)):
        if CPP[index] == "{":
            depth += 1
        elif CPP[index] == "}":
            depth -= 1
            if depth == 0:
                return CPP[opening + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


getter = body_after(
    "AirportItlwmSkywalkInterface::getWCL_BGSCAN_CACHE_RESULT("
)
assert "Phase::Entry" in getter and "Phase::Return" in getter
assert "const IOReturn result = kIOReturnUnsupported;" in getter
assert "return result;" in getter
assert "const uint64_t callSerial = recordNativeScanDispatch(" in getter
assert "result, list, callSerial" in getter
assert "list->" not in getter and "*list" not in getter

scan_request = body_after(
    "AirportItlwmSkywalkInterface::setWCL_SCAN_REQ("
)
assert "Phase::Entry" in scan_request and "Phase::Return" in scan_request
assert "const IOReturn result = _fCommandGate->runAction(nativeRequest, this," in scan_request
assert "reinterpret_cast<void *>(Scan), request" in scan_request
assert "const uint64_t callSerial = recordNativeScanDispatch(" in scan_request
assert "result, request, callSerial" in scan_request
assert "return result;" in scan_request

for name, selector in (
    ("setWCL_CONFIG_BGSCAN", "WclConfigBgscan"),
    ("setWCL_SET_SCAN_HOME_AWAY_TIME", "WclSetScanHomeAwayTime"),
):
    method = body_after(f"AirportItlwmSkywalkInterface::{name}(")
    assert f"Selector::{selector}" in method
    assert "Phase::Entry" in method and "Phase::Return" in method
    assert "const IOReturn result = kIOReturnUnsupported;" in method
    assert "return result;" in method
    assert "const uint64_t callSerial = recordNativeScanDispatch(" in method
    assert "result, request, callSerial" in method

consume_native = body_after("AirportItlwmSkywalkInterface::consumeNative(")
assert "self->publishNativeScanDispatchTrace();" in consume_native

trace_helper = body_after("AirportItlwmSkywalkInterface::recordNativeScanDispatch(")
assert "_fCommandGate" not in trace_helper and "getWorkLoop" not in trace_helper
assert "GateContextUnknown" in trace_helper
assert "if (!argument) input.context |= NullArgument;" in trace_helper

# The published record and snapshot schema contains only numeric metadata and
# fixed-size arrays. The private clock callback's context pointer is not stored.
schema = TRACE[TRACE.index("struct Input"):TRACE.index("static_assert")]
for forbidden in ("void *", "uintptr_t", "ssid", "bssid", "address", "payload", "pid"):
    assert forbidden.lower() not in schema.lower(), forbidden
assert "uint64_t callSerial" in schema
assert "Record latest[8]" in schema
assert "droppedCount" in schema and "overwrittenCount" in schema
assert "GateContextUnknown = 1U << 3" in TRACE
assert "if (phase != uint32_t(Phase::Entry) && phase != uint32_t(Phase::Return)) return 8;" in TRACE

# The four methods stay in their existing virtual positions and preserve the
# ordinary profile's original inline Unsupported implementation.
for method in (
    "getWCL_BGSCAN_CACHE_RESULT",
    "setWCL_SCAN_REQ",
    "setWCL_SET_SCAN_HOME_AWAY_TIME",
    "setWCL_CONFIG_BGSCAN",
):
    positions = [index for index in range(len(HPP)) if HPP.startswith(method, index)]
    assert len(positions) == 2, (method, len(positions))
    directives = []
    for position in positions:
        prefix = HPP[:position]
        directives.append(max(
            (prefix.rfind("#ifdef"), "#ifdef"),
            (prefix.rfind("#else"), "#else"),
            (prefix.rfind("#endif"), "#endif"),
        )[1])
    assert directives == ["#ifdef", "#else"], (method, directives)
    assert "return kIOReturnUnsupported;" in HPP[positions[1]:positions[1] + 180]

print("scan dispatch wiring: PASS")
