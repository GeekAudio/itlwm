#!/usr/bin/env python3
"""Validate the Python wire decoder against a real C++ Snapshot object."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("scan_decoder", Path(__file__).with_name("decode_scan_dispatch.py"))
decoder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)
CPP = r"""
#include "native/scan_dispatch_trace.hpp"
#include <cassert>
#include <cstdio>
using namespace NativeWifi::ScanDispatchTrace;
static uint64_t clockNs(void *p) { return ++*static_cast<uint64_t *>(p); }
int main() {
    Trace trace; uint64_t clock=100;
    for (unsigned i=0;i<10;++i) {
        const auto id=trace.beginCall();
        assert(trace.record({id,1,1,kNoResult,GateContextUnknown},clockNs,&clock));
        assert(trace.record({id,1,2,int32_t(0xe00002c7U),GateContextUnknown},clockNs,&clock));
    }
    Snapshot snapshot {};
    assert(trace.snapshot(&snapshot));
    return fwrite(&snapshot,sizeof(snapshot),1,stdout)==1 ? 0 : 1;
}
"""


def main():
    with tempfile.TemporaryDirectory(prefix="test117-wire-") as tmp:
        source = Path(tmp) / "fixture.cpp"
        binary = Path(tmp) / "fixture"
        source.write_text(CPP)
        subprocess.run(["xcrun", "clang++", "-std=gnu++14", "-Wall", "-Wextra",
                        "-Werror", "-I", str(ROOT), str(source), "-o", str(binary)],
                       check=True)
        raw = subprocess.check_output([str(binary)])
    result = decoder.decode(raw)
    assert result["stable"] and result["record_count"] == 16
    assert result["sequence"] == 20 and result["overwritten"] == 4
    method = result["methods"]["bgscan_cache"]
    assert method["entry_hits"] == method["return_hits"] == 10
    assert method["latest_entry"]["call_serial"] == method["latest_return"]["call_serial"] == 10
    assert method["latest_return"]["result_hex"] == "0xe00002c7"
    assert method["matched_latest_duration_ns"] == 1
    assert method["latest_entry"]["gate_context"] == "unknown"
    for bad in (raw[:-1], struct.pack("<I", 99) + raw[4:]):
        try:
            decoder.decode(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("Malformed wire data was accepted")
    unstable = bytearray(raw)
    struct.pack_into("<II", unstable, 16, 0, 0)
    value = decoder.decode(unstable)
    assert not value["stable"] and not value["records"]
    assert all("latest_entry" not in v for v in value["methods"].values())
    print("C++ Snapshot/Python decoder ABI: PASS")


if __name__ == "__main__":
    main()
