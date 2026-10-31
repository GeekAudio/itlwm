# Test093 trace reader

The decoder reads only fixed-width numeric trace snapshots. It does not parse
SSID, MAC, frame, IE, or credential data.

The scan property is schema 1, an x86_64 little-endian raw snapshot. Pass the
adapter's `NativeScanTraceSchema` and `NativeScanTraceRecordBytes` properties
with the binary property payload:

```sh
python3 developer-tools/test093/decode_trace.py scan scan-snapshot.bin \
  --schema 1 --record-bytes 136
```

Scan layout is asserted in `native/wcl_backend.hpp`: a 40-byte header, sixteen
136-byte records, and a 2216-byte snapshot. Records and unused slots are
zero-filled. `firmware_terminal_consumed_ns` is the host timestamp when the
serialized backend consumes a firmware terminal event. `native237_emit_call_ns`
is the host timestamp immediately before the native event emit callback; it is
not an OS acknowledgement.

The same decoder checks the 1808-byte power trace snapshot, whose 56-byte entry
layout is asserted by `native/native_power_trace.hpp`:

```sh
python3 developer-tools/test093/decode_trace.py power power-snapshot.bin \
  --schema 1 --record-bytes 56
```

Run the host fixture and decoder checks with:

```sh
python3 developer-tools/test093/test_wire.py
python3 developer-tools/test092/run_wcl_asan_ubsan.py
```

The first command compiles a fixture using the actual C++ structs and creates
temporary binary snapshots under `/private/tmp`. It validates the decoder and
wire layout only; it is not runtime or RF evidence.
