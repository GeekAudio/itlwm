# Test112 collector evidence

`test_collect_test112_privacy.py` replays a real Test111 Group2 trace sample
and sends it through the Test104 collector's normal JSONL writer. It checks
that boot/build/kext identity, sample clocks, HCTX, NativeKeyLive, and Group2
remain attached to one sample.

HCTX is retained as decoded metadata plus the original blob length and SHA-256.
Phase 14/15 `result` and `result_detail`, the decoded `counter_value`, and the
matching NativeKeyLive result fields are removed before writing JSONL because
they can expose host-side CCMP sequence counters. Event serials, queue/index,
phase, API version, timestamps, and 64-bit submit-origin serial remain. This
does not prove firmware key installation, radio acknowledgement, AP replay
acceptance, or AirDrop.

The fixture contains only the fixed-size Group2 metadata trace from a real
Test111 sample; it has no packet body, key, nonce, PN, SSID, BSSID, or address.
The HCTX/NativeKeyLive counter values used by the privacy assertions are test
sentinels and are never serialized.

## Test112 echo coordinator

`coordinate_test112.py` is a small Test112 entry point over the strict Test111 coordinator. It keeps the same current-boot, loaded-kext UUID, native I/O Registry identity, interface, reset-counter, live OpenWrt READY, restore, and postflight checks. It uses the existing `monitor_window111.sh` and `openwrt_echo110` wire contract; it does not create another RF or peer protocol. The shared Swift helper now recognizes Test112 as another matched-return build, so Test112 still requires the fresh peer IPv6 and READY receipt plus the current bounded kernel RX lease before its one-shot send. The prior Test107–Test111 plans remain supported.

For the next boot, populate a new private coordinator config with these current values:

- `expected_build`: `25G332-Test112`.
- `expected_boot`: the current boot epoch from `sysctl -n kern.boottime`.
- `expected_uuid`: the UUID shown for the loaded `org.geekaudio.AirportItlwm` by `kmutil showloaded`.
- `expected_reset_count`: current `NativePowerResetCount` from the loaded Test112 controller.
- `identity`: a fresh nonzero 32-character lowercase run token, 16-character lowercase nonce, and current `awdl0`/peer unicast MACs and link-local IPv6 addresses without `%interface` scopes.
- The compiled helper path and SHA-256, its source path and SHA-256, plus the existing monitor script and echo peer binary paths and SHA-256.

Keep the JSON config mode `0600`, bind its output directory to the fresh run token, and use plan mode first. The Test112 coordinator tests use local fake snapshots only. The Test112 Swift helper was compiled into the private preparation directory and passed three argument-only plan tests. The plan exits before device or READY-file access; no device, router, RF, or EFI operation was performed by these tests.
