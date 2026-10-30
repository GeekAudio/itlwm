# Test088 AF_PACKET timing sender

This sender is based on the frozen Test086 controlled probe. It keeps the same 96-byte MPDU, 10-byte Radiotap header, default 16-frame sequence, 80 ms absolute cadence, two-second cap, and explicit `--send --interface NAME --nonce 32hex --wait-go` gate.

Immediately after GO, the sender records `go_received_ns`, starts the existing two-second budget, then writes and flushes one bounded `SENDER_STARTED` event carrying `timing_schema=1`, `clock_domain=CLOCK_MONOTONIC`, `go_received_ns`, and `started_ns`. The parent can timestamp receipt of that event on its Mach clock. Absolute sender ticks are only compared with other sender ticks; the two clock epochs are never subtracted. The timestamp is taken before event output, so output time counts against the existing send budget.

After the sequence, `SENDER_RESULT` reports the same schema/domain and `go_received_ns`, `started_ns`, `finished_ns`. Its bounded `send_timing` array contains one row per actual `send()` attempt, with zero-based ordinal, IEEE 802.11 sequence number, AWDL sequence number, absolute sender-clock `before_ns`/`after_ns`, return byte count, and errno (zero for success or short write, nonzero for `send()` returning -1). Rows are emitted only after the loop, so logging adds no writes or flushes to the send cadence. A frame that never reached `send()` has no row and is not counted as attempted. These samples measure local syscall timing only; they do not prove RF emission, peer receipt, or timing alignment with the Mac ROC clock.

Clock failures stop further sends and keep any already observed send rows. An unavailable per-send timestamp or end timestamp is `null`; it is not converted to zero or treated as proof that the two-second budget expired. If the final clock read fails, both `finished_ns` and `elapsed_ms` are `null`. A failed absolute sleep preserves the `clock_nanosleep` error code in `last_errno`.

The normal host test build hard-disables packet sending. A second deterministic test build simulates `send()` and monotonic time, including a selected `EIO`; it opens no socket and makes no radio calls.

```sh
make host-test
make aarch64 ZIG=/path/to/zig
```

The binary's default mode remains a dry run. The aarch64 build does not transmit.
