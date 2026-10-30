# Test089 single-frame TX status observer

This Linux-only helper reuses the exact 106-byte Test086/Test088 packet: the same 10-byte Radiotap header and the same 96-byte MPDU at sequence slot zero. It is intentionally separate from the frozen Test088 sender. The default invocation is dry-run and opens no socket:

```sh
./test089-txstatus-observer-linux
```

An explicit run requires a Linux monitor interface with link type `ARPHRD_IEEE80211_RADIOTAP`, a fresh 32-character lowercase hex run token, and the coordinator gate:

```sh
./test089-txstatus-observer-linux \
  --send --interface mon0 --nonce 0123456789abcdef0123456789abcdef --wait-go
```

The helper prints `READY frames=1 packet_bytes=106 rx_window_ms=2000`, accepts `WAIT`, `ABORT`, or one matching `GO <nonce>` line, then calls `send()` once. It does not retry or change channel/interface state. The same bound AF_PACKET socket observes for at most two seconds. The capture is bounded by 4096 received packets and 16 exact MPDU matches; no raw packet bytes or MAC addresses are emitted. JSON events include the run token, send attempt/result, setup/send/receive errno fields (zero means none), observation completeness, timeout/deadline state, and classification counts. A clean two-second window with no matching packet reports `no_matching_observation`; if matching packets were seen but none met the status criteria, the result is `no_status_candidate_observed`. Neither result means the frame was dropped.

Each matching event compares exactly 96 MPDU bytes against the frame sent by this invocation. Trailing bytes are rejected unless Radiotap `FLAGS` explicitly marks an FCS; in that case exactly the final four FCS bytes are removed before the exact-length comparison. `PACKET_OUTGOING` is reported as a local outgoing echo. A `PACKET_OTHERHOST` packet is reported as `host_driver_completion_candidate` only when the exact same MPDU also has both Radiotap `TX_FLAGS` and `DATA_RETRIES`. This shape is consistent with a host-driver completion copy reported through mac80211, so it is recorded only as a candidate. The `run_token` is not in the 802.11 frame, so the copy cannot be uniquely correlated with this invocation. It still does not prove firmware TX status, RF delivery, or ACK. In particular, a zero `TX_FLAGS` value is recorded as a raw status value and is not called an ACK. The `run_token`/nonce is only a local coordinator label and is not inserted into the 802.11 frame. `TEST089_SEND`, `TEST089_OBSERVATION`, and `TEST089_RESULT` all carry `firmware_tx_status_proven`, `airborne_proven`, `rf_delivery_proven`, and `acked_proven` as false.

The host test build tests the unchanged packet bytes against the frozen Test088 source and manifest, Radiotap field alignment, packet-type classification, exact-MPDU correlation, and malformed/missing-field rejection. It opens no socket and performs no radio operation:

```sh
make host-test
```

To build for Linux on the target host or as a static aarch64 musl binary:

```sh
make linux
make aarch64 ZIG=/path/to/zig
```

Exit codes distinguish invalid arguments (2), interface/socket setup (3), gate errors (4), send errors (5), and receive errors (6). A completed send with either an observed host completion candidate or no matching return exits zero; the JSON `status` and evidence booleans carry the distinction.
