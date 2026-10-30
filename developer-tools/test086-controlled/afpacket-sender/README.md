# Test086 controlled AF_PACKET sender

This source-only tool builds a bounded AF_PACKET sender for a synthetic controlled probe. The local `fixtures/probe-spec.json` records the expected MPDU and Radiotap bytes and hashes for offline comparison. The default invocation is dry-run and performs no socket or radio operation. A send requires `--send --interface NAME --nonce 32hex --wait-go`; the Linux build accepts only an interface reporting `ARPHRD_IEEE80211_RADIOTAP`, opens a bound AF_PACKET raw socket, then announces `READY` and waits up to 30 seconds for stdin control lines.

The gate accepts `WAIT` (continue waiting), one matching `GO <nonce>` (begin the bounded send sequence), or `ABORT` (report zero sent and exit without transmitting). `GO` nonces are coordinator control tokens only; they are not inserted into the frame. Keep the stdin pipe open through the send window: EOF, ABORT, or any extra control token after GO stops before the next frame. This Test086 host-timing build defaults to 16 frames at 80 ms intervals. The first frame is sent immediately, so 16 frames span 15 × 80 ms = 1200 ms. The sender still caps the count at 16 and keeps the hard 2-second send deadline. This wider train may improve temporal coverage; it does not prove that it overlaps the firmware's actual ROC/RX window. Each AF_PACKET write is nonblocking; any errno or short write stops the sequence without retry. No AP/channel changes are made.

The specification's 96 bytes are the 802.11 MPDU without FCS. Radiotap adds 10 bytes, so AF_PACKET sends 106 bytes. The UDP application payload is only the fixed 8-byte marker. Radiotap requests `NOACK|NOSEQNO`; actual driver/hardware honoring is reported as unknown. JSONL output contains frame counts, lengths, timing, sequence metadata from dry-run, and numeric errno only; it never prints interface names, addresses, or payload bytes.

`SENDER_HOST_TEST` builds hard-disable the send path and are used only for local CLI/gate negative tests. `make aarch64 ZIG=/path/to/zig` creates a static Linux aarch64 binary under `build/`. Building the target binary does not send packets; only an explicit Linux `--send` invocation can use a wireless monitor interface.

```sh
make host-test
make aarch64 ZIG=/path/to/zig
```
