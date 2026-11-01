# Test100 OpenWrt TX provenance contract

## Collection window

The Test100 sender opens a second, read-only AF_PACKET socket on the already
prepared radiotap monitor interface before it prints `READY`. The existing
send socket, 4-frame limit, 10 ms interval, and 40 ms send budget stay intact.
After the one-use `GO`, the receiver first drains the pre-existing socket queue
and then observes concurrently with the send sequence. It does not wait after
the last send. Capture is limited to 128 packets and 16 exact probe matches;
each copied record contains metadata only, not MPDU bytes or MAC addresses.

The run nonce stays in the local protocol. It is not inserted into the MPDU,
so an exact frame hash plus local receive time is still a temporal match, not
unique cryptographic attribution to this run. If the pre-send queue cannot be
drained to `EAGAIN`, the report marks the run-level join ambiguous.

## Evidence levels

| Record | What it establishes | What it does not establish |
| --- | --- | --- |
| `send()` returned 106 bytes with errno 0 | The local AF_PACKET send syscall accepted the complete radiotap+MPDU buffer | Driver completion, firmware status, RF airtime, ACK, or peer receipt |
| exact frame on `PACKET_OUTGOING` | The local packet socket received an outgoing echo | Hardware dequeue or RF transmission |
| exact frame on `PACKET_OTHERHOST` with Radiotap `TX_FLAGS` and `DATA_RETRIES` fields | A generated TX-completion-shaped monitor copy was observed; recorded as a candidate | A PID/cookie-bound firmware TXS, RF transmission, ACK, or peer receipt |
| frame-specific kernel TX status with the sender PID, unique per-frame cookie, and matching MPDU identity | A separately sourced, uniquely bound TX-status record, if a future collector supplies it | By itself, correct over-the-air bytes or peer receipt |

The current Test100 AF_PACKET collector has no source for the last row. It must
therefore serialize `pid_cookie_bound_tx_status="unknown"` and
`pid_cookie_status_source_available=false`. It does not accept status fields
from Radiotap as a substitute. In particular, requested `NOACK|NOSEQNO`,
Radiotap `TX_FLAGS=0`, and `DATA_RETRIES=0` never mean successful RF delivery
or ACK.

## Result schema

`SENDER_RESULT` adds one `tx_provenance` object:

```json
{
  "tx_provenance": {
    "schema": "test100-openwrt-tx-provenance/v1",
    "capture": {
      "window": "send_sequence_span",
      "budget_ns": 40000000,
      "started_ns": 0,
      "ended_ns": 0,
      "rx_packets": 0,
      "dropped_packets": 0,
      "pre_send_queue_empty": true,
      "complete": true,
      "limit_reached": false
    },
    "observations": [],
    "run_nonce_is_local_only": true,
    "nonce_in_mpdu": false,
    "pid_cookie_bound_tx_status": "unknown",
    "pid_cookie_status_source_available": false,
    "rf_transmission_proven": false,
    "peer_receipt_proven": false,
    "ack_proven": false
  }
}
```

Each observation is joined to one of the four send rows by ordinal, exact
MPDU SHA-256, IEEE 802.11 sequence number, and AWDL sequence number. The
classifier recalculates the class from `packet_type` and field-presence bits;
it does not trust a sender-provided class string. It rejects a wrong hash or
sequence, malformed counts, observations outside the capture window, and any
attempt to promote the raw AF_PACKET result into TXS or RF proof.

## Router state discovery

Router status inspection is read-only and conditional on the interfaces that
exist at collection time. The collector does not mount debugfs, create status
nodes, change the `force_tx_status` control, alter modules, or change wireless,
WAN, or LAN configuration. An aggregate `tx_stats`/queue snapshot is not
treated as per-frame TXS.

The CLI is offline by default and reads only a saved local `SENDER_RESULT`:

```sh
python3 developer-tools/test100/openwrt_tx_provenance.py
python3 developer-tools/test100/openwrt_tx_provenance.py --input sender-result.json
PYTHONDONTWRITEBYTECODE=1 python3 developer-tools/test100/test_openwrt_tx_provenance.py
```
