# Test101 schema-4 queue attribution

Test101 also includes a driver candidate and [runtime tools](RUNTIME_TEST101.md).
Failed `ADD_STA_KEY` responses are admitted to the existing command-retirement
path only when their command queue, pending index and narrow host command match.
The raw firmware status is retained separately from enqueue success and peer
delivery. No new key-install success decision is inferred from that status.
The protocol supplies no transaction generation, so a delayed response after
reuse of the same index and command cannot be distinguished by these fields.

The OpenWrt sender still sends four frames, ten milliseconds apart. It now drains
receive observations through the remainder of the existing forty-millisecond
budget after its final send. This changes neither frame count nor the radio
budget. Local echoes and completion copies remain distinct from RF evidence.

The RX149 candidate keeps the 100 ms receive profile, native data-input gate and
pre-owner observation. No receive-filter bit or firmware image is changed. The
firmware review has not established a P2P data-drop branch that would justify
such a change. Actual data ingress and AirDrop require post-reboot validation.

This is an offline report tool for JSONL files produced by `test100/collect_rekey100.py`. It adds no kernel ABI, I/O Registry write, radio action, or EFI change.

Run it against an existing private capture:

```sh
python3 developer-tools/test101/queue_completion_attribution.py \
  --input /path/to/test100-private.jsonl \
  --output /path/to/new-queue-report-private.json
```

The output is created with mode `0600`; an existing output file is never overwritten. Test the pure classifier with:

```sh
python3 -m unittest -v developer-tools/test101/test_queue_completion_attribution.py
```

Each output cut keeps four claims separate:

1. `queue_processed`: true only for a complete current schema-4 ordinary `TX_RSP`, one-frame single-slot interval, and matching unique host origin under the current output/context epochs.
2. `device_status`: the raw `Event0.Status`; raw `1` is labeled firmware-reported success. Other values are retained without guessing an enum meaning.
3. `strict_header_match`: derived separately from the complete strict scan. A zero candidate count and clear bit 29 can be false while the queue layer is true.
4. `peer_receipt`: always `unknown` here. Queue processing or firmware status does not prove an over-air ACK, peer delivery, or AirDrop receipt.

The classifier accepts `identity_epoch=0`, permits source 2 when its own cut and origin are complete, masks the raw SSN and `cur` by the validated power-of-two ring size, and does not require `queued==1` or `cur==exclusive_boundary`. Cumulative retention-loss counters are reported separately; they do not invalidate a complete current event. It never uses a live ring read, a new firmware cookie, strict FC/SC equality, candidate count, or retained seven-event Group2 trace as a new queue-processing prerequisite. The original scalar fields and kernel matcher/reclaim behavior remain untouched.
