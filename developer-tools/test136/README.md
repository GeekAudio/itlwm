# Test136 system query capture helper

This helper is bound to `25G416-Test136`, UUID `39DC43C3-9054-399A-873E-45EE1DCFDC0B`, with the reviewed A profile. It starts one system Bonjour browse for `_airdrop._tcp.local.` using `kDNSServiceFlagsIncludeP2P | kDNSServiceFlagsIncludeAWDL`, then requests `NativeP2PArmOnce` once. It does not restart browse or re-arm; the system DNS-SD service controls its own query scheduling.

## Commands

The default invocation is a read-only build/profile preflight. `--help` is also read-only.

```sh
swift developer-tools/test136/query_capture_test136.swift --help
swift developer-tools/test136/query_capture_test136.swift
```

For an explicitly approved diagnostic run, use a private output path:

```sh
sudo swift developer-tools/test136/query_capture_test136.swift --run \
  > /path/to/private/RuntimeTest136-query-capture-private.json
```

`--run` starts the browse, verifies the build and idle state again, and sets the one-shot ARM property once. Its total observation and passive publication wait share a 20-second deadline measured from the accepted ARM request. It stops the browse as soon as the terminal driver state is stable, then performs only passive IOKit reads; it does not poll the closed DNS socket or restart browse. Receipts report browse elapsed time, probe observation time, and post-cleanup publication wait separately.

## Private receipt and decoder

Keep the JSON in the private RuntimeTest136 evidence directory. It contains private QWR1 command and MPDU bytes as base64, plus address-free QM facts, DataTxTrace numbers, RX-window numbers, and ADRXWIN1 event metadata. Do not publish the raw receipt or its base64 fields.

Decode it to a base64-free summary with:

```sh
python3 developer-tools/test136/test136_diagnostics.py \
  /path/to/private/RuntimeTest136-query-capture-private.json
```

The decoder checks QWS1 status, QWR1 layout and length, legacy QM identity and descriptor fields, and one exact DataTxTrace row. It also checks the row's qid, ring, descriptor index, sequence control, frame control, MPDU length, owner generation, and queue birth. The clock samples are allowed to differ and are checked in producer order: legacy pre-doorbell, raw doorbell, DataTxTrace doorbell-issued, and raw finish.

The ADRXWIN1 decoder reports each MPDU that reached `iwx_rx_mpdu_mq`, sorted within the published Discovery RX window and compared with the matched TX epochs and raw doorbell timestamp. It reports frame class, descriptor/status presence, channel/length/FC availability, command/ROC lease state, AWDL data-candidate bit, and the later early-route result. The lease-qualified flag describes the same command/ROC lease; it does not certify descriptor ownership, a peer, or protocol acceptance. RX service counters separately show work before and around MPDU dispatch. `BridgeRxPending` is a live depth and may decrease between window boundaries.

The RX decoder also requires `RocConfiguration=3` (`GO_NEGOTIATION`) so a window opened for another ROC purpose cannot be joined to this query. An RX event list is bounded at 64 rows. `Overflow=1` leaves the aggregate scalar counts available but marks the event sequence incomplete; it cannot prove that no other frame appeared before or after TX. Events cover only MPDUs that reached `iwx_rx_mpdu_mq`; they do not count every RF frame. Missing event data, unstable snapshots, invalid schema, configuration mismatch, and epoch mismatches stay unknown.

## Evidence limits

The receipt separates browse acceptance, terminal cleanup, raw local command/MPDU capture, submit-path timestamps, local TX response/completion, RX entry, lease classification, and ifnet bridge delivery. QWS1 status 10 means the local raw/facts properties were published successfully. A correlated DataTxTrace completion is a local driver/firmware event; the trace does not receive the full identity tuple from firmware. Neither the raw snapshot, a local TX response, nor an RX-window event proves RF airtime, peer receipt, an mDNS response, or a successful AirDrop transfer.

The decoder tests compile a small C++ fixture against the production QWR1, legacy facts, QWS1, TX ledger, and completion-result APIs, then pass those outputs through the Python decoder. Additional constructed records cover rejection boundaries. These are offline format tests, not runtime evidence.
