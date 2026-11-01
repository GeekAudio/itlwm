# OpenWrt TX observation classifier

This is an offline reader for a saved, bounded `SENDER_RESULT`. It reads JSON
and writes a JSON summary. It does not connect to OpenWrt, open a packet socket,
change Wi-Fi, or send frames.

Raw prefixes can contain nearby frame headers or addresses. Keep collection
outputs local and private; publish only a redacted summary. The included test
fixtures are synthetic and are labeled as such in classified output. Do not
commit runtime JSON or packet samples.

Run it with:

```sh
python3 developer-tools/openwrt-tx-observation/openwrt_tx_observation.py \
  /path/to/saved-sender-result.json --output /path/to/summary.json
```

Run the synthetic boundary tests with:

```sh
python3 -m unittest -v developer-tools/openwrt-tx-observation/test_openwrt_tx_observation.py
```

## Evidence kept separate

- A successful local `send()` is only local syscall acceptance.
- A full exact monitor echo is classified as an outgoing echo or a completion
  copy candidate. Neither proves that the radio transmitted the frame.
- A matching frame hash identifies frame contents, not a unique send run. The
  summary always keeps `invocation_bound` false. A non-empty pre-send queue is
  marked ambiguous; an empty queue only improves the bounded correlation.
- `capture_finished` says the sender recorded a valid actual finish timestamp.
  `ended_ns` is the observation cutoff, `min(actual_finished_ns,
  started_ns + budget_ns)`. The summary reports `actual_horizon_ns` from the
  actual send-loop finish timestamp, so it can exceed the observation budget
  and never implies that packets beyond the cutoff were collected.
- `loss_free` describes the available capture loss counters. It is `null` when
  required kernel statistics are unavailable and no other loss is known. Known
  drops, truncation, receive errors, capture limits, or rejected-sample overflow
  make it false even when kernel statistics are unavailable.
- `decoder_coverage` says whether every received packet was fully decoded. It
  is `null` when no packet arrived. Unsupported or malformed radiotap data can
  make it false while `loss_free` remains true; these values answer different
  questions.
- A rejected radiotap sample contains at most the first 96 bytes of the bytes
  copied from one packet. Its SHA-256 covers that prefix only. The classifier
  validates the length, presence flags, and prefix hash, then marks it
  `rejected_prefix_unmatched`. A prefix cannot establish a full packet hash,
  match a target frame, or prove RF transmission.
- The classifier decodes version, pad, declared header length, and each
  available present-bitmap word from that prefix, then checks every recorded
  value and presence flag against the bytes. Incomplete prefix data stays
  unknown; missing bytes are never treated as zero. Recorded rejected samples
  plus bounded overflow must equal the invalid, unsupported, and truncated
  packet counters.
- Pre-send drain count and queue-empty status are retained. A clean queue makes
  an exact monitor match a bounded correlation candidate; it still does not
  bind that frame to a unique invocation because the nonce is not in the MPDU.
  A non-empty queue is explicitly ambiguous. Every summary keeps
  `invocation_bound` false.
- PID/cookie-bound TX status is `unknown` because this capture path does not
  collect that source. Software TXFREE, a timeout-generated synthetic ACK, and
  raw hardware TXS are distinct event types; none is present in the current
  collector. The classifier does not accept synthetic status events as
  runtime evidence.
- The conditional `not_requested_by_reviewed_noack_path` label comes from the
  offline reviewed NOACK path contract for the reviewed module. It is explicitly
  not an observed PID value, runtime PID selection, or runtime TXS event. The
  sender still reports that its PID/cookie status source is unavailable.
- RF transmission, ACK, and peer receipt remain false in every summary from
  this schema. They need independent, correctly bound observations.

## Schema handling

The reader accepts only `openwrt-tx-observation/v1`. It explicitly rejects the
frozen Test100 `test100-openwrt-tx-provenance/v1` records because those records
do not contain the new bounded raw-sample metadata. Re-run collection with the
new sender before using this reader; the offline parser does not reconstruct
missing metadata from older captures.

The `tx_provenance.capture` object carries independent `capture_finished`,
`loss_free`, and `decoder_coverage` fields plus raw counters. The reader checks
that the summary values agree with those counters. It also checks that packet
decode categories account for every received packet, rejected sample counts
fit the bounded sample list, and each raw prefix matches its declared length
and prefix hash.

`tx_provenance.status_sources` is intentionally not represented as observed
hardware events. The current source only supports the explicit unavailable
labels in the summary; adding a real TXFREE or TXS input requires a separately
implemented collector with per-frame identity and source provenance.
