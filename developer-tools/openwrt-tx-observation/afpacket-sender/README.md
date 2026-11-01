# OpenWrt TX observation sender

This is an isolated follow-up to the frozen Test100 sender. It keeps the same
bounded send recipe: at most four 96-byte MPDUs, spaced 10 ms apart, with a
40 ms send/capture budget and the existing `NOACK|NOSEQNO` request. It does not
change Test100 files or add a production CLI simulation mode.

## Rejected radiotap samples

The receive observer retains at most eight rejected records. Each record stores
at most the first 96 bytes and a SHA-256 of exactly those prefix bytes; the hash
is not a whole-packet or MPDU hash. `received_len` is the length reported by
`recvmsg(MSG_TRUNC)`, `copied_len` is the number of bytes copied into the
4,096-byte receive buffer, and `raw_prefix_len` is `min(copied_len, 96)`. A
sample overflow counter records rejected packets that did not fit the fixed
eight-record array. Prefix bytes are copied during collection; hashing happens
only while serializing the final result.

`capture_finished`, `loss_free`, and `decoder_coverage` mean different things.
`ended_ns` is the logical receive cutoff, clamped to
`min(actual_finished_ns, started_ns + budget_ns)`. `actual_finished_ns` is the
real send-sequence finish timestamp; `actual_horizon_ns` uses that value and
may exceed the 40 ms budget if the process was delayed. `capture_finished` says
that real finish time was recorded; it does not claim the entire 40 ms receive
budget elapsed. `loss_free` is `false` when an error, truncation, sample
overflow, capture limit, or known kernel drop is present, even if kernel
statistics are unavailable; absent statistics with no known loss yields
`null`. It is `true` only with available statistics and a finished, error-free
capture with no kernel drops, truncation, sample overflow, or capture limit.
`decoder_coverage`
is `null` when no packets arrived and is true only when every received packet
was fully supported and decoded.

Exact `PACKET_OUTGOING` matches remain local socket echoes. Other exact matches
remain completion-copy candidates or unclassified observations. The sender
does not observe PID-cookie TX status/TXFREE and does not claim RF transmission,
ACK, peer receipt, or AirDrop success.

## Offline host fixtures

Run `python3 test_sender_observation.py`. The test compiles a host-only fixture
binary, exercises radiotap/parser/sample bounds, and asks the same C serializer
to emit one explicitly synthetic `SENDER_RESULT` for classifier contract
testing. That fixture mode exists only in the test harness; the sender CLI has
no synthetic-output option.
