# Native AWDL DATA TX trace

`awdl_data_tx_trace.hpp` is an address-free, fixed-capacity observation ledger
for one BSD token moving through the existing DATA transmit path. Its eight
records never evict earlier evidence. Capacity or capture loss increments a
drop counter only; it does not stop or alter a transmit.

All ledger writes and snapshot publication run on the P2P main gate. The RX
TX_RSP callback only makes one bounded atomic capture into a scalar sidecar;
the main gate later merges it after checking its immutable record serial and
local sequence, length, queue, and frame-control fields. The observed RX
command-header index is retained as raw metadata and is not matched against
the local TX descriptor index. The firmware response does not echo the BSD
token or the full host generation tuple. Therefore
`FirmwareEchoesFullIdentity` remains false, candidate association is marked
ambiguous for late queue notifications, and matching local fields are not peer
receipt or unique firmware ownership proof. There is no final-MPDU digest;
sequence control and lengths are auxiliary same-packet correlation scalars.

An asynchronous stop/drain path only captures one bounded atomic stop event.
It never mutates the ledger outside the main gate. The current producer calls
this tap only after its `drainResultReady` condition; an empty stop tap does
not prove that every driver stop path was observed. The main-gate publisher
merges a captured event into the matching token row; an unproven drain after
the doorbell is recorded as unknown, while a proven pre-doorbell drain is a
cancellation. Missing, duplicate, stale, or out-of-order stop events increase
the explicit drop/orphan count and do not alter transmit behavior.

Each async tap publishes a bounded state tuple: sequence, consumed sequence,
drop count, and `TapPublicationState`. State 0 means empty or already consumed
(including the initial 0/0 sequence); state 1 means a stable unconsumed event;
state 2 means the snapshot overlapped a writer or changed during the read.
Initial empty TX_RSP and stop taps merge as `NoRecord`, while pending taps are
merged on the main gate. The publisher captures both tap states and the ledger
owner/revision after merging, writes a non-complete body, then takes a second
state snapshot before closing its version. It closes only when both snapshots
have stable empty-or-consumed taps, identical sequence/consumed/drop and active
TX-ticket watermarks, matching owner and content revision. Pending or unstable
state first invalidates any prior even publication with an odd begin version,
then leaves the public version open for a later main-gate retry. A sticky
`CoverageUnknown` value reports any capture or orphan drop; a coherent schema
snapshot with this flag set is not complete evidence coverage. A completed
snapshot is a watermark at that point in time, not a promise that no late event
can arrive later; a late drop advances the ledger snapshot version and remains
visible as unknown.

The trace reuses the already-decoded final MPDU metadata. It exports no MAC
addresses, IPv6 addresses, packet bytes, or payload digests. `QueryClass` and
`QueueEligible` come from the existing queue-head snapshot; they describe the
queued query only and do not establish a reply.

Run the focused state-machine, cancellation, stop handoff, capacity, and
concurrent-sidecar tests with:

```sh
python3 native/tests/test072_data_tx_trace.py
```

The test uses ASan and UBSan, not TSan. It uses a test-only callback barrier to
pause each tap at an odd sequence, verifies the publisher cannot close while
unstable or pending, verifies a successful merge restores a closable snapshot
without drops, and checks that a late post-completion drop becomes unknown and
advances the visible version. The separate concurrent sidecar case proves a
complete old tuple, a complete new tuple, or an explicit drop. These are
offline state-machine checks and do not claim hardware or over-the-air
behavior.
