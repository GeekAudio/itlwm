# Bounded AWDL peer runtime table

`awdl_peer_runtime_table` is a fixed-capacity observer/election helper for
captured `ActionFrameRecord` values. The Tahoe target connects its observation
and scalar publication paths to the driver. It is not a radio scheduler or TX
permission source; election remains an offline-only operation.

## Record admission

- `observe(record, epochs, nowMonotonicUs)` accepts only complete, parser-valid
  PSF (subtype 0) and MIF (subtype 3) frames whose cached parsed fields match a
  fresh parse of the same bytes.
- The RX event time is `record.rxMonotonicUs`, captured at the driver RX tap
  after reorder. `nowMonotonicUs` is only used for age and future-time gates;
  the drain time is never substituted as the receive event time.
- Context, power, and station generations must all match. Any runtime epoch
  change clears live peer state. Inactive state clears the table as well.
- Candidate entries expire after 60 seconds without a valid PSF/MIF. This
  bounds diagnostic history. A valid MIF and a valid PSF each have independent
  5 second leases. Neither subtype refreshes the other subtype's lease.
- PSFs are decoded into their own per-peer synchronization, election, channel,
  version, and timestamp snapshot. A MIF is kept separately with its own
  receive time, GP2, frame timestamps, and shape. PSFs do not require MIF-only
  type-16 ARPA identity data.
- A complete, recognizable embedded sequence in TLV 4 is checked separately
  from the required TLV 18 sequence. If their channel slots disagree, the
  frame remains accepted with `embeddedSequenceMismatch` and the first
  differing slot/channel pair; TLV 18 remains the canonical `channelSlots`.
  No offset rotation is inferred. Malformed recognized copies and missing or
  malformed TLV 18 remain rejected.
- The table holds at most 16 peers and three recent per-peer raw timing tuples.
  Full tables evict the least-recently-seen entry.

## Published state

Snapshots contain no source MAC, master MAC, sync MAC, hostname, or raw frame.
The compact table snapshot exposes the table slot, epoch generations, ages,
counters, up to three raw `{RX tap monotonic, RX descriptor GP2, peer PHY TX}`
tuples, and MIF fields. Each timing tuple carries its PSF/MIF subtype. The MIF's
own RX tap time and raw GP2 stay paired with that MIF's PHY TX and target TX
values, `txDownCounter`, `nextAWSequence`, and channel slots.
`getPsfSnapshot(slot, epochs, now, output)` returns one address-free full PSF
snapshot at a time, with its own RX time, same-frame GP2, synchronization
shape, election values, canonical TLV 18 channel slots, embedded-copy mismatch
flag and first differing slot/channels, age, and `psfFresh` bit. The compact
snapshot reports `latestFreshMifSlot` and `latestFreshPsfSlot` independently;
each is `0xff` when its subtype has no fresh peer.

Numeric rejection diagnostics include the last rejected result, the context
generation in which it occurred, and separate lifetime `rejectedMifTotal` and
`rejectedPsfTotal` counts. `lastMifDecodeStatus` and
`lastPsfDecodeStatus` are updated only when that subtype's decoder is attempted;
PSFs do not hide a MIF decode result and MIFs do not hide a PSF result. `0xff`
means no result has been recorded yet. The accepted/rejected subtype totals
survive epoch changes until `reset()`. A rejected frame cannot mutate either
accepted advertisement or add a timing sample. A valid PSF replaces only PSF
fields; a valid MIF replaces only MIF fields. An accepted sequence-copy
mismatch is a decoder diagnostic, not a rejected frame; `rejectStage` remains
`kNone`, and the table's accepted subtype counter advances.

Expired PSF or MIF fields may remain in a candidate entry while recent frames
of either subtype keep that peer tracked. The relevant `psfFresh` or `mifFresh`
bit becomes false independently; expired values are diagnostic history only.
`selectMaster` uses only fresh MIFs. Epoch changes clear both subtype snapshots;
lifetime aggregate counters survive until `reset()`.

`selectMaster` returns an address-free `SelectionSummary` and a slot index.
It considers only current-epoch MIFs whose sync fields are internally
consistent and whose MIF lease is fresh. This pure election result is not TX
permission. The helper derives no GP2/PHY rate, offset, phase, clock map,
channel timing, or transmission schedule. Until a clock map is independently
verified, callers must not schedule TX from this state.

The existing offline selection rule ignores remote advertisements at height
10 or greater; an accepted remote peer at height 9 can make the local result
height 10. This documents the existing election rule and does not expand it or
change the active driver's election policy.

## Size and verification

Compile and run the offline boundary test with:

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer \
  native/awdl_action_frame.cpp native/awdl_peer_election.cpp \
  native/awdl_peer_runtime_table.cpp native/awdl_action_encode.cpp \
  native/awdl_mif_encode.cpp \
  native/tests/awdl_peer_runtime_table_test.cpp \
  -o /private/tmp/awdl-peer-runtime-table-test
/private/tmp/awdl-peer-runtime-table-test
```

Compile-time assertions cap the compact worker snapshot below 4 KiB, the
single-peer PSF view below 512 bytes, and the table below 12 KiB. The offline
test covers PSF-only candidates, PSF/MIF isolation in both arrival orders,
source-tagged timestamps, ring rollover, independent PSF and MIF lease
boundaries, stale epochs, age/future/ordering gates, nonfatal embedded-copy
mismatch with canonical type-18 fields, malformed parser input, invalid
source, capacity replacement, epoch clear, monotonic-clock regression,
rejected-frame non-mutation, and atomic per-subtype replacement. These are
generated-frame tests under
ASan/UBSan. They do not prove the helper is linked into or running in the
driver, GP2-to-peer-PHY semantics, clock-map accuracy, RF behavior, or AirDrop.

Test047 received seven live PSFs and no MIFs; the then-loaded decoder rejected
all seven because the recognized TLV-4 sequence copy differed from TLV 18.
Test048 integrated the nonfatal conflict handling with canonical TLV 18.
Its recorded single hardware session accepted six PSFs and one MIF without
decoder rejection. Periodic numeric snapshots observed fresh PSF and MIF state,
then expired state after their respective five-second leases. This is evidence
of observation and lease handling, not applied election, synchronization,
schedule execution, native awdl0, or AirDrop. Exact runtime evidence is retained
in IntelWirelessNative/research/test048-runtime-private/.
