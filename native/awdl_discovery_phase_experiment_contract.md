<!-- SPDX-License-Identifier: GPL-2.0-only -->
# Experimental AWDL discovery-phase candidate

`awdl_discovery_phase_experiment.hpp` is an isolated, header-only planner for
one bounded Test064 experiment. It returns only a time candidate. It is not
connected to the formal `NativeAwdlSharedWindow` planner, does not create a
formal MIF peer or admitted peer, and cannot set verified-clock or verified-
airtime state. The caller must preserve the existing peer, unicast, ROC, DMA,
and kernel-safety gates. A successful result always has
`clockMappingVerified=false`, `airtimeVerified=false`, and
`experimentalOnly=true`.

## Required witnesses

The caller supplies a complete PSF observation and a current snapshot under
the same serialization gate. `peerToken` is an opaque, observation-scoped
identity (for example, a peer-table slot plus its incarnation and the PSF RX
time); it is not a MAC address and does not claim a stable formal or MIF peer
identity. `scheduleRevision` identifies that exact PSF observation. The
helper compares every field and all 16 canonical channels against the current
snapshot. Before using a returned candidate, the caller must repeat that full
snapshot/channel/epoch comparison under its normal gate. Any changed token,
revision, PSF field, channel table, context/power/station/ROC epoch, or current
peer state invalidates the candidate.
Context, power, station, and ROC epochs must all be nonzero; matching zero
values are not accepted as a valid generation witness.

The GP2 anchor must be a direct register read bracketed by host monotonic
timestamps before ROC activation, with the matching context, power, station,
and ROC epochs and an explicit firmware-resources-absent witness. This helper
does not read hardware. A host timestamp taken after RX processing is not an
anchor. No active-ROC GP2 read may be introduced for this experiment.

PSF age is limited to 200 ms. The anchor-to-PSF GP2 forward delta must be less
than 900 ms and less than the 32-bit half range. The host bracket must be
ordered and no wider than 5 ms. These are fail-closed experiment limits, not
proofs of a clock rate or mapping. The PSF must advertise presence mode 4,
16-TU AWs, a 1..64 TU TX down-counter, and RX channel 6. The modular
`phyTxTimestampUs - targetTxTimestampUs` delta must be forward, below 65,536
us, and no greater than the down-counter time.

The next schedule slot is calculated as
`(floor(awCounter / 4) + 1) mod 16`. Only the canonical channel for that slot
is used to decide whether the candidate can target local channel 6; a
`nextAwChannel` hint is intentionally not accepted as input. Zero entries in
the canonical array mean unserved slots and are valid; the Test063 schedule
contains such zero entries. Values above 233 are rejected as outside the
channel-number domain.

## Estimate-only timing model

The checked modular delta `phyTxTimestampUs - targetTxTimestampUs` is
subtracted from the TX down-counter before deriving the boundary:
`boundaryGP2 = rxGP2 + txDownTu*1024 - (phyTxTimestampUs-targetTxTimestampUs)`.
The helper rejects a backward/half-range delta, a delta of 65,536 us or more,
or a correction larger than the down-counter. The same corrected interval is
used for the host candidate and returned raw GP2 target.
The maximum in-range modular PHY-target correction is 65,535 us. A test covers
that boundary against a 64-TU down-counter; equal-or-larger corrections are
rejected.

The candidate models the first 16-TU AW after the corrected advertised
down-counter boundary. It removes 3 TU at each edge, then conservatively
removes another 1 TU from each side for an assumed `+/- 1024 us` quantization uncertainty. The
remaining candidate is therefore within `[boundary + 4 TU, boundary + 12 TU)`.
The earliest host bound uses the upper endpoint of the pre-ROC bracket; the
exclusive latest bound uses its lower endpoint. The GP2-to-host projection
assumes one host microsecond per GP2 microsecond only to produce an experiment
candidate. Neither that rate assumption, the TU-quantization error bound, nor
the relation between the peer's timestamps and local radio time has been
verified. Do not describe this as a clock mapping, synchronized slot, safe
airtime interval, transmission, or delivery proof.

The candidate must fit wholly within the strict caller-known lease
`[leaseStartUs, leaseEndUs)` while retaining a fixed 20,000 us reserve at the
end. `nowUs` must precede the exclusive candidate upper bound. A candidate
that is still in the future may be returned; a caller that uses it later must
revalidate the full PSF snapshot, epochs, current state, and lease under its
normal serialized gate. Failed calls leave the output object unchanged.

## Offline test

```sh
clang++ -std=c++14 -O1 -g -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  native/tests/awdl_discovery_phase_experiment_test.cpp \
  -o /tmp/awdl_discovery_phase_experiment_test
/tmp/awdl_discovery_phase_experiment_test
```

The Test063 PSF input checks the expected next slot (slot 8 / channel 6), GP2
projection, candidate interval, and unverified proof flags. Additional cases
cover AW counter wrap, GP2 wrap and half-range ambiguity, stale PSF/schedule/
epochs including each zero epoch, missing or active-resource anchor, channel/timing rejects, lease and
20 ms reserve bounds, output preservation, and arithmetic overflow. Passing
these tests is offline math evidence only; it is not a kernel, RF, Wi-Fi,
AWDL-control, or AirDrop result.
