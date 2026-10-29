# Offline AWDL shared-window interval planner

`awdl_shared_window.{hpp,cpp}` performs conservative interval arithmetic only.
It intersects a caller-supplied peer window with a known local active lease,
accounts for a verified mapping-error bound, caller-verified guards, and a
verified commit-to-air plus packet-airtime budget. It returns inclusive
integer-microsecond commit bounds or a refusal status. It does not authorize a
doorbell, change a TX gate, read GP2/TSF, capture RF, or claim that AWDL data
transmission is connected.

## Required upstream witnesses

The caller must supply nonzero matching context, power, station, and ROC
generations for the current request, MIF peer, mapped peer window, and local
lease. The MIF peer must be valid in that same generation, its identity must
have been checked against the current peer, and a same-peer schedule witness
must be verified and unexpired. The mapped peer start/end bounds and their
maximum error must already be expressed in one verified local time domain.
The caller assigns a nonzero opaque peer token to each peer incarnation and
provides that same token with the MIF witness and mapped window. This token is
only an in-memory association value; it is not a MAC address and carries no
peer identity data. A token mismatch or zero token is refused even when epoch
and channel match.
The caller also assigns a nonzero `scheduleRevision` to each accepted peer
schedule snapshot. `PeerWitness::scheduleRevision` and
`MappedPeerWindow::scheduleRevision` must match: the latter identifies the
exact schedule revision used to derive its time window. Whenever the caller
accepts a new schedule snapshot, it must advance/change the revision and
invalidate any prior mapped window and candidate. It must recompute a mapped
window for the new revision before use; extending the old window's
`validUntil` does not make it describe the new schedule.
The planner expands the peer start by that error and contracts the peer end by
the same error. It does not derive a mapping from samples.

The mapped peer window is half-open: `[peerStartUs, peerEndUs)`. A transmission
plus trailing guard may finish exactly at `peerEndUs`, but no part may extend
beyond it.

The local lease must be known and active. Its guaranteed-active interval is
`[start.latestUs, end.earliestUs)`, and the current time must lie inside it.
Peer, schedule, mapping, and lease evidence are capped by their validity
deadlines. Peer and local channels must be the same nonzero channel; the caller
must provide the channel actually serviced by the local radio.

`Request::nowUs`, every observed/valid-until timestamp, mapped peer bound, and
local lease bound must use the same already-verified monotonic microsecond
domain. The planner does not convert clock domains. A returned `Candidate` is
only a calculation snapshot: before using it later, the caller must reacquire
`nowUs` and recheck the candidate bounds and the full epoch, lease, peer,
schedule, and mapping gates. The result does not remain valid on its own.

Guard values are caller-verified policy outputs and must be at least 3 TU on
each edge. The caller must separately verify the applicable traffic-class and
schedule policy before asserting this witness. Three TU is not a universal
AWDL transmission rule: the 16-TU/slot constraints, fixed-single-channel
exception, and any slot-specific restrictions (including slot 0 or 10) must be
resolved by an upstream policy extractor. This module does not parse TLVs,
classify traffic, select slots, or prove that the exception applies. A stricter
caller-provided guard shrinks the candidate interval.

The TX budget must attest a verified worst-case delay from commit submission
to on-air start and packet airtime. The planner reserves both in addition to
the trailing guard. It assumes only the supplied bounds and makes no hardware
measurement.

## Evidence boundary

The Test062 late-RX tuples pair peer PHY TX time, RX descriptor GP2, and a
host timestamp sampled after RX processing. They do not establish a verified
peer-to-local clock mapping, a bounded drift/error interval, an AW/slot phase,
or TX-on-air timing. Test062 also lacks an admitted MIF peer for this planner's
input. Such data must be rejected; it must not be promoted to `mappingVerified`
or `mifPeerValid` by this module.

Clock mapping, peer election, MIF/PSF field extraction, schedule freshness,
local lease witnessing, traffic policy, and TX-delay measurement remain
unimplemented upstream prerequisites. This is an offline mathematical helper,
not proof that shared AWDL slots, native `awdl0` data, or AirDrop are working.
No MAC address, SSID, IP address, credential, or other peer identifier is
stored by this module.

## Test

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -O1 -g \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  native/awdl_shared_window.cpp native/tests/awdl_shared_window_test.cpp \
  -o /tmp/awdl_shared_window_test
/tmp/awdl_shared_window_test
```
