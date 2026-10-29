# Offline per-ticket AWDL time evidence

`awdl_tx_window_evidence.{hpp,cpp}` is an isolated, single-consumer ledger for
up to four PSF/MIF tickets and four peer schedule witnesses. It uses fixed
arrays and no dynamic allocation. It stores only scalar identity and time
evidence; no MAC, IP, credential, packet buffer, firmware pointer, or DMA
resource is present. Existing driver ticket and peer-table types remain
separate; this ledger is not connected to them.

## Immutable ticket identity and schedule revisions

Each local ticket identity contains diagnostic generation, PSF/MIF kind, frame
ordinal and sequence control, opaque ticket token, context/power/station/ROC
epochs, queue ID, ring size, and descriptor index. These fields suffice to
record the local causal timeline without peer state. The optional peer binding
is a caller-assigned opaque nonzero peer-incarnation token and schedule
revision. Both zero means explicitly unbound; only one zero is invalid. An
unbound ticket can still record its local submission and completion, including
the first local MIF before any peer has been observed.
`LocalTicketRecordedUnbound` means the local record was retained; it is not a
TX failure signal. Its retrospective result is always
`RetrospectiveUnknown`.

If a nonzero peer binding is supplied, it is marked bound only when a current,
verified schedule witness matches at ticket creation. Otherwise the local
ticket is still recorded as `LocalTicketRecordedUnbound`; later schedule
evidence cannot retroactively bind or rewrite it. The caller must issue a new
`scheduleRevision` whenever validated peer TLV18 schedule content changes,
even when the peer and runtime epoch stay the same. Observing such a revision
invalidates older bound tickets for that peer. Revisions must strictly increase
without wrap or reuse within a peer incarnation. Repeating the current revision
is idempotent only for the identical stored channel and observation/expiry
times; it cannot refresh validity. Conflicting evidence invalidates that
revision's binding. The upstream producer must guarantee that all TLV18 content
is immutable under one revision; the module does not parse TLV18 or calculate
revisions itself.

Records are never overwritten to make room. A full ticket or schedule table
fails closed. The only clearing operation is an explicit, strictly newer
`beginDiagnosticGeneration()` call. Epoch changes alone do not clear records.

## Causal time evidence

Every timestamp is in one already-verified monotonic microsecond domain. A
ticket's `beginTicket(nowUs)` argument is its actual local record-creation event
time, not an analysis/import wall clock. It is stored immutably; a submission
lower bound earlier than that event invalidates the ticket. Creation and
submission may fall in the same integer microsecond.

A submission witness is an attested sample taken immediately before the actual
doorbell, stored as a lower bound on doorbell time. A completion witness must
be the same ticket and identity's successful firmware notification tap, with
an attested timestamp upper bound. Duplicate evidence cannot replace the
first accepted submission or completion. Failed, unknown, flushed, expired,
wrong-ticket, wrong-epoch, wrong-descriptor, stale-schedule, and
out-of-order evidence is rejected. A late poll is not a notification tap and
cannot be used as the completion upper bound.

Only the explicit `FirmwareOutcome::Success` value can close a successful
record. Unknown and out-of-range outcome values permanently invalidate it.
`snapshotTicket()` returns a value copy of a used fixed slot and no internal
pointer. Out-of-range, unused, or null-output reads fail without changing the
output; snapshots cannot rewrite identity or add a peer binding. Callers must
serialize snapshot reads with every ledger mutation.

The completion identity must come from the verified producer's live ticket,
context, queue, and descriptor match. It must not be reconstructed by joining
only on the raw response sequence field; that field can be diagnostic metadata
and may differ on firmware failure responses. If a post-doorbell finish path
fails or ticket state becomes unknown, the submission record stays submitted
but without a successful matching tap the retrospective result remains
`RetrospectiveUnknown`.

If a future producer reports a post-doorbell finish failure, it must retain the
submitted ticket and mark its outcome unknown; it must not discard the submit
record or use the failure itself as a completion tap. Without a valid matching
success tap, retrospective containment remains unknown. This ledger is not
such a producer hook and must not influence whether the driver transmits.

A firmware completion is not proof that the packet reached the air, that a
remote peer received it, or that AirDrop accepted it. The completion tap time
is never called an air timestamp. An AWDL action-header PHY timestamp may be
assigned in the driver before DCF medium-access delays and is not a strict
hardware air-time measurement; see
[the 2018 AWDL paper, §§5.1 and 7.3](https://arxiv.org/pdf/1808.03156). The
ledger does not use late-RX host time to construct a clock mapping.

## Retrospective containment only

`assessRetrospectively()` accepts an independently verified, already-guarded
shared-window witness. It is not the `Candidate` output from a submit-window
planner and carries no TX budget. The only result is one of
`RetrospectiveCovered`, `RetrospectiveNotContained`, or
`RetrospectiveUnknown`. The check asks only whether the local host causal
bracket `[preDoorbellLower, completionTapUpper]` is geometrically contained in
the supplied half-open window `[start,end)`, while the window witness remains
valid for that historical bracket. This is a host-time containment check, not
a MIF transmission license.

The 2018 AWDL paper notes that AWDL action-header PHY timestamps can precede
DCF medium access and need not be strict air timestamps. Periodic MIF scheduling and
peer-control behavior must not be judged by directly applying the data-frame
shared-AW rule. In particular, the first local MIF must not wait for a
received peer MIF, which would create a startup cycle. Even
`RetrospectiveCovered` does not prove compliance with an AWDL MIF scheduling
requirement, actual on-air slot placement, packet reception, or AirDrop
success. This offline containment result must not be connected to the current
MIF-valid TX gate or used to authorize future submission.

The result is a snapshot, not a persistent permit. The ledger does not claim
thread safety, runtime integration safety, verified worst-case TX delay, or
hardware behavior. Clock mapping, event-to-ticket correlation, schedule
revision production, and shared-window verification remain upstream evidence
requirements.

## Test

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -O1 -g \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  native/awdl_tx_window_evidence.cpp \
  native/tests/awdl_tx_window_evidence_test.cpp \
  -o /tmp/awdl_tx_window_evidence_test
/tmp/awdl_tx_window_evidence_test
```
