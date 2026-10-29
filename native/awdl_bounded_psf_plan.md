# Bounded PSF input model

`awdl_bounded_psf_plan.{hpp,cpp}` builds inputs for one observation-only PSF.
Test042 links this model and the encoder into AirportItlwm. The explicit
`NativeP2PAwdlPsfObservationOnly` profile can transmit one experimental PSF
after an administrator arms the manual probe and a matching ROC START arrives.
The model itself does not access hardware.

## What it accepts

The caller supplies one host-monotonic microsecond sample, an Intel P2P MAC, a
confirmed social-channel ROC window, the accepted ROC hard deadline, an
explicit 802.11 sequence number, and confirmed HT capabilities. The sample
must fall inside the confirmed ROC. `Request::nativeAddressVerified` is false
by default. The HAL sets it true only after confirming, for the same generation,
that the P2P MAC equals the native AWDL interface identity. The planner copies
that evidence to `PsfInput::advertiseAwdlAddress`; false preserves the previous
wire shape and true emits only the identity field. The encoder has no second
MAC input. Failures leave the outputs untouched.

The model uses that one sample as its local experimental schedule origin and
copies its low 32 bits into both PSF timestamp fields. It builds each of the 16
channel slots from four 16-TU AWs (65,536 microseconds per slot), marking the
slot available only if the entire slot fits before the ROC deadline. A partial
tail is left as unavailable. A ROC longer than one 1,048,576-microsecond
sequence is rejected instead of implying an unbounded repeat.

For a 900 ms ROC beginning at the sample, the result is 13 channel-6 slots
(851,968 microseconds), followed by three zero slots. The remaining 48,032
microseconds of the ROC do not fill a complete slot and are not advertised.
Thus the model never calls a 900 ms ROC a fully available 1.048576 s cycle.

AWDL channel sequences normally repeat. The slot table has no lease-expiry
field, so those 13 channel slots describe only the first experimental sequence
cycle; they do not stop a peer from inferring that the same sequence continues
after the ROC deadline. Test042 therefore uses an explicit temporary,
control-only experiment: the P2P MAC is temporary, Data Path State flags are
zero, and no persistent native availability is claimed. The strict production
gate still rejects missing clock mapping, incomplete sequence coverage, and
unbounded expiry. This is not a completed real-time scheduler.

The driver uses the actual programmed TU duration (900 ms becomes 878 TU or
899,072 microseconds), starts its conservative deadline at command issue, and
subtracts 20,000 microseconds. It rechecks the matching generation, START/END,
candidate age, and remaining host lease before submission. This does not bound
firmware-to-air latency or prove advertised on-air coverage; those diagnostics
remain explicitly unproven.

The standalone seed is now calculated by `awdl_host_phase.{hpp,cpp}` from one
fixed local sample origin and the original channel table. At the exact origin,
the pinned OWL formula gives `txDownCounterTu=64`,
`remainingAwLengthTu=16`, `nextAwSequenceNumber=0`, and `apAlignment=0`.
Later PSF/MIF candidates must keep that same origin and table; they update the
current sequence and countdown from elapsed host-monotonic time. This is only
the OWL host-clock experiment model, not a mapping to Intel GP2/TSF or proof
that the firmware served those slots. The one-node self-master seed uses the P2P MAC for
master and sync addresses, zero counters and distance, and metric 60, following
the pinned OWL initialization and AWDL recommendation. The encoder keeps the
legacy flags-zero Data Path State when the HAL identity flag is false. When
true, it writes flags `0x0004` and `sourceAddress` in the Data Path State.
`Summary` reports the actual flags and address-field presence, and always leaves
`dataPathReady=false`; address advertisement does not prove packet delivery or
AirDrop readiness.

## What it does not prove

Test043 adds the explicit `NativeP2PAwdlMifFollowup` profile. After a successful
matched PSF completion it may submit exactly one MIF on the same idle queue
within the same live ROC. The MIF retains the first PSF's phase origin,
channel table and temporary identity; its time-dependent fields are refreshed
from that origin. The worker records each result separately and skips the MIF
on failed prerequisites or END. Both frames remain a temporary control-only
experiment, not a persistent native AWDL service.

Without `nativeAddressVerified`, the P2P MAC is not represented as a native
`awdl0` identity and the legacy empty Data Path value is kept. With the flag,
the planner trusts the HAL's same-generation identity check only for advertising
that address. The model still does not prove AWDL clock alignment, sustained
periodic PSFs, peer discovery, an IPv6 data path, AirDrop, or transfer. Its
success status means only that an observation-only PSF input was built from the
supplied evidence.

The caller is the manually armed P2P worker in `ItlIwxP2PProbe.cpp`, with the
existing station/queue/TX-ticket/ROC cleanup path. A failed preflight does not
fall back to the legacy vendor diagnostic frame. Firmware TX completion is
distinct from peer reception, synchronization, or data transfer; a broadcast
does not provide a peer ACK. A persistent AWDL implementation still needs a
stable native interface identity, a scheduler, live election and sequence
ownership, clock mapping, receive processing, and a working data path.

## Test

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/awdl_action_frame.cpp \
  native/awdl_action_encode.cpp native/awdl_host_phase.cpp \
  native/awdl_bounded_psf_plan.cpp \
  native/tests/awdl_bounded_psf_plan_test.cpp \
  -o /private/tmp/awdl-bounded-psf-plan-test
/private/tmp/awdl-bounded-psf-plan-test
```

The test checks exact slot boundaries, the 900 ms case, timestamp truncation,
both default legacy and address-verified profiles, Data Path summary values,
invalid evidence, and output preservation on rejection. Inputs in tests are
synthetic; the test is not runtime or radio evidence.
