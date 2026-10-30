# Test086 controlled receive probe

These tools prepare a bounded channel-149 receive experiment for a later boot.
They keep the OpenWrt 802.11 sender, macOS native probe, and `awdl0` UDP
listener as separate evidence sources.

`run_controlled_probe_once.py` defaults to a local plan. Its explicit
`--readiness-only` mode temporarily creates an OpenWrt monitor interface,
waits for the sender's `READY`, sends `ABORT` before `GO`, and requires a
zero-send result plus verified monitor/AP/temp-file cleanup. This mode does
not read or change Test086 metadata, inspect the kext, consume the shared boot
claim, start the listener, arm the native probe, or send a frame.
Both the readiness runner and full coordinator accept `--ap wlan7` to select
the current live AP interface; the default remains `wlan1`. The monitor PHY is
derived from that AP's current `iw dev <ap> info` output, while the channel-149
and 80 MHz gates remain enforced.

The test OpenWrt router's 2024 `mt76-connac` module panicked on a NULL pointer.
These host-side budget and receipt fixes do not repair that router driver;
pause RF runs on the affected module until it is fixed and verified.
This public source snapshot is updated independently; the frozen private IWN
preparation copy is not automatically synchronized. Compare its manifest and
hashes before a later manual sync.

`controlled_run_coordinator.py` is the separate, explicit full-run entry point.
New reports label their host protocol as
`setter_success_before_go_v2` and include the explicit 16-frame, 80 ms,
2-second sender profile; older report files are left unchanged.
It starts the native worker, waits for its identity/host-TX/claim preflight,
then requires both router sender and `awdl0` listener readiness before one
`ARM <run-token>`. The native actor consumes the boot claim and invokes the
Swift helper once with its existing 5 second helper timeout. The coordinator
allows 6 seconds for the terminal ARM event so a timeout/failure result can be
flushed and read. The native worker emits `NATIVE_ARMED` only after the helper
returns a successful `arm_property_accepted=true`; the event also says
`roc_start_observed=false`. A helper refusal, timeout, or invalid result emits
`NATIVE_ARM_FAILED`; the coordinator then sends router `ABORT` and never GO.
The boot claim remains consumed in either case, with no retry. Without `--run`,
it only prints a static plan. It never accepts or invents a phone-ready flag.

The full-run report preserves `events_parent_monotonic_ns[].monotonic_ns`
with its existing Python process-local meaning. A sibling
`events_parent_boot_monotonic_ns` records `mach_absolute_time` converted with
`mach_timebase_info` using checked integer arithmetic. Each pair brackets the
Python monotonic sample and records lower/upper boot-clock values, bracket
width, and an error bound. The report includes pre/post pairs and labels both
clock domains. Python clock epochs are explicitly not assumed to be shared
across processes; no child timestamp is translated using a guessed epoch.
The original `management_trace_u32_evidence` and
`NATIVE_RESULT.management_trace_valid` keep their legacy meaning. A sibling
`controlled_trace_review` separately classifies a production-guarded, stable
zero-event timeline as `not_applicable_empty_timeline`; it records no control
or data frame and cannot promote peer receipt or AirDrop.

If Mach time or its timebase is unavailable or invalid, the new boot-clock
timestamp is null with status `unsupported` and domain `unknown`. Python
`monotonic_ns` is never substituted as a boot-clock value. The sender now
requests 16 frames at 80 ms intervals, a 1200 ms span from the first to final
frame, within the unchanged 2 second transmit deadline. This increases the
observation window but does not establish overlap with an asynchronous ROC/RX
window. A possible one-second ROC scheduling delay means 1200 ms by itself is
not a coverage guarantee. GO write begin/end events bracket the coordinator's
actual stdin write and flush using Mach boot-clock samples; the legacy
process-monotonic values keep their previous meaning. If the lower bound of
GO-write begin is after the upper bound of native ROC END, or the upper bound
of the router-result receipt precedes the lower bound of ROC START, the sample
has a non-overlapping host-control envelope; delayed hardware emission remains
unknown. If the outer interval from GO-write begin to
router-result receipt intersects the ROC interval, overlap remains unknown
because the sender has no per-frame shared clock. This does not prove radio
delivery, native data input, peer receipt, or AirDrop. Historical 16/50 ms
results are not rewritten under the new sender contract.
The frozen native bundle metadata and kext build receipt remain unchanged;
the 80 ms sender is separately bound to its private binary hash and build
receipt.

The future controlled run is single-use per boot. It requires the frozen
Test086 build receipt and matching disarmed private metadata, a new boot epoch,
the expected loaded UUID, zero host-TX counters, native/receiver/router
readiness, and one shared `ObservationClaims/BootGlobal` claim. A missing
readiness gate aborts before ARM. Once ARM consumes the claim, no retry is
allowed. The sender requests `NOACK|NOSEQNO`; `sent` only means the local
router kernel accepted a complete `send()` call. It does not prove RF delivery,
native `ifnet_input`, UDP reception, peer discovery, or AirDrop.

The listener is receive-only and starts only with explicit
`--listen T086RX01 --run-token <32-hex> --recv-anyif`. The fixed eight-byte
marker is not a nonce. Its run token correlates local logs only. Logs omit the
peer address and packet content. A missing UDP marker remains separate from a
valid native `ifnet_input` receipt.

Offline tests:

```sh
python3 -m unittest discover -s developer-tools/test086-controlled/tests -v
```

No sender binary is stored in this public source directory; the statically
linked OpenWrt binary and its hash are held in the task-private preparation
directory.
