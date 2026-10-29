# Native Tahoe Wi-Fi and AWDL adapter

This directory contains experimental Tahoe Wi-Fi and AWDL work built on the
OpenIntelWireless V2/HAL/net80211 driver. The WCL path handles native scan,
association, and event flow. The separate P2P/AWDL path experiments with action
frames, peer timing, transmit queues, RX tracing, and the native `awdl0`
interface lifecycle.

The current development candidate, Test079, targets x86_64 macOS Tahoe 26.7.2
(build 25G332) and the AX201 device match documented in the main README. It adds
guarded post-bootstrap pairing and bounded RX observation draining, and has no
runtime validation yet. Test078 booted with native `awdl0` and passed two short
Wi-Fi observation windows, but a later disconnect and watchdog remain unresolved.
Its AWDL run selected a control-only MIF bootstrap and did not submit a data query.
There is no confirmed peer data return or AirDrop file transfer.
See [the RX review](../developer-tools/RX-DATA-PATH.md) for the current boundary.

Some early WCL ABI investigation used macOS build 25G241. That is an analysis
reference, not a claim that all private interfaces are validated across Tahoe
releases. The Tahoe declarations are locally reconstructed interfaces; the
driver does not load Lilu or a legacy IO80211 family.

`wcl_wire` reads bounded kernel-owned WCL requests: scan441 is `0x1550` bytes;
association442 is `0x6f8` bytes. Local analysis notes are kept outside the
repository. Wire offsets are read explicitly rather than reinterpreting an
unrelated older C++ structure.

`wcl_backend` owns request state and secret material. It accepts open networks
and explicit WPA2-PSK/CCMP with a PMK, a bounded passphrase, or 64hex key. It rejects
WPA3-only, mandatory PMF, enterprise/extended AKMs, MLO, unsupported additional
security/behavior flags, and unimplemented alternate key carriers. Optional SAE
advertisements are preserved in the original RSN bytes; no scan IE is rewritten
to downgrade security. An accepted request is not reported as connected until
real association, a real associated BSSID beacon, and real port authorization
have all arrived.

Scan requests retain one firmware lease. Only a true terminal scan event can
produce successful event237. Cancellation is asynchronous: Aborted237 is delayed
until the terminal event, and new requests remain Busy during draining. A reset
or READY notification is not treated as proof that old notifications drained.
The caller's request ID is not used as a firmware completion identity.

The accepted timing family is home `{0,40,110}`, active `{0,20,40}`, passive
`{0,110}`, rest `{0,45}`. These canonical Apple producer defaults select the
**official Intel firmware-default timing policy**. They are not exact dwell or
home/rest passthrough. Noncanonical custom timings return Unsupported; requested
values and the selected policy are exposed as numeric/string diagnostics.

`Ingress` synchronously copies real borrowed RX bytes into a fixed queue, then
uses a resident `THREAD_CALL_OPTIONS_ONCE` callback to enter the actual driver
command gate. RX never calls WCL directly. The bounded queue reserves control
slots during beacon bursts; overload is counted and never invents success.

Per-network address changes keep BSD, the interface property, native Ethernet
registration cache, and net80211's address consistent. Failure quarantines later
requests; there is no implicit factory-address fallback. A new network's native
address request quiesces the previous association and scan before changing any
address layer. In-flight init, join and overlapping address transactions remain
Busy. The stopped hardware retires pending scans, and a restart waits for the
real HAL READY event before deferred join.
These are software coherence checks, not a firmware/on-air MAC readback.
Each private scan generates a fresh LAA distinct from primary and previous scan
addresses. The HAL snapshots that source into the probe-frame header while
leaving the station address and MAC_CONTEXT untouched. Previous scan identity
advances only after the corresponding real terminal event. The official Linux
scan implementation independently supports this template-source contract; this
is still not an RF readback of the resulting frame.

The first target uses the original BSD packet path. `registration` provides only
framework-owned Ethernet metadata plus an explicitly borrowed Network prefix;
it does not fabricate native logical links, pools, or queue sets. The borrowed
prefix is detached before parent stop/free, and native logical-link registration
is rejected. Other native registration helpers are not called by this path.

BSD preparation stays on the incoming caller thread and synchronously enters
the exact native workqueue gate. It checks `inGate && !onThread`, preserves the
full `IOReturn`, and publishes only after success. A failed native preparation
is finalized inside that gate before BSD detachment outside it. An unsupported
detach context retains its references until reboot and records quarantine.

Normal unload/hot-detach is not validated. The original HAL tears down some DMA
resources before its task queues are destroyed, so retain counts or the ingress
barrier alone do not prove all radio producers drained. Testing is by a backed-up
reboot deployment, not live kext unload/reload. No hardware result follows from a
syntax check or the portable fixtures.

Run the bounded parser/state tests from the repository root:

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/wcl_wire.cpp native/wcl_backend.cpp \
  native/tests/wcl_test.cpp -o /private/tmp/intel-native-wcl-test
/private/tmp/intel-native-wcl-test
python3 native/tests/check_adapter_syntax.py
```

The parser/state tests execute portable code with fake radio operations,
including truncated request lengths, timing policies, key validation, delayed
cancellation, stale generations, and deferred joins. The syntax check requires
Apple's Xcode tools and a locally supplied `MacKernelSDK`; that SDK is not
distributed in this repository. Some ABI and request-contract tests also depend
on local linked-image analysis files and notes that are not distributed.
Therefore a fresh clone can run the portable tests, but cannot run every test in
`native/tests` without those local analysis dependencies. Hardware scans,
association, RF behavior, peer data return, Bluetooth, and AirDrop need separate
runtime verification.

The Tahoe adapter and AWDL code are experimental additions to
OpenIntelWireless/itlwm. The project follows GPL-2.0; upstream code and firmware
retain their respective notices and licenses.
