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
It starts the native worker, waits for its identity/host-TX/claim preflight,
then requires both router sender and `awdl0` listener readiness before one
`ARM <run-token>`. It sends `GO <same-token>` only after the native actor
confirms that the shared boot claim was consumed. Without `--run`, it only
prints a static plan. It never accepts or invents a phone-ready flag.

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
