# Test088 sender timing adapter

`controlled_run_test088.py` is a Test088 **tools** revision for the frozen
`25G332-Test087` driver (UUID `A73745C1-8CF6-3534-A138-988D61FF4E48`). It
reuses Test087's native worker, private metadata and build binding, arm helper,
one-per-boot claim, counters, listener, AP control transport, and existing
readiness and cleanup guards. It does not change or deploy the kext.

The adapter binds the Test088 AF_PACKET sender at
`afpacket-sender/build/awdl_probe_sender-aarch64-linux-musl` with SHA-256
`f134be242075e19f38b61ca105d89dfa148133fd3dafdf37480fcd3d7c0fd222`. On GO,
it preserves the bounded raw protocol lines and samples the Mac Mach boot
clock immediately after `SENDER_STARTED` and `SENDER_RESULT` arrive. It first
validates the legacy result fields with Test087's frozen parser; added timing
fields are parsed separately. Incomplete or invalid timing stays unknown and
cannot override native RX/input evidence. GO results with `aborted` or any
status other than `complete` and `failed` are rejected after cleanup.

Default invocation is a plan and performs no boot-epoch read, SSH, native
helper, claim, or RF action:

```sh
python3 developer-tools/test088/controlled_run_test088.py
```

The single-use action requires an explicit `--run`, an existing authenticated
OpenWrt SSH ControlMaster socket, the confirmed AP interface `wlan7`, and a new
boot epoch greater than `1793365591`:

```sh
python3 developer-tools/test088/controlled_run_test088.py \
  --run --host "$ROUTER_HOST" \
  --control-path "$ROUTER_CONTROL_PATH" --ap wlan7
```

The output directory is created under the ignored Test087 runtime root as
`test088-tools-boot<epoch>`. Existing output and boot claims are never cleared
or reused. The host fake-pipe integration tests do not use SSH, EFI, the
driver, or a radio. They do not represent an iPhone AirDrop transfer.

`send_timing.py` preserves IEEE 802.11 and AWDL sequence values separately and
correlates per-send Linux timestamps with bounded Mac Mach-clock receipt
samples. The driver's ROC timestamp uses the same boot clock: XNU's
[`clock_get_uptime`](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/clock.c)
returns `mach_absolute_time`, then XNU converts it to nanoseconds. The driver
publishes floored microseconds, so its ROC interval is expanded by at most
999 ns. The sender's Linux `CLOCK_MONOTONIC` epoch remains separate; its nominal
equal-rate mapping is labeled an unmeasured estimate. Clock failures preserve
known send rows but remain failed or incomplete, never budget-expired
successes. `send()` return values do not prove RF emission, peer receipt, or
AirDrop success.

Run the host-only adapter and parser tests with:

```sh
python3 -m unittest discover -s developer-tools/test088/tests -v
```
