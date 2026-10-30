# Test092: Wi-Fi reopen recovery and RX149 gate recovery

Test092 combines two offline changes for AirportItlwm on macOS build 25G332:

- The WCL backend retains a scan or join request when the radio returns `Busy`, then retries it within a fixed deadline. A queued scan expires after 20 seconds; a queued join has a 30-second admission deadline. If the radio accepts the join, the existing join-completion timeout starts from that submission. A newer valid request can replace a queued request of the same kind. It does not interrupt an already submitted scan or join. Abort and driver-off clear queued scans; driver-off, leave, or timeout clear queued joins. A submitted scan completes only on its matching firmware terminal event; a join still requires the existing association, authorization, and beacon completion conditions.
- RX149 data-input recovery uses the Test092 HAL gate and requires the existing initialization, fault, ROC, and queue-drain checks. The candidate keeps the 100 ms channel-149 receive window, the four-second numeric pre-owner observation, and blocks host management/data transmission.

The WCL host tests cover Busy retry, deadlines, request replacement, cancellation, power-off, stale generations, and preservation of `NotReady`/failure behavior. The RX bridge and HAL tests check production code through host shims. These checks do not load a kext, exercise firmware, verify Wi-Fi recovery on hardware, demonstrate an over-the-air receive, or prove AirDrop.

## Offline checks

The Test092 candidate builder runs these focused checks as part of its full pre-build suite:

```sh
python3 developer-tools/test092/run_wcl_asan_ubsan.py
python3 native/tests/test086_native_rx_data_input.py
python3 native/tests/test086_legacy_bsd_bridge.py
python3 native/tests/test092_rx149_recovery_hal_integration.py
```

The WCL binary and the bridge/HAL harness binaries are created in temporary directories, not in the repository. The bridge test also runs its existing ThreadSanitizer check.

Build the offline candidate and save its private receipt with:

```sh
python3 ../IntelWirelessNative/research/build_test092_candidate.py
```

The build does not install the kext or perform RF activity. Deployment and runtime validation are separate steps. A successful offline build does not establish that the Wi-Fi toggle issue is fixed on the machine, or that AWDL receives data.
