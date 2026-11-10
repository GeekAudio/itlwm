# Test137 current-AW fallback diagnostic helper

Test137 is generated from the frozen Test137 kext identity and reuses the Test136 one-shot collector. It changes the exact build/UUID binding, enables `NativeAwdlDiscoveryCurrentAwFallbackEnabled` in the profile preflight, and adds the numeric `NativeAwdlDiscoveryRxWindowTerminal*` properties to each IOKit snapshot. The helper keeps the existing IncludeP2P plus IncludeAWDL browse, one `NativeP2PArmOnce`, 20-second total deadline, cleanup gate, and passive post-cleanup wait.

The builder reads `NativeTestBuild` from the kext personality and takes the UUID only from the x86_64 Mach-O slice. It compiles a private helper and does not load or install the kext, access the arm property, start Bonjour, or perform RF activity.

```sh
python3 developer-tools/test137/build_helper_test137.py \
  --kext /path/to/frozen/AirportItlwm.kext
```

The default invocation of the generated helper performs the existing read-only IOKit/profile preflight. `--help` is also read-only. The generated helper supports `--run`, which performs one system `_airdrop._tcp.local.` browse and one explicit ARM; it is not invoked by the builder or offline tests.

The private receipt keeps the old QWR1/QWS1, 288-byte facts, DataTxTrace, RX-window scalar, and ADRXWIN1 event formats unchanged. `test137_diagnostics.py` calls the existing Test136 decoder for those records and adds a separate numeric summary for the RX-window terminal observer. It preserves Begin/Close results, observer state, first/latest publish status, and the terminal receipt's Published marker. That marker commits only the terminal diagnostic tuple; it does not mean the RX window was successfully published. Missing or nonnumeric values stay unknown. Same-snapshot epoch matching is kept separate from the current-run join: the latter also requires a valid terminal identity, a nonzero context advance, and final context equal to the frozen cleanup context. Old or late snapshots stay unknown/stale. The driver generation is reported as a value without an assumed join. These fields do not change cleanup proof or peer-proof conclusions. The existing Current-AW attempt-only decoder reports whether the profile flag was enabled and whether the fallback planner was actually used. That remains local attempt evidence, not proof of send or peer receipt.

Run the existing 12-case decoder/producer regression unchanged, then the Test137-specific binding and stage tests:

```sh
python3 developer-tools/test136/test_test136_diagnostics.py
python3 developer-tools/test137/test_test137_helper.py
```

These are offline format and template checks; they do not execute the generated helper with `--run`.
