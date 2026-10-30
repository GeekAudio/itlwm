# Read saved Test088 reports

`readout.py` reads an existing Test088 output directory containing
`test088-tools-private.json` and `native-controlled-capture-private.json`. For
older Test087 output, it accepts `controlled-run-private.json` with the native
capture report. It only reads saved files; it does not contact the Mac, router,
or driver.

Pass both the input directory and output path explicitly:

```sh
python3 developer-tools/test088/readout.py \
  /path/to/test088-tools-boot1234567890 \
  --output /path/to/private-readout.json
```

Input reports must be regular files owned by the current user with mode `0600`.
The output is created with mode `0600`; an existing output is never overwritten.

The summary keeps unmeasured nominal timing separate from strict clock bounds
and preserves missing or incomplete values as unknown. `lossCount` is trace
accounting, not a count of lost radio packets; non-149 witness truncation and
deadline rejection are listed separately. `Unknown` RX-class events are called
non-MPDU stage events only when known MPDU classes reconcile with
`mpduEntryCount`. A local `send()` result does not prove RF emission, peer
receipt, or AirDrop success.
