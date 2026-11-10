# Test138 local QM MPDU receipt

Test138 reuses the Test137 one-shot collector and binds its helper to the
Test138 build, Mach-O UUID, MIF current-slot profile, current-AW fallback
profile, and `NativeAwdlQmNoKnownAnswerCompiled` marker. The generated helper
keeps the existing 20-second bound and requires one explicit `--run` for the
system browse plus manual ARM. Building it and `--help` do not start the browse
or ARM the driver.

```sh
python3 developer-tools/test138/build_helper_test138.py \
  --kext /path/to/frozen/Test138/AirportItlwm.kext
```

Decode one private JSON receipt with:

```sh
python3 developer-tools/test138/test138_diagnostics.py PRIVATE_RECEIPT.json
```

The decoder first consumes Test136's QWR1/QWS1, legacy facts, and DataTxTrace
join. It then parses the exact MPDU bytes in that joined QWR1 capture. A valid
final packet must have the expected IPv6/UDP lengths and checksum, the
`_airdrop._tcp.local` PTR/IN QM question, zero DNS ID/flags, QDCOUNT 1, and
AN/NS/AR counts zero. The final ANCOUNT is direct packet evidence; no pre-strip
ANCOUNT witness exists, so original ANCOUNT 1 is labeled as an inference from
the exact Test138 guarded success path. Neither result proves RF airtime, peer
acknowledgement, peer receipt, or completed AirDrop.

Offline regressions:

```sh
python3 developer-tools/test138/test_test138_helper.py
```

The C++ fixture calls the production Known-Answer transform and MPDU encoder.
It is a format regression fixture, not runtime evidence.
