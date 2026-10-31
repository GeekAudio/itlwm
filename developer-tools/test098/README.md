# Test098 TX completion publication harness

This offline harness exercises the bounded ordinary-completion publication
policy, the TX-completion observer, and the schema-2 decoder's publication
seqlock fields. It does not load a kext or access hardware.

Run:

```sh
python3 developer-tools/test098/test_completion_publication.py
```

When a TX response falls inside a Group2 sidecar interval, the RX completion
path captures an exact bounded observer cut and stores it in a one-slot
pending buffer. A later ordinary TX response cannot overwrite that cut. The
serialized main-gate drain checks only the pending stamp on unchanged ticks;
when dirty, it claims and publishes that exact cut, then acknowledges it only
after the scalar batch succeeds. A successful batch carries a publication
sequence equal to its even snapshot version and a source marker:
`1` for ordinary completion, `2` for a frozen watchdog snapshot. The decoder
continues to accept older schema-2 snapshots without those additive fields.
The changing `LiveRelatedCutLostCount` and
`LiveRelatedRecordDroppedCount` properties are standalone live counters; they
are deliberately distinct from the similarly named counters inside the
versioned snapshot, so they cannot make an older even snapshot appear torn or
fresh.

The watchdog-owned completion snapshot remains frozen once pending; ordinary
periodic publication does not overwrite it. These fields prove only a local
host-side completion observation, never firmware acceptance or peer receipt.
