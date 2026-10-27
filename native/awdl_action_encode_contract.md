# AWDL PSF encoder contract

`awdl_action_encode.{hpp,cpp}` serializes one PSF into a complete 802.11
Management Action MPDU. It is an offline format module. It is not linked into
the kext, does not call a radio or clock API, and does not advertise an active
AWDL interface or AirDrop service.

## Wire profile

The serializer emits the PSF field order specified by the pinned independent
AWDL spec: TLV types `4, 5, 18, 24, 6, 7, 12, 21`. Each TLV length and each
multi-byte field is little-endian. Type 4 contains a 57-byte synchronization
value, including the six-byte sequence header, 16 simple channel slots, and
two zero pad bytes. Type 18 contains the same sequence header and slots plus
three zero pad bytes. Only simple channel encoding is supported here; slot
values are restricted to `0`, `6`, `44`, and `149`, with at least one social
channel. The caller must provide the schedule that the radio will actually
serve; the encoder cannot verify radio scheduling.

The 802.11 header uses a broadcast destination, the caller-provided source MAC,
and AWDL BSSID `00:25:00:ff:94:73`. The source must be a nonzero unicast address.
The action header is AWDL 1.0 PSF. `phyTxTimestampUs` and
`targetTxTimestampUs` are copied verbatim. The spec defines them as the
transmission and scheduled-transmission timestamps in microseconds, but does
not define their epoch or a host-monotonic, firmware TSF, or GP2 conversion.
The serializer does not derive them. For an explicitly experimental bounded
PSF probe, a caller may snapshot `clock_get_uptime()` once, convert it to
microseconds, and pass its low 32 bits in both fields, matching the pinned OWL
implementation. OWL itself calls that offset arbitrary and samples before
`wlan_send`, so this is a way to test peer response, not proof of an accurate
on-air timestamp or a production AWDL clock mapping. Any related local sync
fields must come from the same snapshot.

The election TLVs are serialized from one caller-provided election snapshot.
Version 1 and version 2 fields share the same master, distance, and metric
values; a distance above 255 is rejected because TLV 5 cannot represent it.
Reserved fields and service parameters are emitted as zero. The HT TLV requires
explicit capability, A-MPDU, and one-to-four-byte MCS mask inputs. The Data Path
State TLV has flags `0`; no AWDL address or functioning data path is claimed.
The Version TLV requires an explicit version and macOS device class `1`.

## Bounded PSF probe: available inputs and remaining work

The source tree has enough pieces to plan a bounded control-frame experiment,
but not enough to publish a truthful working `awdl0` or AirDrop data path.

Available or source-backed for a limited probe:

- The Intel P2P role has a firmware MAC in `sc_p2p.mac_address`, and the P2P
  action TX path already uses that address. It is a candidate source address
  for a radio-only experiment. It is **not** established as the address of a
  native AWDL interface. The independent spec requires the advertised 802.11
  source to equal the AWDL interface MAC and remain stable while visible, so
  this P2P address cannot be presented as a conforming AirDrop identity until
  a native AWDL interface owns it.
- Host monotonic microseconds are already sampled in the P2P RX path. The OWL
  precedent above makes the same clock a bounded, low-confidence PSF timestamp
  experiment; it does not make firmware GP2 or TSF mapping a prerequisite for
  the first observation-only probe.
- A 900 ms channel-6 remain-on-channel window bounds how long a probe can hold
  the radio on that social channel. It is not itself an AWDL schedule. The
  independent spec defines an AW as 16 TU, each slot as four AWs, and the
  sequence as 16 slots. With the encoder's current 16 TU AW period and
  presence mode 4, a full sequence cycle is 1024 TU (1,048,576 µs), longer
  than 900 ms. Do not claim all 16 slots are served for that full cycle based
  only on one 900 ms ROC. A scheduler must anchor the cycle, set the down
  counter/next-AW fields, advertise only channels actually served in each
  slot, and stop or retune at the matching boundaries. A one-frame TX/RX
  observation can be time-bounded separately, but it does not validate the
  schedule or peer reachability.
- A one-node election can be initialized as a self-master rather than filled
  with arbitrary zeros: the pinned OWL implementation initializes master
  and sync addresses to the node's own address, distance to zero, metric to
  60, and counter to zero; the independent spec recommends metric 60 and
  counter 0. This is a source-backed starting election snapshot, not a
  replacement for maintaining counters and adopting a peer election when
  peers appear.
- The action source is a broadcast management frame and the encoder's type 12
  Data Path State currently has flags `0`, which advertises no optional data
  path fields. That is appropriate for a control-frame-only experiment; it
  also deliberately does not claim an AWDL IPv6/data path and cannot make
  AirDrop transfers work.
- AWDL 1.0, macOS device class 1, the action sequence field, and the 802.11
  sequence counter have clear wire representations. The sequence counter
  still needs a live owner and must advance per transmitted frame.

The bounded probe must remain observation-only until the native interface,
schedule, and receive path are ready. Its success criterion is a peer response
or a captured, independently verified PSF—not AirDrop discovery, `awdl0`
readiness, or data transfer.

## Values that still require native state

The API deliberately has no guessed production defaults. A production caller
must supply values from the corresponding runtime component:

- A native AWDL interface whose stable MAC exactly matches the advertised
  source address. The current target does not create `awdl0`.
- A host-clock-to-peer synchronization strategy and a measured TX timing
  bound. A bounded OWL-style host-clock experiment exists, but an exact
  Intel GP2/TSF-to-AWDL mapping is still unavailable and is not inferred from
  matching units.
- A running election worker that updates master/sync addresses, metrics,
  counters, and distance as peers appear and disappear.
- A live AWDL scheduler that owns the truthful 16-slot radio schedule, next
  channel, TU down-counter, remaining AW length, next-AW sequence, and AP
  alignment. The 900 ms ROC alone supplies none of those values.
- HT capability and RX MCS values bridged from the actual radio/driver
  capability set.
- Data Path State address fields and a functioning AWDL data path. These stay
  unannounced until a native AWDL interface and data path exist.

Tests use synthetic values only to verify byte layout, boundary rejection, and
parser compatibility. Passing an encoder test does not prove a valid schedule,
peer discovery, RX, AWDL data transfer, or AirDrop.

## Validation

From the repository root:

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/awdl_action_frame.cpp \
  native/awdl_action_encode.cpp native/tests/awdl_action_encode_test.cpp \
  -o /private/tmp/awdl-action-encode-test
/private/tmp/awdl-action-encode-test
```

The tests compare field-level golden bytes and fixed TLV offsets against the
wire tables, then also pass the result through the existing parser. This keeps
the parser as an interoperability check, not the serializer's only oracle.

## References

- [Pinned AWDL spec, commit `9a676e11d011c34ea32798a2541f2b1eeb66e731`](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/docs/SPEC.md)
- [OWL frame definitions, commit `0ee3263f944ea721c355f826aa90d636d012a512`](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/frame.h)
- [OWL monotonic clock](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/state.c), [PSF timestamps](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/tx.c), and [single-node election initialization](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/election.c)
- [Pinned AWDL parser, commit `9a676e11d011c34ea32798a2541f2b1eeb66e731`](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/crates/owly-awdl/src/tlv.rs)

These sources were used to check wire fields and values. No third-party source
implementation was copied into this module.
