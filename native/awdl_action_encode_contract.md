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
explicit capability, A-MPDU, and one-to-four-byte MCS mask inputs. Data Path
State has two exact profiles. Aggregate-zero `advertiseAwdlAddress=false`
preserves the legacy two-byte `00 00` value. When the caller sets it true, the
serializer emits flags `0x0004` followed by the same six bytes used in 802.11
Addr2; it has no second MAC input. The encoder only serializes the caller's
profile. It does not verify interface identity or claim that the AWDL data path
is ready. Production callers may set the flag only after the HAL verifies the
native interface identity for the same generation.

The maximum PSF is 237 bytes: the legacy four-byte MCS profile remains 231
bytes and the address form adds exactly six bytes. Smaller MCS masks retain
their prior legacy frame lengths. The Version TLV requires an explicit version
and macOS device class `1`.

## Bounded PSF probe: available inputs and remaining work

The source tree has enough pieces to plan a bounded control-frame experiment,
but not enough to publish a truthful working `awdl0` or AirDrop data path.

Available or source-backed for a limited probe:

- The P2P action path has a firmware MAC, but the encoder does not infer that it
  is a native AWDL identity. The optional address field is enabled only when
  the HAL supplies a same-generation identity check; the serializer then uses
  exactly `sourceAddress` for Addr2 and the advertised AWDL address.
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
- The action source is a broadcast management frame. Type 12 either keeps the
  legacy flags-zero value or announces only the verified address field with
  flags `0x0004`. Address advertisement is not proof of an AWDL IPv6/data path
  and cannot by itself make AirDrop transfers work.
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
- A functioning AWDL data path. The optional address field is an identity
  advertisement only; it does not prove packet delivery or data readiness.

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

The tests compare fixed raw golden bytes, field-level values, and TLV offsets
against the wire tables, then also pass both Data Path profiles through the
existing parser. This keeps the parser as an interoperability check, not the
serializer's only oracle.

## References

- [Pinned AWDL spec, commit `9a676e11d011c34ea32798a2541f2b1eeb66e731`](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/docs/SPEC.md)
- [OWL frame definitions, commit `0ee3263f944ea721c355f826aa90d636d012a512`](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/frame.h)
- [OWL monotonic clock](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/state.c), [PSF timestamps](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/tx.c), and [single-node election initialization](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/election.c)
- [Pinned AWDL parser, commit `9a676e11d011c34ea32798a2541f2b1eeb66e731`](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/crates/owly-awdl/src/tlv.rs)

These sources were used to check wire fields and values. No third-party source
implementation was copied into this module.
