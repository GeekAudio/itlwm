# AWDL IPv6 data-frame codec contract

`awdl_data_frame.{hpp,cpp}` is a bounded, portable parser and serializer. It
performs no radio I/O, allocation, interface creation, or system networking calls
itself. Test051 links it into the explicit resident-data candidate; the native
BSD/Intel adapter owns all I/O and lifetime work. Earlier candidates used this
codec only offline. See `awdl_resident_data_contract_25G332.md` for the integration
and its unverified runtime boundaries.

## Supported wire subset

The decoder accepts one complete 802.11 MPDU without radiotap, FCS, encryption
overhead, or reassembly. It supports three-address, no-DS ordinary Data and
QoS Data headers using the AWDL BSSID `00:25:00:ff:94:73`. QoS control may
select one unaggregated payload or an A-MSDU. A-MSDU parsing is bounded to 16
subframes, validates each big-endian subframe length before reading, and skips
the required four-byte alignment padding only when another subframe follows.
The final subframe has no required padding.

Each body must contain the eight-byte LLC/SNAP prefix (`AA AA 03`, OUI
`00:17:F2`, protocol `0x0800`), then the eight-byte AWDL data header: little-
endian head `0x0403`, little-endian per-frame sequence, zero pad, and big-endian
ethertype `0x86DD`. The rest must be exactly one non-jumbogram IPv6 packet:
version 6 and a payload length matching the available bytes. Decoded packet
views point into the caller's input buffer.

The encoder emits one unaggregated, non-QoS Data MPDU in that same subset. It
takes both sequence numbers and the source/destination MACs from the caller;
it does not allocate or validate ownership of an AWDL interface address. It
does not emit radiotap or FCS bytes. Encoder input, output, and length pointer
must be valid and non-overlapping.

Both APIs commit output only after all validation succeeds. A failure leaves
the output frame / decoded structure and the encoder's `written` value
unchanged.

## Rejections and limits

The decoder rejects management/control frames, data subtypes other than Data
and QoS Data, DS-addressed frames, protected or fragmented frames, QoS mesh
control, wrong BSSID, invalid addresses, malformed LLC/AWDL fields, non-IPv6
ethertype, invalid IPv6 length/version, truncated A-MSDU headers or payloads,
and more than 16 subframes. It does not verify checksums or parse IPv6
extension/transport headers. The encoder does not aggregate packets.

Passing these format tests proves only this codec's byte layout and bounds. It
does not prove that firmware can transmit or receive ordinary data frames,
that the source MAC is owned by a native AWDL interface, that an `awdl0` data
path exists, or that AirDrop works.

## Validation

Run from the repository root:

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -O1 -g \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  native/awdl_data_frame.cpp native/tests/awdl_data_frame_test.cpp \
  -o /private/tmp/awdl-data-frame-test
/private/tmp/awdl-data-frame-test
```

The offline tests check exact encoded bytes and decode round-trip; every
truncated prefix of plain frames; malformed field and length cases; QoS and
A-MSDU boundaries, including 16 and 17 subframes; and unchanged outputs on
failure. A prefix ending exactly at a complete A-MSDU subframe boundary is
itself a valid shorter aggregate, so that case is tested as a one-subframe
success rather than mislabeled truncation.

## Wire references

- [Pinned independent AWDL spec, commit `9a676e11d011c34ea32798a2541f2b1eeb66e731`](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/docs/SPEC.md), AWDL-1, AWDL-13, and AWDL-14.
- [OWL frame definitions, commit `0ee3263f944ea721c355f826aa90d636d012a512`](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/frame.h), confirming the BSSID, LLC protocol ID, OUI, and eight-byte data header layout.
- [OWL TX path at the same commit](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/tx.c), confirming little-endian `0x0403`/sequence/zero pad, big-endian IPv6 ethertype, and LLC/SNAP serialization.
- [OWL RX path at the same commit](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/rx.c), confirming QoS A-MSDU dispatch and subframe length/padding handling.

The implementation was written from the public wire contract; no OWL or Owly
source code is copied into this module.
