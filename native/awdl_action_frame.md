# AWDL frame parser experiment

This parser is linked into the Tahoe kext and used by the bounded P2P RX tap.
It does not transmit frames, create a P2P interface, or advertise AirDrop support.

The parser accepts a complete 802.11 management Action MPDU with an AWDL vendor
action header: category `127`, OUI `00:17:f2`, type `8`, version `1.0`, and PSF
or MIF subtype (`0` or `3`). It checks the fixed header, mandatory TLV presence,
length boundaries, known fixed/minimum lengths, channel-sequence encoding, and
the allowed short zero padding. It drops unknown action subtypes. The IEEE
802.11 container (type 17) and unknown TLV types are skipped after validating
their outer length; the container's contents are not decoded. Data Path flags
accept the known field mask and the exact legacy value `0x8f24`, with the same
known-field lengths and optional two-byte zero extension checks. Other unknown
flag combinations remain rejected. It does not return
source/destination addresses, peer names, or TLV payload bytes.

## What blocks actual AirDrop

The Tahoe target compiles `AirportItlwmV2.cpp`,
`AirportItlwmEthernetInterface.cpp`, and `AirportItlwmSkywalkInterface.cpp`.
The older `AirportItlwm.cpp`, `AirportSTAIOCTL.cpp`, and `AirportAWDL.cpp`
sources are not in that target's Sources phase. The current Tahoe path has no
AWDL/P2P interface or active low-latency peer session. The generic output path
queues Ethernet data through net80211. Test029 has a manually armed diagnostic
P2P firmware MAC, raw Action TX and bounded RX tap; these are not connected to
the native AWDL protocol or an AWDL scheduler/data path.

The tested PCI 8086:7af0 device selects `iwlwifi-so-a0-hr-b0-68.ucode`
and the AX210 transport family with gen3 TX commands, despite its AX201-class
HR2 radio. The earlier QuZ fixture did not represent this machine. Firmware
P2P command support confirms a prerequisite only; it does not establish support for
Apple AWDL timing, channel hopping, or the native macOS interface contract.
Before integration, the missing work is a concrete native AWDL protocol class,
production management-frame TX/RX, a coexistence-safe AWDL time/channel
scheduler, AWDL data frames, and a complete two-way transfer test.

On 2026-10-27 Test029 received firmware TX status 1 and retired its one-shot
descriptor, queue and station. Its Session Protection notifications were
START status 1 and END status 0, so the full scheduled dwell did not pass.
The test frame was not AWDL and no peer reception was established. A later
Wi-Fi off/on, saved-network rejoin and six small interface-bound HTTP transfers
passed; these do not establish long-term stability or maximum throughput.

Test031 fixes two receive-parser interoperability errors: legacy `0x8f24`
Data Path flags and bounded type-17 containers were previously rejected. Fresh
synthetic PSF/MIF frames reproduced both failures in the old parser and failed
to enter the RX router. Parser and router tests now pass with ASan/UBSan, while
truncation, invalid extension and unknown-flag rejection remain covered. This
is offline validation, not evidence that a peer frame reached this hardware.
At Test031 the required PSF/MIF TLV sequences, including type 7, were unchanged.
Whether type 7 should be optional in PSF remains a separate interoperability
question.

## Test036 receive compatibility

Test035's single 900 ms window received six AWDL envelopes, all rejected by
the then-current parser. The last numeric trace was `4,5,18,19,6`, with
type 6 declaring 15 bytes; rejection occurred at the fixed-order check before
that value was examined. No payload bytes were captured, so a synthetic frame
with that trace is not a replay or proof that the real value was valid.

Test036 follows OWL's per-TLV receive dispatch instead of imposing the encoder's
transmit order. Mandatory fields and duplicate rejection remain. Type 24
(Election Parameters v2) is optional, matching OWL's explicit v1 fallback;
when present it must still be exactly 40 bytes and unique. Type 5 remains
mandatory, so v2-only frames are still unsupported. Diagnostic bit positions
are preserved, and the required mask excludes only the type-24 bit.

Service Parameters (type 6) are validated using the Wireshark layout:
three reserved bytes, a two-byte SUI, a four-byte bitmap, then one value byte
for each set bit. The required length is `9 + popcount(bitmap)`, not a fixed
9 or 15. Existing truncation and outer-boundary checks remain in force.

A separate header-only diagnostic pass records the first 16 types, counts at
most 128 headers, and stops at an outer-length overrun. This allows subsequent
well-bounded types to remain visible after a semantic rejection, without
retaining peer addresses or payloads. `RequiredOrder=5` remains reserved for
historical records and is no longer emitted. Real peer acceptance still needs
the next boot's single diagnostic; no second probe was run in Test035.

## Test

From the repository root:

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/awdl_action_frame.cpp \
  native/tests/awdl_action_frame_test.cpp -o /private/tmp/intel-awdl-frame-test
/private/tmp/intel-awdl-frame-test
```

The test uses synthetic PSF/MIF frames, malformed lengths and fields, short
padding, unknown TLVs/actions, and deterministic mutation/random-input fuzzing.
No captured user frame, live interface, or firmware TX path is involved.

## Protocol references

- Milan Stute et al., [One Billion Apples’ Secret Sauce: Recipe for the Apple
  Wireless Direct Link Ad hoc Protocol](https://arxiv.org/abs/1808.03156).
- SEEMOO Lab, [Open Wireless Link frame definitions](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/frame.h)
  and [receive parser](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/rx.c).
- The independently written [AWDL protocol specification](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/docs/SPEC.md)
  documents TLV lengths and trailing zero padding.
- Wireshark, [AWDL dissector](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-awdl.c),
  Service Parameters bitmap and value-byte layout.

The parser is a fresh implementation of the wire checks above; it does not copy
those projects' source code.
