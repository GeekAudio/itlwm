# AWDL peer election candidate

`awdl_peer_election.{hpp,cpp}` is a standalone, offline-tested decoder and
pure election helper. It is not linked into AirportItlwm and does not enable a
radio schedule or publish an interface.

`decodePsf` and `decodeMif` parse the same synchronization, election, version,
and channel-sequence advertisement from subtypes 0 and 3. Both require a valid
source address, nonzero Version/device-class values, bounded synchronization
fields, and an Election Parameters TLV. Type 24 is authoritative when present;
otherwise type 5 supplies version-1 zero counters and sender-as-sync behavior.
The master in Synchronization Parameters must agree with the selected election
master. A PSF carries these fields directly and does not require MIF-only type
16 ARPA identity data. The output contains numeric election fields and six-byte
address values supplied by the caller; callers must keep these values private.
The runtime table can therefore keep a fresh PSF advertisement without
treating it as a MIF identity record.

`selectMaster` follows the pinned Owly reference algorithm: compare master
metric then counter for Apple-style ranking, ignore a peer that follows this
node, cap followed peer height at 9, then prefer shorter paths and the higher
peer address on a tie. Counter-first ranking is exposed as a comparison mode.
It is a pure selector: local identity, own metric/counter, and a current set of
valid peers are explicit inputs. It does not age peers, update counters, raise
metrics, or retain an election result.

The bounded runtime table keeps PSF advertisement fields and MIF fields with
separate receive times and leases. `selectMaster` still considers only fresh,
internally consistent MIFs. Neither decoder nor selector changes a radio
schedule. A production scheduler still needs a stable native AWDL interface
MAC, validated clock alignment, truthful channel service, election
counter/metric maintenance, and a firmware channel/availability-window owner.
The helper's tests prove byte-field extraction and table lease behavior only;
they are not runtime synchronization or AirDrop evidence.

The required Channel Sequence TLV 18 is canonical in a decoded advertisement.
If the optional, recognizable copy after offset 33 of Synchronization
Parameters TLV 4 is structurally valid but has different channel values, the
decoder accepts the advertisement, records `embeddedSequenceMismatch` and the
first differing slot/channel pair, leaves `embeddedSequenceVerified` false,
and returns the TLV 18 values in `channelSlots`. It does not rotate or merge
the arrays: the pinned reference does not define a separate offset for the
embedded copy. Malformed recognized copies and missing or malformed TLV 18
still fail closed. A matching copy sets `embeddedSequenceVerified`; this only
proves agreement between duplicate fields, not radio-clock synchronization or
schedule execution.

Field layout and policy basis are the independently maintained pinned Owly
specification and implementation:

- https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/docs/SPEC.md#32-action-frames
- https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/crates/owly-awdl/src/tlv.rs
- https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/crates/owly-awdl/src/election.rs

The helper is intentionally not added to the Xcode project or active driver
target. Its standalone test command is:

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/awdl_action_frame.cpp \
  native/awdl_action_encode.cpp native/awdl_mif_encode.cpp \
  native/awdl_peer_election.cpp native/tests/awdl_peer_election_test.cpp \
  -o /private/tmp/awdl-peer-election-test
/private/tmp/awdl-peer-election-test
```
