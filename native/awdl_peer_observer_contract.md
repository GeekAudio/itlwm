# AWDL peer observation contract

`awdl_peer_observer.{hpp,cpp}` is an offline-tested, fixed-capacity observer
for `ActionFrameRecord`s that already passed the bounded RX parser. It does not
create an AWDL interface, publish an AirDrop peer, send frames, or carry data.

The observer keys a private 16-slot table by the transmitter's 802.11 Addr2.
It counts a peer only after a MIF and nonzero Version/device-class fields,
matching the validity rule in the pinned Owly peer model. It stores no name,
raw frame, or published MAC address. A generation change, inactive context, or
more than 60 seconds without a refresh clears the table; a full table replaces
the least recently observed slot.

The RX record's `rxMonotonicUs` must be captured in the RX tap. Both it and the
observer's `nowMonotonicUs` are monotonic microseconds. The observer rejects
missing, future, over-age, out-of-order, truncated, or stale-generation input.
Its snapshot exposes only a valid-peer count, the latest driver's RX channel
index, numeric Synchronization Parameters fields, a field-sanity bit, and age.
The channel value is the driver's channel index, not necessarily an IEEE
channel number.

TLV 4 fields follow the pinned AWDL reference: offsets 0, 1, 3, 5, 7, 27, and
29 contain next-AW channel, TX down-counter, master channel, AW period, action
frame period, presence mode, and next-AW sequence. The master address at offset
21 is not retained. `syncFieldsValid` checks only a down-counter no greater
than 64 TU, AW period 16 TU, and presence mode 4. It does not establish clock
alignment, infer TSF/GP2 correspondence, or prove the channel schedule works.

Useful source references:

- [Pinned Owly AWDL field reference](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/docs/SPEC.md)
- [Pinned Owly sync-field parser](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/crates/owly-awdl/src/tlv.rs)
- [Pinned Owly peer-validity rule](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/crates/owly-awdl/src/peer.rs)
- [OWL protocol field definitions](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/frame.h)

## Worker integration point

The consumer of `Router::popRecord` can pass `record.payload.actionFrame`, the
current context/power/station generations plus active state, and the current
monotonic microsecond time to `Observer::observe`. Call `snapshot` on that same
serialized worker. Keep this output separate from device discovery and
IORegistry publication. The existing RX STA path must continue processing its
original mbuf regardless of observer results.

Test032 links the observer into the Tahoe target. The RX tap records uptime
microseconds and all three generations. The watchdog is on a separate workloop,
so it uses the main command gate's nonblocking `attemptAction` before consuming
records or examining current epochs. A busy main gate defers consumption until
the next watchdog tick. No firmware command, ownership transfer, or automatic
retry is introduced by this observer.

Observation lifetime differs from radio-lease lifetime: a successfully retired
bounded lease can already be inactive when its records are consumed. The
observer retains evidence for the same current epochs while the infrastructure
radio is running, and clears it on epoch changes, inactive radio, or TTL expiry.
That retention does not authorize further transmission. Accepted/rejected frame
counts are cumulative diagnostics; current valid-peer count remains separate.

The router also exposes bounded AWDL-envelope and parser-rejection counters,
including the last numeric rejected parse status. These distinguish no
qualifying RX from a parser rejection without publishing addresses or raw
frames. Last-result diagnostics start at `UINT32_MAX` (not observed), rather
than enum zero (success). Consumed router slots are cleared before publishing
the consumer cursor so old raw frame bytes do not remain in the ring.

## Offline test

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/awdl_action_frame.cpp \
  native/awdl_peer_observer.cpp native/tests/awdl_peer_observer_test.cpp \
  -o /private/tmp/awdl-peer-observer-test
/private/tmp/awdl-peer-observer-test
```

The tests use generated PSF/MIF frames. They prove that synthetic valid peers
can enter the observer and stale, over-age, truncated, future-timestamp, and
invalid-source cases are rejected. They do not prove that a real peer frame
reaches this driver's RX path or that AirDrop works at runtime.

## Test033 rejection diagnostics

Test032 delivered three AWDL envelopes to the host, but each returned
`InvalidTlv`; no peer was admitted. Test033 retains the parser acceptance
policy and records numeric rejection detail: reason, subtype, current/expected
TLV type, offset, declared/available lengths, observed/required masks and the
first 16 TLV types (two packed 64-bit values). The full header count indicates
trace truncation. No TLV payload, address or host name is published.

Reasons are None=0, LengthOverrun=1, InvalidValue=2, ArpaInPsf=3,
DuplicateRequired=4, RequiredOrder=5, MissingRequired=6 and EmptyList=7.
The low byte of each trace word contains its earliest TLV type. IORegistry
may print these words as signed integers; readers must mask them to 64 bits
before decoding. A rejection detail is diagnostic evidence, not peer admission.

From Test036, `RequiredOrder=5` is retained only for historical records. Receive
TLVs may be reordered; type 24 is optional but still checked for length and
duplicates. `requiredMask` omits its original bit, while `seenMask` keeps the
same stable type-to-bit mapping. `expectedType` is the first missing mandatory
type rather than the next required wire position. The numeric trace now uses
a separate bounded scan of up to 128 TLV headers, stopping at length overrun,
so later types remain visible after an earlier semantic rejection. This does
not change peer admission, epoch checks or the no-payload diagnostic boundary.
