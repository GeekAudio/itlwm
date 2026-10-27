# AWDL MIF synchronization-field decoder

`IntelAwdlElection::decodeMif` decodes one already-framed MIF. It does not
perform clock mapping, elect a runtime master, switch channels, or grant TX
permission.

`decodePsf` uses the same bounded synchronization/election/channel-sequence
decoder for subtype 0. PSF contains the same advertisement fields in TLVs 4, 5,
18, optional 24, and 21; unlike MIF, it has no required type-16 ARPA identity
TLV. The runtime table stores PSF and MIF results separately, with independent
receive times, GP2 values, shape, and freshness. Their shared numeric decoder
diagnostic structure does not merge the two per-subtype histories.

## Source basis

- The pinned Owly AWDL specification describes fields 0–30 of Synchronization
  Parameters TLV 4, calls the independent Channel Sequence TLV 18 required,
  and says a reader needs only offsets 0–30. It also documents the copied
  sequence after offset 33 as the same layout as TLV 18, with no separate
  phase/index field. The document labels
  itself an independent specification, not an Apple publication:
  [SPEC.md at 9a676e11](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/docs/SPEC.md#L159-L184).
- The pinned OWL receive implementation reads `tx_down_counter` at offset 1
  and the AW sequence at offset 29 from TLV 4. It handles TLV 18 in a separate
  parser; it does not parse or compare the optional copied sequence inside
  TLV 4:
  [rx.c at 0ee3263](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/rx.c#L34-L90),
  [TLV dispatch](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/rx.c#L208-L225).
- OWL's transmitter writes the channel sequence into TLV 4 and emits TLV 18
  separately. Owly does the same when it constructs frames:
  [OWL tx.c](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/tx.c#L98-L146),
  [Owly tlv.rs at 9a676e11](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/crates/owly-awdl/src/tlv.rs#L90-L120),
  [Owly TLV construction](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/crates/owly-awdl/src/tlv.rs#L367-L415).

These sources describe the two fields as duplicate encodings of one sequence,
not two schedules with a documented relative offset. A complete mismatch is
therefore retained as an anomaly; the decoder does not rotate either array or
claim that the mismatch is a valid phase difference. Since both reference
receivers consume the independent TLV 18 and ignore the copied sequence for
peer parsing, the required, structurally valid TLV 18 remains canonical for
the Advertisement.

These sources justify consuming the fixed synchronization prefix and the
independent required channel-sequence TLV. They do not prove that every Apple
firmware version emits a copied sequence in TLV 4, so the copy is optional
evidence rather than an admission requirement.

## Decoder behavior

- The generic action parser still enforces complete outer TLV boundaries,
  mandatory MIF TLVs, and a minimum 31-byte value for TLV 4. TLV 18 remains
  mandatory and must decode completely.
- The MIF decoder reads required synchronization fields through offset 30.
  AP alignment is read only if both bytes are present. The embedded-sequence
  tail begins at offset 33; the declared TLV length bounds every read and any
  unparsed tail is skipped without copying it.
- A tail is recognized as a channel-sequence header only when all fixed
  header fields match: slot-count-minus-one 15, encoding 0/1/3, duplicate count
  0, step count 3, and fill channel `0xffff`. A matching but truncated or
  malformed block is rejected. TLV 18 is independently required and fully
  decoded. A complete, recognized embedded copy that differs from TLV 18 sets
  `embeddedSequenceMismatch`, records the first differing slot and both
  channel numbers, leaves `embeddedSequenceVerified` false, and does not reject
  the otherwise valid advertisement. Advertisement channel slots always come
  from TLV 18; no offset normalization or schedule inference is performed.
- No embedded sequence, a partial AP-alignment area, or an unrecognized tail
  leaves `embeddedSequenceVerified` false and does not reject an otherwise
  valid MIF. A recognized, matching copy sets it true. A recognized but
  disagreeing copy is distinguished by `embeddedSequenceMismatch` and its
  first-slot/channel diagnostics. The five shape fields
  (`syncParameterLength`, `syncTailLength`, `embeddedSequencePresent`,
  `embeddedSequenceRecognized`, `embeddedSequenceVerified`) are copied from
  the same accepted Advertisement into its PeerSnapshot.
- `syncConsistent` means parsed synchronization fields are in their accepted
  ranges and the synchronization master matches the election master. It does
  not mean the local radio is synchronized to the peer, that an advertised
  channel schedule was actually served, or that a clock map is verified.

## Diagnostics

`DecodeDiagnostics` stores only numeric stages, TLV type/offset/lengths,
synchronization scalars, embedded-sequence shape, and (on a nonfatal mismatch)
the mismatch flag plus first differing slot and both channel numbers. It
retains no MAC addresses or frame bytes. A nonfatal mismatch has
`rejectStage=kNone`. `Table.lastMifRejectDiagnostics` is updated by MIF
decode attempts and left unchanged by later PSFs. It may describe another
peer's most recent MIF attempt; per-peer five-field shape stays with that
peer's MIF snapshot and must be read separately. A zero `rejectStage` means
the last decode did not stop at a recognized `InvalidSync` branch; the rest of
the fields can still carry the last attempt's shape.

Neither the decoder nor the table turns a valid parse or an embedded-copy
match into timing, mapping, scheduling, or transmission proof.

## Offline coverage

The election tests exercise both `decodeMif` and `decodePsf` on generated
frames. The election and runtime-table tests cover a complete matching embedded
copy, nonfatal conflicts in either direction with TLV 18 remaining canonical,
the required type-18 sequence without an embedded copy, an unknown bounded
tail, a recognized truncated sequence, numeric rejection diagnostics, and
persistence of the last MIF diagnostic across a later PSF. These are pure
offline parser/table checks, not live-radio or AirDrop validation.

`embeddedSequenceVerified` describes only the recognized sequence header and
slot values compared with TLV 18. Bounded unknown suffix bytes following that
copy are ignored and are not validated by that flag. A 32-byte TLV 4 exposes
only the required 31-byte prefix; its incomplete AP alignment is not read or
used. Tests cover 30/32/33-byte boundaries, absent type18, zero version/device
class, and a recognized copy followed by an unknown suffix.
