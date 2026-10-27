# AWDL MIF encoder contract

`awdl_mif_encode.cpp` builds an MIF by calling the existing PSF encoder, then
inserting the required type-16 ARPA TLV before Data Path State and changing the
AWDL action subtype to 3. The other PSF fields are reused byte-for-byte. The
caller supplies every `PsfInput` value and a bounded host label; the encoder
does not invent clock, election, channel-scheduler, HT, version, identity, or
host-name values.

The ARPA value is encoded as flags `3`, one length byte, the caller's single
ASCII DNS host label (1–63 characters), and the fixed `c0 0c` compressed `.local`
suffix. Dots, NUL, non-ASCII bytes, underscores, malformed hyphen placement,
and caller-supplied compressed layouts are rejected. The host label must omit
`.local`. Data Path State remains the existing empty value (`00 00` flags); this
encoder does not claim an active `awdl0` or data path.

The wire shape follows the primary OWL sources: `src/frame.h` declares MIF
subtype 3 and the type-16 ARPA fields; `src/tx.c` emits flags 3, the supplied
name bytes, and `AWDL_DNS_SHORT_LOCAL` (`0xc00c`, commented `.local`), and adds
ARPA only to MIF. This implementation independently bounds the hostname and
uses the local parser to validate both the reused PSF and resulting MIF.

Source references:

- [OWL `frame.h`](https://github.com/seemoo-lab/owl/blob/master/src/frame.h)
- [OWL `tx.c`](https://github.com/seemoo-lab/owl/blob/master/src/tx.c)
- Local parser: `native/awdl_action_frame.cpp`
- Shared serializer: `native/awdl_action_encode.cpp`

## Focused sanitizer test

From the repository root:

```sh
clang++ -std=c++17 -O1 -g -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/tests/awdl_mif_encode_test.cpp \
  native/awdl_mif_encode.cpp native/awdl_action_encode.cpp \
  native/awdl_action_frame.cpp -o /tmp/awdl_mif_encode_test_asan
/tmp/awdl_mif_encode_test_asan
```

The test is offline and synthetic. It covers MIF parse round-trip, byte/layout
bounds, zero Data Path State, malformed labels, maximum label/capacity, and
output-preservation on failure. It does not test radio TX/RX, native `awdl0`,
peer acknowledgement, or AirDrop.
