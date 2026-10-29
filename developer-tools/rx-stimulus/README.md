# Offline AWDL RX fixture

This small developer tool creates exactly one synthetic, unprotected AWDL Data
MPDU and checks it with the production encoder, header classifier, and decoder.
It uses a locally administered source MAC, a synthetic `fe80::` IPv6 source,
`ff02::1` multicast destination, and the fixed nonce `IWN-RX-TEST-0001`. The
IPv6 UDP checksum is computed and verified independently.

The fixed nonce is a deterministic fixture marker, not a fresh experiment
identity. Any later live experiment needs its own session-bound nonce and
matching receive evidence.

The default run keeps the frame in memory and reports validation only. It has no
network API, raw socket, SSH client, router command, or RF transmit path. Use
the optional output argument only to save the already checked synthetic fixture:

```sh
xcrun clang++ -std=c++14 -Wall -Wextra -Werror -Inative \
  developer-tools/rx-stimulus/awdl_rx_fixture.cpp native/awdl_data_frame.cpp \
  -o /tmp/awdl-rx-fixture
/tmp/awdl-rx-fixture
/tmp/awdl-rx-fixture --output /tmp/awdl-rx-fixture.pcap
# or: /tmp/awdl-rx-fixture --output /tmp/awdl-rx-fixture.hex
```

The output is created with mode `0600`; an existing file is never overwritten.
PCAP output uses a minimal radiotap header and one 802.11 frame. Hex output is
the raw MPDU. Neither output is transmitted by this program.

The existing production BSD bridge host-shim suite is a separate software
check: [`native/tests/test060_native_bridge_asan.py`](../../native/tests/test060_native_bridge_asan.py)
and [`native/tests/awdl_bsd_bridge_shim_test.cpp`](../../native/tests/awdl_bsd_bridge_shim_test.cpp).
Together those checks exercise host decode/bridge behavior; they do not prove
firmware acceptance, RF airtime, Mac RX, or peer receipt.

## What a later RX observation can prove

If a future, explicitly authorized and bounded OpenWrt experiment sends this
exact synthetic nonce and the Mac logs the same decoded nonce at the expected
RX stages, that is evidence of a synthetic frame reaching those driver stages.
It is not an iPhone, AirDrop, or general AWDL interoperability result. A missing
nonce remains ambiguous between router TX not happening, RF/channel mismatch,
and Mac RX not accepting the frame.

Current OpenWrt tooling only proves passive monitor-capture support. It does
not establish that the installed radio/driver can inject a monitor MPDU while
the AP stays on channel. A local monitor capture marked `PACKET_OUTGOING` only
proves a host-side transmit request; it is not proof of RF airtime. No injector
or router package changes are included here.
