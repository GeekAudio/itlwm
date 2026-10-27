# Tahoe AWDL virtual interface contract

This note records the confirmed macOS 26.7.1 (25G241) interface path found in
the local linked IO80211Family and AppleBCMWLANCore images. It is a reverse
engineering note, not a claim that AirportItlwm currently creates `awdl0`.

## Confirmed creation path

The Tahoe `apple80211_virt_if_create_data` layout in
`include/Airport/apple80211_ioctl.h` is 32 bytes: version at 0, six-byte MAC at
4, reserved field at 10, 32-bit role at 12, and BSD name at 16. The existing
enum assigns role 6 to AWDL on this target.

In 25G241, `AppleBCMWLANCore::setVIRTUAL_IF_CREATE` routes role 6 to
`createProxInterface`. That routine copies the supplied MAC, creates an
`AppleBCMWLANProximityInterface` with the literal name `awdl`, attaches it to
the core, builds `IOSkywalkEthernetInterface::RegistrationInfo`, then starts
the proximity interface. This is the concrete native path behind the request.

The generic `IO80211Controller::createVirtualInterface` is a different path:
it accepts role 7 only and initializes the object with name `ap`. It cannot be
used as the AWDL creator without adding the native ProximityInterface setup.

The `IO80211VirtualInterface` implementation routes `createPeerManager()` as
follows: role 6 constructs an `IO80211AWDLPeerManager`; role 7 constructs the
regular `IO80211PeerManager`; roles 8/9 and 10 route to the NAN manager types.
`configureIfnet()` checks role mask `0x740`, which includes role 6, and calls
`peerToPeerConfigureIfnet()`. This confirms that role 6 is wired for a P2P
network interface in IO80211Family.

## What is still missing in AirportItlwm

The current Tahoe interface returns `kIOReturnUnsupported` for
`setVIRTUAL_IF_CREATE`. It has no equivalent of Apple's ProximityInterface
registration/start sequence, no AWDL peer manager lifecycle, no Intel firmware
time/channel scheduler, and no raw action-frame TX/RX or AWDL data path. The
role and interface ABI are now known; the Intel implementation and data plane
remain unimplemented.

The separate `awdl_virtual_request` helper only parses the request prefix,
accepts role 6 and a valid unicast MAC, and returns a copied request value. It
does not call kernel interfaces, register a BSD interface, or advertise
AirDrop. It is not linked into the kext.

## Local evidence and reproducibility

- IO80211Family linked image:
  `../SkywalkLegacyCompat/src/awdl_compat/evidence/native-IO80211-linked-25G241/IO80211Family.linked-analysis.macho`
- AppleBCMWLANCoreMac linked image:
  `../SkywalkLegacyCompat/research/evidence/native-BCMWLANCoreMac-linked-25G241/AppleBCMWLANCoreMac.linked-analysis.macho`
- Header/vtable extraction:
  `include/Tahoe/evidence/25G241-native-vtables.json`
- Relevant symbols: `IO80211VirtualInterface::createPeerManager`,
  `IO80211VirtualInterface::configureIfnet`,
  `IO80211Controller::createVirtualInterface`,
  `AppleBCMWLANCore::setVIRTUAL_IF_CREATE`, and
  `AppleBCMWLANCore::createProxInterface`.

Run the standalone parser test with:

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/awdl_virtual_request.cpp \
  native/tests/awdl_virtual_request_test.cpp -o /private/tmp/intel-awdl-request-test
/private/tmp/intel-awdl-request-test
```

The tests cover the fixed request shape, version, role, and unicast MAC checks.
No device, interface, firmware, or user network data is used.
