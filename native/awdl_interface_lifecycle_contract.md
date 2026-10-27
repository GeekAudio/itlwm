# Tahoe AWDL interface lifecycle (25G241)

This is an offline lifecycle skeleton, not a working interface implementation. The generic `IO80211VirtualInterface` is abstract and cannot be used as a role-6 AWDL object. A concrete kext class derived from `IO80211AWDLProtocol` is required for Apple's native AWDL protocol cast. The current source does not define that class or wire the lifecycle into the `setVIRTUAL_IF_CREATE` entry point.

## Native class and protocol boundary

The current Tahoe `IO80211InfraProtocol` has `setVIRTUAL_IF_CREATE(apple80211_virt_if_create_data*)` at vtable offset `0x1160`; `AirportItlwmSkywalkInterface` still returns `kIOReturnUnsupported` there. The selector 149/151 routes cast the interface to `IO80211AWDLProtocol` and call slots `+0x1110` and `+0x1118`. Static analysis of 25G241 confirms `IO80211AWDLProtocol` derives from `IO80211VirtualInterface`, but both classes' metaclass allocators return null.

The old generic VIF allocator has been removed. The lifecycle allocation operation returns `NotReady` until a concrete AWDL subclass is reconstructed and registered. The existing lifecycle preserves its hardware `ready()` gate and does not publish a generic object or claim link state.

The two callback signatures are corroborated by the Apple BCM subclass vtable: `setAWDL_OOB_REQUEST(apple80211_awdl_oob_request*)` and `setAWDL_SYNC_FRAME_TEMPLATE(apple80211_awdl_sync_frame_template*)`. This confirms callback slot names and signatures only; it does not establish that Intel can reuse BCM firmware behavior or the opaque selector 149 request fields.

## Required creation order

The system sends role-6 `setVIRTUAL_IF_CREATE` to the existing STA protocol. Once the request is validated, the Intel adapter must pass the hardware-ready gate and prepare its owned firmware resources before publishing or starting a distinct concrete AWDL protocol object. Native attach/start then creates the native peer manager. Consequently the native Action-frame receive path can only be tested after the concrete VIF and manager exist; an RX probe cannot precede VIF creation. Startup callbacks may initiate advertisement traffic, so selector 149/151 must stay fail-closed until their TX, scheduler, and resource cleanup paths are proven.

Stop first quiesces/releases Intel resources, then detaches through the native controller, identity-checks and clears the AWDL pointer, and releases the object. A failed cleanup retains the lifecycle object and returns `CleanupPending`.

## Hardware callback boundary

No production Intel AWDL adapter is ready. `ready`, `prepare`, and `stop` remain mandatory; without a concrete AWDL protocol object, firmware P2P MAC/queue ownership, compatible PHY/channel scheduling, Action TX/RX, and the native data path, the interface must remain unsupported. Successful native service startup alone would not prove firmware operation, peer discovery, or AirDrop transfer.

The BCM proximity service has its own core-specific interface and `IOSkywalkEthernetInterface::RegistrationInfo` path. Its 0x130-byte registration record and firmware methods are not part of this Intel adapter.

## Evidence and checks

Detailed private ABI evidence is in `include/Tahoe/evidence/awdl-protocol-abi-25G241.md` and `include/Tahoe/evidence/awdl-vtable-25G241.md`; original local image provenance and method addresses are recorded in `include/Tahoe/evidence/awdl-native-interface-25G241.txt`. The pointer-slot sequence and pure-slot mapping are now extracted, but a compile-verified C++ declaration is still absent: the symbols do not encode return types or member layout. The binary analysis images are outside this repository. This lifecycle remains fail-closed and does not add or link a concrete subclass.

The portable lifecycle state machine remains fault-injected by `native/tests/awdl_interface_test.cpp`. This does not test an instantiated native AWDL object or hardware traffic.
