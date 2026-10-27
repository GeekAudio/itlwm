# 25G332 native AWDL object lifecycle contract

This is an offline design and host-mock test for the object owner only. It is
not in the active Xcode target, does not build a kext, and does not create an
IOKit object. The target witness is the retained, non-loadable
IO80211Family-25G332.linked-analysis.macho (SHA-256
8732ea8838331d115e16697acefa22ca5b3d0c516c48293de2e2ebbaf891d047) plus the
exact-build reports under ../IntelWirelessNative/research/.

## Confirmed 25G332 ABI

| Entry | Confirmed ABI / behavior | Evidence |
|---|---|---|
| IO80211VirtualInterface::init | bool init(IO80211Controller*, ether_addr*, unsigned int role, const char*); role 6 and MAC are consumed. It calls IO80211SkywalkInterface::init(controller, MAC), stores the role, then creates private locks/list/flow-queue state. | Symbol __ZN23IO80211VirtualInterface4initEP17IO80211ControllerP10ether_addrjPKc, 0xffffff8002335a58; disassembly in the 25G332 linked image. |
| IO80211VirtualInterface::attach | bool attach(IOService *provider); calls the IO80211-plane child hook when available, then returns the superclass IOService::attach(provider) result. | __ZN23IO80211VirtualInterface6attachEP9IOService, 0xffffff800233569a. |
| IO80211VirtualInterface::start | bool start(IOService *provider); tail-calls IO80211SkywalkInterface::start(provider). | __ZN23IO80211VirtualInterface5startEP9IOService, 0xffffff8002335d0a. |
| Skywalk start provider | The 25G332 body calls the superclass start, then meta-casts its provider to IO80211Controller. The null-cast and missing-work-loop exits preserve a true result, so a true bool does not establish complete state. A direct role-6 binding must pass the matching controller and verify native state independently. | __ZN23IO80211SkywalkInterface5startEP9IOService, 0xffffff80022fa5f2. At 0x22fa6a3 R13B becomes 1; the null-controller branch at 0x22fa6a9 and null-work-loop branch at 0x22fa6dc go to the shared return. Selected exact-build disassembly is in test050-native-start-analysis-private.txt. This is static evidence, not a started-interface runtime result. |
| Controller factory helper | bool attachVirtualInterface(IO80211VirtualInterface **out, ether_addr *mac, unsigned int role, bool start) calls its controller factory vtable slot, then attach(controller). If requested, it calls start(nullptr) but does not inspect the returned bool; it stores the object and returns true after attach. Attach failure calls release(). | __ZN17IO80211Controller22attachVirtualInterfaceEPP23IO80211VirtualInterfaceP10ether_addrjb, 0xffffff800229b39e. |
| Generic controller factory | createVirtualInterface(mac, role) accepts role 7 only, allocates IO80211VirtualInterface, and calls init(controller, mac, 7, "ap"); init failure releases the object. It cannot create a role-6 AWDL subclass. | __ZN17IO80211Controller23createVirtualInterfaceEP10ether_addrj, 0xffffff800229b422. |
| Controller terminate helper | detachVirtualInterface(object, bool) maps false to terminate(1) and true to terminate(3), then returns that bool. It does not release the object. | __ZN17IO80211Controller22detachVirtualInterfaceEP23IO80211VirtualInterfaceb, 0xffffff800229b40a. |
| AWDL pointer slot | getAwdlInterface() reads controller expansion +0x190; setAwdlInterface(ptr) writes it. Setter has no retain/release call or lock prefix, so an owning object must outlive the alias and teardown must clear by identity. | Getter 0xffffff800229854a; setter 0xffffff800229ef18; corroborated by test041-native-vif-gate-private.json. |

The native role-6 request report establishes MAC at request +4, role 6 at
+12, and the status-only return. The native IO80211 init implementation does
not read its final name argument; "awdl" is passed by this test adapter as
the role-6 convention, not because 25G332 init consumes it.

## RegistrationInfo boundary

IO80211VirtualInterface::start takes only an IOService pointer; it has no
RegistrationInfo pointer argument. The inherited IOSkywalkEthernetInterface
record is 0x130 bytes, but the BCM role-6 factory's
AppleBCMWLANProximityInterface::start(core, RegistrationInfo*) is a different
class-specific path. The retained 25G332 evidence does not justify passing
BCM's record to the Intel native VIF. Nor does it yet prove whether a later
AWDL networking stage needs an independently constructed Ethernet/Skywalk
registration record; keep that question separate from this object lifecycle.

The current native/registration.cpp is a separate Ethernet registration
adapter. It is not called by this owner helper and must not be treated as
evidence that the AWDL class start ABI takes that record.

## Failure and ownership contract

There is no single native failCleanup entry point. Generic native callers
release on init/attach failure, but this does not establish that every partial
role-6 allocation is safe to release. The owner requires a state-aware cleanup
binding and does the following:

1. Adopt the reference returned by the concrete metaclass allocator.
2. On init/attach failure, call prepareRelease with the exact release state.
   A false result retains the owner and its controller alias; it does not call
   dynamic free on an unproven partial allocation.
3. A false native start returns StartFailedNeedsStop. A true return must also
   pass verifyStarted; otherwise return StartStateIncompleteNeedsStop and keep
   the object attached and owned. The witness must include the matching
   controller/work-loop, role-6 peer manager and later required allocations.
4. stop uses a state-aware terminate binding. Native Skywalk stop dereferences
   its peer-manager private field without a null check for role 6; a binding
   must reject unsafe partial states before invoking that native path. A mock
   terminate returning true does not establish real partial-start cleanup.
5. After successful terminate, call prepareRelease before clearing this
   object's raw controller alias and dropping its owned reference. Failed
   cleanup is retained for retry; a completed terminate is never repeated.

Test049 has now exercised one unpublished native init and cleanup on the
machine: PM deregistration result 0, final flags 0x37ff, references before
release 1, native base free returned. It did not attach or start the object;
that result cannot validate this owner's started-interface binding.

The controller getter/setter have no synchronization. Any concrete binding
must serialize owner create/stop with the controller's AWDL operations. This
host helper does not invent a lock or claim the native callsites are already
serialized. It also does not set the raw pointer during creation: the 25G332
role-6 publication order and any internal setter callsite remain unproven.

## Offline check

~~~sh
clang++ -std=c++17 -Wall -Wextra -Werror \
  native/awdl_native_owner_25G332.cpp \
  native/tests/awdl_native_owner_25G332_test.cpp \
  -o /tmp/awdl-native-owner-25G332-test
/tmp/awdl-native-owner-25G332-test
~~~

The mock checks argument forwarding, owner retention, cleanup ordering, and
failure/retry behavior. It does not execute the private ABI or prove a native
awdl0, firmware scheduling, peer traffic, or AirDrop.
