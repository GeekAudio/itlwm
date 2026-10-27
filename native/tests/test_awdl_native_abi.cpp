// Compile-only size and signature witness for the verified 25G241 facts.
// This intentionally does not declare or instantiate a VIF/AWDL subclass.
#include <type_traits>

#include "Tahoe/IO80211AWDLProtocolABI25G241.hpp"
#include "Tahoe/IO80211SkywalkInterface.h"

using namespace TahoeAwdl25G241ABI;

static_assert(sizeof(IO80211SkywalkInterface) == kSkywalkInterfaceInstanceSize,
              "reconstructed Skywalk base size differs from 25G241");
static_assert(sizeof(void *) == 8, "this probe is for x86_64 Tahoe");
static_assert(sizeof(IO80211SkywalkInterface) + sizeof(void *) ==
                  kVirtualInterfaceInstanceSize,
              "VIF's 25G241 size is not base plus its observed private pointer");
static_assert(kVirtualInterfacePrivatePointerOffset ==
                  sizeof(IO80211SkywalkInterface),
              "VIF private pointer offset no longer follows the base");
static_assert(kAwdlProtocolInstanceSize == kVirtualInterfaceInstanceSize,
              "AWDLProtocol adds unexpected object storage");
static_assert(kFirstAwdlProtocolSlot - kSetMacAddressSlot - 1 == 16,
              "VIF reserved slot range changed");
static_assert(kLastAwdlProtocolSlot + 1 == kAwdlProtocolVtableSlots,
              "AWDLProtocol final slot boundary changed");
static_assert(kPureSlotCount == 1 +
                  (kAwdlProtocolVtableSlots - kFirstAwdlProtocolSlot),
              "pure slot total changed");
static_assert(std::is_member_function_pointer<SetAwdlOobRequest>::value,
              "OOB callback must be a member-function pointer type");
static_assert(std::is_member_function_pointer<SetAwdlSyncFrameTemplate>::value,
              "sync template callback must be a member-function pointer type");
static_assert(sizeof(SetAwdlOobRequest) == 2 * sizeof(void *),
              "unexpected x86_64 Itanium member-function pointer ABI");
static_assert(sizeof(SetAwdlSyncFrameTemplate) == 2 * sizeof(void *),
              "unexpected x86_64 Itanium member-function pointer ABI");
