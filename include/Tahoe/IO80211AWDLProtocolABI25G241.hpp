// ABI facts recovered from the local macOS 26.7.1 (25G241) linked images.
// This is an index of verified facts, not a declaration of Apple's classes.
#pragma once

#include "Types.h"

class IO80211AWDLProtocol;

namespace TahoeAwdl25G241ABI {

// OSMetaClass registration sizes and vtable counts from the linked image.
constexpr unsigned int kSkywalkInterfaceInstanceSize = 0x128;
constexpr unsigned int kVirtualInterfaceInstanceSize = 0x130;
constexpr unsigned int kAwdlProtocolInstanceSize = 0x130;
constexpr unsigned int kSkywalkInterfaceVtableSlots = 461;
constexpr unsigned int kVirtualInterfaceVtableSlots = 505;
constexpr unsigned int kAwdlProtocolVtableSlots = 568;

// IO80211VirtualInterface::init writes its private data pointer at this
// offset. The pointee type and internal structure remain intentionally opaque.
constexpr unsigned int kVirtualInterfacePrivatePointerOffset = 0x128;

// Pure virtual slots recovered by comparing the native and BCM concrete
// vtables. The inherited setMacAddress slot plus the 63 AWDL protocol slots
// account for all 64 pure slots in IO80211AWDLProtocol.
constexpr unsigned int kSetMacAddressSlot = 488;
constexpr unsigned int kFirstAwdlProtocolSlot = 505;
constexpr unsigned int kSetAwdlOobRequestSlot = 546;
constexpr unsigned int kSetAwdlSyncFrameTemplateSlot = 547;
constexpr unsigned int kLastAwdlProtocolSlot = 567;
constexpr unsigned int kPureSlotCount = 64;

// These two callback types are the only AWDLProtocol callback signatures
// independently established by selector 149/151 call paths and the BCM
// concrete vtable. No other callback member types are asserted here.
using SetAwdlOobRequest =
    IOReturn (IO80211AWDLProtocol::*)(apple80211_awdl_oob_request *);
using SetAwdlSyncFrameTemplate =
    IOReturn (IO80211AWDLProtocol::*)(apple80211_awdl_sync_frame_template *);

static_assert(kSetAwdlOobRequestSlot * sizeof(void *) == 0x1110,
              "selector 149 slot offset changed");
static_assert(kSetAwdlSyncFrameTemplateSlot * sizeof(void *) == 0x1118,
              "selector 151 slot offset changed");
static_assert(kAwdlProtocolVtableSlots - kFirstAwdlProtocolSlot == 63,
              "AWDLProtocol added slot count changed");

} // namespace TahoeAwdl25G241ABI
