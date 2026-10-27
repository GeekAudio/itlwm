// Compile-only AWDLProtocol layout and callback-signature witness.
// This translation unit never constructs, links, or registers an AWDL object.
#include <type_traits>

#include "Tahoe/IO80211AWDLProtocolLayoutABI25G241.hpp"

using TahoeAwdl25G241VifABI::IO80211VirtualInterfaceLayoutWitness25G241;
using TahoeAwdl25G241AwdlABI::IO80211AWDLProtocolLayoutWitness25G241;

IO80211VirtualInterfaceLayoutWitness25G241::
    ~IO80211VirtualInterfaceLayoutWitness25G241() = default;
IO80211AWDLProtocolLayoutWitness25G241::
    ~IO80211AWDLProtocolLayoutWitness25G241() = default;

using OobRequest = IOReturn (IO80211AWDLProtocolLayoutWitness25G241::*)(
    apple80211_awdl_oob_request *);
using SyncFrameTemplate = IOReturn (
    IO80211AWDLProtocolLayoutWitness25G241::*)(
    apple80211_awdl_sync_frame_template *);

static_assert(std::is_same<
                  decltype(&IO80211AWDLProtocolLayoutWitness25G241::
                               setAWDL_OOB_REQUEST),
                  OobRequest>::value,
              "selector 149 callback signature changed");
static_assert(std::is_same<
                  decltype(&IO80211AWDLProtocolLayoutWitness25G241::
                               setAWDL_SYNC_FRAME_TEMPLATE),
                  SyncFrameTemplate>::value,
              "selector 151 callback signature changed");
static_assert(sizeof(OobRequest) == 2 * sizeof(void *),
              "unexpected x86_64 member-function pointer ABI");
static_assert(sizeof(SyncFrameTemplate) == 2 * sizeof(void *),
              "unexpected x86_64 member-function pointer ABI");
