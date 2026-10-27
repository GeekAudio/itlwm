// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include "Types.h"

class IO80211Controller;
class IOService;

// Minimal call surface for lifecycle methods inherited by a future concrete
// Tahoe AWDL interface. IO80211VirtualInterface is abstract on 25G241, so this
// header intentionally exposes no allocator for that class. A concrete class
// deriving from IO80211AWDLProtocol is still required before these calls can be
// used for an AWDL interface.
namespace TahoeAwdlABI {

constexpr unsigned int kRoleAwdl = 6;

bool initializeVirtualInterface(IOService *interface,
                                IO80211Controller *controller,
                                ether_addr *address,
                                unsigned int role,
                                const char *bsdName);
bool attachVirtualInterface(IOService *interface, IOService *provider);
bool startVirtualInterface(IOService *interface, IOService *provider);
bool detachVirtualInterface(IO80211Controller *controller,
                            IOService *interface);
bool hasPublishedAwdlInterface(IO80211Controller *controller);
void publishAwdlInterface(IO80211Controller *controller,
                          IOService *interface);
void clearAwdlInterface(IO80211Controller *controller,
                        IOService *interface);
void releaseVirtualInterface(IOService *interface);

} // namespace TahoeAwdlABI
