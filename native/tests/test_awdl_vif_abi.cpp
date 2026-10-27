// Compile-only witnesses for the local 25G241 IO80211VirtualInterface layout.
// This translation unit never constructs or links the abstract layout model.
#include <type_traits>

#include "Tahoe/IO80211VirtualInterfaceABI25G241.hpp"

using TahoeAwdl25G241VifABI::IO80211VirtualInterfaceLayoutWitness25G241;
using TahoeAwdl25G241VifABI::Status32;

// A key-function definition forces Clang to emit the abstract witness vtable;
// it does not instantiate the class or provide behavior for any slot.
IO80211VirtualInterfaceLayoutWitness25G241::~IO80211VirtualInterfaceLayoutWitness25G241() = default;

using InputPacket = IOReturn (IO80211VirtualInterfaceLayoutWitness25G241::*)(
    IO80211NetworkPacket *, packet_info_tag *, ether_header *, bool *, bool);
using HandleIoctl = Status32 (IO80211VirtualInterfaceLayoutWitness25G241::*)(
    __ifnet *, unsigned long, void *);
using PeerSlotStats = Status32 (IO80211VirtualInterfaceLayoutWitness25G241::*)(
    ether_addr *, bool, peerSlotDataStats *);
using MulticastBatch = unsigned int (IO80211VirtualInterfaceLayoutWitness25G241::*)(
    IO80211NetworkPacket **, unsigned int);
using MacAddressStatus = Status32 (IO80211VirtualInterfaceLayoutWitness25G241::*)(
    ether_addr &);

static_assert(std::is_same<decltype(static_cast<InputPacket>(
                               &IO80211VirtualInterfaceLayoutWitness25G241::inputPacket)),
                           InputPacket>::value,
              "native inputPacket override ABI changed");
static_assert(std::is_same<decltype(&IO80211VirtualInterfaceLayoutWitness25G241::handleIoctl),
                           HandleIoctl>::value,
              "native handleIoctl forwarding status ABI changed");
static_assert(std::is_same<decltype(&IO80211VirtualInterfaceLayoutWitness25G241::getPeerSlotDataStats),
                           PeerSlotStats>::value,
              "native peer slot stats status ABI changed");
static_assert(std::is_same<decltype(static_cast<MulticastBatch>(
                               &IO80211VirtualInterfaceLayoutWitness25G241::p2pMulticastTx)),
                           MulticastBatch>::value,
              "native multicast batch count ABI changed");
static_assert(std::is_same<decltype(&IO80211VirtualInterfaceLayoutWitness25G241::setMacAddress),
                           MacAddressStatus>::value,
              "native pure MAC setter status width changed");
