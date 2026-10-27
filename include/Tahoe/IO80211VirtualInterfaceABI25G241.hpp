// Compile-only vtable/layout witness for IO80211VirtualInterface on macOS
// 26.7.1 (25G241). This is not a production class declaration: methods have
// no definitions, the native private pointee is unknown, and selected return
// types remain explicit slot-only placeholders. Never instantiate or call it.
#pragma once

#include <stdint.h>
#include <type_traits>

#include "Types.h"
#include "IO80211SkywalkInterface.h"

struct peerSlotDataStats;
struct packetCounters_t;

namespace TahoeAwdl25G241VifABI {

using Status32 = int32_t;

constexpr unsigned int kParentVtableSlots = 461;
constexpr unsigned int kFirstVifSlot = 461;
constexpr unsigned int kLastVifSlot = 504;
constexpr unsigned int kVifVtableSlots = 505;
constexpr unsigned int kInputPacketSlot = 362;
constexpr unsigned int kForwardPacketSlot = 463;
constexpr unsigned int kSetMacAddressSlot = 488;
constexpr unsigned int kReservedFirstSlot = 489;
constexpr unsigned int kReservedLastSlot = 504;
constexpr unsigned int kPrivatePointerOffset = 0x128;
constexpr unsigned int kInstanceSize = 0x130;

// The local parent header intentionally models native findPeer at slot 410 as
// an opaque no-argument declaration. The child layout witness must override
// that declaration to keep the slot in place. The actual native symbol is
// IO80211VirtualInterface::findPeer(ether_addr&); this surrogate is not that
// callable signature and is not a declaration of its source return type.
class IO80211VirtualInterfaceLayoutWitness25G241
    : public IO80211SkywalkInterface {
public:
    virtual ~IO80211VirtualInterfaceLayoutWitness25G241() override;
    const OSMetaClass *getMetaClass() const override;
    void free() override;
    IOReturn configureReport(IOReportChannelList *, unsigned int, void *, void *) override;
    IOReturn updateReport(IOReportChannelList *, unsigned int, void *, void *) override;
    bool start(IOService *) override;
    void stop(IOService *) override;
    bool terminate(IOOptionBits options = 0) override;
    bool attach(IOService *) override;
    void detach(IOService *) override;
    IOReturn newUserClient(task *, void *, unsigned int, OSDictionary *, IOUserClient **) override;
    const char *stringFromReturn(int) override;
    IOReturn enable(unsigned int) override;
    IOReturn prepareBSDInterface(__ifnet *, unsigned int) override;
    IOReturn processBSDCommand(__ifnet *, unsigned int, void *) override;
    SInt32 setInterfaceEnable(bool) override;
    UInt getFeatureFlags() override;
    bool bpfTap(unsigned int, unsigned int) override;
    bool setMulticastAddresses(ether_addr const *, unsigned int) override;
    void *createPeerManager() override;
    void postMessage(unsigned int, void *, unsigned long, bool) override;
    void logTxPacket(IO80211NetworkPacket *, PacketSkywalkScratch *, apple80211_wme_ac, bool) override;
    void logTxCompletionPacket(IO80211NetworkPacket *, PacketSkywalkScratch *, unsigned char *, apple80211_wme_ac, int, unsigned int, bool, bool) override;
    IOReturn inputPacket(IO80211NetworkPacket *, packet_info_tag *, ether_header *, bool *, bool) override;
    void logSkywalkTxReqPacket(IO80211NetworkPacket *, PacketSkywalkScratch *, unsigned char *, apple80211_wme_ac, bool) override;
    SInt64 pendingPackets(unsigned char) override;
    SInt64 packetSpace(unsigned char) override;
    IO80211LinkState linkState() override;
    void setScanningState(unsigned int, bool, apple80211_scan_data *, int) override;
    void updateLinkParameters(apple80211_interface_availability *) override;
    void updateInterfaceCoexRiskPct(unsigned long long) override;
    void setInterfaceNF(apple80211_channel, long long) override;
    void setDebugFlags(unsigned long long, unsigned int) override;
    SInt64 debugFlags() override;
    void setInterfaceChipCounters(apple80211_stat_report *, apple80211_chip_counters_tx *, apple80211_chip_error_counters_tx *, apple80211_chip_counters_rx *) override;
    void setInterfaceMIBdot11(apple80211_stat_report *, apple80211_ManagementInformationBasedot11_counters *) override;
    void setFrameStats(apple80211_stat_report *, apple80211_frame_counters *) override;
    void setInfraSpecificFrameStats(apple80211_stat_report *, apple80211_infra_specific_stats *) override;
    SInt64 getWmeTxCounters(unsigned long long *) override;
    void setWoWEnabled(bool) override;
    bool wowEnabled() override;
    void printDataPath(userPrintCtx *) override;
    bool findOrCreateFlowQueue(IO80211FlowQueueHash) override;
    UInt64 findOrCreateFlowQueueWithCache(IO80211FlowQueueHash, bool *) override;
    UInt64 findExistingFlowQueue(IO80211FlowQueueHash) override;
    void removePacketQueue(IO80211FlowQueueHash const *) override;
    void flushPacketQueues() override;
    void cachePeer(ether_addr *, unsigned int *) override;
    bool shouldLog(unsigned long long) override;
    void vlogDebug(unsigned long long, char const *, va_list) override;
    void vlogDebugBPF(unsigned long long, char const *, va_list) override;
    void *getP2PSkywalkPeerMgr() override;

private:
    // Slot-only override for the parent's intentionally opaque slot-410
    // declaration. See the class note above; the native argument is unknown
    // to the current Tahoe base header.
    void __tahoe_slot_cd0() override;

public:
    int getEventPipeSize() override;
    UInt64 createEventPipe(IO80211APIUserClient *) override;

    // Slots 461–487. Parameters are from exact native vtable target symbols.
    // A slot-only void return below means the linked implementation/callers do
    // not settle a C++ return type; it must not be used as a callable API.
    virtual bool init(IO80211Controller *, ether_addr *, unsigned int, char const *);
    virtual void setLinkState(IO80211LinkState, unsigned int);
    virtual void forwardPacket(IO80211NetworkPacket *); // return ABI unresolved; layout only
    virtual Status32 handleIoctl(__ifnet *, unsigned long, void *);
    virtual void addPeerToCache(unsigned char *); // return ABI unresolved; layout only
    virtual void deletePeerFromCache(unsigned char *); // return ABI unresolved; layout only
    virtual bool handleDebugCmd(apple80211_debug_command *);
    virtual Status32 getPeerSlotDataStats(ether_addr *, bool, peerSlotDataStats *);
    virtual void getPeerDataStats(ether_addr *, bool, packetCounters_t *); // return ABI unresolved; layout only
    virtual void clearPeerDataStats(ether_addr *, bool); // return ABI unresolved; layout only
    virtual void setAwdlCurrentChannelSequenceIndex(unsigned int);
    virtual bool isOutputFlowControlled();
    virtual void setOutputFlowControlled();
    virtual void clearOutputFlowControlled();
    virtual void flushFlowQueues(ether_addr *);
    virtual void configureAQMOutput(); // old header says UInt32; 25G241 callers do not resolve it
    virtual bool attachToBpf();
    virtual bool configureIfnet();
    virtual void reset(); // EAX32 zero is visible; source return type/call contract unresolved
    virtual void dupAndTransmitMcastPacket(IO80211NetworkPacket *, unsigned char *, unsigned char *);
    virtual void freeMulticastPacket(IO80211NetworkPacket *);
    virtual void triggerAWDLMulticastTx(unsigned int, unsigned char);
    virtual unsigned int p2pMulticastTx(IO80211NetworkPacket **, unsigned int);
    virtual void p2pMulticastTx(unsigned int, bool);
    virtual void signalMulticastPackets(unsigned int, unsigned int);
    virtual void sendPendingPacketsToStack(IO80211NetworkPacket **, unsigned int);
    virtual void freePendingPackets(IO80211NetworkPacket **, unsigned int);

    // Concrete Broadcom implementation returns EAX32 and the native caller
    // consumes that value as a status. int32_t preserves the ABI width without
    // claiming the original Apple typedef.
    virtual Status32 setMacAddress(ether_addr &) = 0;

    virtual void _RESERVEDIO80211VirtualInterface0();
    virtual void _RESERVEDIO80211VirtualInterface1();
    virtual void _RESERVEDIO80211VirtualInterface2();
    virtual void _RESERVEDIO80211VirtualInterface3();
    virtual void _RESERVEDIO80211VirtualInterface4();
    virtual void _RESERVEDIO80211VirtualInterface5();
    virtual void _RESERVEDIO80211VirtualInterface6();
    virtual void _RESERVEDIO80211VirtualInterface7();
    virtual void _RESERVEDIO80211VirtualInterface8();
    virtual void _RESERVEDIO80211VirtualInterface9();
    virtual void _RESERVEDIO80211VirtualInterface10();
    virtual void _RESERVEDIO80211VirtualInterface11();
    virtual void _RESERVEDIO80211VirtualInterface12();
    virtual void _RESERVEDIO80211VirtualInterface13();
    virtual void _RESERVEDIO80211VirtualInterface14();
    virtual void _RESERVEDIO80211VirtualInterface15();

private:
    // The pointee and the surrounding private allocation are opaque. The
    // pointer's presence and offset are the only field facts established.
    void *__opaque_private_pointer;
};

static_assert(sizeof(void *) == 8, "25G241 VIF witness requires x86_64");
static_assert(sizeof(IO80211SkywalkInterface) == kPrivatePointerOffset,
              "native VIF private pointer offset no longer follows its base");
static_assert(sizeof(IO80211VirtualInterfaceLayoutWitness25G241) == kInstanceSize,
              "VIF layout witness differs from the native 0x130-byte object");
static_assert(std::is_abstract<IO80211VirtualInterfaceLayoutWitness25G241>::value,
              "the witness must remain non-instantiable");
static_assert(kVifVtableSlots - kParentVtableSlots == 44,
              "native VIF-added slot count changed");
static_assert(kLastVifSlot + 1 == kVifVtableSlots,
              "native VIF final slot boundary changed");
static_assert(kReservedLastSlot - kReservedFirstSlot + 1 == 16,
              "native VIF reserved slot range changed");

} // namespace TahoeAwdl25G241VifABI
