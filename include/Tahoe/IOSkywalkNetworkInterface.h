// Independently reconstructed from this machine's Apple25G241 BootKC.
// No third-party port header was copied. See evidence/25G241-native-vtables.json.
#pragma once
#include "Types.h"
#include "IOSkywalkInterface.h"

class IOSkywalkNetworkInterface : public IOSkywalkInterface {
    OSDeclareAbstractStructors(IOSkywalkNetworkInterface)
public:
    // Native register requires version1/size>=0x108 and copies0x108.
    struct RegistrationInfo { uint8_t opaque[0x108]; } __attribute__((packed));
    struct IOSkywalkTSOOptions;
public:
    void reportLinkStatus(unsigned int, unsigned int);
    void setFastlaneCapable(bool);

    // native virtual slot 0x90
public:
    virtual void free() override;

    // native virtual slot 0x248
public:
    virtual bool init(OSDictionary*) override;

    // native virtual slot 0x400
public:
    virtual bool willTerminate(IOService*, unsigned int) override;

    // native virtual slot 0x5c8
public:
    virtual void stop(IOService*) override;

    // native virtual slot 0x7a0
public:
    virtual void joinPMtree(IOService*) override;

    // native virtual slot 0x7c0
public:
    virtual IOReturn setAggressiveness(unsigned long, unsigned long) override;

    // native virtual slot 0x850
public:
    virtual IOReturn enable(unsigned int) override;

    // native virtual slot 0x858
public:
    virtual IOReturn disable(unsigned int) override;

    // native virtual slot 0x8d0
public:
    virtual IOReturn registerNetworkInterfaceWithLogicalLink(IOSkywalkNetworkInterface::RegistrationInfo const*, IOSkywalkLogicalLink*, IOSkywalkPacketBufferPool*, IOSkywalkPacketBufferPool*, unsigned int);

    // native virtual slot 0x8d8
public:
    virtual IOReturn deregisterLogicalLink();

    // native virtual slot 0x8e0
public:
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams*, sockaddr_dl**) = 0;

    // native virtual slot 0x8e8
public:
    // Apple25G241 returns a full IOReturn (zero succeeds), not a boolean.
    virtual IOReturn prepareBSDInterface(__ifnet*, unsigned int);

    // native virtual slot 0x8f0
public:
    virtual void finalizeBSDInterface(__ifnet*, unsigned int);

    // native virtual slot 0x8f8
public:
    virtual ifnet_t getBSDInterface() const;

    // native virtual slot 0x900
public:
    virtual void setBSDName(char const*);

    // native virtual slot 0x908
public:
    virtual const char * getBSDName() const;

    // native virtual slot 0x910
public:
    virtual IOReturn processBSDCommand(__ifnet*, unsigned int, void*);

    // native virtual slot 0x918
public:
    virtual IOReturn processInterfaceCommand(ifdrv*);

    // native virtual slot 0x920
public:
    virtual IOReturn interfaceAdvisoryEnable(bool);

    // native virtual slot 0x928
private:
    virtual void __tahoe_slot_928() __asm__("__ZN25IOSkywalkNetworkInterface17setRxFlowSteeringEjP31ifnet_traffic_descriptor_commonj");

    // native virtual slot 0x930
public:
    virtual SInt32 setInterfaceEnable(bool);

    // native virtual slot 0x938
public:
    virtual SInt32 setRunningState(bool);

    // native virtual slot 0x940
public:
    virtual IOReturn handleChosenMedia(unsigned int);

    // native virtual slot 0x948
public:
    virtual void * getSupportedMediaArray(unsigned int*, unsigned int*);

    // native virtual slot 0x950
public:
    virtual void * getPacketTapInfo(unsigned int*, unsigned int*);

    // native virtual slot 0x958
public:
    virtual UInt getUnsentDataByteCount(unsigned int*, unsigned int*, unsigned int) const;

    // native virtual slot 0x960
public:
    virtual UInt32 getSupportedWakeFlags(unsigned int*);

    // native virtual slot 0x968
public:
    virtual void enableNetworkWake(unsigned int);

    // native virtual slot 0x970
public:
    virtual void calculateRingSizeForQueue(IOSkywalkPacketQueue const*, unsigned int*) const;

    // native virtual slot 0x978
public:
    virtual UInt getMaxTransferUnit();

    // native virtual slot 0x980
public:
    virtual void setMaxTransferUnit(unsigned int);

    // native virtual slot 0x988
public:
    virtual UInt getMinPacketSize();

    // native virtual slot 0x990
public:
    virtual UInt getHardwareAssists();

    // native virtual slot 0x998
public:
    virtual void setHardwareAssists(unsigned int, unsigned int);

    // native virtual slot 0x9a0
public:
    virtual void * getInterfaceFamily();

    // native virtual slot 0x9a8
public:
    virtual void * getInterfaceSubFamily();

    // native virtual slot 0x9b0
public:
    virtual UInt getInitialMedia();

    // native virtual slot 0x9b8
public:
    virtual UInt getFeatureFlags();

    // native virtual slot 0x9c0
public:
    virtual UInt getTxDataOffset();

    // native virtual slot 0x9c8
public:
    virtual UInt captureInterfaceState(unsigned int);

    // native virtual slot 0x9d0
public:
    virtual void restoreInterfaceState(unsigned int);

    // native virtual slot 0x9d8
public:
    virtual void setMTU(unsigned int);

    // native virtual slot 0x9e0
public:
    virtual bool bpfTap(unsigned int, unsigned int);

    // native virtual slot 0x9e8
public:
    virtual const char * getBSDNamePrefix();

    // native virtual slot 0x9f0
public:
    virtual UInt getBSDUnitNumber();

    // native virtual slot 0x9f8
public:
    virtual const char * classNameOverride();

    // native virtual slot 0xa00
public:
    virtual void deferBSDAttach(bool);

    // native virtual slot 0xa08
public:
    virtual void reportDetailedLinkStatus(if_link_status const*);

    // native virtual slot 0xa10
public:
    virtual UInt getTSOOptions(IOSkywalkNetworkInterface::IOSkywalkTSOOptions*);

    // native virtual slot 0xa18
public:
    virtual void _RESERVEDIOSkywalkNetworkInterface0();

    // native virtual slot 0xa20
public:
    virtual void _RESERVEDIOSkywalkNetworkInterface1();

    // native virtual slot 0xa28
public:
    virtual void _RESERVEDIOSkywalkNetworkInterface2();

    // native virtual slot 0xa30
public:
    virtual void _RESERVEDIOSkywalkNetworkInterface3();

    // native virtual slot 0xa38
public:
    virtual void _RESERVEDIOSkywalkNetworkInterface4();

    // native virtual slot 0xa40
public:
    virtual void _RESERVEDIOSkywalkNetworkInterface5();

    // native virtual slot 0xa48
public:
    virtual void _RESERVEDIOSkywalkNetworkInterface6();

    // native virtual slot 0xa50
public:
    virtual void _RESERVEDIOSkywalkNetworkInterface7();

    // native virtual slot 0xa58
public:
    virtual void _RESERVEDIOSkywalkNetworkInterface8();

    // native virtual slot 0xa60
public:
    virtual void _RESERVEDIOSkywalkNetworkInterface9();

protected:
    uint8_t __tahoe_opaque_state[0x30];
};
static_assert(sizeof(IOSkywalkNetworkInterface) == 0xe0, "25G241 IOSkywalkNetworkInterface size");
static_assert(sizeof(IOSkywalkNetworkInterface::RegistrationInfo) == 0x108, "25G241 registration record size");
