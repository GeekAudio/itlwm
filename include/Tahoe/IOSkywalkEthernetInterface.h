// Independently reconstructed from this machine's Apple25G241 BootKC.
// No third-party port header was copied. See evidence/25G241-native-vtables.json.
#pragma once
#include "Types.h"
#include "IOSkywalkNetworkInterface.h"

class IOSkywalkEthernetInterface : public IOSkywalkNetworkInterface {
    OSDeclareAbstractStructors(IOSkywalkEthernetInterface)
public:
    struct RegistrationInfo { uint8_t opaque[0x130]; } __attribute__((packed));
public:
    // Native ownership APIs replace direct registration-cache writes.
    bool initRegistrationInfo(RegistrationInfo *, unsigned int, unsigned long);
    IOReturn copyRegistrationInfo(RegistrationInfo const *);

    // native virtual slot 0x90
public:
    virtual void free() override;

    // native virtual slot 0x248
public:
    virtual bool init(OSDictionary*) override;

    // native virtual slot 0x770
public:
    virtual IOReturn newUserClient(task*, void*, unsigned int, OSDictionary*, IOUserClient**) override;

    // native virtual slot 0x7e8
public:
    virtual IOReturn setPowerState(unsigned long, IOService*) override;

    // native virtual slot 0x850
public:
    virtual IOReturn enable(unsigned int) override;

    // native virtual slot 0x8e0
public:
    virtual SInt32 initBSDInterfaceParameters(ifnet_init_eparams*, sockaddr_dl**) override;

    // native virtual slot 0x8e8
public:
    virtual IOReturn prepareBSDInterface(__ifnet*, unsigned int) override;

    // native virtual slot 0x910
public:
    virtual IOReturn processBSDCommand(__ifnet*, unsigned int, void*) override;

    // native virtual slot 0x950
public:
    virtual void * getPacketTapInfo(unsigned int*, unsigned int*) override;

    // native virtual slot 0x968
public:
    virtual void enableNetworkWake(unsigned int) override;

    // native virtual slot 0x978
public:
    virtual UInt getMaxTransferUnit() override;

    // native virtual slot 0x988
public:
    virtual UInt getMinPacketSize() override;

    // native virtual slot 0x9a0
public:
    virtual void * getInterfaceFamily() override;

    // native virtual slot 0x9a8
public:
    virtual void * getInterfaceSubFamily() override;

    // native virtual slot 0x9b0
public:
    virtual UInt getInitialMedia() override;

    // native virtual slot 0x9e8
public:
    virtual const char * getBSDNamePrefix() override;

    // native virtual slot 0xa68
public:
    virtual void getHardwareAddress(ether_addr*);

    // native virtual slot 0xa70
public:
    virtual void setHardwareAddress(ether_addr*);

    // native virtual slot 0xa78
public:
    virtual void setLinkLayerAddress(ether_addr*);

    // native virtual slot 0xa80
public:
    virtual bool configureMulticastFilter(unsigned int, ether_addr const*, unsigned int);

    // native virtual slot 0xa88
public:
    virtual bool setMulticastAddresses(ether_addr const*, unsigned int);

    // native virtual slot 0xa90
public:
    virtual void setAllMulticastModeEnable(bool);

    // native virtual slot 0xa98
public:
    virtual IOReturn setPromiscuousModeEnable(bool, unsigned int);

    // native virtual slot 0xaa0
public:
    virtual void reportNicProxyLimits(nicproxy_limits_info_s);

    // native virtual slot 0xaa8
public:
    virtual void hwConfigNicProxyData(nicproxy_info_s*);

    // native virtual slot 0xab0
public:
    virtual void _RESERVEDIOSkywalkEthernetInterface0();

    // native virtual slot 0xab8
public:
    virtual void _RESERVEDIOSkywalkEthernetInterface1();

    // native virtual slot 0xac0
public:
    virtual void _RESERVEDIOSkywalkEthernetInterface2();

    // native virtual slot 0xac8
public:
    virtual void _RESERVEDIOSkywalkEthernetInterface3();

    // native virtual slot 0xad0
public:
    virtual void _RESERVEDIOSkywalkEthernetInterface4();

    // native virtual slot 0xad8
public:
    virtual void _RESERVEDIOSkywalkEthernetInterface5();

    // native virtual slot 0xae0
public:
    virtual void _RESERVEDIOSkywalkEthernetInterface6();

    // native virtual slot 0xae8
public:
    virtual void _RESERVEDIOSkywalkEthernetInterface7();

    // native virtual slot 0xaf0
public:
    virtual void _RESERVEDIOSkywalkEthernetInterface8();

    // native virtual slot 0xaf8
public:
    virtual void _RESERVEDIOSkywalkEthernetInterface9();

    // native virtual slot 0xb00
public:
    virtual void _RESERVEDIOSkywalkEthernetInterface10();

protected:
    uint8_t __tahoe_opaque_state[0x40];
};
static_assert(sizeof(IOSkywalkEthernetInterface) == 0x120, "25G241 IOSkywalkEthernetInterface size");
static_assert(sizeof(IOSkywalkEthernetInterface::RegistrationInfo) == 0x130, "25G241 registration record size");
