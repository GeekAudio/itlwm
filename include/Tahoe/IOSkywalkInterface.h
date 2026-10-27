// Independently reconstructed from this machine's Apple25G241 BootKC.
// No third-party port header was copied. See evidence/25G241-native-vtables.json.
#pragma once
#include "Types.h"
#include <IOKit/IOService.h>

class IOSkywalkInterface : public IOService {
    OSDeclareAbstractStructors(IOSkywalkInterface)

    // native virtual slot 0x90
public:
    virtual void free() override;

    // native virtual slot 0x248
public:
    virtual bool init(OSDictionary*) override;

    // native virtual slot 0x400
public:
    virtual bool willTerminate(IOService*, unsigned int) override;

    // native virtual slot 0x408
public:
    virtual bool didTerminate(IOService*, unsigned int, bool*) override;

    // native virtual slot 0x5e8
public:
    virtual bool handleOpen(IOService*, unsigned int, void*) override;

    // native virtual slot 0x5f0
public:
    virtual void handleClose(IOService*, unsigned int) override;

    // native virtual slot 0x5f8
public:
    virtual bool handleIsOpen(IOService const*) const override;

    // native virtual slot 0x850
public:
    virtual IOReturn enable(unsigned int) = 0;

    // native virtual slot 0x858
public:
    virtual IOReturn disable(unsigned int) = 0;

    // native virtual slot 0x860
public:
    virtual IOReturn clientConnectWithTask(task*, IOService*, unsigned int);

    // native virtual slot 0x868
public:
    virtual void clientDisconnect(IOService*, unsigned int);

    // native virtual slot 0x870
public:
    virtual bool isTerminating();

    // native virtual slot 0x878
public:
    virtual void _RESERVEDIOSkywalkInterface0();

    // native virtual slot 0x880
public:
    virtual void _RESERVEDIOSkywalkInterface1();

    // native virtual slot 0x888
public:
    virtual void _RESERVEDIOSkywalkInterface2();

    // native virtual slot 0x890
public:
    virtual void _RESERVEDIOSkywalkInterface3();

    // native virtual slot 0x898
public:
    virtual void _RESERVEDIOSkywalkInterface4();

    // native virtual slot 0x8a0
public:
    virtual void _RESERVEDIOSkywalkInterface5();

    // native virtual slot 0x8a8
public:
    virtual void _RESERVEDIOSkywalkInterface6();

    // native virtual slot 0x8b0
public:
    virtual void _RESERVEDIOSkywalkInterface7();

    // native virtual slot 0x8b8
public:
    virtual void _RESERVEDIOSkywalkInterface8();

    // native virtual slot 0x8c0
public:
    virtual void _RESERVEDIOSkywalkInterface9();

    // native virtual slot 0x8c8
public:
    virtual void _RESERVEDIOSkywalkInterface10();

protected:
    uint8_t __tahoe_opaque_state[0x28];
};
static_assert(sizeof(IOSkywalkInterface) == 0xb0, "25G241 IOSkywalkInterface size");
