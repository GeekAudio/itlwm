//
//  AirportItlwmEthernetInterface.hpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef AirportItlwmEthernetInterface_hpp
#define AirportItlwmEthernetInterface_hpp

extern "C" {
#include <net/bpf.h>
}
#include "Airport/Apple80211.h"
#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>
#include <sys/kernel_types.h>
#include <IOKit/network/IOEthernetInterface.h>

class AirportItlwmEthernetInterface : public IOEthernetInterface {
    OSDeclareDefaultStructors(AirportItlwmEthernetInterface)
    
public:
    virtual IOReturn attachToDataLinkLayer( IOOptionBits options,
                                            void *       parameter ) override;
    
    virtual void     detachFromDataLinkLayer( IOOptionBits options,
                                              void *       parameter ) override;
    
    virtual bool initWithSkywalkInterfaceAndProvider(IONetworkController *controller, IO80211SkywalkInterface *interface);
    
    virtual bool setLinkState(IO80211LinkState state);
    
    static errno_t bpfOutputPacket(ifnet_t interface, u_int32_t data_link_type,
                                  mbuf_t packet);
    
    static errno_t bpfTap(ifnet_t interface, u_int32_t data_link_type,
                          bpf_tap_mode direction);
    
    virtual UInt32   inputPacket(
                                 mbuf_t          packet,
                                 UInt32          length  = 0,
                                 IOOptionBits    options = 0,
                                 void *          param   = 0 ) override;
    
    virtual IOService * getProvider( void ) const override;
    
private:
    IO80211SkywalkInterface *interface;
    bool isAttach;
#ifdef AIRPORT_TAHOE
    struct NativeBSDContext;
    bool acquireNativeBSDContext(NativeBSDContext &context);
    bool acquireNativeBSDIfnet(NativeBSDContext &context);
    void releaseNativeBSDContext(NativeBSDContext &context);
    void quarantineNativeBSD(NativeBSDContext &context, IOReturn result);
    static IOReturn nativeBSDAction(OSObject *target, void *context,
                                    void *, void *, void *);
    bool nativePrepared {false};
    uint32_t nativeBSDOperation {0};
    uint32_t nativeBSDQuarantined {0};
    IO80211SkywalkInterface *quarantineInterface {nullptr};
    IO80211Controller *quarantineController {nullptr};
    IO80211WorkQueue *quarantineQueue {nullptr};
    ifnet_t quarantineIfnet {nullptr};
#endif
};

#endif /* AirportItlwmEthernetInterface_hpp */
