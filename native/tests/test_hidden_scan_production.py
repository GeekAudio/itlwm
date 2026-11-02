#!/usr/bin/env python3
"""Offline tests of actual target capture, firmware packing and channel selection.

OS/firmware I/O is modeled. No interface, socket, scan or device is used.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DRIVER = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
REG = (ROOT / "itlwm/hal_iwx/if_iwxreg.h").read_text()
HEADER = (ROOT / "itlwm/hal_iwx/ItlIwx.hpp").read_text()


def definition(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if depth == 0:
            return source[start:end + 1]
    raise AssertionError(marker)


PREFIX = r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include "native/scan_ssid_targets.h"
#define AIRPORT_TAHOE 1
#define __packed __attribute__((packed))
#define IEEE80211_NWID_LEN 32
#define IEEE80211_CHAN_MAX 255
#define IEEE80211_ELEMID_SSID 0
#define IEEE80211_S_RUN 4
#define IEEE80211_F_RSNON 1
#define IWX_UCODE_TLV_API_SCAN_EXT_CHAN_VER 0
#define IWX_PHY_BAND_24 0
#define IWX_PHY_BAND_5 1
#define IEEE80211_IS_CHAN_2GHZ(c) ((c)->ic_freq < 3000)
#define isset(p,n) (((p)[(n)/8] & (1u << ((n)%8))) != 0)
static uint16_t htole16(uint16_t v) { return v; }
static uint32_t htole32(uint32_t v) { return v; }
struct OSObject {};
enum { kIOReturnSuccess=0, kIOReturnBadArgument=1, kIOReturnBusy=2 };
using IOReturn = int;
struct ieee80211_node { bool ni_port_valid=true, ni_pmf_link_pending=false; };
struct ieee80211_channel { unsigned ic_flags=0, ic_freq=0; };
struct ieee80211com {
    uint8_t ic_myaddr[6]{2,0,0,0,0,1}, ic_des_essid[32]{};
    uint8_t ic_des_esslen=0;
    bool ic_tahoe_scan_requested=false, ic_tahoe_scan_passive=false;
    bool ic_tahoe_scan_private_random_requested=false;
    uint32_t ic_tahoe_scan_generation=0;
    uint8_t ic_tahoe_scan_ssid[32]{}, ic_tahoe_scan_ssid_len=0;
    uint8_t ic_tahoe_scan_source_addr[6]{}, ic_tahoe_scan_channels[32]{};
    itl_scan_ssid_targets ic_tahoe_scan_targets{};
    unsigned ic_state=IEEE80211_S_RUN, ic_flags=0;
    ieee80211_node *ic_bss=nullptr;
    ieee80211_channel ic_channels[256]{};
};
struct iwx_softc {
    ieee80211com sc_ic;
    uint8_t sc_ucode_api[1]{};
    unsigned sc_capa_n_scan_channels=256;
};
static uint8_t ieee80211_mhz2ieee(unsigned mhz, unsigned) {
    return uint8_t(mhz < 3000 ? (mhz-2407)/5 : (mhz-5000)/5);
}
'''

TESTS = r'''
int main() {
    ieee80211com ic;
    itl_iwx_scan_policy policy{};
    const uint8_t name[] = {0,0xe9,0x9a,0x90,' ', 'x'};
    ic.ic_tahoe_scan_requested=true;
    ic.ic_tahoe_scan_generation=17;
    auto &t=ic.ic_tahoe_scan_targets;
    t.count=10;
    for (unsigned i=0;i<9;++i) {
        t.entries[i].length=sizeof(name);
        memcpy(t.entries[i].bytes,name,sizeof(name));
    }
    assert(itl_iwx_scan_policy_for(&ic,0,&policy));
    memset(&t,0xff,sizeof(t)); // Snapshot owns all ten records.
    iwx_ssid_ie packed[11]{};
    memset(&packed[10],0xa5,sizeof(packed[10]));
    assert(itl_iwx_fill_direct_scan(packed,10,&policy)==10);
    for (unsigned i=0;i<9;++i) {
        assert(packed[i].id==0 && packed[i].len==sizeof(name));
        assert(!memcmp(packed[i].ssid,name,sizeof(name)));
    }
    assert(packed[9].len==0); // Explicit empty target is retained, not a terminator.
    for (auto c:reinterpret_cast<const uint8_t (&)[sizeof(iwx_ssid_ie)]>(packed[10]))
        assert(c==0xa5);
    iwx_ssid_ie rejected[10]; memset(rejected,0xa5,sizeof(rejected));
    assert(itl_iwx_fill_direct_scan(rejected,9,&policy)==0);
    for (auto c:reinterpret_cast<const uint8_t (&)[sizeof(rejected)]>(rejected))
        assert(c==0xa5);
    iwx_softc sc;
    sc.sc_ic.ic_channels[6]={1,2437};
    sc.sc_ic.ic_channels[149]={1,5745};
    iwx_scan_channel_cfg_umac channels[2]{};
    ItlIwx hal;
    assert(hal.iwx_umac_scan_fill_channels(&sc,channels,1,1,&policy)==2);
    assert(channels[0].flags==1023 && channels[1].flags==1023);
    policy.active=false;
    memset(channels,0,sizeof(channels));
    assert(itl_iwx_fill_direct_scan(rejected,10,&policy)==0);
    assert(hal.iwx_umac_scan_fill_channels(&sc,channels,0,1,&policy)==2);
    assert(channels[0].flags==0 && channels[1].flags==0);
    policy.active=true; policy.restricted=true; policy.channels[0]=1u<<6;
    memset(channels,0,sizeof(channels));
    assert(hal.iwx_umac_scan_fill_channels(&sc,channels,1,0,&policy)==1);
    assert(channels[0].v1.channel_num==6);
    policy.targets.count=11;
    assert(!itl_scan_targets_bitmap(&policy.targets));
    assert(itl_iwx_fill_direct_scan(rejected,10,&policy)==0);

    // Join-driven scan uses the current explicit network, never a stale WCL list.
    memset(&ic.ic_tahoe_scan_targets,0xff,sizeof(ic.ic_tahoe_scan_targets));
    ic.ic_tahoe_scan_requested=false; ic.ic_des_esslen=sizeof(name);
    memcpy(ic.ic_des_essid,name,sizeof(name));
    assert(itl_iwx_scan_policy_for(&ic,0,&policy));
    assert(policy.targets.count==1 && policy.targets.entries[0].length==sizeof(name));
    assert(!memcmp(policy.targets.entries[0].bytes,name,sizeof(name)));
    assert(!policy.requested && policy.active);
    assert(itl_iwx_scan_policy_for(&ic,1,&policy) && !policy.active);
    int bgscan=1;
    ieee80211_node ni;
    ic.ic_bss=&ni; ic.ic_flags=IEEE80211_F_RSNON;
    assert(itl_iwx_capture_scan_policy(nullptr,&ic,&policy,&bgscan,nullptr)==0);
    ni.ni_port_valid=false;
    assert(itl_iwx_capture_scan_policy(nullptr,&ic,&policy,&bgscan,nullptr)==kIOReturnBusy);
    ni.ni_port_valid=true; ni.ni_pmf_link_pending=true;
    assert(itl_iwx_capture_scan_policy(nullptr,&ic,&policy,&bgscan,nullptr)==kIOReturnBusy);
    ic.ic_bss=nullptr;
    assert(itl_iwx_capture_scan_policy(nullptr,&ic,&policy,&bgscan,nullptr)==kIOReturnBusy);
}
'''


def main():
    policy = definition(HEADER, "struct itl_iwx_scan_policy {") + ";"
    ssid = definition(REG, "struct iwx_ssid_ie {") + " __packed;"
    channel = definition(REG, "struct iwx_scan_channel_cfg_umac {") + " __packed;"
    capture = definition(DRIVER, "static bool\nitl_iwx_scan_policy_for(")
    capture_gate = definition(DRIVER, "static IOReturn\nitl_iwx_capture_scan_policy(")
    pack = definition(DRIVER, "static unsigned\nitl_iwx_fill_direct_scan(")
    fill = definition(DRIVER, "uint8_t ItlIwx::\niwx_umac_scan_fill_channels(")
    declarations = r'''
class ItlIwx { public:
    uint8_t iwx_umac_scan_fill_channels(iwx_softc*, iwx_scan_channel_cfg_umac*,
        int,int,const itl_iwx_scan_policy*);
};
'''
    # Each production builder must call the tested packer and use captured data.
    for marker in ("iwx_umac_scan(struct", "iwx_umac_scan_v12(struct", "iwx_umac_scan_v14(struct"):
        body = definition(DRIVER, marker)
        assert "itl_iwx_fill_direct_scan" in body
        assert "scan.source_addr" in body
        assert "direct_scan[0]" not in body
    adapter = (ROOT / "AirportItlwm/AirportItlwmSkywalkInterface.cpp").read_text()
    assert "ic->ic_tahoe_scan_targets = plan.targets" in adapter
    source = "\n".join((PREFIX,policy,ssid,channel,declarations,capture,capture_gate,pack,fill,TESTS))
    with tempfile.TemporaryDirectory(prefix="hidden-scan-production-") as temp:
        cpp=Path(temp)/"test.cpp"; exe=Path(temp)/"test"
        cpp.write_text(source)
        subprocess.run(["clang++","-std=c++14","-Wall","-Wextra","-Werror",
            "-Wno-unused-function","-fsanitize=address,undefined","-fno-omit-frame-pointer",
            "-I",str(ROOT),str(cpp),"-o",str(exe)],check=True)
        subprocess.run([str(exe)],check=True,env=dict(os.environ,
            ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",UBSAN_OPTIONS="halt_on_error=1"))
    print("PASS: actual hidden-scan policy capture, target packing, channel bitmap and key-window gates")


if __name__ == "__main__":
    main()
