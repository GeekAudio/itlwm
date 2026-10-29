#!/usr/bin/env python3
"""Execute the production RX method with an observing side tap; no radio I/O."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
text = (root / 'itlwm/hal_iwx/ItlIwx.cpp').read_text()
header = (root / 'itlwm/hal_iwx/ItlIwx.hpp').read_text()
assert 'device_timestamp = le32toh(desc->v3.gp2_on_air_rise);' in text
assert 'device_timestamp = le32toh(desc->v1.gp2_on_air_rise);' in text
# Keep the production LE decode and reorder-save/restore contracts covered;
# the extracted iwx_rx_frame fixture below verifies the decoded GP2 value is
# forwarded to the side tap.
assert 'entries[index].device_timestamp = device_timestamp;' in text
assert 'device_timestamp = entries[index].device_timestamp;' in text
start = text.index('void ItlIwx::\niwx_rx_frame(')
brace = text.index('{', start)
end, depth = brace + 1, 1
while depth:
    depth += (text[end] == '{') - (text[end] == '}')
    end += 1
method = text[start:end]
assert ('device_timestamp, true, rxMacPhyIndex,\n'
        '                      rxMacPhyIndexPresent);' in method)
assert 'tahoe_awdl_rx_stage_counters_.record(' in method
assert 'tahoe_awdl_rx_stage_counters_.recordData(' in method
assert 'NativeAwdlData::isAwdlDataCandidate(' in method
counter_start = header.index('struct TahoeAwdlRxStageCounters {')
counter_end = header.index('\n};\n#endif', counter_start) + len('\n};')
counter_struct = header[counter_start:counter_end]
fixture = r'''
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include "native/awdl_data_frame.hpp"
#define AIRPORT_TAHOE 1
#define NBPFILTER 0
#define IEEE80211_FC1_PROTECTED 0x40
#define IEEE80211_RXI_HWDEC 1
#define nitems(x) (sizeof(x)/sizeof((x)[0]))
struct Packet { uint8_t bytes[64]{}; size_t length=64; bool freed=false; };
using mbuf_t=Packet*;
#define mtod(m,T) reinterpret_cast<T>((m)->bytes)
static size_t mbuf_len(mbuf_t m) { return m->length; }
static void mbuf_freem(mbuf_t m) { assert(!m->freed); m->freed=true; }
struct ieee80211_frame { uint8_t i_fc[2]; uint8_t rest[22]; };
struct ieee80211_node {};
struct ieee80211_channel {};
struct NetStats { unsigned inputErrors=0; };
struct _ifnet { NetStats *netStat; };
struct ieee80211com {
    ieee80211_channel ic_channels[197];
    ieee80211_channel *ic_ibss_chan=&ic_channels[6];
    NetStats stats;
    _ifnet ic_if{&stats};
};
struct iwx_softc { ieee80211com sc_ic; };
struct ieee80211_rxinfo { uint32_t rxi_flags=0; };
struct mbuf_list {};
#define IC2IFP(ic) (&(ic)->ic_if)
static ieee80211_node node;
static unsigned inputs=0,releases=0;
static mbuf_t observedInput=nullptr;
static ieee80211_node *ieee80211_find_rxnode(ieee80211com*,ieee80211_frame*) { return &node; }
static unsigned ieee80211_chan2ieee(ieee80211com*,ieee80211_channel*) { return 6; }
static void ieee80211_release_node(ieee80211com*,ieee80211_node *n) { assert(n==&node); ++releases; }
static void ieee80211_inputm(_ifnet*,mbuf_t m,ieee80211_node *n,ieee80211_rxinfo*,mbuf_list*) {
    assert(!m->freed&&n==&node); observedInput=m; ++inputs;
}
''' + counter_struct + r'''
struct ItlIwx {
    TahoeAwdlRxStageCounters tahoe_awdl_rx_stage_counters_;
    unsigned taps=0; bool sawProtected=false,decapFails=false,tapDrops=false;
    uint16_t sawChannel=0;
    uint32_t sawGp2=0; bool sawGp2Present=false;
    uint32_t sawRxMacPhyIndex=0; bool sawRxMacPhyIndexPresent=false;
    int iwx_ccmp_decap(iwx_softc*,mbuf_t m,ieee80211_node*,ieee80211_rxinfo*) {
        if(decapFails)return 1;
        m->bytes[1]&=~IEEE80211_FC1_PROTECTED;
        return 0;
    }
    void tahoeP2pTapAction(iwx_softc*,const uint8_t*,size_t length,
                           bool protectedFrame,uint16_t channel,uint32_t gp2,
                           bool gp2Present,uint32_t rxMacPhyIndex,
                           bool rxMacPhyIndexPresent) {
        assert(inputs==0&&length==64); ++taps; sawProtected=protectedFrame;sawChannel=channel;
        sawGp2=gp2;sawGp2Present=gp2Present;
        sawRxMacPhyIndex=rxMacPhyIndex;
        sawRxMacPhyIndexPresent=rxMacPhyIndexPresent;
        if(tapDrops)return; // A rejected/full side queue never owns the packet.
    }
    void iwx_rx_frame(iwx_softc*,mbuf_t,int,uint32_t,int,int,uint32_t,
                      ieee80211_rxinfo*,mbuf_list*,uint32_t=0,uint8_t=0,
                      uint32_t=0,bool=false);
};
'''
tests = r'''
int main() {
    for(unsigned test=0;test<5;++test) {
        ItlIwx driver; iwx_softc sc; Packet packet; ieee80211_rxinfo info; mbuf_list list;
        inputs=releases=0;observedInput=nullptr;
        if(test==1||test==2) { packet.bytes[1]=IEEE80211_FC1_PROTECTED;info.rxi_flags=IEEE80211_RXI_HWDEC; }
        driver.decapFails=test==2;driver.tapDrops=test==4;
        const uint32_t ownerGeneration=test==0?0:77;
        const uint8_t frameKind=test==3?
            TahoeAwdlRxStageCounters::kMif:TahoeAwdlRxStageCounters::kPsf;
        const uint32_t macPhyIndex=17+test;
        const bool macPhyIndexPresent=test!=3;
        if(ownerGeneration)
            driver.tahoe_awdl_rx_stage_counters_.beginOwner(ownerGeneration);
        driver.iwx_rx_frame(&sc,&packet,test==3?-1:36,0,0,0,0x78563412,
            &info,&list,ownerGeneration,frameKind,macPhyIndex,
            macPhyIndexPresent);
        if(test==2) {
            assert(driver.taps==0&&inputs==0&&packet.freed);
            assert(sc.sc_ic.stats.inputErrors==1);
        } else {
            assert(driver.taps==1&&inputs==1&&!packet.freed&&observedInput==&packet);
            assert(driver.sawProtected==(test==1));
            assert(driver.sawChannel==(test==3?6:36));
            assert(driver.sawGp2==0x78563412&&driver.sawGp2Present);
            assert(driver.sawRxMacPhyIndex==macPhyIndex);
            assert(driver.sawRxMacPhyIndexPresent==macPhyIndexPresent);
        }
        const auto rxStages=driver.tahoe_awdl_rx_stage_counters_.snapshot();
        const uint32_t expectedTapCount=ownerGeneration&&test!=2?1:0;
        assert(rxStages.counts[TahoeAwdlRxStageCounters::kTap]
                                [unsigned(frameKind)-1]==expectedTapCount);
        assert(releases==1);
    }
}
'''
with tempfile.TemporaryDirectory(prefix='iwx-p2p-rx-tap-') as tmp:
    cpp, binary = Path(tmp)/'fixture.cpp', Path(tmp)/'fixture'
    cpp.write_text(fixture + method + tests)
    subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
                    '-Wno-unused-parameter','-Wno-sign-compare',
                    '-fsanitize=address,undefined','-fno-omit-frame-pointer',
                    '-I',str(root),str(cpp),
                    str(root/'native/awdl_data_frame.cpp'),'-o',str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: RX input ownership, protection, side-tap drop, and GP2 pass-through; source checks enforce LE decode and reorder preservation')
