#!/usr/bin/env python3
"""Exercise actual channel callback bodies with bounded HAL fixtures under ASan."""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def block(text, marker, include_semicolon=False):
    start = text.index(marker)
    opening = text.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    if include_semicolon:
        end = text.index(';', end) + 1
    return text[start:end]


source = (ROOT / 'AirportItlwm/AirportItlwmSkywalkInterface.cpp').read_text()
var = (ROOT / 'include/Airport/apple80211_var.h').read_text()
ioctl = (ROOT / 'include/Airport/apple80211_ioctl.h').read_text()
ieee_var = (ROOT / 'itl80211/openbsd/net80211/ieee80211_var.h').read_text()
def numeric_define(text, name):
    return re.search(r'^#define\s+' + name + r'\s+(\d+)\s*$',
                     text, re.MULTILINE).group(1)
declarations = '\n'.join([
    block(var, 'struct apple80211_channel\n', True),
    block(ioctl, 'struct apple80211_sup_channel_data\n', True),
    block(ioctl, 'struct apple80211_channels_info {', True),
])
definitions = '\n'.join(block(source,
    'IOReturn AirportItlwmSkywalkInterface::\n' + name + '(')
    for name in ('getSUPPORTED_CHANNELS', 'getHW_SUPPORTED_CHANNELS',
                 'getCHANNELS_INFO'))
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#define APPLE80211_MAX_CHANNELS @APPLE_MAX@
#define APPLE80211_VERSION @APPLE_VERSION@
#define IEEE80211_CHAN_MAX @IEEE_MAX@
#define IEEE80211_IS_CHAN_VHT80(c) (((c)->ic_flags & 1u) != 0)
#define IEEE80211_IS_CHAN_HT40(c) (((c)->ic_flags & 2u) != 0)
#define IEEE80211_IS_CHAN_VHT40(c) (((c)->ic_flags & 4u) != 0)
using IOReturn = int;
constexpr int kIOReturnSuccess=0, kIOReturnBadArgument=1, kIOReturnNotReady=2;
struct ieee80211_channel { unsigned ic_freq; unsigned ic_flags; };
struct ieee80211com { ieee80211_channel ic_channels[IEEE80211_CHAN_MAX+1]; };
unsigned ieee80211_chan2ieee(ieee80211com *ic, ieee80211_channel *c) {
    return unsigned(c - ic->ic_channels);
}
unsigned ieeeChanFlag2appleScanFlagVentura(unsigned flags) { return flags; }
struct Hal {
    ieee80211com *ic;
    ieee80211com *get80211Controller() { return ic; }
};
'''
fixture = fixture.replace('@APPLE_MAX@', numeric_define(var, 'APPLE80211_MAX_CHANNELS'))
fixture = fixture.replace('@APPLE_VERSION@', numeric_define(ioctl, 'APPLE80211_VERSION'))
fixture = fixture.replace('@IEEE_MAX@', numeric_define(ieee_var, 'IEEE80211_CHAN_MAX'))
fixture += declarations + r'''
class AirportItlwmSkywalkInterface {
public:
    Hal *fHalService;
    IOReturn getSUPPORTED_CHANNELS(apple80211_sup_channel_data *);
    IOReturn getHW_SUPPORTED_CHANNELS(apple80211_sup_channel_data *);
    IOReturn getCHANNELS_INFO(apple80211_channels_info *);
};
'''
fixture += definitions + r'''
int main() {
    ieee80211com ic{};
    Hal hal{&ic};
    AirportItlwmSkywalkInterface iface{&hal};
    struct { apple80211_sup_channel_data value; uint64_t canary; } list{};
    struct { apple80211_channels_info value; uint64_t canary; } info{};
    list.canary = info.canary = 0x123456789abcdef0ULL;
    assert(iface.getSUPPORTED_CHANNELS(nullptr) == kIOReturnBadArgument);
    assert(iface.getHW_SUPPORTED_CHANNELS(nullptr) == kIOReturnBadArgument);
    assert(iface.getCHANNELS_INFO(nullptr) == kIOReturnBadArgument);
    iface.fHalService = nullptr;
    assert(iface.getSUPPORTED_CHANNELS(&list.value) == kIOReturnNotReady);
    assert(iface.getHW_SUPPORTED_CHANNELS(&list.value) == kIOReturnNotReady);
    assert(iface.getCHANNELS_INFO(&info.value) == kIOReturnNotReady);
    iface.fHalService = &hal; hal.ic = nullptr;
    assert(iface.getSUPPORTED_CHANNELS(&list.value) == kIOReturnNotReady);
    assert(iface.getHW_SUPPORTED_CHANNELS(&list.value) == kIOReturnNotReady);
    assert(iface.getCHANNELS_INFO(&info.value) == kIOReturnNotReady);
    hal.ic = &ic;

    // Populate every real HAL array entry, exceeding the ABI's capacity.
    for (unsigned i=0; i<=IEEE80211_CHAN_MAX; ++i)
        ic.ic_channels[i] = {2400+i, i & 7u};
    memset(&list.value, 0xa5, sizeof(list.value));
    assert(iface.getHW_SUPPORTED_CHANNELS(&list.value) == kIOReturnSuccess);
    assert(list.value.version == 1 && list.value.num_channels == 128);
    assert(list.value.supported_channels[0].channel == 0);
    assert(list.value.supported_channels[127].channel == 127);
    assert(list.canary == 0x123456789abcdef0ULL);
    memset(&info.value, 0xa5, sizeof(info.value));
    assert(iface.getCHANNELS_INFO(&info.value) == kIOReturnSuccess);
    assert(info.value.version == 1 && info.value.num_chan_specs == 128);
    assert(info.value.chan_num[127] == 127);
    assert(info.value.support_80Mhz[1] == 1);
    assert(info.value.support_40Mhz[2] == 1);
    assert(info.value.support_40Mhz[4] == 1);
    assert(info.value.chan_spec[0] == 0 && info.value.per_chan[127] == 0);
    assert(info.value.indoor_restric[127] == 0 && info.value.chan_bitmap[127] == 0);
    assert(info.canary == 0x123456789abcdef0ULL);

    // Exercise the last index visited by the production '< CHAN_MAX' loop.
    memset(&ic, 0, sizeof(ic));
    constexpr unsigned lastVisited = IEEE80211_CHAN_MAX-1;
    ic.ic_channels[lastVisited] = {5900, 3};
    assert(iface.getHW_SUPPORTED_CHANNELS(&list.value) == kIOReturnSuccess);
    assert(list.value.num_channels == 1);
    assert(list.value.supported_channels[0].channel == lastVisited);
    assert(list.value.supported_channels[1].channel == 0);
    assert(iface.getCHANNELS_INFO(&info.value) == kIOReturnSuccess);
    assert(info.value.num_chan_specs == 1 && info.value.chan_num[0] == lastVisited);
    assert(info.value.chan_num[1] == 0);
    memset(&ic, 0, sizeof(ic));
    assert(iface.getHW_SUPPORTED_CHANNELS(&list.value) == kIOReturnSuccess);
    assert(iface.getCHANNELS_INFO(&info.value) == kIOReturnSuccess);
    assert(list.value.num_channels == 0 && info.value.num_chan_specs == 0);
    assert(list.value.supported_channels[0].channel == 0);
    assert(info.value.chan_num[0] == 0);
}
'''
with tempfile.TemporaryDirectory(prefix='tahoe-channel-callbacks-') as directory:
    cpp = Path(directory) / 'callbacks.cpp'
    binary = Path(directory) / 'callbacks'
    cpp.write_text(fixture)
    subprocess.run(['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra',
                    '-Werror', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    str(cpp), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('Actual callback bodies: null/unready, 256-to-128 bound, sparse/empty and zero fields passed ASan/UBSan.')
