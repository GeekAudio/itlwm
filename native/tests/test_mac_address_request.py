#!/usr/bin/env python3
"""Exercise the actual native MAC adapter body without hardware or kernel IO."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'AirportItlwm/AirportItlwmSkywalkInterface.cpp').read_text()
start = source.index('IOReturn AirportItlwmSkywalkInterface::setMacAddress(')
opening = source.index('{', start)
end, depth = opening + 1, 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
body = source[start:end]

shim = r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
using IOReturn = int32_t;
constexpr IOReturn kIOReturnUnsupported = int32_t(0xe00002c7);
constexpr IOReturn kIOReturnNotReady = int32_t(0xe00002d8);
constexpr IOReturn kIOReturnBusy = int32_t(0xe00002d5);
struct mloAddrArray { uint8_t bytes[26]; };
struct Controller {
    unsigned calls = 0;
    IOReturn result = 0;
    uint8_t address[6] {};
    IOReturn setHardwareAddress(const void *p, uint32_t n) {
        assert(n == 6); ++calls; memcpy(address, p, 6); return result;
    }
};
struct AirportItlwmSkywalkInterface {
    Controller *instance = nullptr;
    std::map<std::string, uint32_t> metadata;
    void setProperty(const char *key, uint32_t value, unsigned bits) {
        assert(bits == 32); metadata[key] = value;
    }
    IOReturn setMacAddress(mloAddrArray &);
};
'''
main = r'''
int main() {
    // 25G241's native producer sets byte 24 from its previous client ID.
    // Both producer states are valid on a card with no 11be/MLO links.
    for (uint8_t previousClientNonzero : {0, 1}) {
        Controller c; AirportItlwmSkywalkInterface f; f.instance = &c;
        mloAddrArray request {}; const uint8_t privateMAC[6] = {2,1,2,3,4,5};
        memcpy(request.bytes, privateMAC, 6);
        memset(request.bytes + 6, 0x9b, 18); // Unused auxiliary slots.
        request.bytes[24] = previousClientNonzero; request.bytes[25] = 1;
        const auto before = request;
        assert(f.setMacAddress(request) == 0);
        assert(c.calls == 1 && !memcmp(c.address, privateMAC, 6));
        assert(!memcmp(&request, &before, sizeof request));
        assert(f.metadata.at("NativeAddressRequestFlags") == (256U | previousClientNonzero));
        assert(f.metadata.at("NativeAddressResult") == 0);
    }
    for (auto flags : {uint16_t(0x0102), uint16_t(0x0001), uint16_t(0x0201)}) {
        Controller c; AirportItlwmSkywalkInterface f; f.instance = &c;
        mloAddrArray request {}; request.bytes[24] = uint8_t(flags);
        request.bytes[25] = uint8_t(flags >> 8);
        assert(f.setMacAddress(request) == kIOReturnUnsupported && c.calls == 0);
    }
    { AirportItlwmSkywalkInterface f; mloAddrArray request {};
      request.bytes[24] = request.bytes[25] = 1;
      assert(f.setMacAddress(request) == kIOReturnNotReady); }
    { Controller c; c.result = kIOReturnBusy;
      AirportItlwmSkywalkInterface f; f.instance = &c;
      auto request = new mloAddrArray {}; request->bytes[0] = 2;
      request->bytes[24] = request->bytes[25] = 1;
      assert(f.setMacAddress(*request) == kIOReturnBusy && c.calls == 1);
      assert(f.metadata.at("NativeAddressResult") == uint32_t(kIOReturnBusy));
      delete request; }
}
'''
with tempfile.TemporaryDirectory(prefix='intel-native-mac-') as directory:
    path = Path(directory)
    (path / 'test.cpp').write_text(shim + body + main)
    subprocess.run(['xcrun', 'clang++', '-std=c++14', '-O1',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    str(path / 'test.cpp'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
print('PASS: native 0/1 and 1/1 flags, exact private MAC, input bounds, rejected flags, HAL error propagation')
