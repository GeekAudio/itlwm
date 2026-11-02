// SPDX-License-Identifier: GPL-2.0-only
#include "../wcl_wire.hpp"
#include <assert.h>
#include <string.h>
#include <vector>

using namespace NativeWifi;
namespace {
std::vector<uint8_t> rsn(uint8_t akm, uint16_t capabilities,
                         bool groupManagement = true) {
    std::vector<uint8_t> p {48, 0, 1, 0, 0, 15, 172, 4,
                           1, 0, 0, 15, 172, 4,
                           1, 0, 0, 15, 172, akm,
                           uint8_t(capabilities), uint8_t(capabilities >> 8)};
    if (groupManagement) p.insert(p.end(), {0, 0, 0, 15, 172, 6});
    p[1] = uint8_t(p.size() - 2);
    return p;
}
std::vector<uint8_t> join(uint32_t upper, const std::vector<uint8_t> &ie,
                          const std::vector<uint8_t> &password) {
    std::vector<uint8_t> p(JoinWireSize);
    write16(p.data()+0xc, 2); write32(p.data()+0x10, 1);
    write32(p.data()+0x14, upper);
    write32(p.data()+0x1c, 1); p[0x20] = 'x';
    write32(p.data()+0x44, uint32_t(password.size()));
    write32(p.data()+0x48, 10);
    memcpy(p.data()+0x50, password.data(), password.size());
    write16(p.data()+0xd4, uint16_t(ie.size()));
    memcpy(p.data()+0xd6, ie.data(), ie.size());
    write32(p.data()+0x214, 1); p[0x21c] = 2; p[0x221] = 1;
    if (upper == 0x1000) {
        write32(p.data()+0x1ec, 32);
        memset(p.data()+0x1f0, 0x5a, 32);
        write32(p.data()+0x210, 0x100);
    }
    return p;
}
void denied(const std::vector<uint8_t> &p) {
    JoinPlan result;
    memset(&result, 0xa5, sizeof(result));
    assert(decodeJoin(p.data(), p.size(), result) != DecodeResult::Ok);
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&result);
    for (size_t i=0; i<sizeof(result); ++i) assert(bytes[i] == 0);
}
}
int main() {
    const std::vector<uint8_t> password {'s','e','c','r','e','t','1','2'};
    JoinPlan p {};
    for (uint16_t caps : {uint16_t(0), uint16_t(0x80), uint16_t(0xc0)}) {
        auto w = join(8, rsn(2, caps), password);
        assert(decodeJoin(w.data(), w.size(), p) == DecodeResult::Ok);
        assert(p.authentication == Authentication::Psk && p.derivePmk);
        assert(p.pmfCapable == bool(caps & 0x80));
        assert(p.pmfRequired == bool(caps & 0x40));
    }
    auto sha = join(0x400, rsn(6, 0xc0), password);
    assert(decodeJoin(sha.data(), sha.size(), p) == DecodeResult::Ok);
    assert(p.authentication == Authentication::PskSha256 && p.pmfRequired);
    // Explicit selections never silently turn into another authentication.
    denied(join(0x400, rsn(2, 0xc0), password));
    denied(join(8, rsn(6, 0xc0), password));
    denied(join(0x1000, rsn(2, 0xc0), password));
    denied(join(0x1000, rsn(8, 0), password));
    denied(join(0x1000, rsn(8, 0x40), password));
    denied(join(8, rsn(2, 0x40), password));
    for (uint16_t caps : {uint16_t(0x80), uint16_t(0xc0)}) {
        for (bool explicitBip : {false, true}) {
            auto ie = rsn(8, caps, explicitBip);
            auto w = join(0x1000, ie, {'x'});
            assert(decodeJoin(w.data(), w.size(), p) == DecodeResult::Ok);
            assert(p.authentication == Authentication::Sae && p.secured);
            assert(p.pmfCapable && p.pmfRequired && !p.derivePmk);
            assert(p.passwordLength == 1 && p.password[0] == 'x');
            assert(p.rsnLength == ie.size() && !memcmp(p.rsn, ie.data(), ie.size()));
            for (uint8_t b : p.pmk) assert(!b);
        }
    }
    // A 64-byte SAE password is not a hexadecimal PSK/PMK representation.
    auto w = join(0x1000, rsn(8, 0xc0), std::vector<uint8_t>(64, 'z'));
    assert(decodeJoin(w.data(), w.size(), p) == DecodeResult::Ok);
    assert(p.passwordLength == 64 && !p.derivePmk && p.password[63] == 'z');
    auto utf8 = join(0x1000, rsn(8, 0xc0), {0xe5,0xaf,0x86,0xe7,0xa0,0x81});
    assert(decodeJoin(utf8.data(), utf8.size(), p) == DecodeResult::Ok);
    utf8[0x52] = 0; denied(utf8);
    denied(join(0x1000, rsn(8, 0xc0), {}));
    for (uint32_t cipher : {6U, 7U}) {
        auto pmk = join(0x1000, rsn(8, 0xc0), std::vector<uint8_t>(32, 0x5a));
        write32(pmk.data()+0x48, cipher); denied(pmk);
    }
    for (uint32_t allowed : {0U, 4U, 0x40000004U, 0x100U, 0x40000100U}) {
        auto native = join(0x1000, rsn(8, 0xc0), password);
        write32(native.data()+0x210, allowed);
        assert(decodeJoin(native.data(), native.size(), p) == DecodeResult::Ok);
        assert(p.allowedAuth == allowed && !p.derivePmk);
        for (uint8_t b : p.pmk) assert(!b);
    }
    for (uint32_t length : {0U, 31U, 33U}) {
        auto bad = join(0x1000, rsn(8, 0xc0), password);
        write32(bad.data()+0x1ec, length); denied(bad);
    }
    for (uint32_t policy : {0x104U, 0x200U, 0x400U}) {
        auto bad = join(0x1000, rsn(8, 0xc0), password);
        write32(bad.data()+0x210, policy); denied(bad);
    }
    // Mixed advertisements are valid only when the selected suite is present.
    auto mixed = rsn(2, 0x80);
    mixed.insert(mixed.begin()+20, {0,15,172,8}); mixed[14] = 2;
    mixed[1] = uint8_t(mixed.size()-2);
    for (uint32_t upper : {8U, 0x1000U}) {
        w = join(upper, mixed, password);
        assert(decodeJoin(w.data(), w.size(), p) == DecodeResult::Ok);
        assert(p.authentication == (upper == 8 ? Authentication::Psk : Authentication::Sae));
    }
    // Unsupported management ciphers, OWE/FT and malformed suite lists deny.
    auto ie = rsn(8, 0xc0); ie.back() = 12;
    denied(join(0x1000, ie, password));
    for (uint8_t akm : {uint8_t(9), uint8_t(18)})
        denied(join(0x1000, rsn(akm, 0xc0), password));
    denied(join(0x2000, rsn(9, 0xc0), password));
    ie = rsn(8, 0xc0); ie[14] = 0xff;
    denied(join(0x1000, ie, password));
    ie = rsn(8, 0xc0); ie[22] = 0xff;
    denied(join(0x1000, ie, password));
    auto full = rsn(8, 0xc0);
    for (size_t n=0; n<full.size(); ++n) {
        auto cut = std::vector<uint8_t>(full.begin(), full.begin()+n);
        // A complete RSN element ending at its capabilities has implicit BIP.
        if (n == 22 || n == 24) continue;
        if (cut.size() > 1) cut[1] = uint8_t(cut.size()-2);
        denied(join(0x1000, cut, password));
    }
    // The selected SAE upper-auth bit must not be OR'ed with a PSK fallback.
    denied(join(0x1008, rsn(8, 0xc0), password));
}
