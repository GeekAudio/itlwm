// SPDX-License-Identifier: GPL-2.0-only
#include "wcl_wire.hpp"

namespace NativeWifi {
namespace {
DecodeResult rejected(uint32_t *field, uint32_t offset, DecodeResult result) {
    if (field) *field = offset;
    return result;
}
void copy(uint8_t *out, const uint8_t *in, size_t n) {
    for (size_t i = 0; i != n; ++i) out[i] = in[i];
}
bool allZero(const uint8_t *p, size_t n) {
    uint8_t bits = 0;
    for (size_t i = 0; i != n; ++i) bits |= p[i];
    return !bits;
}
bool unicast(const uint8_t *p) { return !(p[0] & 1) && !allZero(p, 6); }
bool takeSuites(const uint8_t *p, size_t end, size_t &offset,
                uint8_t expected, bool requireOne) {
    if (offset > end || end - offset < 2) return false;
    const uint16_t count = read16(p + offset);
    offset += 2;
    if ((requireOne && !count) || count > (end - offset) / 4) return false;
    bool found = false;
    for (unsigned i = 0; i < count; ++i, offset += 4) {
        const uint8_t *suite = p + offset;
        if (suite[0] || suite[1] != 0x0f || suite[2] != 0xac) return false;
        if (suite[3] == expected) found = true;
        // An optional SAE offer may coexist with an explicitly selected PSK.
        // It is preserved byte for byte and never converted into PSK.
        else if (!(expected == 2 && suite[3] == 8)) return false;
    }
    return found;
}
bool pskCCMP(const uint8_t *p, size_t n) {
    if (!p || n < 2 || p[0] != 48 || size_t(p[1]) + 2 != n || n < 10 ||
        read16(p + 2) != 1 || p[4] || p[5] != 0x0f ||
        p[6] != 0xac || p[7] != 4) return false;
    size_t offset = 8;
    if (!takeSuites(p, n, offset, 4, true) ||
        !takeSuites(p, n, offset, 2, true)) return false;
    if (offset == n) return true;
    if (n - offset < 2 || (read16(p + offset) & 0x40)) return false;
    offset += 2; // MFPC may be offered; MFPR is unsupported.
    if (offset == n) return true;
    if (n - offset < 2) return false;
    const uint16_t pmkids = read16(p + offset);
    offset += 2;
    if (pmkids > (n - offset) / 16) return false;
    offset += size_t(pmkids) * 16;
    if (offset == n) return true;
    // Optional group-management suite is an offer, not an MFP requirement.
    return n - offset == 4 && !p[offset] && p[offset+1] == 0x0f &&
           p[offset+2] == 0xac && p[offset+3] == 6;
}
}

void erase(void *buffer, size_t n) {
    volatile uint8_t *p = static_cast<volatile uint8_t *>(buffer);
    for (size_t i = 0; i != n; ++i) p[i] = 0;
}
uint16_t read16(const uint8_t *p) { return uint16_t(p[0]) | uint16_t(p[1]) << 8; }
uint32_t read32(const uint8_t *p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 |
           uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
void write16(uint8_t *p, uint16_t x) { p[0] = uint8_t(x); p[1] = uint8_t(x >> 8); }
void write32(uint8_t *p, uint32_t x) {
    for (unsigned i = 0; i < 4; ++i) p[i] = uint8_t(x >> (8*i));
}
bool validateIEs(const uint8_t *p, size_t n) {
    if ((!p && n) || n > MaximumIEBytes) return false;
    while (n) {
        if (n < 2 || size_t(p[1]) + 2 > n) return false;
        const size_t consumed = size_t(p[1]) + 2;
        p += consumed; n -= consumed;
    }
    return true;
}
bool selectedChannel(const ScanPlan &p, unsigned channel) {
    return channel && channel < 256 &&
        (!p.restricted || (p.channels[channel / 8] & uint8_t(1U << (channel % 8))));
}
DecodeResult decodeScan(const void *buffer, size_t n, ScanPlan &out, uint32_t *field) {
    if (field) *field=0xffffffffU;
    erase(&out, sizeof(out));
    if (!buffer || n != ScanWireSize) return DecodeResult::Malformed;
    const auto p = static_cast<const uint8_t *>(buffer);
    const uint32_t count = read32(p + 0x54), ssid = read32(p + 0x1c);
    const uint32_t type = read32(p + 0x40);
    if (count > 400) return rejected(field,0x54,DecodeResult::Malformed);
    if (ssid > 32) return rejected(field,0x1c,DecodeResult::Malformed);
    if (p[4] > 1) return rejected(field,4,DecodeResult::Malformed);
    if (type < 1 || type > 2) return rejected(field,0x40,DecodeResult::Unsupported);
    // Multiple-SSID and additional scan modes need an explicit HAL contract.
    if (read32(p+0x1318)) return rejected(field,0x1318,DecodeResult::Unsupported);
    if (read32(p+0x154c)) return rejected(field,0x154c,DecodeResult::Unsupported);
    if (!allZero(p+0x14,6)) return rejected(field,0x14,DecodeResult::Unsupported);
    ScanPlan plan = {};
    plan.identifier = read32(p);
    plan.privateAddressRequired = p[4] != 0;
    plan.type = type;
    plan.homeTime = read32(p + 8);
    plan.activeTime = read32(p + 0x48);
    plan.passiveTime = read32(p + 0x4c);
    plan.restTime = read32(p + 0x50);
    // Canonical Apple producer defaults select Intel's own audited firmware
    // default policy. This is not exact dwell-unit or home/rest passthrough.
    if (plan.homeTime!=0 && plan.homeTime!=40 && plan.homeTime!=110)
        return rejected(field,8,DecodeResult::Unsupported);
    if (plan.activeTime!=0 && plan.activeTime!=20 && plan.activeTime!=40)
        return rejected(field,0x48,DecodeResult::Unsupported);
    if (plan.passiveTime!=0 && plan.passiveTime!=110)
        return rejected(field,0x4c,DecodeResult::Unsupported);
    if (plan.restTime!=0 && plan.restTime!=45)
        return rejected(field,0x50,DecodeResult::Unsupported);
    plan.flags = read16(p + 0x44);
    plan.ssidLength = uint8_t(ssid);
    copy(plan.ssid, p + 0x20, ssid);
    plan.restricted = count != 0;
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *c = p + 0x58 + size_t(i) * 12;
        const uint32_t channel = read32(c + 4), flags = read32(c + 8);
        if (read32(c) != 1 || !channel || channel > 196 ||
            (flags & 0x2000) || (((flags & 8) != 0) == ((flags & 16) != 0)) ||
            ((flags & 8) && channel > 14) || ((flags & 16) && channel <= 14))
            return rejected(field,uint32_t(0x58+size_t(i)*12),DecodeResult::Unsupported);
        plan.channels[channel / 8] |= uint8_t(1U << (channel % 8));
    }
    out = plan;
    return DecodeResult::Ok;
}
DecodeResult decodeJoin(const void *buffer, size_t n, JoinPlan &out, uint32_t *field) {
    if (field) *field=0xffffffffU;
    erase(&out, sizeof(out));
    if (!buffer || n != JoinWireSize) return DecodeResult::Malformed;
    const auto p = static_cast<const uint8_t *>(buffer);
    const uint32_t count = read32(p + 0x214), ssid = read32(p + 0x1c);
    const uint32_t keyLength = read32(p + 0x44);
    const uint16_t rsnLength = read16(p + 0xd4);
    if (!count || count>10) return rejected(field,0x214,DecodeResult::Malformed);
    if (!ssid || ssid>32) return rejected(field,0x1c,DecodeResult::Malformed);
    if (keyLength>64) return rejected(field,0x44,DecodeResult::Malformed);
    if (rsnLength>257) return rejected(field,0xd4,DecodeResult::Malformed);
    if (!unicast(p+0x21c)) return rejected(field,0x21c,DecodeResult::Malformed);
    const uint32_t lower = read32(p + 0x10), upper = read32(p + 0x14);
    const uint32_t allowed = read32(p + 0x210);
    if (read16(p+0xc)!=2) return rejected(field,0xc,DecodeResult::Unsupported);
    if (lower!=1) return rejected(field,0x10,DecodeResult::Unsupported);
    if (upper!=0&&upper!=8) return rejected(field,0x14,DecodeResult::Unsupported);
    if (read32(p+0x18)) return rejected(field,0x18,DecodeResult::Unsupported);
    // First-candidate security/behavior subset: ordinary join flags only.
    // +1e4 bit1 is the proven native default produced from the zero policy
    // selector. Other unimplemented flags/extensions are never silently lost.
    if (read32(p+0x1e0)) return rejected(field,0x1e0,DecodeResult::Unsupported);
    if (read32(p+0x1e4)&~uint32_t(2)) return rejected(field,0x1e4,DecodeResult::Unsupported);
    if (read32(p+0x1e8)) return rejected(field,0x1e8,DecodeResult::Unsupported);
    if (read16(p+0x2cc)) return rejected(field,0x2cc,DecodeResult::Unsupported);
    if (p[0x1dd] || (read32(p+0x1e0)&0x80)) return rejected(field,0x1dd,DecodeResult::Unsupported); // MLO
    if (allowed!=0&&allowed!=4&&allowed!=0x40000004)
        return rejected(field,0x210,DecodeResult::Unsupported);
    if (read32(p+0x1ec) || !allZero(p+0x1f0,32))
        return rejected(field,0x1ec,DecodeResult::Unsupported);
    if (!upper) {
        if (keyLength || rsnLength || !allZero(p + 0x50, 64))
            return rejected(field,0x40,DecodeResult::Unsupported);
    } else {
        const uint32_t cipher = read32(p + 0x48);
        const bool pmk = (cipher == 6 || cipher == 7) && keyLength == 32;
        const bool password = cipher == 10 && keyLength >= 8 && keyLength <= 64;
        if (!pmk&&!password) return rejected(field,0x48,DecodeResult::Unsupported);
        if (!pskCCMP(p+0xd6,rsnLength)) return rejected(field,0xd6,DecodeResult::Unsupported);
        if (password) for (uint32_t i=0; i<keyLength; ++i) {
            const uint8_t c=p[0x50+i];
            if (keyLength == 64 ? !((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')) : (c<32 || c>126))
                return rejected(field,0x50,DecodeResult::Unsupported);
        }
    }
    JoinPlan plan = {};
    plan.lowerAuth = lower; plan.upperAuth = upper; plan.allowedAuth = allowed;
    plan.ssidLength = uint8_t(ssid); plan.secured = upper != 0;
    plan.rsnLength = rsnLength; plan.channelSpec = read16(p + 0x228);
    copy(plan.ssid, p + 0x20, ssid); copy(plan.bssid, p + 0x21c, 6);
    if (upper && read32(p + 0x48) == 10) {
        plan.derivePmk = true; plan.passwordLength = uint8_t(keyLength);
        copy(plan.password, p + 0x50, keyLength);
    } else copy(plan.pmk, p + 0x50, keyLength);
    copy(plan.rsn, p + 0xd6, rsnLength);
    out = plan;
    erase(&plan, sizeof(plan));
    return DecodeResult::Ok;
}
}
