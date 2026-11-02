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
                uint8_t expected) {
    if (offset > end || end - offset < 2) return false;
    const uint16_t count = read16(p + offset);
    offset += 2;
    if (!count || count > (end - offset) / 4) return false;
    bool found = false;
    for (unsigned i = 0; i < count; ++i, offset += 4) {
        const uint8_t *suite = p + offset;
        if (suite[0] || suite[1] != 0x0f || suite[2] != 0xac) return false;
        if (suite[3] == expected) found = true;
        // Other offered suites do not change the explicitly selected AKM or
        // cipher. In particular, a selected SAE request never becomes PSK.
    }
    return found;
}
bool personalCCMP(const uint8_t *p, size_t n, uint8_t selectedAkm,
                  bool &pmfCapable, bool &pmfRequired) {
    pmfCapable = pmfRequired = false;
    if (!p || n < 2 || p[0] != 48 || size_t(p[1]) + 2 != n || n < 10 ||
        read16(p + 2) != 1 || p[4] || p[5] != 0x0f ||
        p[6] != 0xac || p[7] != 4) return false;
    size_t offset = 8;
    if (!takeSuites(p, n, offset, 4) ||
        !takeSuites(p, n, offset, selectedAkm)) return false;
    if (offset == n) return selectedAkm != 8;
    if (n - offset < 2) return false;
    const uint16_t capabilities = read16(p + offset);
    pmfCapable = (capabilities & 0x80) != 0;
    pmfRequired = (capabilities & 0x40) != 0;
    if (pmfRequired && !pmfCapable) return false;
    // SAE always negotiates management protection, including on a transition
    // BSS whose advertisement makes PMF optional for its PSK clients.
    if (selectedAkm == 8) {
        if (!pmfCapable) return false;
        pmfRequired = true;
    }
    offset += 2;
    if (offset == n) return true;
    if (n - offset < 2) return false;
    const uint16_t pmkids = read16(p + offset);
    offset += 2;
    if (pmkids > (n - offset) / 16) return false;
    offset += size_t(pmkids) * 16;
    if (offset == n) return true;
    // Absent group-management suite defaults to BIP-CMAC-128. It is the only
    // management cipher implemented by this connection path.
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
    // 25G332 producer + IO80211ScanRequest copy: count followed by ten
    // 56-byte version/length/SSID/metadata records. Never use the legacy
    // apple80211_scan_multiple_data layout for scan441.
    const uint32_t targetCount = read32(p + 0x1318);
    if (targetCount > ITL_SCAN_TARGET_CAPACITY)
        return rejected(field,0x1318,DecodeResult::Malformed);
    if (targetCount && ssid)
        return rejected(field,0x1c,DecodeResult::Unsupported);
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
    if (targetCount) {
        plan.targets.count = uint8_t(targetCount);
        for (uint32_t i = 0; i < targetCount; ++i) {
            const uint32_t offset = 0x131c + i * 56;
            const uint8_t *entry = p + offset;
            const uint32_t version = read32(entry), length = read32(entry + 4);
            if (length > ITL_SCAN_SSID_BYTES)
                return rejected(field,offset + 4,DecodeResult::Malformed);
            // The saved producer leaves its trailing zero-length record
            // zero-filled, only in the final slot. Explicit records have
            // version 1 (including an explicit empty SSID). Unknown per-SSID
            // metadata must not be silently discarded.
            if (version != 1 && !(version == 0 && i + 1 == targetCount &&
                                  !length && allZero(entry,56)))
                return rejected(field,offset,DecodeResult::Unsupported);
            if (!allZero(entry + 40,16) || (!length && !allZero(entry + 8,32)))
                return rejected(field,offset + 40,DecodeResult::Unsupported);
            plan.targets.entries[i].length = uint8_t(length);
            copy(plan.targets.entries[i].bytes, entry + 8, length);
        }
    } else {
        plan.targets.count = 1;
        plan.targets.entries[0].length = uint8_t(ssid);
        copy(plan.targets.entries[0].bytes, p + 0x20, ssid);
    }
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
    if (upper!=0&&upper!=8&&upper!=0x400&&upper!=0x1000)
        return rejected(field,0x14,DecodeResult::Unsupported);
    if (read32(p+0x18)) return rejected(field,0x18,DecodeResult::Unsupported);
    // First-candidate security/behavior subset: ordinary join flags only.
    // +1e4 bit1 is the proven native default produced from the zero policy
    // selector. Other unimplemented flags/extensions are never silently lost.
    if (read32(p+0x1e0)) return rejected(field,0x1e0,DecodeResult::Unsupported);
    if (read32(p+0x1e4)&~uint32_t(2)) return rejected(field,0x1e4,DecodeResult::Unsupported);
    if (read32(p+0x1e8)) return rejected(field,0x1e8,DecodeResult::Unsupported);
    if (read16(p+0x2cc)) return rejected(field,0x2cc,DecodeResult::Unsupported);
    if (p[0x1dd] || (read32(p+0x1e0)&0x80)) return rejected(field,0x1dd,DecodeResult::Unsupported); // MLO
    if (upper == 0x1000) {
        // The pinned native SAE producer emits its SAE restriction policy and
        // an auxiliary 32-byte password-parser result. WCL copies these into
        // the driver request at +0x210 and +0x1ec/+0x1f0 respectively. That
        // parser result is not the PMK negotiated by SAE; never import it.
        // The SAE producer also has a conditional transition-policy edge
        // emitting 0x40000004; AllowedAuth is not the selected-auth enum.
        if (allowed!=0&&allowed!=4&&allowed!=0x40000004&&
            allowed!=0x100&&allowed!=0x40000100)
            return rejected(field,0x210,DecodeResult::Unsupported);
        if (read32(p+0x1ec) != 32)
            return rejected(field,0x1ec,DecodeResult::Unsupported);
    } else {
        if (allowed!=0&&allowed!=4&&allowed!=0x40000004)
            return rejected(field,0x210,DecodeResult::Unsupported);
        if (read32(p+0x1ec) || !allZero(p+0x1f0,32))
            return rejected(field,0x1ec,DecodeResult::Unsupported);
    }
    bool pmfCapable = false, pmfRequired = false;
    if (!upper) {
        if (keyLength || rsnLength || !allZero(p + 0x50, 64))
            return rejected(field,0x40,DecodeResult::Unsupported);
    } else {
        const uint32_t cipher = read32(p + 0x48);
        const bool sae = upper == 0x1000;
        const bool pmk = !sae && (cipher == 6 || cipher == 7) && keyLength == 32;
        const bool password = cipher == 10 && keyLength >= (sae ? 1U : 8U) && keyLength <= 64;
        if (!pmk&&!password) return rejected(field,0x48,DecodeResult::Unsupported);
        const uint8_t akm = sae ? 8 : (upper == 0x400 ? 6 : 2);
        if (!personalCCMP(p+0xd6,rsnLength,akm,pmfCapable,pmfRequired))
            return rejected(field,0xd6,DecodeResult::Unsupported);
        if (password) for (uint32_t i=0; i<keyLength; ++i) {
            const uint8_t c=p[0x50+i];
            // SAE receives a password, never a 64-character hexadecimal PMK.
            // Preserve non-ASCII password bytes; embedded NUL has no supported
            // native/SAE string representation and is rejected explicitly.
            if (sae ? c == 0 : (keyLength == 64 ?
                !((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')) : (c<32 || c>126)))
                return rejected(field,0x50,DecodeResult::Unsupported);
        }
    }
    JoinPlan plan = {};
    plan.lowerAuth = lower; plan.upperAuth = upper; plan.allowedAuth = allowed;
    plan.authentication = !upper ? Authentication::Open :
        (upper == 0x1000 ? Authentication::Sae :
         (upper == 0x400 ? Authentication::PskSha256 : Authentication::Psk));
    plan.pmfCapable = pmfCapable; plan.pmfRequired = pmfRequired;
    plan.ssidLength = uint8_t(ssid); plan.secured = upper != 0;
    plan.rsnLength = rsnLength; plan.channelSpec = read16(p + 0x228);
    copy(plan.ssid, p + 0x20, ssid); copy(plan.bssid, p + 0x21c, 6);
    if (upper && read32(p + 0x48) == 10) {
        plan.derivePmk = plan.authentication != Authentication::Sae;
        plan.passwordLength = uint8_t(keyLength);
        copy(plan.password, p + 0x50, keyLength);
    } else copy(plan.pmk, p + 0x50, keyLength);
    copy(plan.rsn, p + 0xd6, rsnLength);
    out = plan;
    erase(&plan, sizeof(plan));
    return DecodeResult::Ok;
}
}
