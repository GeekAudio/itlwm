// SPDX-License-Identifier: GPL-2.0-only
// User-space test of the bounded adapter. CommonCrypto substitutes only the
// already-existing upstream PBKDF2 primitive; this does not test the HAL.
#include "../key_material.hpp"
#include <CommonCrypto/CommonKeyDerivation.h>
#include <assert.h>
#include <string.h>
#include <vector>

static unsigned derivations;
static bool failPrimitive;

int pbkdf2_sha1(const char *password, const uint8_t *ssid, size_t length,
                int iterations, uint8_t *out, size_t outputLength)
{
    ++derivations;
    assert(strlen(password) >= 8 && strlen(password) <= 63);
    assert(iterations == 4096 && outputLength == 32);
    if (failPrimitive) { memset(out, 0xa5, 32); return -1; }
    return CCKeyDerivationPBKDF(kCCPBKDF2, password, strlen(password), ssid,
        length, kCCPRFHmacAlgSHA1, iterations, out, outputLength);
}

static bool zero(const uint8_t *p)
{
    uint8_t bits = 0;
    for (unsigned i = 0; i < 32; ++i) bits |= p[i];
    return bits == 0;
}

int main()
{
    const uint8_t salt[] = {'I','E','E','E'};
    const uint8_t expected[32] = {
        0xf4,0x2c,0x6f,0xc5,0x2d,0xf0,0xeb,0xef,0x9e,0xbb,0x4b,0x90,0xb3,0x8a,0x5f,0x90,
        0x2e,0x83,0xfe,0x1b,0x13,0x5a,0x70,0xe2,0x3a,0xed,0x76,0x2e,0x97,0x10,0xa1,0x2e};
    uint8_t out[32];
    std::vector<uint8_t> password {'p','a','s','s','w','o','r','d'};
    assert(NativeWifi::deriveWPA2Pmk(password.data(), password.size(), salt, sizeof(salt), out));
    assert(!memcmp(out, expected, 32));
    for (size_t length = 0; length <= 80; ++length) {
        std::vector<uint8_t> key(length, 'a');
        memset(out, 0xa5, sizeof(out));
        bool result = NativeWifi::deriveWPA2Pmk(key.data(), length, salt, sizeof(salt), out);
        assert(result == (length >= 8 && length <= 64));
        if (!result) assert(zero(out));
    }
    std::vector<uint8_t> text(64, 'A');
    unsigned count = derivations;
    assert(NativeWifi::deriveWPA2Pmk(text.data(), text.size(), salt, sizeof(salt), out));
    assert(derivations == count);
    for (unsigned i = 0; i < 32; ++i) assert(out[i] == 0xaa);
    text[63] = 'z';
    assert(!NativeWifi::deriveWPA2Pmk(text.data(), text.size(), salt, sizeof(salt), out) && zero(out));
    for (uint8_t bad : {uint8_t(0),uint8_t(0x1f),uint8_t(0x7f),uint8_t(0xff)}) {
        password[7] = bad;
        assert(!NativeWifi::deriveWPA2Pmk(password.data(), password.size(), salt, sizeof(salt), out) && zero(out));
    }
    password[7] = 'd';
    assert(!NativeWifi::deriveWPA2Pmk(nullptr, 8, salt, 4, out) && zero(out));
    assert(!NativeWifi::deriveWPA2Pmk(password.data(), 8, nullptr, 4, out) && zero(out));
    assert(!NativeWifi::deriveWPA2Pmk(password.data(), 8, salt, 0, out) && zero(out));
    assert(!NativeWifi::deriveWPA2Pmk(password.data(), 8, salt, 33, out) && zero(out));
    assert(!NativeWifi::deriveWPA2Pmk(password.data(), 8, salt, 4, nullptr));
    failPrimitive = true;
    assert(!NativeWifi::deriveWPA2Pmk(password.data(), 8, salt, 4, out) && zero(out));
}
