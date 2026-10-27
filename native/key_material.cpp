// SPDX-License-Identifier: GPL-2.0-only
#include "key_material.hpp"

// Existing upstream implementation in openbsd/crypto/sha1-pbkdf2.c. The
// project's C sources are compiled as C++; this matches crypto/sha1.h exactly.
int pbkdf2_sha1(const char *, const uint8_t *, size_t, int, uint8_t *, size_t);

namespace NativeWifi {
namespace {
void clear(void *buffer, size_t length)
{
    volatile uint8_t *p = static_cast<volatile uint8_t *>(buffer);
    while (length--)
        *p++ = 0;
}

int hex(uint8_t value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}
}

bool deriveWPA2Pmk(const uint8_t *key, size_t keyLength, const uint8_t *ssid,
                   size_t ssidLength, uint8_t out[32])
{
    if (!out)
        return false;
    clear(out, 32);
    if (!key || !ssid || !ssidLength || ssidLength > 32 ||
        keyLength < 8 || keyLength > 64)
        return false;

    if (keyLength == 64) {
        for (size_t i = 0; i < 32; ++i) {
            const int high = hex(key[2 * i]), low = hex(key[2 * i + 1]);
            if (high < 0 || low < 0) {
                clear(out, 32);
                return false;
            }
            out[i] = uint8_t((high << 4) | low);
        }
        return true;
    }

    char password[64] {};
    for (size_t i = 0; i < keyLength; ++i) {
        if (key[i] < 0x20 || key[i] > 0x7e) {
            clear(password, sizeof(password));
            return false;
        }
        password[i] = char(key[i]);
    }
    const bool result = pbkdf2_sha1(password, ssid, ssidLength, 4096, out, 32) == 0;
    clear(password, sizeof(password));
    if (!result)
        clear(out, 32);
    return result;
}
}
