#include "../iwx_eapol_priority.hpp"
#include "../iwx_sta_auth_trace.h"

#include <assert.h>
#include <string.h>

static void makeGroup2(uint8_t *body, uint16_t keyInfo = 0x0302)
{
    memset(body, 0, IwxEapolPriority::kRsnGroup2BodyBytes);
    const uint8_t llc[8] = {0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e};
    memcpy(body, llc, sizeof(llc));
    uint8_t *key = body + IwxEapolPriority::kLlcSnapBytes;
    key[0] = 1;
    key[1] = 3;
    key[2] = 0;
    key[3] = 95;
    key[4] = 2;
    key[5] = static_cast<uint8_t>(keyInfo >> 8);
    key[6] = static_cast<uint8_t>(keyInfo);
}

static bool classify(const uint8_t *body, size_t length,
                     uint8_t fc0 = 0x08, uint8_t fc1 = 0x41,
                     uint8_t address1FirstOctet = 0x00,
                     uint16_t sequenceControl = 0)
{
    return IwxEapolPriority::isRsnGroup2(
        fc0, fc1, address1FirstOctet, sequenceControl, body, length);
}

int main()
{
    uint8_t body[IwxEapolPriority::kRsnGroup2BodyBytes];
    makeGroup2(body, 0x0302);
    assert(classify(body, sizeof(body)));
    makeGroup2(body, 0x0303);
    assert(classify(body, sizeof(body)));

    /* A retry or power-management bit does not change Group2 identity. */
    assert(classify(body, sizeof(body), 0x08, 0x59));
    assert(classify(body, sizeof(body), 0x08, 0x51));

    assert(!classify(body, sizeof(body), 0x28)); /* QoS Data */
    assert(!classify(body, sizeof(body), 0x48)); /* data subtype mismatch */
    assert(!classify(body, sizeof(body), 0x08, 0x40)); /* not ToDS */
    assert(!classify(body, sizeof(body), 0x08, 0x43)); /* FromDS */
    assert(!classify(body, sizeof(body), 0x08, 0x45)); /* fragmented */
    /* Final fragment has MoreFrag clear, but a nonzero fragment number. */
    assert(!classify(body, sizeof(body), 0x08, 0x41, 0x00, 0x0001));
    assert(classify(body, sizeof(body), 0x08, 0x41, 0x00, 0x0010));
    assert(!classify(body, sizeof(body), 0xc1)); /* Order/HT shape */
    assert(!classify(body, sizeof(body), 0x08, 0x01)); /* unprotected */
    assert(!classify(body, sizeof(body), 0x08, 0x41, 0x01)); /* multicast */
    assert(!classify(nullptr, sizeof(body)));
    assert(!classify(body, sizeof(body) - 1));
    uint8_t extended[IwxEapolPriority::kRsnGroup2BodyBytes + 1];
    memcpy(extended, body, sizeof(body));
    extended[sizeof(body)] = 0;
    assert(!classify(extended, sizeof(extended)));

    const size_t keyOffset = IwxEapolPriority::kLlcSnapBytes;
    const uint16_t badKeyInfo[] = {
        0x030a, /* pairwise bit: four-way message shape */
        0x0382, /* key acknowledgement */
        0x0702, /* error */
        0x0342, /* install */
        0x1302, /* encrypted key data */
        0x0b02, /* request */
        0x0300, /* unknown / descriptor version zero */
        0x8302  /* SMK/unsupported bits */
    };
    for (size_t i = 0; i < sizeof(badKeyInfo) / sizeof(badKeyInfo[0]); ++i) {
        makeGroup2(body, badKeyInfo[i]);
        assert(!classify(body, sizeof(body)));
    }

    makeGroup2(body);
    body[keyOffset + 4] = 254; /* WPA descriptor */
    assert(!classify(body, sizeof(body)));
    makeGroup2(body);
    body[keyOffset + 0] = 2;
    assert(!classify(body, sizeof(body)));
    makeGroup2(body);
    body[keyOffset + 1] = 0;
    assert(!classify(body, sizeof(body)));
    makeGroup2(body);
    body[keyOffset + 3] = 94;
    assert(!classify(body, sizeof(body)));
    makeGroup2(body);
    body[keyOffset + 7] = 0;
    body[keyOffset + 8] = 16;
    assert(!classify(body, sizeof(body)));
    makeGroup2(body);
    body[keyOffset + 97] = 0;
    body[keyOffset + 98] = 1;
    assert(!classify(body, sizeof(body)));
    makeGroup2(body);
    body[6] = 0x88;
    body[7] = 0x8f;
    assert(!classify(body, sizeof(body)));

    uint8_t received[8] = {0, 0, 0, 0, 0, 0, 1, 0};
    uint8_t transmitted[8] = {0, 0, 0, 0, 0, 0, 1, 0};
    assert(iwx_sta_auth_replay_echo_flags(received, transmitted) ==
        (IWX_STA_FLAG_GROUP2_REPLAY_ECHO_CHECKED |
         IWX_STA_FLAG_GROUP2_REPLAY_ECHO_EQUAL));
    transmitted[7] = 1;
    assert(iwx_sta_auth_replay_echo_flags(received, transmitted) ==
        (IWX_STA_FLAG_GROUP2_REPLAY_ECHO_CHECKED |
         IWX_STA_FLAG_GROUP2_REPLAY_ECHO_MISMATCH));
    assert(iwx_sta_auth_replay_echo_flags(nullptr, transmitted) == 0);

    return 0;
}
