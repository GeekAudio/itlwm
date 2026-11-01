#ifndef IWX_EAPOL_PRIORITY_HPP
#define IWX_EAPOL_PRIORITY_HPP

#include <stddef.h>
#include <stdint.h>

namespace IwxEapolPriority {

static constexpr size_t kGroup2KeyBytes = 99;
static constexpr size_t kLlcSnapBytes = 8;
static constexpr size_t kRsnGroup2BodyBytes = kLlcSnapBytes + kGroup2KeyBytes;

static constexpr uint32_t kHighPriorityFlag = 1u << 2;
static constexpr uint16_t kSequenceFragmentMask = 0x000fu;

/*
 * Fail-closed recognition of the exact unfragmented STA->AP RSN Group Key
 * Message 2 emitted by net80211. This runs before CCMP IV/MIC insertion, so
 * the EAPOL body is still plaintext while the 802.11 Protected bit is set.
 * Retry and Power-Management may vary across retransmission/power state.
 */
inline bool isRsnGroup2(const uint8_t frameControl0,
                        const uint8_t frameControl1,
                        const uint8_t address1FirstOctet,
                        const uint16_t sequenceControl,
                        const uint8_t *body,
                        const size_t bodyLength)
{
    if (body == nullptr || bodyLength != kRsnGroup2BodyBytes)
        return false;

    /* Version 0, ordinary non-QoS Data subtype. */
    if (frameControl0 != 0x08)
        return false;

    /* STA->AP only, Protected, non-fragmented. Allow Retry/PM/MoreData. */
    if ((frameControl1 & 0x03u) != 0x01u ||
        (frameControl1 & 0x40u) == 0 ||
        (frameControl1 & 0x04u) != 0 ||
        (frameControl1 & 0x80u) != 0)
        return false;

    /* Reject fragments even when this is the final fragment (MoreFrag=0). */
    if ((sequenceControl & kSequenceFragmentMask) != 0)
        return false;

    /* EAPOL must be unicast to the AP. */
    if ((address1FirstOctet & 0x01u) != 0)
        return false;

    static const uint8_t kLlcSnapEapol[kLlcSnapBytes] = {
        0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e
    };
    for (size_t i = 0; i < kLlcSnapBytes; ++i) {
        if (body[i] != kLlcSnapEapol[i])
            return false;
    }

    const uint8_t *key = body + kLlcSnapBytes;
    if (key[0] != 1 ||             /* EAPOL version */
        key[1] != 3 ||             /* EAPOL-Key */
        key[2] != 0 || key[3] != 95 ||
        key[4] != 2 ||             /* RSN key descriptor */
        key[7] != 0 || key[8] != 0 || /* no WPA key length */
        key[97] != 0 || key[98] != 0) /* no key data */
        return false;

    const uint16_t keyInfo =
        (static_cast<uint16_t>(key[5]) << 8) | key[6];
    /* Only MIC + SECURE + RSN descriptor version 2 or 3 are expected. */
    if (keyInfo != 0x0302u && keyInfo != 0x0303u)
        return false;

    return true;
}

} // namespace IwxEapolPriority

#endif
