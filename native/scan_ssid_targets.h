/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ITL_SCAN_SSID_TARGETS_H
#define ITL_SCAN_SSID_TARGETS_H

#include <stddef.h>
#include <stdint.h>

/* 25G332 scan441 carries ten 56-byte records. Firmware has twenty slots. */
#define ITL_SCAN_TARGET_CAPACITY 10
#define ITL_SCAN_SSID_BYTES 32

struct itl_scan_ssid_target {
    uint8_t length;
    uint8_t bytes[ITL_SCAN_SSID_BYTES];
};

struct itl_scan_ssid_targets {
    uint8_t count;
    struct itl_scan_ssid_target entries[ITL_SCAN_TARGET_CAPACITY];
};

static inline int
itl_scan_targets_valid(const struct itl_scan_ssid_targets *targets)
{
    if (!targets || targets->count == 0 ||
        targets->count > ITL_SCAN_TARGET_CAPACITY)
        return 0;
    for (unsigned i = 0; i < targets->count; ++i)
        if (targets->entries[i].length > ITL_SCAN_SSID_BYTES)
            return 0;
    return 1;
}

static inline int
itl_scan_targets_directed(const struct itl_scan_ssid_targets *targets)
{
    if (!itl_scan_targets_valid(targets))
        return 0;
    for (unsigned i = 0; i < targets->count; ++i)
        if (targets->entries[i].length != 0)
            return 1;
    return 0;
}

static inline uint32_t
itl_scan_targets_bitmap(const struct itl_scan_ssid_targets *targets)
{
    return itl_scan_targets_valid(targets) ?
        ((uint32_t)1u << targets->count) - 1u : 0u;
}

#endif
