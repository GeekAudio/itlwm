#!/usr/bin/env python3
"""Compile and exercise the production RSN/WPA Group1 handlers on the host.

The test extracts the functions and Tahoe observer helpers from
ieee80211_pae_input.c, then supplies only the surrounding kernel/net80211
types and callbacks. It builds both the legacy preprocessor path and the
AIRPORT_TAHOE diagnostic path so instrumentation can be checked against the
same production control flow.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itl80211/openbsd/net80211/ieee80211_pae_input.c"


def extract_function(source: str, marker: str) -> str:
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"production function not found: {marker}")
    brace = source.find("{", start)
    if brace < 0:
        raise AssertionError(f"function body not found: {marker}")

    depth = 0
    index = brace
    state = "code"
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                state = "block_comment"
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[start : index + 1]
        elif state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 2
                continue
        elif state in ("string", "char"):
            if char == "\\":
                index += 2
                continue
            if (state == "string" and char == '"') or (
                state == "char" and char == "'"
            ):
                state = "code"
        index += 1
    raise AssertionError(f"unterminated function: {marker}")


HARNESS_PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#ifdef AIRPORT_TAHOE
#include "native/iwx_sta_auth_trace.h"
#endif

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;

#define XYLog(...) ((void)0)
#define DPRINTF(...) ((void)0)

#define IEEE80211_CIPHER_NONE 0
#define IEEE80211_CIPHER_CCMP 1
#define IEEE80211_CIPHER_BIP 2
#define IEEE80211_KEY_GROUP 0x01u
#define IEEE80211_KEY_TX 0x02u
#define IEEE80211_KEY_IGTK 0x04u
#define IEEE80211_NODE_MFP 0x01u
#define IEEE80211_M_STA 1
#define IEEE80211_M_IBSS 2
#define RNSA_SUPP_PTKDONE 4
#define IEEE80211_ELEMID_VENDOR 221
#define IEEE80211_KDE_GTK 1
#define IEEE80211_KDE_IGTK 9
#define IEEE80211_REASON_AUTH_LEAVE 3
#define IEEE80211_FC0_SUBTYPE_DEAUTH 0xc0
#define IEEE80211_EAPOL_KEY_ENCRYPTED 0x1000u
#define EAPOL_KEY_ENCRYPTED IEEE80211_EAPOL_KEY_ENCRYPTED
#define EAPOL_KEY_SECURE 0x0200u
#define EAPOL_KEY_WPA_KID_SHIFT 4
#define EAPOL_KEY_WPA_TX 0x0008u
#define IFF_DEBUG 0x01u
#define LINK_STATE_UP 1
#define IEEE80211_S_SCAN 1

static const uint8_t iwx_test_oui[3] = {0x00, 0x0f, 0xac};
#define IEEE80211_OUI iwx_test_oui

static uint16_t read_be16(const uint8_t *p)
{ return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }
static uint64_t read_be64(const uint8_t *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value = (value << 8) | p[i];
    return value;
}
static uint64_t read_le6(const uint8_t *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 6; ++i) value |= (uint64_t)p[i] << (8 * i);
    return value;
}
#define BE_READ_2(p) read_be16((const uint8_t *)(p))
#define BE_READ_8(p) read_be64((const uint8_t *)(p))
#define LE_READ_2(p) ((uint16_t)((const uint8_t *)(p))[0] | \
    (uint16_t)((const uint8_t *)(p))[1] << 8)
#define LE_READ_6(p) read_le6((const uint8_t *)(p))

enum ieee80211_cipher {
    IEEE80211_CIPHER_NONE_VALUE = IEEE80211_CIPHER_NONE,
    IEEE80211_CIPHER_CCMP_VALUE = IEEE80211_CIPHER_CCMP,
    IEEE80211_CIPHER_BIP_VALUE = IEEE80211_CIPHER_BIP
};

struct ieee80211_key {
    uint8_t k_id;
    enum ieee80211_cipher k_cipher;
    unsigned k_flags;
    unsigned k_len;
    uint64_t k_rsc[16];
    uint64_t k_mgmt_rsc;
    uint64_t k_tsc;
    uint8_t k_key[32];
    void *k_priv;
};

struct ieee80211_eapol_key {
    uint8_t info[2];
    uint8_t keylen[2];
    uint8_t replaycnt[8];
    uint8_t rsc[8];
    uint8_t paylen[2];
};

struct ieee80211_node {
    int ni_rsn_supp_state;
    uint64_t ni_replaycnt;
    struct { uint8_t kck[16]; uint8_t kek[16]; } ni_ptk;
    enum ieee80211_cipher ni_rsngroupcipher;
    enum ieee80211_cipher ni_rsngroupmgmtcipher;
    unsigned ni_flags;
    int ni_port_valid;
    unsigned ni_key_count;
    int ni_assoc_fail;
    uint8_t ni_macaddr[6];
};

struct ieee80211_stats {
    unsigned is_rx_eapol_replay;
    unsigned is_rx_eapol_badmic;
};

struct ieee80211_if {
    unsigned if_flags;
    const char *if_xname;
};

struct ieee80211com;
struct IwxStaAuthSubmitReceipt;
typedef int (*key_callback)(struct ieee80211com *, struct ieee80211_node *,
                            struct ieee80211_key *);
typedef int (*mgmt_callback)(struct ieee80211com *, struct ieee80211_node *,
                             int, int, void *);

struct ieee80211com {
    int ic_opmode;
    struct ieee80211_if ic_if;
    struct ieee80211_stats ic_stats;
    struct ieee80211_key ic_nw_keys[6];
    key_callback ic_set_key;
    mgmt_callback ic_send_mgmt;
    unsigned scan_requests;
    unsigned link_state;
#ifdef AIRPORT_TAHOE
    int (*ic_tahoe_set_key_observed)(struct ieee80211com *,
        struct ieee80211_node *, struct ieee80211_key *, uint32_t,
        struct IwxStaAuthSubmitReceipt *);
    struct IwxStaAuthTrace ic_tahoe_auth_trace;
#endif
};

static unsigned g_key_calls;
static unsigned g_mgmt_calls;
static unsigned g_m2_calls;
static unsigned g_mic_calls;
static unsigned g_decrypt_calls;
static int g_key_result;
static int g_mgmt_result;
static int g_m2_result;
static int g_mic_result;
static int g_decrypt_result;
static unsigned g_expected_kid;
static uint8_t g_expected_key[16];
#ifdef AIRPORT_TAHOE
static const uint64_t kMonotonicBase = 0x102030405060ULL;
#endif

#ifdef AIRPORT_TAHOE
static void microuptime(struct timeval *tv)
{
    static uint64_t tick;
    const uint64_t value = kMonotonicBase + ++tick;
    tv->tv_sec = (time_t)(value / 1000000ULL);
    tv->tv_usec = (suseconds_t)(value % 1000000ULL);
}
#endif

static int key_callback_impl(struct ieee80211com *ic,
    struct ieee80211_node *ni, struct ieee80211_key *key)
{
    (void)ic; (void)ni;
    ++g_key_calls;
    assert(key->k_id == g_expected_kid);
    assert(key->k_len == sizeof(g_expected_key));
    assert(memcmp(key->k_key, g_expected_key, sizeof(g_expected_key)) == 0);
    return g_key_result;
}

#ifdef AIRPORT_TAHOE
static int key_callback_observed(struct ieee80211com *ic,
    struct ieee80211_node *ni, struct ieee80211_key *key, uint32_t attempt,
    struct IwxStaAuthSubmitReceipt *receipt)
{
    assert(attempt != 0);
    const int result = key_callback_impl(ic, ni, key);
    receipt->key_callback_result = result;
    if (result == EAGAIN) {
        receipt->state = IWX_STA_SUBMIT_REJECTED_BEFORE_RING;
        receipt->raw_command_result = EBUSY;
    } else if (result == 0 || result == EBUSY) {
        receipt->state = IWX_STA_SUBMIT_LOCAL_ENQUEUE;
        receipt->queue_id = 7;
        receipt->queue_index = 11;
    } else {
        receipt->state = IWX_STA_SUBMIT_OTHER_ERROR;
    }
    return result;
}
#endif

static int mgmt_callback_impl(struct ieee80211com *ic,
    struct ieee80211_node *ni, int subtype, int argument, void *extra)
{
    (void)ic; (void)ni; (void)extra;
    assert(subtype == IEEE80211_FC0_SUBTYPE_DEAUTH);
    assert(argument == IEEE80211_REASON_AUTH_LEAVE);
    ++g_mgmt_calls;
    return g_mgmt_result;
}

#define IEEE80211_SEND_MGMT(ic, ni, subtype, argument) \
    ((ic)->ic_send_mgmt((ic), (ni), (subtype), (argument), NULL))

static int ieee80211_eapol_key_check_mic(struct ieee80211_eapol_key *key,
                                          const uint8_t *kck)
{
    (void)key; (void)kck;
    ++g_mic_calls;
    return g_mic_result;
}

static int ieee80211_eapol_key_decrypt(struct ieee80211_eapol_key *key,
                                        const uint8_t *kek)
{
    (void)key; (void)kek;
    ++g_decrypt_calls;
    return g_decrypt_result;
}

static int ieee80211_cipher_keylen(enum ieee80211_cipher cipher)
{ return cipher == IEEE80211_CIPHER_CCMP_VALUE ? 16 : 0; }

static int ieee80211_send_group_msg2(struct ieee80211com *ic,
    struct ieee80211_node *ni, struct ieee80211_key *key)
{
    (void)ic; (void)ni; (void)key;
    ++g_m2_calls;
    return g_m2_result;
}

static void ieee80211_new_state(struct ieee80211com *ic, int state, int arg)
{
    assert(state == 1); /* IEEE80211_S_SCAN */
    assert(arg == -1);
    ++ic->scan_requests;
}

static void ieee80211_set_link_state(struct ieee80211com *ic, unsigned state)
{ ic->link_state = state; }

struct fixture {
    struct ieee80211com ic;
    struct ieee80211_node ni;
    uint8_t key_storage[sizeof(struct ieee80211_eapol_key) + 128];
};

static void reset_globals(void)
{
    g_key_calls = g_mgmt_calls = g_m2_calls = 0;
    g_mic_calls = g_decrypt_calls = 0;
    g_key_result = g_mgmt_result = g_m2_result = 0;
    g_mic_result = g_decrypt_result = 0;
    g_expected_kid = 1;
    for (unsigned i = 0; i < sizeof(g_expected_key); ++i)
        g_expected_key[i] = (uint8_t)(0xd3u ^ (i * 7u));
}

static void init_fixture(struct fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->ic.ic_opmode = IEEE80211_M_STA;
    fixture->ic.ic_set_key = key_callback_impl;
    fixture->ic.ic_send_mgmt = mgmt_callback_impl;
    fixture->ni.ni_rsn_supp_state = RNSA_SUPP_PTKDONE;
    fixture->ni.ni_replaycnt = 5;
    fixture->ni.ni_rsngroupcipher = IEEE80211_CIPHER_CCMP_VALUE;
    fixture->ni.ni_rsngroupmgmtcipher = IEEE80211_CIPHER_BIP_VALUE;
#ifdef AIRPORT_TAHOE
    iwx_sta_auth_trace_init(&fixture->ic.ic_tahoe_auth_trace, 3);
    fixture->ic.ic_tahoe_set_key_observed = key_callback_observed;
#endif
}

static struct ieee80211_eapol_key *init_rsn_group1(struct fixture *fixture,
    uint64_t replay, int include_gtk, int secure)
{
    struct ieee80211_eapol_key *key =
        (struct ieee80211_eapol_key *)(void *)fixture->key_storage;
    memset(fixture->key_storage, 0, sizeof(fixture->key_storage));
    key->info[0] = (uint8_t)((IEEE80211_EAPOL_KEY_ENCRYPTED |
        (secure ? EAPOL_KEY_SECURE : 0)) >> 8);
    key->info[1] = (uint8_t)(IEEE80211_EAPOL_KEY_ENCRYPTED |
        (secure ? EAPOL_KEY_SECURE : 0));
    for (unsigned i = 0; i < 8; ++i)
        key->replaycnt[7 - i] = (uint8_t)(replay >> (8 * i));
    key->rsc[0] = 1;
    if (include_gtk) {
        uint8_t *gtk = (uint8_t *)&key[1];
        gtk[0] = IEEE80211_ELEMID_VENDOR;
        gtk[1] = 22;
        memcpy(&gtk[2], IEEE80211_OUI, 3);
        gtk[5] = IEEE80211_KDE_GTK;
        gtk[6] = (uint8_t)g_expected_kid;
        gtk[7] = 0;
        memcpy(&gtk[8], g_expected_key, sizeof(g_expected_key));
        key->paylen[0] = 0;
        key->paylen[1] = 24;
    }
    return key;
}

static struct ieee80211_eapol_key *init_wpa_group1(struct fixture *fixture,
    uint64_t replay)
{
    struct ieee80211_eapol_key *key =
        (struct ieee80211_eapol_key *)(void *)fixture->key_storage;
    memset(fixture->key_storage, 0, sizeof(fixture->key_storage));
    const uint16_t info = (uint16_t)(IEEE80211_EAPOL_KEY_ENCRYPTED |
        EAPOL_KEY_SECURE | (g_expected_kid << EAPOL_KEY_WPA_KID_SHIFT));
    key->info[0] = (uint8_t)(info >> 8);
    key->info[1] = (uint8_t)info;
    key->keylen[0] = 0;
    key->keylen[1] = (uint8_t)sizeof(g_expected_key);
    for (unsigned i = 0; i < 8; ++i)
        key->replaycnt[7 - i] = (uint8_t)(replay >> (8 * i));
    key->rsc[0] = 1;
    key->paylen[0] = 0;
    key->paylen[1] = (uint8_t)sizeof(g_expected_key);
    memcpy(&key[1], g_expected_key, sizeof(g_expected_key));
    return key;
}

#ifdef AIRPORT_TAHOE
static int bytes_contain(const void *haystack, size_t haystack_length,
    const void *needle, size_t needle_length)
{
    const uint8_t *bytes = (const uint8_t *)haystack;
    const uint8_t *pattern = (const uint8_t *)needle;
    for (size_t i = 0; i + needle_length <= haystack_length; ++i)
        if (memcmp(bytes + i, pattern, needle_length) == 0)
            return 1;
    return 0;
}
#endif

'''


HARNESS_SUFFIX = r'''
static void test_replay_early_return(void)
{
    reset_globals();
    struct fixture f; init_fixture(&f);
    struct ieee80211_eapol_key *key = init_rsn_group1(&f, 5, 1, 1);
    ieee80211_recv_rsn_group_msg1(&f.ic, key, &f.ni);
    assert(g_mic_calls == 0 && g_decrypt_calls == 0 && g_key_calls == 0);
    assert(g_m2_calls == 0 && g_mgmt_calls == 0 && f.ic.scan_requests == 0);
    assert(f.ni.ni_replaycnt == 5);
    printf("replay:%u,%u,%u,%u,%u,%llu\n", g_mic_calls, g_key_calls,
        g_m2_calls, g_mgmt_calls, f.ic.scan_requests,
        (unsigned long long)f.ni.ni_replaycnt);
}

static void test_mic_early_return(void)
{
    reset_globals();
    struct fixture f; init_fixture(&f);
    g_mic_result = EACCES;
    struct ieee80211_eapol_key *key = init_rsn_group1(&f, 6, 1, 1);
    ieee80211_recv_rsn_group_msg1(&f.ic, key, &f.ni);
    assert(g_mic_calls == 1 && g_decrypt_calls == 0 && g_key_calls == 0);
    assert(g_m2_calls == 0 && g_mgmt_calls == 0 && f.ic.scan_requests == 0);
    assert(f.ic.ic_stats.is_rx_eapol_badmic == 1);
    assert(f.ni.ni_replaycnt == 5);
    printf("mic:%u,%u,%u,%u,%u,%llu\n", g_mic_calls, g_key_calls,
        g_m2_calls, g_mgmt_calls, f.ic.scan_requests,
        (unsigned long long)f.ni.ni_replaycnt);
}

static void test_same_key_skip(void)
{
    reset_globals();
    struct fixture f; init_fixture(&f);
    struct ieee80211_key *slot = &f.ic.ic_nw_keys[g_expected_kid];
    slot->k_cipher = IEEE80211_CIPHER_CCMP_VALUE;
    slot->k_len = sizeof(g_expected_key);
    memcpy(slot->k_key, g_expected_key, sizeof(g_expected_key));
    struct ieee80211_eapol_key *key = init_rsn_group1(&f, 6, 1, 1);
    ieee80211_recv_rsn_group_msg1(&f.ic, key, &f.ni);
    assert(g_key_calls == 0 && g_m2_calls == 1);
    assert(g_mgmt_calls == 0 && f.ic.scan_requests == 0);
    assert(f.ni.ni_replaycnt == 6 && f.ni.ni_port_valid == 1);
#ifdef AIRPORT_TAHOE
    struct IwxStaAuthTraceSnapshot snapshot;
    assert(iwx_sta_auth_trace_snapshot(&f.ic.ic_tahoe_auth_trace, &snapshot));
    int saw_skip = 0;
    for (uint32_t i = 0; i < snapshot.live_count; ++i)
        saw_skip |= snapshot.live[i].kind == IWX_STA_TRACE_KEY_COMPONENT &&
            (snapshot.live[i].flags & IWX_STA_FLAG_COMPONENT_SKIPPED) != 0;
    assert(saw_skip);
    assert(!bytes_contain(&snapshot, sizeof(snapshot), g_expected_key,
                          sizeof(g_expected_key)));
#endif
    printf("same-key:%u,%u,%u,%llu\n", g_key_calls, g_m2_calls,
        f.ic.scan_requests, (unsigned long long)f.ni.ni_replaycnt);
}

static void test_callback_result(int callback_result, int expected_m2,
    int expected_mgmt, int expected_scan, const char *label)
{
    reset_globals();
    struct fixture f; init_fixture(&f);
    g_key_result = callback_result;
    g_mgmt_result = EIO;
    g_m2_result = ENOBUFS;
    struct ieee80211_eapol_key *key = init_rsn_group1(&f, 6, 1, 1);
    ieee80211_recv_rsn_group_msg1(&f.ic, key, &f.ni);
    assert(g_key_calls == 1);
    assert(g_m2_calls == (unsigned)expected_m2);
    assert(g_mgmt_calls == (unsigned)expected_mgmt);
    assert(f.ic.scan_requests == (unsigned)expected_scan);
    if (callback_result == EAGAIN) {
        assert(f.ni.ni_replaycnt == 5);
        assert(f.ni.ni_port_valid == 0);
    } else {
        assert(f.ni.ni_replaycnt == 6);
        assert(f.ni.ni_port_valid == 1);
    }
#ifdef AIRPORT_TAHOE
    struct IwxStaAuthTraceSnapshot snapshot;
    assert(iwx_sta_auth_trace_snapshot(&f.ic.ic_tahoe_auth_trace, &snapshot));
    assert(!bytes_contain(&snapshot, sizeof(snapshot), g_expected_key,
                          sizeof(g_expected_key)));
    if (callback_result == EAGAIN) {
        assert(snapshot.first_state == 2u && snapshot.first_count != 0u);
        int saw_pre_ring_failure = 0;
        for (uint32_t i = 0; i < snapshot.live_count; ++i)
            saw_pre_ring_failure |=
                snapshot.live[i].kind == IWX_STA_TRACE_KEY_SUBMIT &&
                (snapshot.live[i].flags &
                    IWX_STA_FLAG_SUBMIT_REJECTED_BEFORE_RING) != 0;
        assert(saw_pre_ring_failure);
    }
#endif
    printf("%s:%u,%u,%u,%u,%llu\n", label, g_key_calls, g_m2_calls,
        g_mgmt_calls, f.ic.scan_requests,
        (unsigned long long)f.ni.ni_replaycnt);
}

static void test_group2_failure_ignored(void)
{
    reset_globals();
    struct fixture f; init_fixture(&f);
    g_key_result = 0;
    g_m2_result = ENOBUFS;
    struct ieee80211_eapol_key *key = init_rsn_group1(&f, 6, 1, 1);
    ieee80211_recv_rsn_group_msg1(&f.ic, key, &f.ni);
    assert(g_key_calls == 1 && g_m2_calls == 1);
    assert(g_mgmt_calls == 0 && f.ic.scan_requests == 0);
    assert(f.ni.ni_replaycnt == 6);
#ifdef AIRPORT_TAHOE
    struct IwxStaAuthTraceSnapshot snapshot;
    assert(iwx_sta_auth_trace_snapshot(&f.ic.ic_tahoe_auth_trace, &snapshot));
    int saw_m2_error = 0;
    for (uint32_t i = 0; i < snapshot.live_count; ++i)
        saw_m2_error |= snapshot.live[i].kind == IWX_STA_TRACE_GROUP2_RESULT &&
            snapshot.live[i].result == ENOBUFS;
    assert(saw_m2_error && snapshot.first_state == 2u);
    assert(!bytes_contain(&snapshot, sizeof(snapshot), g_expected_key,
                          sizeof(g_expected_key)));
#endif
    printf("m2-failure:%u,%u,%u,%llu\n", g_key_calls, g_m2_calls,
        f.ic.scan_requests, (unsigned long long)f.ni.ni_replaycnt);
}

static void test_wpa_group1_callback_eagain(void)
{
    reset_globals();
    struct fixture f; init_fixture(&f);
    g_key_result = EAGAIN;
    struct ieee80211_eapol_key *key = init_wpa_group1(&f, 6);
    ieee80211_recv_wpa_group_msg1(&f.ic, key, &f.ni);
    assert(g_key_calls == 1 && g_m2_calls == 0);
    assert(g_mgmt_calls == 1 && f.ic.scan_requests == 1);
    assert(f.ni.ni_replaycnt == 5);
#ifdef AIRPORT_TAHOE
    struct IwxStaAuthTraceSnapshot snapshot;
    assert(iwx_sta_auth_trace_snapshot(&f.ic.ic_tahoe_auth_trace, &snapshot));
    assert(snapshot.first_state == 2u &&
        !bytes_contain(&snapshot, sizeof(snapshot), g_expected_key,
                       sizeof(g_expected_key)));
#endif
    printf("wpa-eagain:%u,%u,%u,%u,%llu\n", g_key_calls, g_m2_calls,
        g_mgmt_calls, f.ic.scan_requests,
        (unsigned long long)f.ni.ni_replaycnt);
}

int main(void)
{
    test_replay_early_return();
    test_mic_early_return();
    test_same_key_skip();
    test_callback_result(0, 1, 0, 0, "callback-zero");
    test_callback_result(EBUSY, 1, 0, 0, "callback-ebusy");
    test_callback_result(EAGAIN, 0, 1, 1, "callback-eagain");
    test_group2_failure_ignored();
    test_wpa_group1_callback_eagain();
    return 0;
}
'''


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    must_update = extract_function(
        source,
        "int\nieee80211_must_update_group_key(struct ieee80211_key *k",
    )
    rsn_group1 = extract_function(
        source, "void\nieee80211_recv_rsn_group_msg1(struct ieee80211com *ic"
    )
    wpa_group1 = extract_function(
        source, "void\nieee80211_recv_wpa_group_msg1(struct ieee80211com *ic"
    )
    helpers = "\n".join(
        extract_function(source, marker)
        for marker in (
            "static uint64_t ieee80211_tahoe_trace_time_us(void)",
            "static void ieee80211_tahoe_trace_group(struct ieee80211com *ic",
            "static int ieee80211_tahoe_install_group_key(struct ieee80211com *ic",
        )
    )
    generated = (
        HARNESS_PREFIX
        + "\n"
        + must_update
        + "\n#ifdef AIRPORT_TAHOE\n"
        + helpers
        + "\n#endif\n"
        + rsn_group1
        + "\n"
        + wpa_group1
        + "\n"
        + HARNESS_SUFFIX
    )

    with tempfile.TemporaryDirectory(prefix="iwx-group1-host-") as temp:
        temp_path = Path(temp)
        harness_path = temp_path / "group1_host.c"
        harness_path.write_text(generated, encoding="utf-8")
        outputs = []
        for name, tahoe in (("legacy", False), ("tahoe", True)):
            binary = temp_path / name
            command = [
                "clang",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Wno-sign-compare",
                "-Werror",
                "-I",
                str(ROOT),
            ]
            if tahoe:
                command.append("-DAIRPORT_TAHOE=1")
            command.extend([str(harness_path), "-o", str(binary)])
            try:
                subprocess.run(command, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as error:
                raise AssertionError(
                    f"{name} Group1 host compile failed:\n{error.stderr}"
                ) from error
            result = subprocess.run(
                [str(binary)], check=True, capture_output=True, text=True
            )
            outputs.append(result.stdout)

        if outputs[0] != outputs[1]:
            raise AssertionError(
                "instrumented Group1 behavior differs from the legacy path:\n"
                f"legacy:\n{outputs[0]}\nTahoe:\n{outputs[1]}"
            )
        print("PASS: RSN/WPA Group1 legacy behavior matches Tahoe trace build")
        print(outputs[1], end="")


if __name__ == "__main__":
    main()
