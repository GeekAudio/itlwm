#!/usr/bin/env python3
"""Compile and exercise production STA_ONLY SA Query function bodies."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / "itl80211/openbsd/net80211/ieee80211_input.c"
PROTO = ROOT / "itl80211/openbsd/net80211/ieee80211_proto.c"
NODE = ROOT / "itl80211/openbsd/net80211/ieee80211_node.c"
CRYPTO = ROOT / "itl80211/openbsd/net80211/ieee80211_crypto.c"


def production_function(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    index = opening
    while index < len(source):
        ch = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line"
                index += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block"
                index += 2
                continue
            if ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[start : index + 1]
        elif state == "line":
            if ch == "\n":
                state = "code"
        elif state == "block":
            if ch == "*" and nxt == "/":
                state = "code"
                index += 2
                continue
        elif state in ("string", "char"):
            if ch == "\\":
                index += 2
                continue
            if (state == "string" and ch == '"') or (
                state == "char" and ch == "'"
            ):
                state = "code"
        index += 1
    raise AssertionError(f"unterminated production function: {marker}")


def production_function_after(source: str, anchor: str, marker: str) -> str:
    offset = source.index(anchor)
    return production_function(source[offset:], marker)


PREAMBLE = r"""
#define IEEE80211_STA_ONLY 1
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" void free(void *);

using u_int8_t = uint8_t;
using u_int16_t = uint16_t;
using u_int32_t = uint32_t;
using u_int = unsigned int;

constexpr int IEEE80211_M_STA = 1;
constexpr int IEEE80211_S_AUTH = 2;
constexpr int IEEE80211_S_INIT = 0;
constexpr int IEEE80211_S_RUN = 4;
constexpr int LINK_STATE_DOWN = 0;
constexpr int IEEE80211_C_MFP = 0x01;
constexpr int IEEE80211_F_RSNON = 0x02;
constexpr int IEEE80211_FC0_SUBTYPE_ACTION = 0xd0;
constexpr int IEEE80211_FC0_SUBTYPE_DEAUTH = 0xc0;
constexpr int IEEE80211_FC0_SUBTYPE_DISASSOC = 0xa0;
constexpr int IEEE80211_FC1_PROTECTED = 0x40;
constexpr int IEEE80211_CATEG_SA_QUERY = 8;
constexpr int IEEE80211_ACTION_SA_QUERY_REQ = 0;
constexpr int IEEE80211_ACTION_SA_QUERY_RESP = 1;
constexpr int IEEE80211_REASON_NOT_AUTHED = 6;
constexpr int IEEE80211_REASON_NOT_ASSOCED = 7;
constexpr int IEEE80211_REASON_AUTH_EXPIRE = 2;
constexpr uint32_t IEEE80211_NODE_RXMGMTPROT = 0x0020;
constexpr uint32_t IEEE80211_NODE_TXMGMTPROT = 0x0040;
constexpr uint32_t IEEE80211_NODE_MFP = 0x0080;
constexpr uint32_t IEEE80211_NODE_SA_QUERY = 0x0800;
constexpr uint32_t IEEE80211_NODE_SA_QUERY_FAILED = 0x1000;
constexpr uint32_t IEEE80211_NODE_TXRXPROT = 0x2000;
constexpr unsigned IEEE80211_ADDR_LEN = 6;
constexpr int IEEE80211_SA_QUERY_STA_MAX_ATTEMPTS = 5;
constexpr int IEEE80211_SA_QUERY_STA_RETRY_MS = 204;
constexpr int IEEE80211_GROUP_NKID = 6;
constexpr int RSNA_SUPP_INITIALIZE = 0;

enum ieee80211_cipher {
    IEEE80211_CIPHER_NONE = 0,
    IEEE80211_CIPHER_CCMP = 1,
    IEEE80211_CIPHER_BIP = 2,
};

#define DPRINTF(...) ((void)0)
#define IEEE80211_ADDR_EQ(a, b) (std::memcmp((a), (b), IEEE80211_ADDR_LEN) == 0)
#define IEEE80211_IS_MULTICAST(a) (((a)[0] & 1) != 0)
#define mtod(m, t) reinterpret_cast<t>((m)->bytes)
#define LE_READ_2(p) ((uint16_t)((const uint8_t *)(p))[0] | ((uint16_t)((const uint8_t *)(p))[1] << 8))
#define IEEE80211_SEND_ACTION(ic, ni, category, action, arg) \
    test_send_action((ic), (ni), IEEE80211_FC0_SUBTYPE_ACTION, \
        ((category) << 16) | (action), (arg))

struct CTimeout { bool pending = false; int delay_ms = 0; int serial = 0; };
struct ieee80211com;
struct ieee80211_node;
struct ieee80211_key {
    ieee80211_cipher k_cipher = IEEE80211_CIPHER_NONE;
    uint8_t k_key[32]{};
    unsigned k_len = 0;
    unsigned k_id = 0;
    uint32_t k_flags = 0;
};
struct timeval { long tv_sec = 0; long tv_usec = 0; };
#define timersub(a, b, result) do { \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
    if ((result)->tv_usec < 0) { \
        --(result)->tv_sec; \
        (result)->tv_usec += 1000000; \
    } \
} while (0)
struct ieee80211_node {
    ieee80211com *ni_ic = nullptr;
    uint32_t ni_flags = 0;
    int ni_port_valid = 0;
    int ni_pmf_link_pending = 0;
    uint32_t ni_pmf_key_epoch = 0;
    uint8_t ni_pmf_key_batch_ready = 0;
    uint8_t ni_pmf_pending_key_ids = 0;
    uint8_t ni_replaycnt_ok = 0;
    int ni_rsn_supp_state = 0;
    uint8_t ni_macaddr[6]{};
    uint8_t ni_bssid[6]{};
    uint8_t *ni_rsnie = nullptr;
    uint8_t *ni_rsnie_tlv = nullptr;
    uint32_t ni_rsnie_tlv_len = 0;
    ieee80211_key ni_pairwise_key{};
    uint8_t ni_ptk[64]{};
    void (*ni_unref_cb)(ieee80211com *, ieee80211_node *) = nullptr;
    void *ni_unref_arg = nullptr;
    size_t ni_unref_arg_size = 0;
    CTimeout *ni_eapol_to = nullptr;
    uint16_t ni_sa_query_trid = 0;
    CTimeout *ni_sa_query_to = nullptr;
    int ni_sa_query_count = 0;
    uint16_t ni_sa_query_trids[IEEE80211_SA_QUERY_STA_MAX_ATTEMPTS]{};
    uint8_t ni_sa_query_bssid[6]{};
    uint8_t ni_sa_query_local[6]{};
    timeval ni_sa_query_last_unprot{};
};
struct ieee80211com {
    int ic_opmode = IEEE80211_M_STA;
    int ic_state = IEEE80211_S_RUN;
    int ic_caps = IEEE80211_C_MFP;
    int ic_flags = IEEE80211_F_RSNON;
    int ic_deauth_reason = 0;
    int ic_def_txkey = 0;
    int ic_igtk_kid = 0;
    uint8_t ic_myaddr[6]{};
    ieee80211_node *ic_bss = nullptr;
    ieee80211_key ic_nw_keys[IEEE80211_GROUP_NKID]{};
    void (*ic_delete_key)(ieee80211com *, ieee80211_node *, ieee80211_key *) = nullptr;
    void (*ic_pmf_cancel_keys)(ieee80211com *, ieee80211_node *) = nullptr;
};
struct __attribute__((packed)) ieee80211_frame {
    uint8_t i_fc[2];
    uint8_t i_dur[2];
    uint8_t i_addr1[6];
    uint8_t i_addr2[6];
    uint8_t i_addr3[6];
    uint8_t i_seq[2];
};
static_assert(sizeof(ieee80211_frame) == 24, "802.11 mgmt header size");
struct mbuf { uint8_t bytes[64]{}; int len = 0; };
using mbuf_t = mbuf *;
static int mbuf_len(mbuf *m) { return m->len; }
[[maybe_unused]] static const char *ether_sprintf(const uint8_t *) { return "peer"; }
static int gActionCount = 0;
static int gLastActionCode = 0;
static uint16_t gLastActionTrid = 0;
static int gTimerScheduleCount = 0;
static int gTimerScheduleResult = 1;
static int gNextTimerSerial = 1;
static int gTimerFreeCount = 0;
static int gLastFreedTimerSerial = 0;
static int gNewStateCount = 0;
static int gNewStateResult = 0;
static int gLinkState = -1;
static bool gPortClosedBeforeState = false;
static int gRandomValue = 0x1200;
static long gNowSec = 100;
static long gNowUsec = 0;
static int gSecurityEvent = 0;
static int gPmfCancelEvent = 0;
static int gKeyDeleteEvent = 0;
static int gPmfCancelCount = 0;
static int gKeyDeleteCount = 0;
static uint8_t gPmfCancelledBssid[IEEE80211_ADDR_LEN]{};
static bool gLeaveFramesQueued = false;
static bool gPmfCancelSawLinkDown = false;
static bool gPmfCancelSawLeaveQueued = false;
static bool gPmfCancelSawQueryCleared = false;

static void test_delete_key(ieee80211com *, ieee80211_node *, ieee80211_key *);
static void test_pmf_cancel_keys(ieee80211com *, ieee80211_node *);

static void test_explicit_bzero(void *ptr, size_t len) {
    std::memset(ptr, 0, len);
}
#define explicit_bzero test_explicit_bzero

static void timeout_free(CTimeout **to) {
    if (*to == nullptr)
        return;
    assert(!(*to)->pending && "timer must be cancelled before it is freed");
    gLastFreedTimerSerial = (*to)->serial;
    ++gTimerFreeCount;
    delete *to;
    *to = nullptr;
}
static void ieee80211_crypto_clear_groupkeys(ieee80211com *);
static void ieee80211_pmf_keys_cancel(ieee80211com *, ieee80211_node *);
static void ieee80211_sta_security_cleanup(ieee80211com *, ieee80211_node *);
static void ieee80211_node_cleanup(ieee80211com *, ieee80211_node *);
static void ieee80211_node_set_timeouts(ieee80211_node *ni) {
    if (ni->ni_sa_query_to == nullptr) {
        ni->ni_sa_query_to = new CTimeout;
        ni->ni_sa_query_to->serial = gNextTimerSerial++;
    }
}
static void ieee80211_ba_del(ieee80211_node *) {}
static void ieee80211_ba_free(ieee80211_node *) {}
static void ieee80211_save_ie(const uint8_t *, uint8_t **) {}
static void ieee80211_save_ie_tlv(const uint8_t *, uint8_t **, uint32_t *,
                                  uint32_t) {}
static void test_delete_key(ieee80211com *, ieee80211_node *, ieee80211_key *) {
    ++gKeyDeleteCount;
    gKeyDeleteEvent = ++gSecurityEvent;
}
static void test_pmf_cancel_keys(ieee80211com *, ieee80211_node *ni) {
    ++gPmfCancelCount;
    gPmfCancelEvent = ++gSecurityEvent;
    std::memcpy(gPmfCancelledBssid, ni->ni_bssid, sizeof(gPmfCancelledBssid));
    gPmfCancelSawLinkDown = gLinkState == LINK_STATE_DOWN;
    gPmfCancelSawLeaveQueued = gLeaveFramesQueued;
    gPmfCancelSawQueryCleared =
        (ni->ni_flags & (IEEE80211_NODE_SA_QUERY |
            IEEE80211_NODE_SA_QUERY_FAILED)) == 0 &&
        ni->ni_sa_query_count == 0 && ni->ni_sa_query_trid == 0;
}
static int test_send_action(ieee80211com *, ieee80211_node *ni, int subtype,
                            int actionCode, int) {
    assert(subtype == IEEE80211_FC0_SUBTYPE_ACTION);
    ++gActionCount;
    gLastActionCode = actionCode;
    gLastActionTrid = ni->ni_sa_query_trid;
    return 0;
}
static void arc4random_buf(void *ptr, size_t len) {
    auto *bytes = static_cast<uint8_t *>(ptr);
    for (size_t i = 0; i < len; ++i)
        bytes[i] = static_cast<uint8_t>(gRandomValue >> (i * 8));
    ++gRandomValue;
}
static int timeout_add_msec(CTimeout **to, int ms) {
    ++gTimerScheduleCount;
    if (!gTimerScheduleResult)
        return 0;
    if (*to == nullptr) {
        *to = new CTimeout;
        (*to)->serial = gNextTimerSerial++;
    }
    (*to)->delay_ms = ms;
    (*to)->pending = true;
    return 1;
}
static int timeout_del(CTimeout **to) {
    if (*to != nullptr)
        (*to)->pending = false;
    return 1;
}
static int splnet() { return 1; }
static void splx(int) {}
static void microuptime(timeval *tv) {
    tv->tv_sec = gNowSec;
    tv->tv_usec = gNowUsec;
}
static void ieee80211_set_link_state(ieee80211com *ic, int state) {
    (void)ic;
    gLinkState = state;
}
static int ieee80211_new_state(ieee80211com *ic, int state, int) {
    ++gNewStateCount;
    if (state == IEEE80211_S_AUTH)
        gPortClosedBeforeState = ic->ic_bss->ni_port_valid == 0 &&
            gLinkState == LINK_STATE_DOWN;
    if (gNewStateResult == 0)
        ic->ic_state = state;
    return gNewStateResult;
}

int ieee80211_sa_query_sta_authorized(ieee80211com *, ieee80211_node *);
void ieee80211_sa_query_timeout(void *);
void ieee80211_sa_query_request(ieee80211com *, ieee80211_node *);
static int ieee80211_sa_query_sta_send(ieee80211com *, ieee80211_node *);
static void ieee80211_sa_query_sta_clear(ieee80211_node *);
void ieee80211_recv_sa_query_req(ieee80211com *, mbuf *, ieee80211_node *);
void ieee80211_recv_sa_query_resp(ieee80211com *, mbuf *, ieee80211_node *);
static int ieee80211_sta_sa_query_unprotected_disconnect(ieee80211com *,
    ieee80211_node *, const ieee80211_frame *, mbuf *, int);

static void setup(ieee80211com &ic, ieee80211_node &ni) {
    std::memset(&ic, 0, sizeof(ic));
    std::memset(&ni, 0, sizeof(ni));
    ic.ic_opmode = IEEE80211_M_STA;
    ic.ic_state = IEEE80211_S_RUN;
    ic.ic_caps = IEEE80211_C_MFP;
    ic.ic_flags = IEEE80211_F_RSNON;
    ic.ic_delete_key = test_delete_key;
    ic.ic_pmf_cancel_keys = test_pmf_cancel_keys;
    const uint8_t local[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t ap[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    std::memcpy(ic.ic_myaddr, local, sizeof(local));
    std::memcpy(ni.ni_bssid, ap, sizeof(ap));
    ni.ni_ic = &ic;
    ni.ni_flags = IEEE80211_NODE_MFP | IEEE80211_NODE_RXMGMTPROT |
        IEEE80211_NODE_TXMGMTPROT;
    ni.ni_port_valid = 1;
    ni.ni_pmf_link_pending = 0;
    ic.ic_bss = &ni;
    gActionCount = 0;
    gLastActionCode = 0;
    gLastActionTrid = 0;
    gTimerScheduleCount = 0;
    gTimerScheduleResult = 1;
    gNextTimerSerial = 1;
    gTimerFreeCount = 0;
    gLastFreedTimerSerial = 0;
    gNewStateCount = 0;
    gNewStateResult = 0;
    gLinkState = -1;
    gPortClosedBeforeState = false;
    gRandomValue = 0x1200;
    gNowSec = 100;
    gNowUsec = 0;
    gSecurityEvent = 0;
    gPmfCancelEvent = 0;
    gKeyDeleteEvent = 0;
    gPmfCancelCount = 0;
    gKeyDeleteCount = 0;
    std::memset(gPmfCancelledBssid, 0, sizeof(gPmfCancelledBssid));
    gLeaveFramesQueued = false;
    gPmfCancelSawLinkDown = false;
    gPmfCancelSawLeaveQueued = false;
    gPmfCancelSawQueryCleared = false;
}
static mbuf make_disconnect(const ieee80211com &ic,
                            const ieee80211_node &ni, uint16_t reason,
                            int subtype = IEEE80211_FC0_SUBTYPE_DEAUTH,
                            bool protect = false) {
    mbuf m{};
    auto *wh = reinterpret_cast<ieee80211_frame *>(m.bytes);
    wh->i_fc[0] = static_cast<uint8_t>(subtype);
    wh->i_fc[1] = protect ? IEEE80211_FC1_PROTECTED : 0;
    std::memcpy(wh->i_addr1, ic.ic_myaddr, 6);
    std::memcpy(wh->i_addr2, ni.ni_bssid, 6);
    std::memcpy(wh->i_addr3, ni.ni_bssid, 6);
    m.len = sizeof(*wh) + 2;
    m.bytes[sizeof(*wh)] = static_cast<uint8_t>(reason);
    m.bytes[sizeof(*wh) + 1] = static_cast<uint8_t>(reason >> 8);
    return m;
}
static mbuf make_action(const ieee80211com &ic, const ieee80211_node &ni,
                        uint16_t trid, bool response = true) {
    mbuf m{};
    auto *wh = reinterpret_cast<ieee80211_frame *>(m.bytes);
    wh->i_fc[0] = IEEE80211_FC0_SUBTYPE_ACTION;
    wh->i_fc[1] = IEEE80211_FC1_PROTECTED;
    std::memcpy(wh->i_addr1, ic.ic_myaddr, 6);
    std::memcpy(wh->i_addr2, ni.ni_bssid, 6);
    std::memcpy(wh->i_addr3, ni.ni_bssid, 6);
    m.len = sizeof(*wh) + 4;
    m.bytes[sizeof(*wh)] = IEEE80211_CATEG_SA_QUERY;
    m.bytes[sizeof(*wh) + 1] = response ? IEEE80211_ACTION_SA_QUERY_RESP :
        IEEE80211_ACTION_SA_QUERY_REQ;
    m.bytes[sizeof(*wh) + 2] = static_cast<uint8_t>(trid);
    m.bytes[sizeof(*wh) + 3] = static_cast<uint8_t>(trid >> 8);
    return m;
}
"""


SUFFIX = r"""
static void run_trigger_tests() {
    ieee80211com ic{};
    ieee80211_node ni{};
    setup(ic, ni);
    auto m6 = make_disconnect(ic, ni, IEEE80211_REASON_NOT_AUTHED);
    assert(ieee80211_sta_sa_query_unprotected_disconnect(&ic, &ni,
        reinterpret_cast<ieee80211_frame *>(m6.bytes), &m6,
        IEEE80211_FC0_SUBTYPE_DEAUTH) == 1);
    assert((ni.ni_flags & IEEE80211_NODE_SA_QUERY) != 0);
    assert(ni.ni_sa_query_count == 1 && gActionCount == 1);
    assert(gLastActionCode == ((IEEE80211_CATEG_SA_QUERY << 16) |
        IEEE80211_ACTION_SA_QUERY_REQ));
    assert(gLastActionTrid == ni.ni_sa_query_trids[0]);
    assert(ni.ni_sa_query_to->pending && ni.ni_sa_query_to->delay_ms == 204);
    assert(ic.ic_state == IEEE80211_S_RUN && gNewStateCount == 0);

    const int originalSchedules = gTimerScheduleCount;
    gNowSec = 109; /* An active query must not extend the 10-second throttle. */
    auto duplicate = make_disconnect(ic, ni, IEEE80211_REASON_NOT_ASSOCED,
        IEEE80211_FC0_SUBTYPE_DISASSOC);
    assert(ieee80211_sta_sa_query_unprotected_disconnect(&ic, &ni,
        reinterpret_cast<ieee80211_frame *>(duplicate.bytes), &duplicate,
        IEEE80211_FC0_SUBTYPE_DISASSOC) == 1);
    assert(ni.ni_sa_query_count == 1 && gActionCount == 1);
    assert(gTimerScheduleCount == originalSchedules);

    setup(ic, ni);
    auto m7 = make_disconnect(ic, ni, IEEE80211_REASON_NOT_ASSOCED,
        IEEE80211_FC0_SUBTYPE_DISASSOC);
    assert(ieee80211_sta_sa_query_unprotected_disconnect(&ic, &ni,
        reinterpret_cast<ieee80211_frame *>(m7.bytes), &m7,
        IEEE80211_FC0_SUBTYPE_DISASSOC) == 1);
    assert((ni.ni_flags & IEEE80211_NODE_SA_QUERY) != 0);

    setup(ic, ni);
    auto otherReason = make_disconnect(ic, ni, 8);
    assert(ieee80211_sta_sa_query_unprotected_disconnect(&ic, &ni,
        reinterpret_cast<ieee80211_frame *>(otherReason.bytes), &otherReason,
        IEEE80211_FC0_SUBTYPE_DEAUTH) == 1);
    assert(gActionCount == 0 && (ni.ni_flags & IEEE80211_NODE_SA_QUERY) == 0);

    setup(ic, ni);
    auto protectedFrame = make_disconnect(ic, ni, 6,
        IEEE80211_FC0_SUBTYPE_DEAUTH, true);
    assert(ieee80211_sta_sa_query_unprotected_disconnect(&ic, &ni,
        reinterpret_cast<ieee80211_frame *>(protectedFrame.bytes),
        &protectedFrame, IEEE80211_FC0_SUBTYPE_DEAUTH) == 0);
    assert(gActionCount == 0);

    setup(ic, ni);
    ni.ni_port_valid = 0;
    auto unauthorized = make_disconnect(ic, ni, 6);
    assert(ieee80211_sta_sa_query_unprotected_disconnect(&ic, &ni,
        reinterpret_cast<ieee80211_frame *>(unauthorized.bytes), &unauthorized,
        IEEE80211_FC0_SUBTYPE_DEAUTH) == 0);
    assert(gActionCount == 0);

    setup(ic, ni);
    auto foreign = make_disconnect(ic, ni, 6);
    auto *foreignWh = reinterpret_cast<ieee80211_frame *>(foreign.bytes);
    foreignWh->i_addr2[5] ^= 1;
    foreignWh->i_addr3[5] ^= 1;
    assert(ieee80211_sta_sa_query_unprotected_disconnect(&ic, &ni,
        foreignWh, &foreign, IEEE80211_FC0_SUBTYPE_DEAUTH) == 1);
    assert(gActionCount == 0 && ic.ic_state == IEEE80211_S_RUN);
}

static void run_response_tests() {
    ieee80211com ic{};
    ieee80211_node ni{};
    setup(ic, ni);
    ieee80211_sa_query_request(&ic, &ni);
    const uint16_t first = ni.ni_sa_query_trids[0];
    ni.ni_sa_query_to->pending = false;
    ieee80211_sa_query_timeout(&ni);
    assert(ni.ni_sa_query_count == 2 && gActionCount == 2);

    auto badId = make_action(ic, ni, static_cast<uint16_t>(first + 0x4000));
    ieee80211_recv_sa_query_resp(&ic, &badId, &ni);
    assert((ni.ni_flags & IEEE80211_NODE_SA_QUERY) != 0);
    assert(ni.ni_sa_query_to->pending);

    auto wrongSource = make_action(ic, ni, first);
    auto *wrongSourceWh = reinterpret_cast<ieee80211_frame *>(wrongSource.bytes);
    wrongSourceWh->i_addr2[5] ^= 1;
    ieee80211_recv_sa_query_resp(&ic, &wrongSource, &ni);
    assert((ni.ni_flags & IEEE80211_NODE_SA_QUERY) != 0);

    auto wrongLocal = make_action(ic, ni, first);
    auto *wrongLocalWh = reinterpret_cast<ieee80211_frame *>(wrongLocal.bytes);
    wrongLocalWh->i_addr1[5] ^= 1;
    ieee80211_recv_sa_query_resp(&ic, &wrongLocal, &ni);
    assert((ni.ni_flags & IEEE80211_NODE_SA_QUERY) != 0);

    /* A late response to the first request remains valid after retry two. */
    auto valid = make_action(ic, ni, first);
    ieee80211_recv_sa_query_resp(&ic, &valid, &ni);
    assert((ni.ni_flags & IEEE80211_NODE_SA_QUERY) == 0);
    assert(ni.ni_sa_query_count == 0 && !ni.ni_sa_query_to->pending);
    assert(ic.ic_state == IEEE80211_S_RUN && gNewStateCount == 0);
    for (uint8_t byte : ni.ni_sa_query_bssid) assert(byte == 0);

    ieee80211_recv_sa_query_resp(&ic, &valid, &ni);
    assert(gNewStateCount == 0 && ic.ic_state == IEEE80211_S_RUN);

    auto unprotected = make_disconnect(ic, ni, IEEE80211_REASON_NOT_AUTHED);
    const int actionsBeforeRateLimit = gActionCount;
    assert(ieee80211_sta_sa_query_unprotected_disconnect(&ic, &ni,
        reinterpret_cast<ieee80211_frame *>(unprotected.bytes), &unprotected,
        IEEE80211_FC0_SUBTYPE_DEAUTH) == 1);
    assert(gActionCount == actionsBeforeRateLimit + 1);
    auto completeSecondQuery = make_action(ic, ni, ni.ni_sa_query_trids[0]);
    ieee80211_recv_sa_query_resp(&ic, &completeSecondQuery, &ni);
    gNowSec = 101;
    assert(ieee80211_sta_sa_query_unprotected_disconnect(&ic, &ni,
        reinterpret_cast<ieee80211_frame *>(unprotected.bytes), &unprotected,
        IEEE80211_FC0_SUBTYPE_DEAUTH) == 1);
    assert(gActionCount == actionsBeforeRateLimit + 1);
    gNowSec = 110;
    assert(ieee80211_sta_sa_query_unprotected_disconnect(&ic, &ni,
        reinterpret_cast<ieee80211_frame *>(unprotected.bytes), &unprotected,
        IEEE80211_FC0_SUBTYPE_DEAUTH) == 1);
    assert(gActionCount == actionsBeforeRateLimit + 2);
}

static void run_request_response_tests() {
    ieee80211com ic{};
    ieee80211_node ni{};
    setup(ic, ni);
    ni.ni_sa_query_trid = 0x55aa;
    auto request = make_action(ic, ni, 0xabcd, false);
    ieee80211_recv_sa_query_req(&ic, &request, &ni);
    assert(gActionCount == 1);
    assert(gLastActionCode == ((IEEE80211_CATEG_SA_QUERY << 16) |
        IEEE80211_ACTION_SA_QUERY_RESP));
    assert(gLastActionTrid == 0xabcd);
    assert(ni.ni_sa_query_trid == 0x55aa);

    setup(ic, ni);
    auto invalid = make_action(ic, ni, 0xabcd, false);
    reinterpret_cast<ieee80211_frame *>(invalid.bytes)->i_addr2[5] ^= 1;
    ieee80211_recv_sa_query_req(&ic, &invalid, &ni);
    assert(gActionCount == 0);
}

static void run_timeout_tests() {
    ieee80211com ic{};
    ieee80211_node ni{};
    setup(ic, ni);
    ieee80211_sa_query_request(&ic, &ni);
    for (int retry = 0; retry < 4; ++retry) {
        ni.ni_sa_query_to->pending = false;
        ieee80211_sa_query_timeout(&ni);
        assert((ni.ni_flags & IEEE80211_NODE_SA_QUERY) != 0);
    }
    assert(ni.ni_sa_query_count == IEEE80211_SA_QUERY_STA_MAX_ATTEMPTS);
    assert(gActionCount == IEEE80211_SA_QUERY_STA_MAX_ATTEMPTS);
    ni.ni_sa_query_to->pending = false;
    ieee80211_sa_query_timeout(&ni);
    assert((ni.ni_flags & IEEE80211_NODE_SA_QUERY) == 0);
    assert(ni.ni_sa_query_count == 0 && gActionCount == 5);
    assert(ic.ic_state == IEEE80211_S_AUTH);
    assert(ic.ic_deauth_reason == IEEE80211_REASON_AUTH_EXPIRE);
    assert(gNewStateCount == 1);
    assert(ni.ni_port_valid == 0 && gLinkState == LINK_STATE_DOWN);
    assert(gPortClosedBeforeState);

    setup(ic, ni);
    ieee80211_sa_query_request(&ic, &ni);
    std::memset(ic.ic_myaddr, 0x77, sizeof(ic.ic_myaddr));
    ni.ni_sa_query_to->pending = false;
    ieee80211_sa_query_timeout(&ni);
    assert((ni.ni_flags & IEEE80211_NODE_SA_QUERY) == 0);
    assert(ic.ic_state == IEEE80211_S_RUN && gNewStateCount == 0);

    setup(ic, ni);
    gTimerScheduleResult = 0;
    ieee80211_sa_query_request(&ic, &ni);
    assert((ni.ni_flags & IEEE80211_NODE_SA_QUERY) == 0);
    assert(ic.ic_state == IEEE80211_S_AUTH && gNewStateCount == 1);
    assert(ni.ni_port_valid == 0 && gLinkState == LINK_STATE_DOWN);

    setup(ic, ni);
    gNewStateResult = 16; /* Simulate a busy async newstate queue. */
    ieee80211_sa_query_request(&ic, &ni);
    for (int retry = 0; retry < 5; ++retry) {
        ni.ni_sa_query_to->pending = false;
        ieee80211_sa_query_timeout(&ni);
    }
    assert(gNewStateCount == 1);
    assert(ic.ic_state == IEEE80211_S_RUN); /* Queue rejected AUTH. */
    assert(ni.ni_port_valid == 0 && gLinkState == LINK_STATE_DOWN);
    assert(gPortClosedBeforeState);
    assert((ni.ni_flags & (IEEE80211_NODE_RXMGMTPROT |
        IEEE80211_NODE_TXMGMTPROT)) ==
        (IEEE80211_NODE_RXMGMTPROT | IEEE80211_NODE_TXMGMTPROT));
}

static void run_node_copy_cleanup_tests() {
    ieee80211com ic{};
    ieee80211_node dst{};
    ieee80211_node src{};
    setup(ic, dst);
    const uint8_t oldBssid[IEEE80211_ADDR_LEN] =
        {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    const uint8_t newBssid[IEEE80211_ADDR_LEN] =
        {0x02, 0x10, 0x20, 0x30, 0x40, 0x50};
    std::memcpy(dst.ni_bssid, oldBssid, sizeof(oldBssid));
    dst.ni_pmf_key_epoch = 17;
    dst.ni_pmf_key_batch_ready = 1;
    dst.ni_pmf_pending_key_ids = 3;
    dst.ni_flags |= IEEE80211_NODE_SA_QUERY |
        IEEE80211_NODE_SA_QUERY_FAILED | IEEE80211_NODE_TXRXPROT;
    dst.ni_sa_query_to = new CTimeout{true, 204, gNextTimerSerial++};
    const int oldTimerSerial = dst.ni_sa_query_to->serial;
    dst.ni_sa_query_count = 3;
    dst.ni_sa_query_trid = 0x1234;
    std::memset(dst.ni_sa_query_trids, 0x11, sizeof(dst.ni_sa_query_trids));
    std::memcpy(dst.ni_sa_query_bssid, oldBssid, sizeof(oldBssid));
    std::memset(dst.ni_sa_query_local, 0x22, sizeof(dst.ni_sa_query_local));
    dst.ni_sa_query_last_unprot.tv_sec = 7;
    dst.ni_port_valid = 1;
    dst.ni_replaycnt_ok = 1;
    dst.ni_pairwise_key.k_cipher = IEEE80211_CIPHER_CCMP;
    dst.ni_pairwise_key.k_len = 16;
    std::memset(dst.ni_pairwise_key.k_key, 0xa1,
        sizeof(dst.ni_pairwise_key.k_key));
    std::memset(dst.ni_ptk, 0xb2, sizeof(dst.ni_ptk));
    ic.ic_nw_keys[0].k_cipher = IEEE80211_CIPHER_CCMP;
    ic.ic_nw_keys[0].k_len = 16;
    ic.ic_nw_keys[4].k_cipher = IEEE80211_CIPHER_BIP;
    ic.ic_nw_keys[4].k_len = 16;
    ic.ic_def_txkey = 1;
    ic.ic_igtk_kid = 5;
    ic.ic_bss = &dst;
    dst.ni_ic = &ic;
    src.ni_ic = &ic;
    std::memcpy(src.ni_bssid, newBssid, sizeof(newBssid));
    src.ni_flags = 0;
    src.ni_port_valid = 0;

    gLinkState = LINK_STATE_DOWN;
    const int timerFreesBefore = gTimerFreeCount;
    ieee80211_node_copy(&ic, &dst, &src);

    assert(gPmfCancelCount == 1);
    assert(std::memcmp(gPmfCancelledBssid, oldBssid, sizeof(oldBssid)) == 0);
    assert(gPmfCancelEvent != 0 && gKeyDeleteEvent > gPmfCancelEvent);
    assert(gPmfCancelSawLinkDown);
    assert(gPmfCancelSawQueryCleared);
    assert(gTimerFreeCount == timerFreesBefore + 1);
    assert(gLastFreedTimerSerial == oldTimerSerial);
    assert(dst.ni_sa_query_to != nullptr &&
        dst.ni_sa_query_to->serial != oldTimerSerial &&
        !dst.ni_sa_query_to->pending);
    assert(std::memcmp(dst.ni_bssid, newBssid, sizeof(newBssid)) == 0);
    assert(dst.ni_sa_query_count == 0 && dst.ni_sa_query_trid == 0);
    assert((dst.ni_flags & (IEEE80211_NODE_SA_QUERY |
        IEEE80211_NODE_SA_QUERY_FAILED)) == 0);
    for (uint8_t byte : dst.ni_sa_query_trids) assert(byte == 0);
    for (uint8_t byte : dst.ni_sa_query_bssid) assert(byte == 0);
    for (uint8_t byte : dst.ni_sa_query_local) assert(byte == 0);
    for (uint8_t byte : dst.ni_ptk) assert(byte == 0);
    for (uint8_t byte : dst.ni_pairwise_key.k_key) assert(byte == 0);
    assert(dst.ni_pairwise_key.k_cipher == IEEE80211_CIPHER_NONE);
    assert(dst.ni_replaycnt_ok == 0);
    assert(ic.ic_nw_keys[0].k_cipher == IEEE80211_CIPHER_NONE);
    assert(ic.ic_nw_keys[4].k_cipher == IEEE80211_CIPHER_NONE);
    assert(ic.ic_def_txkey == 0 && ic.ic_igtk_kid == 4);
    timeout_del(&dst.ni_sa_query_to);
    timeout_free(&dst.ni_sa_query_to);
}

static void run_newstate_security_hook_tests() {
    ieee80211com ic{};
    ieee80211_node ni{};
    setup(ic, ni);
    ni.ni_flags |= IEEE80211_NODE_SA_QUERY |
        IEEE80211_NODE_SA_QUERY_FAILED | IEEE80211_NODE_TXRXPROT;
    ni.ni_sa_query_to = new CTimeout{true, 204, gNextTimerSerial++};
    ni.ni_sa_query_count = 2;
    ni.ni_sa_query_trid = 0x2468;
    ni.ni_port_valid = 1;
    ni.ni_pmf_key_epoch = 4;
    ni.ni_pmf_key_batch_ready = 1;
    ni.ni_pmf_pending_key_ids = 3;
    ni.ni_pairwise_key.k_cipher = IEEE80211_CIPHER_CCMP;
    ic.ic_nw_keys[0].k_cipher = IEEE80211_CIPHER_CCMP;
    ic.ic_bss = &ni;

    test_production_newstate_security_hooks(&ic, IEEE80211_S_INIT,
        IEEE80211_S_RUN);

    assert(ic.ic_state == IEEE80211_S_INIT);
    assert(gPmfCancelCount == 1 && gPmfCancelSawLinkDown);
    assert(gPmfCancelSawLeaveQueued);
    assert(ni.ni_port_valid == 0);
    assert((ni.ni_flags & (IEEE80211_NODE_RXMGMTPROT |
        IEEE80211_NODE_TXMGMTPROT | IEEE80211_NODE_TXRXPROT |
        IEEE80211_NODE_SA_QUERY | IEEE80211_NODE_SA_QUERY_FAILED)) == 0);
    assert(!ni.ni_sa_query_to->pending);
    assert(ni.ni_sa_query_count == 0 && ni.ni_sa_query_trid == 0);
    assert(ni.ni_pmf_key_batch_ready == 0 &&
        ni.ni_pmf_pending_key_ids == 0);
    assert(ni.ni_pairwise_key.k_cipher == IEEE80211_CIPHER_NONE);
    assert(ic.ic_nw_keys[0].k_cipher == IEEE80211_CIPHER_NONE);
    timeout_free(&ni.ni_sa_query_to);

    setup(ic, ni);
    ni.ni_flags |= IEEE80211_NODE_SA_QUERY;
    ni.ni_sa_query_to = new CTimeout{true, 204, gNextTimerSerial++};
    test_production_newstate_security_hooks(&ic, IEEE80211_S_RUN,
        IEEE80211_S_RUN);
    assert((ni.ni_flags & IEEE80211_NODE_SA_QUERY) != 0);
    assert(ni.ni_sa_query_to->pending);
    assert(gPmfCancelCount == 0);
    timeout_del(&ni.ni_sa_query_to);
    timeout_free(&ni.ni_sa_query_to);

    setup(ic, ni);
    ni.ni_flags |= IEEE80211_NODE_SA_QUERY;
    ni.ni_sa_query_to = new CTimeout{true, 204, gNextTimerSerial++};
    test_production_newstate_security_hooks(&ic, IEEE80211_S_AUTH,
        IEEE80211_S_AUTH);
    assert((ni.ni_flags & IEEE80211_NODE_SA_QUERY) == 0);
    assert(!ni.ni_sa_query_to->pending);
    assert(gPmfCancelCount == 0);
    timeout_free(&ni.ni_sa_query_to);
}

int main() {
    run_trigger_tests();
    run_response_tests();
    run_request_response_tests();
    run_timeout_tests();
    run_node_copy_cleanup_tests();
    run_newstate_security_hook_tests();
    std::puts("PASS: production STA_ONLY SA Query, security cleanup, BSS copy, timer lifetime, and state hooks");
}
"""


def main() -> None:
    input_source = INPUT.read_text(encoding="utf-8")
    proto_source = PROTO.read_text(encoding="utf-8")
    node_source = NODE.read_text(encoding="utf-8")
    crypto_source = CRYPTO.read_text(encoding="utf-8")
    node_copy = production_function(node_source, "void\nieee80211_node_copy(")
    node_free = production_function(node_source, "void\nieee80211_node_free(")
    node_cleanup = production_function(node_source,
        "void\nieee80211_node_cleanup(")

    newstate_start = proto_source.index("int\nieee80211_newstate(")
    query_hook = "#ifdef IEEE80211_STA_ONLY\n    if (ic->ic_bss != NULL && nstate != IEEE80211_S_RUN)\n        ieee80211_sa_query_sta_clear(ic->ic_bss);\n#endif"
    query_hook_offset = proto_source.index(query_hook, newstate_start)
    state_write_offset = proto_source.index("ic->ic_state = nstate;", newstate_start)
    link_down_hook = "ieee80211_set_link_state(ic, LINK_STATE_DOWN);"
    link_down_offset = proto_source.index(link_down_hook, state_write_offset)
    state_switch_offset = proto_source.index("switch (nstate)", link_down_offset)
    security_hook = ("    if (ic->ic_opmode == IEEE80211_M_STA &&\n"
        "        ic->ic_state != IEEE80211_S_RUN &&\n"
        "        (ostate == IEEE80211_S_RUN || nstate == IEEE80211_S_INIT))\n"
        "        ieee80211_sta_security_cleanup(ic, ic->ic_bss);")
    security_hook_offset = proto_source.index(security_hook, state_switch_offset)
    state_return_offset = proto_source.index("return 0;", security_hook_offset)
    assert query_hook_offset < state_write_offset < link_down_offset
    assert state_switch_offset < security_hook_offset < state_return_offset

    state_hook_test = ("static void test_production_newstate_security_hooks(\n"
        "    ieee80211com *ic, int nstate, int ostate) {\n" + query_hook +
        "\n    ic->ic_state = nstate;\n    " + link_down_hook +
        "\n    if (nstate == IEEE80211_S_INIT && ostate == IEEE80211_S_RUN)\n"
        "        gLeaveFramesQueued = true;\n" + security_hook +
        "\n    gLeaveFramesQueued = false;\n}\n")

    call = input_source.index("ieee80211_sta_sa_query_unprotected_disconnect(ic, ni,")
    rx_gate = input_source.index("if (ni->ni_flags & IEEE80211_NODE_RXMGMTPROT)", call)
    assert call < rx_gate, "clear unprotected disconnect must be consumed before generic PMF fallback"
    assert "#ifdef IEEE80211_STA_ONLY\n            if (robust &&" in input_source
    assert "case IEEE80211_ACTION_SA_QUERY_RESP:\n                    ieee80211_recv_sa_query_resp" in input_source
    assert "timeout_set(&ni->ni_sa_query_to, ieee80211_sa_query_timeout, ni);" in node_source
    assert "ni->ni_sa_query_trids, 0, sizeof(ni->ni_sa_query_trids)" in node_source
    assert node_copy.index("timeout_free(&dst->ni_sa_query_to)") < node_copy.index("*dst = *src")
    assert node_copy.index("ieee80211_node_cleanup(ic, dst)") < node_copy.index(
        "*dst = *src")
    assert node_copy.index("dst->ni_sa_query_to = NULL") < node_copy.index(
        "ieee80211_node_set_timeouts(dst)"
    )
    assert node_cleanup.index("ieee80211_sta_security_cleanup(ic, ni)") < \
        node_cleanup.index("free(ni->ni_rsnie)")
    assert node_free.index("ieee80211_node_cleanup(ic, ni)") < \
        node_free.index("timeout_del(&ni->ni_sa_query_to)") < \
        node_free.index("timeout_free(&ni->ni_sa_query_to)")

    functions = [
        production_function(crypto_source,
            "void\nieee80211_crypto_clear_groupkeys("),
        production_function(node_source,
            "void\nieee80211_pmf_keys_cancel("),
        production_function(node_source,
            "void\nieee80211_sta_security_cleanup("),
        production_function(node_source,
            "void\nieee80211_node_cleanup("),
        production_function(node_source,
            "void\nieee80211_node_copy("),
        state_hook_test,
        production_function(proto_source, "int\nieee80211_sa_query_sta_authorized("),
        production_function(proto_source, "static void\nieee80211_sa_query_sta_clear("),
        production_function(proto_source, "static void\nieee80211_sa_query_sta_fail("),
        production_function(proto_source, "static u_int16_t\nieee80211_sa_query_sta_next_trid("),
        production_function(proto_source, "static int\nieee80211_sa_query_sta_send("),
        production_function_after(
            proto_source,
            "/*\n * Hostap uses 201 TU retries",
            "void\nieee80211_sa_query_timeout(void *arg)",
        ),
        production_function_after(
            proto_source,
            "/*\n * Hostap uses 201 TU retries",
            "void\nieee80211_sa_query_request(struct ieee80211com *ic,\n",
        ),
        production_function(input_source, "static int\nieee80211_sta_sa_query_unprotected_disconnect("),
        production_function(input_source, "void\nieee80211_recv_sa_query_req("),
        production_function_after(
            input_source,
            "/*\n * STA confirmation accepts any transaction ID",
            "void\nieee80211_recv_sa_query_resp(",
        ),
    ]

    compiler = shutil.which("clang++") or shutil.which("c++")
    if not compiler:
        raise SystemExit("No C++ compiler found")
    with tempfile.TemporaryDirectory(prefix="sta-sa-query-") as directory:
        harness = Path(directory) / "sta_sa_query.cpp"
        binary = Path(directory) / "sta_sa_query"
        harness.write_text(PREAMBLE + "\n" + "\n".join(functions) + "\n" + SUFFIX,
                          encoding="utf-8")
        result = subprocess.run(
            [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             str(harness), "-o", str(binary)],
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise RuntimeError(result.stderr or result.stdout)
        run = subprocess.run([str(binary)], capture_output=True, text=True)
        if run.returncode:
            raise AssertionError(run.stdout + run.stderr)
        print(run.stdout, end="")


if __name__ == "__main__":
    main()
