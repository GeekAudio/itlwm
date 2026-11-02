#!/usr/bin/env python3
"""ASan/UBSan tests that compile the production PMF key and BIP functions."""

from __future__ import annotations

import os
import pathlib
import shutil
import hashlib
import struct
import subprocess
import tempfile
import textwrap


ROOT = pathlib.Path(__file__).resolve().parents[2]
CRYPTO = ROOT / "itl80211/openbsd/net80211/ieee80211_crypto.c"
BIP = ROOT / "itl80211/openbsd/net80211/ieee80211_crypto_bip.c"
PAE = ROOT / "itl80211/openbsd/net80211/ieee80211_pae_input.c"
OPENBSD = ROOT / "itl80211/openbsd"
DRIVER = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
FIRMWARE = ROOT / "itlwm/firmware/iwlwifi-so-a0-hr-b0-68.ucode"
OUTPUT = OPENBSD / "net80211/ieee80211_output.c"


def function_body(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : end]
    raise AssertionError(f"unterminated production function: {marker}")


def struct_source(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start : end + 1] + ";"
    raise AssertionError(f"unterminated production struct: {marker}")


def test_iwx_async_ack_contract() -> None:
    source = DRIVER.read_text()
    rx_body = function_body(source, "iwx_rx_pkt(struct iwx_softc *sc,")
    completion_body = function_body(
        source, "iwx_pmf_key_completion_task(struct iwx_softc *sc)")
    cmd_done_body = function_body(
        source, "iwx_cmd_done(struct iwx_softc *sc, int qid, int idx, int code)")
    firmware_body = function_body(source, "iwx_read_firmware(struct iwx_softc *sc)")
    igtk_send_body = function_body(
        source, "iwx_set_mgmt_mcast_key(struct iwx_softc *sc,")

    # Route failed command responses through the normal response case so the
    # command ring is retired. Keep the raw failure bit for rejection.
    normalized = rx_body.index("pkt->hdr.group_id & ~IWX_CMD_FAILED_MSK")
    dispatch = rx_body.index("switch (code)")
    assert normalized < dispatch
    assert "pkt->hdr.group_id & IWX_CMD_FAILED_MSK" in rx_body[dispatch:]
    assert "iwx_cmd_done(sc, qid, idx, code)" in rx_body
    assert "pkt_len > sc->sc_cmd_resp_len[idx]" in rx_body
    assert "memcpy(sc->sc_cmd_resp_pkt[idx], pkt, pkt_len)" in rx_body

    # Production completion uses distinct payload contracts for the two FW
    # commands; only the recognized SO68 identity can use its four-byte IGTK
    # status reply.
    assert "itl_pmf_add_sta_key_response_ok(" in completion_body
    assert "itl_pmf_igtk_response_ok(" in completion_body
    assert "payloadLength == sizeof(struct iwx_cmd_response)" in completion_body
    assert "le32toh(response->status), 1U" in completion_body
    assert "sc->sc_pmf_igtk_status1_abi" in completion_body
    assert "pending->igtk_status1_abi &&" in completion_body
    assert "itl_pmf_ack_response_matches(" in completion_body
    assert "pending->key->k_flags |= IEEE80211_KEY_FWACTIVE" in completion_body

    # The response allocation remains 8 bytes for unknown firmware and grows
    # to the complete 12-byte packet only for the exact SO68 identity.
    assert "itl_pmf_so68_igtk_status1_firmware_identity(sc->sc_fwname" in firmware_body
    assert "le32toh(uhdr->ver), le32toh(uhdr->build)" in firmware_body
    assert "uhdr->human_readable" in firmware_body
    assert "sc->sc_pmf_igtk_status1_abi = 0" in firmware_body
    assert "fw->fw_rawsize < sizeof(*uhdr)" in firmware_body
    assert "sizeof(struct iwx_rx_packet) +" in igtk_send_body
    assert "sc->sc_pmf_igtk_status1_abi ?" in igtk_send_body
    assert "sizeof(struct iwx_cmd_response) : 0" in igtk_send_body
    assert "if (trackAck && !sc->sc_pmf_igtk_status1_abi)" in igtk_send_body
    assert "pending->igtk_status1_abi =" in source

    # The real completion path selects the response by the command queue and
    # the pending qid/index tuple before it captures this response buffer.
    assert "if (qid != IWX_DQA_CMD_QUEUE)" in cmd_done_body
    assert "itl_pmf_ack_find_ring_slot(" in cmd_done_body
    assert "sc->sc_pmf_key_cmd, nitems(sc->sc_pmf_key_cmd), qid, idx" in cmd_done_body
    assert "pending->response_pkt = sc->sc_cmd_resp_pkt[idx]" in cmd_done_body
    assert "pending->response_command_id = iwx_cmd_opcode(code)" in cmd_done_body

    # Check the pinned local image header used by the identity gate.
    firmware = FIRMWARE.read_bytes()
    assert hashlib.sha256(firmware).hexdigest() == (
        "1550c08c54ae779ae3d3a6d5e99a4239af2ef99c8404463a0869cd242a806ba0")
    assert struct.unpack_from("<I", firmware, 4)[0] == 0x0A4C5749
    assert struct.unpack_from("<I", firmware, 72)[0] == 68
    assert struct.unpack_from("<I", firmware, 76)[0] == 0x01D30B0C
    assert firmware[8:72] == b"release/core66_LinADLPV::01d30b0c".ljust(64, b"\0")


def test_bip_tx_order_and_post_encapsulation_check() -> None:
    source = DRIVER.read_text()
    tx_body = function_body(
        source, "iwx_tx(struct iwx_softc *sc, mbuf_t m,")
    mgmt_source = OUTPUT.read_text()
    mgmt_body = function_body(
        mgmt_source, "ieee80211_mgmt_output(struct _ifnet *ifp,")

    # net80211 marks robust management for the driver, then iwx_tx checks the
    # selected IGTK before invoking software BIP (which clears that bit).
    assert "wh->i_fc[1] |= IEEE80211_FC1_PROTECTED" in mgmt_body
    protected_gate = tx_body.index(
        "if (wh->i_fc[1] & IEEE80211_FC1_PROTECTED)")
    key_ready = tx_body.index("itl_pmf_key_tx_ready(", protected_gate)
    bip_encap = tx_body.index("ieee80211_encrypt(ic, m, k)", key_ready)
    mmie_check = tx_body.index("itl_pmf_bip_tx_frame_valid(", bip_encap)
    tx_doorbell = tx_body.index(
        "IWX_WRITE(sc, IWX_HBUS_TARG_WRPTR, ring->qid << 16 | ring->cur)")
    assert protected_gate < key_ready < bip_encap < mmie_check < tx_doorbell
    assert "packetLength -\n                            IEEE80211_MMIE_LEN" in tx_body[mmie_check - 500:mmie_check]


HARNESS = r"""
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

typedef unsigned int u_int;
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint64_t u_int64_t;

extern "C" {
#include <crypto/aes.h>
#include <crypto/cmac.h>
}
#include "native/pmf_crypto_policy.h"

#define IEEE80211_ADDR_LEN 6
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_MGT 0x00
#define IEEE80211_FC0_TYPE_DATA 0x08
#define IEEE80211_FC0_SUBTYPE_MASK 0xf0
#define IEEE80211_FC0_SUBTYPE_ACTION 0xd0
#define IEEE80211_FC0_SUBTYPE_DISASSOC 0xa0
#define IEEE80211_FC0_SUBTYPE_DEAUTH 0xc0
#define IEEE80211_IS_MULTICAST(a) (((const uint8_t *)(a))[0] & 1)
#define IEEE80211_FC1_DIR_NODS 0x00
#define IEEE80211_FC1_PROTECTED 0x40
#define IEEE80211_FC1_RETRY 0x08
#define IEEE80211_FC1_PWR_MGT 0x10
#define IEEE80211_FC1_MORE_DATA 0x20
#define IEEE80211_ELEMID_MMIE 76
#define IEEE80211_MMIE_LEN 18
#define IEEE80211_CIPHER_NONE 0
#define IEEE80211_CIPHER_CCMP 1
#define IEEE80211_CIPHER_BIP 2
#define IEEE80211_KEY_GROUP 0x01
#define IEEE80211_KEY_IGTK 0x02
#define IEEE80211_KEY_SWCRYPTO 0x80
#define IEEE80211_F_RSNON 0x01
#define IEEE80211_C_MFP 0x100
#define IEEE80211_NODE_MFP 0x01
#define IEEE80211_NODE_SA_QUERY 0x02
#define IEEE80211_NODE_SA_QUERY_FAILED 0x04
#define IEEE80211_NODE_TXMGMTPROT 0x08
#define IEEE80211_CIPHER_USEGROUP 0
#define IEEE80211_M_STA 0
#define IEEE80211_M_IBSS 1
#define IEEE80211_M_HOSTAP 2
#define IEEE80211_FC0_VERSION_0 0
#define IEEE80211_FC0_SUBTYPE_PROBE_RESP 0x50
#define IEEE80211_FC0_SUBTYPE_SHIFT 4
#define IEEE80211_SEQ_SEQ_SHIFT 4
#define IEEE80211_CATEG_SA_QUERY 8
#define IEEE80211_ACTION_SA_QUERY_REQ 0
#define IEEE80211_ACTION_SA_QUERY_RESP 1
#define IFF_DEBUG 0x01
#define MBUF_DONTWAIT 0
#define MT_DATA 0
#define __packed __attribute__((packed))
#define _KASSERT(c) assert(c)
static void test_log(const char *, ...) {}
#define XYLog(...) test_log(__VA_ARGS__)
#define DPRINTF(...) ((void)0)
#define LE_READ_2(p) ((uint16_t)((const uint8_t *)(p))[0] | \
    ((uint16_t)((const uint8_t *)(p))[1] << 8))
#define LE_READ_6(p) ((uint64_t)((const uint8_t *)(p))[0] | \
    ((uint64_t)((const uint8_t *)(p))[1] << 8) | \
    ((uint64_t)((const uint8_t *)(p))[2] << 16) | \
    ((uint64_t)((const uint8_t *)(p))[3] << 24) | \
    ((uint64_t)((const uint8_t *)(p))[4] << 32) | \
    ((uint64_t)((const uint8_t *)(p))[5] << 40))
#define LE_WRITE_2(p, v) do { ((uint8_t *)(p))[0] = (uint8_t)(v); \
    ((uint8_t *)(p))[1] = (uint8_t)((v) >> 8); } while (0)
#define IEEE80211_ADDR_COPY(d, s) memcpy((d), (s), IEEE80211_ADDR_LEN)
#define mtod(m, t) ((t)((m)->bytes + (m)->offset))
#define IEEE80211_SEND_ACTION(ic, ni, cat, act, arg) \
    ((void)test_send_action((ic), (ni), (cat), (act), (arg)))
#define htole16(v) (v)

static inline void test_explicit_bzero(void *ptr, size_t len) {
    volatile uint8_t *p = static_cast<volatile uint8_t *>(ptr);
    while (len--) *p++ = 0;
}
#define explicit_bzero test_explicit_bzero
static inline void *malloc(size_t size, int, int) { return std::malloc(size); }

struct mbuf {
    uint8_t bytes[1024]{};
    size_t offset = 64;
    size_t len = 0;
    size_t pkthdr_len = 0;
    size_t capacity = sizeof(bytes);
    size_t m_len = 0;
    struct mbuf *next = nullptr;
};
using mbuf_t = struct mbuf *;
struct mbuf_queue { std::vector<mbuf_t> packets; };

static mbuf_t new_mbuf(size_t len) {
    auto *m = new mbuf;
    assert(m->offset + len <= m->capacity);
    m->len = m->pkthdr_len = len;
    m->m_len = len;
    return m;
}
static size_t mbuf_len(mbuf_t m) { return m->len; }
static size_t mbuf_pkthdr_len(mbuf_t m) { return m->pkthdr_len; }
static void mbuf_setlen(mbuf_t m, size_t len) {
    m->len = len;
    m->m_len = len;
}
static void mbuf_pkthdr_setlen(mbuf_t m, size_t len) { m->pkthdr_len = len; }
static size_t mbuf_trailingspace(mbuf_t m) {
    return m->capacity - m->offset - m->len;
}
static int mbuf_type(mbuf_t) { return MT_DATA; }
static void mbuf_setnext(mbuf_t m, mbuf_t next) { m->next = next; }
static void mbuf_mclget(int, int, mbuf_t *out) { *out = new_mbuf(0); }
static void mbuf_freem(mbuf_t m) {
    while (m) {
        mbuf_t next = m->next;
        delete m;
        m = next;
    }
}
static void mbuf_adj(mbuf_t m, int amount) {
    assert(amount <= 0 && static_cast<size_t>(-amount) <= m->len);
    m->len -= static_cast<size_t>(-amount);
    m->pkthdr_len -= static_cast<size_t>(-amount);
    m->m_len = m->len;
}
static void mbuf_prepend(mbuf_t *mp, size_t amount, int) {
    mbuf_t m = *mp;
    if (m->offset < amount) { *mp = nullptr; return; }
    m->offset -= amount;
    m->len += amount;
    m->pkthdr_len += amount;
    m->m_len = m->len;
    memset(m->bytes + m->offset, 0, amount);
}
static void mbuf_pkthdr_setrcvif(mbuf_t, void *) {}

struct test_timeout { bool active = false; unsigned int delay = 0; };
static void timeout_del(test_timeout *t) { t->active = false; }
static void timeout_add_msec(test_timeout *t, unsigned int delay) {
    t->active = true; t->delay = delay;
}
static int splnet() { return 0; }
static void splx(int) {}

struct ieee80211_frame {
    uint8_t i_fc[2];
    uint8_t i_dur[2];
    uint8_t i_addr1[6];
    uint8_t i_addr2[6];
    uint8_t i_addr3[6];
    uint8_t i_seq[2];
};
struct ieee80211_key {
    int k_cipher = IEEE80211_CIPHER_NONE;
    uint32_t k_flags = 0;
    uint8_t k_id = 0;
    uint8_t k_len = 0;
    uint8_t k_key[32]{};
    uint64_t k_tsc = 0;
    uint64_t k_mgmt_rsc = 0;
    void *k_priv = nullptr;
};
struct ieee80211_node {
    int ni_rsncipher = IEEE80211_CIPHER_CCMP;
    uint32_t ni_flags = 0;
    struct ieee80211_key ni_pairwise_key{};
    uint16_t ni_sa_query_trid = 0;
    uint8_t ni_sa_query_count = 0;
    uint16_t ni_txseq = 0;
    uint8_t ni_macaddr[6]{};
    uint8_t ni_bssid[6]{};
    void *ni_chan = nullptr;
    struct ieee80211com *ni_ic = nullptr;
    struct test_timeout ni_sa_query_to{};
    int ni_inact = 0;
};
struct ieee80211com {
    uint32_t ic_flags = IEEE80211_F_RSNON;
    uint32_t ic_caps = 0;
    int ic_opmode = 0;
    int ic_curmode = 0;
    uint8_t ic_def_txkey = 1;
    uint8_t ic_igtk_kid = 4;
    uint8_t ic_myaddr[6]{};
    struct mbuf_queue ic_mgtq{};
    struct _ifnet *outer_ifp = nullptr;
    struct ieee80211_key ic_nw_keys[6]{};
    struct { int is_tx_nombuf = 0; int is_cmac_replays = 0;
             int is_cmac_icv_errs = 0; } ic_stats;
};

struct _ifnet {
    struct ieee80211com ic;
    int if_flags = 0;
    int if_timer = 0;
    char if_xname[16]{};
    void (*if_start)(struct _ifnet *) = nullptr;
};
using ifnet_t = void *;
static void mq_enqueue(struct mbuf_queue *q, mbuf_t m) {
    q->packets.push_back(m);
}
static const char *ether_sprintf(const uint8_t *) { return "peer"; }
static const char *ieee80211_action_name(const ieee80211_frame *) {
    return "SA Query";
}
static const char *ieee80211_mgt_subtype_name[16] = {};
static const char *ieee80211_phymode_name[4] = {};
static unsigned int ieee80211_chan2ieee(struct ieee80211com *, void *) {
    return 1;
}
static int ieee80211_pwrsave(struct ieee80211com *, mbuf_t,
                             struct ieee80211_node *) { return 0; }
static void panic(const char *) { std::abort(); }
static mbuf_t ieee80211_getmgmt(int, int, unsigned int);
static int ieee80211_mgmt_output(struct _ifnet *, struct ieee80211_node *,
                                 mbuf_t, int);
static void ieee80211_sa_query_request(struct ieee80211com *,
                                       struct ieee80211_node *);
static int test_send_action(struct ieee80211com *, struct ieee80211_node *,
                            uint8_t, uint8_t, int);
static void if_start_stub(struct _ifnet *) {}
static mbuf_t ieee80211_getmgmt(int, int, unsigned int len) {
    return new_mbuf(len);
}

static int ieee80211_cipher_keylen(int cipher) { return cipher == 1 ? 16 : 0; }
void ieee80211_bip_delete_key(struct ieee80211com *, struct ieee80211_key *);

"""


def build_harness() -> str:
    crypto = CRYPTO.read_text()
    bip = BIP.read_text()
    pae = PAE.read_text()
    output = (ROOT / "itl80211/openbsd/net80211/ieee80211_output.c").read_text()
    input_source = (ROOT / "itl80211/openbsd/net80211/ieee80211_input.c").read_text()
    proto = (ROOT / "itl80211/openbsd/net80211/ieee80211_proto.c").read_text()
    components = [
        "struct ieee80211_bip_ctx",
        "struct ieee80211_bip_frame",
    ]
    structs = "\n".join(struct_source(bip, marker) for marker in components)
    functions = [
        (crypto, "ieee80211_get_txkey(struct ieee80211com *ic,", "struct ieee80211_key *\nieee80211_get_txkey(struct ieee80211com *ic, const struct ieee80211_frame *wh, struct ieee80211_node *ni)"),
        (pae, "ieee80211_must_update_group_key(struct ieee80211_key *k,", "int\nieee80211_must_update_group_key(struct ieee80211_key *k, const uint8_t *gtk, int len)"),
        (bip, "ieee80211_bip_set_key(struct ieee80211com *ic,", "int\nieee80211_bip_set_key(struct ieee80211com *ic, struct ieee80211_key *k)"),
        (bip, "ieee80211_bip_delete_key(struct ieee80211com *ic,", "void\nieee80211_bip_delete_key(struct ieee80211com *ic, struct ieee80211_key *k)"),
        (bip, "ieee80211_bip_encap(struct ieee80211com *ic,", "mbuf_t\nieee80211_bip_encap(struct ieee80211com *ic, mbuf_t m0, struct ieee80211_key *k)"),
        (bip, "ieee80211_bip_decap(struct ieee80211com *ic,", "mbuf_t\nieee80211_bip_decap(struct ieee80211com *ic, mbuf_t m0, struct ieee80211_key *k)"),
        (output, "ieee80211_get_sa_query(struct ieee80211com *ic,", "mbuf_t\nieee80211_get_sa_query(struct ieee80211com *ic, struct ieee80211_node *ni, u_int8_t action)"),
        (output, "ieee80211_mgmt_output(struct _ifnet *ifp,", "int\nieee80211_mgmt_output(struct _ifnet *ifp, struct ieee80211_node *ni, mbuf_t m, int type)"),
        (input_source, "ieee80211_recv_sa_query_resp(struct ieee80211com *ic,", "void\nieee80211_recv_sa_query_resp(struct ieee80211com *ic, mbuf_t m, struct ieee80211_node *ni)"),
        (proto, "ieee80211_sa_query_timeout(void *arg)", "void\nieee80211_sa_query_timeout(void *arg)"),
        (proto, "ieee80211_sa_query_request(struct ieee80211com *ic,", "void\nieee80211_sa_query_request(struct ieee80211com *ic, struct ieee80211_node *ni)"),
    ]
    extracted = []
    for source, marker, signature in functions:
        extracted.append(signature + " {" + function_body(source, marker) + "}\n")
    return HARNESS + structs + "\n".join(extracted) + TESTS


TESTS = r"""
static mbuf_t frame_with_body(uint8_t subtype, uint8_t category,
                              bool multicast = true) {
    auto *m = new_mbuf(sizeof(ieee80211_frame) + 3);
    auto *wh = mtod(m, ieee80211_frame *);
    memset(wh, 0, sizeof(*wh));
    wh->i_fc[0] = subtype;
    wh->i_fc[1] = IEEE80211_FC1_PROTECTED;
    wh->i_addr1[0] = multicast ? 1 : 2;
    wh->i_addr2[0] = 4;
    wh->i_addr3[0] = 6;
    reinterpret_cast<uint8_t *>(&wh[1])[0] = category;
    reinterpret_cast<uint8_t *>(&wh[1])[1] = 0x31;
    reinterpret_cast<uint8_t *>(&wh[1])[2] = 0x42;
    return m;
}

static mbuf_t from_wire(const std::vector<uint8_t> &wire) {
    auto *m = new_mbuf(wire.size());
    memcpy(mtod(m, uint8_t *), wire.data(), wire.size());
    return m;
}

static std::vector<uint8_t> wire_bytes(mbuf_t m) {
    auto *p = mtod(m, uint8_t *);
    return std::vector<uint8_t>(p, p + mbuf_len(m));
}

static void test_production_key_selection() {
    ieee80211com ic{};
    ieee80211_node ni{};
    ni.ni_flags = IEEE80211_NODE_MFP;
    ic.ic_def_txkey = 2;
    ic.ic_igtk_kid = 5;

    auto *data = frame_with_body(IEEE80211_FC0_TYPE_DATA, 8);
    auto *data_wh = mtod(data, ieee80211_frame *);
    assert(ieee80211_get_txkey(&ic, data_wh, &ni) == &ic.ic_nw_keys[2]);
    mbuf_freem(data);

    auto *action = frame_with_body(IEEE80211_FC0_SUBTYPE_ACTION, 8);
    auto *action_wh = mtod(action, ieee80211_frame *);
    assert(ieee80211_get_txkey(&ic, action_wh, &ni) == &ic.ic_nw_keys[5]);
    mbuf_freem(action);

    auto *public_action = frame_with_body(IEEE80211_FC0_SUBTYPE_ACTION, 4);
    auto *public_wh = mtod(public_action, ieee80211_frame *);
    assert(ieee80211_get_txkey(&ic, public_wh, &ni) == &ic.ic_nw_keys[2]);
    mbuf_freem(public_action);
}

static void test_production_group_key_rotation_predicate() {
    ieee80211_key key{};
    key.k_cipher = IEEE80211_CIPHER_CCMP;
    key.k_len = 16;
    memset(key.k_key, 0x5a, 16);
    uint8_t same[16];
    memset(same, 0x5a, sizeof(same));
    uint8_t rotated[16];
    memset(rotated, 0xa5, sizeof(rotated));
    assert(!ieee80211_must_update_group_key(&key, same, 16));
    assert(ieee80211_must_update_group_key(&key, rotated, 16));
    key.k_mgmt_rsc = itl_pmf_bip_ipn_high_watermark(key.k_mgmt_rsc, 50);
    key.k_mgmt_rsc = itl_pmf_bip_ipn_high_watermark(key.k_mgmt_rsc, 42);
    assert(key.k_mgmt_rsc == 50);
    key.k_mgmt_rsc = itl_pmf_bip_ipn_high_watermark(key.k_mgmt_rsc, 51);
    assert(key.k_mgmt_rsc == 51);
}

static void test_production_bip_mic_kid_replay_and_ipn() {
    ieee80211com ic{};
    ieee80211_key tx{};
    tx.k_cipher = IEEE80211_CIPHER_BIP;
    tx.k_id = 4;
    tx.k_len = 16;
    tx.k_tsc = 1;
    for (size_t i = 0; i < 16; ++i) tx.k_key[i] = uint8_t(i + 1);
    assert(ieee80211_bip_set_key(&ic, &tx) == 0);

    auto *plain = frame_with_body(IEEE80211_FC0_SUBTYPE_ACTION, 8);
    auto *encoded = ieee80211_bip_encap(&ic, plain, &tx);
    assert(encoded != nullptr);
    auto *wh = mtod(encoded, ieee80211_frame *);
    assert((wh->i_fc[1] & IEEE80211_FC1_PROTECTED) == 0);
    const auto wire1 = wire_bytes(encoded);

    ieee80211_key rx = tx;
    rx.k_mgmt_rsc = 0;
    auto *good = from_wire(wire1);
    auto *decoded = ieee80211_bip_decap(&ic, good, &rx);
    assert(decoded != nullptr);
    assert(rx.k_mgmt_rsc == 1);
    assert(mbuf_len(decoded) + IEEE80211_MMIE_LEN == wire1.size());
    mbuf_freem(decoded);

    auto tampered = wire1;
    tampered.back() ^= 0x80;
    assert(ieee80211_bip_decap(&ic, from_wire(tampered), &rx) == nullptr);

    auto wrongKid = wire1;
    wrongKid[wrongKid.size() - IEEE80211_MMIE_LEN + 2] = 5;
    assert(ieee80211_bip_decap(&ic, from_wire(wrongKid), &rx) == nullptr);

    // Equal and decreasing IPNs are replay drops, including a valid lower
    // frame presented after a higher authenticated frame.
    assert(ieee80211_bip_decap(&ic, from_wire(wire1), &rx) == nullptr);
    auto *lowFrame = ieee80211_bip_encap(
        &ic, frame_with_body(IEEE80211_FC0_SUBTYPE_ACTION, 8), &tx);
    const auto wire2 = wire_bytes(lowFrame);
    mbuf_freem(lowFrame);
    auto *highFrame = ieee80211_bip_encap(
        &ic, frame_with_body(IEEE80211_FC0_SUBTYPE_ACTION, 8), &tx);
    const auto wire3 = wire_bytes(highFrame);
    mbuf_freem(highFrame);
    ieee80211_key rx2 = tx;
    rx2.k_mgmt_rsc = 0;
    auto *high = ieee80211_bip_decap(&ic, from_wire(wire3), &rx2);
    assert(high != nullptr);
    mbuf_freem(high);
    assert(ieee80211_bip_decap(&ic, from_wire(wire2), &rx2) == nullptr);

    tx.k_tsc = UINT64_C(0x0000ffffffffffff);
    auto *lastPn = ieee80211_bip_encap(
        &ic, frame_with_body(IEEE80211_FC0_SUBTYPE_ACTION, 8), &tx);
    assert(lastPn != nullptr);
    const auto maxWire = wire_bytes(lastPn);
    const size_t mmieStart = maxWire.size() - IEEE80211_MMIE_LEN;
    assert(LE_READ_6(&maxWire[mmieStart + 4]) ==
           UINT64_C(0x0000ffffffffffff));
    mbuf_freem(lastPn);
    assert(ieee80211_bip_encap(
        &ic, frame_with_body(IEEE80211_FC0_SUBTYPE_ACTION, 8), &tx) == nullptr);

    ieee80211_bip_delete_key(&ic, &tx);
    assert(tx.k_priv == nullptr);
}

static int test_send_action(struct ieee80211com *ic,
                            struct ieee80211_node *ni,
                            uint8_t category, uint8_t action, int) {
    assert(category == IEEE80211_CATEG_SA_QUERY);
    mbuf_t m = ieee80211_get_sa_query(ic, ni, action);
    return ieee80211_mgmt_output(ic->outer_ifp, ni, m,
                                 IEEE80211_FC0_SUBTYPE_ACTION);
}

static mbuf_t sa_query_response(uint16_t id) {
    auto *m = new_mbuf(sizeof(ieee80211_frame) + 4);
    auto *wh = mtod(m, ieee80211_frame *);
    memset(wh, 0, sizeof(*wh));
    wh->i_fc[0] = IEEE80211_FC0_SUBTYPE_ACTION;
    reinterpret_cast<uint8_t *>(&wh[1])[0] = IEEE80211_CATEG_SA_QUERY;
    reinterpret_cast<uint8_t *>(&wh[1])[1] = IEEE80211_ACTION_SA_QUERY_RESP;
    LE_WRITE_2(reinterpret_cast<uint8_t *>(&wh[1]) + 2, id);
    return m;
}

static void assert_last_sa_query(struct ieee80211com *ic, uint8_t action,
                                 uint16_t expectedId) {
    assert(!ic->ic_mgtq.packets.empty());
    mbuf_t m = ic->ic_mgtq.packets.back();
    auto *wh = mtod(m, ieee80211_frame *);
    assert((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
           IEEE80211_FC0_SUBTYPE_ACTION);
    assert(wh->i_fc[1] & IEEE80211_FC1_PROTECTED);
    const auto *frm = reinterpret_cast<const uint8_t *>(&wh[1]);
    assert(frm[0] == IEEE80211_CATEG_SA_QUERY);
    assert(frm[1] == action);
    assert(LE_READ_2(frm + 2) == expectedId);
}

static void drain_mgmt_queue(struct ieee80211com *ic) {
    for (auto *m : ic->ic_mgtq.packets) mbuf_freem(m);
    ic->ic_mgtq.packets.clear();
}

static void test_production_sa_query_ids_timeout_and_protection() {
    struct _ifnet ifp{};
    struct ieee80211com *ic = &ifp.ic;
    struct ieee80211_node ni{};
    ic->outer_ifp = &ifp;
    ic->ic_caps = IEEE80211_C_MFP;
    ic->ic_opmode = IEEE80211_M_STA;
    ifp.if_start = if_start_stub;
    ni.ni_ic = ic;
    ni.ni_flags = IEEE80211_NODE_MFP | IEEE80211_NODE_TXMGMTPROT;
    ni.ni_macaddr[0] = 2;
    ni.ni_bssid[0] = 4;

    ieee80211_sa_query_request(ic, &ni);
    assert(ni.ni_flags & IEEE80211_NODE_SA_QUERY);
    assert(!(ni.ni_flags & IEEE80211_NODE_SA_QUERY_FAILED));
    assert(ni.ni_sa_query_count == 0);
    assert(ni.ni_sa_query_trid == 1);
    assert(ni.ni_sa_query_to.active && ni.ni_sa_query_to.delay == 10);
    assert_last_sa_query(ic, IEEE80211_ACTION_SA_QUERY_REQ, 1);

    mbuf_t wrong = sa_query_response(0x8877);
    ieee80211_recv_sa_query_resp(ic, wrong, &ni);
    mbuf_freem(wrong);
    assert(ni.ni_flags & IEEE80211_NODE_SA_QUERY);
    assert(ni.ni_sa_query_to.active);

    mbuf_t right = sa_query_response(1);
    ieee80211_recv_sa_query_resp(ic, right, &ni);
    mbuf_freem(right);
    assert(!(ni.ni_flags & IEEE80211_NODE_SA_QUERY));
    assert(!ni.ni_sa_query_to.active);
    drain_mgmt_queue(ic);

    ieee80211_sa_query_request(ic, &ni);
    assert_last_sa_query(ic, IEEE80211_ACTION_SA_QUERY_REQ, 2);
    ieee80211_sa_query_timeout(&ni);
    assert(ni.ni_sa_query_count == 1 && ni.ni_sa_query_trid == 3);
    assert_last_sa_query(ic, IEEE80211_ACTION_SA_QUERY_REQ, 3);
    ieee80211_sa_query_timeout(&ni);
    assert(ni.ni_sa_query_count == 2 && ni.ni_sa_query_trid == 4);
    assert_last_sa_query(ic, IEEE80211_ACTION_SA_QUERY_REQ, 4);
    ieee80211_sa_query_timeout(&ni);
    assert(ni.ni_sa_query_count == 3);
    assert(!(ni.ni_flags & IEEE80211_NODE_SA_QUERY));
    assert(ni.ni_flags & IEEE80211_NODE_SA_QUERY_FAILED);
    drain_mgmt_queue(ic);
}

int main() {
    test_production_key_selection();
    test_production_group_key_rotation_predicate();
    test_production_bip_mic_kid_replay_and_ipn();
    test_production_sa_query_ids_timeout_and_protection();
    std::puts("PMF production crypto tests passed");
    return 0;
}
"""


def main() -> None:
    test_iwx_async_ack_contract()
    test_bip_tx_order_and_post_encapsulation_check()
    compiler = os.environ.get("CXX") or shutil.which("clang++")
    c_compiler = os.environ.get("CC") or shutil.which("clang")
    if not compiler or not c_compiler:
        raise SystemExit("clang/clang++ required for PMF sanitizer harness")

    with tempfile.TemporaryDirectory(prefix="itl-pmf-production-") as tmp:
        temp = pathlib.Path(tmp)
        shim = temp / "shim"
        (shim / "sys").mkdir(parents=True)
        (shim / "IOKit").mkdir(parents=True)
        (shim / "IOKit/IOLib.h").write_text("/* host-only shim */\n")
        (shim / "sys/param.h").write_text(textwrap.dedent("""\
            #ifndef TEST_SYS_PARAM_H
            #define TEST_SYS_PARAM_H
            #include <sys/types.h>
            #include <stdint.h>
            #include <stddef.h>
            #define MIN(a,b) ((a) < (b) ? (a) : (b))
            #endif
            """))
        (shim / "sys/systm.h").write_text(textwrap.dedent("""\
            #ifndef TEST_SYS_SYSTM_H
            #define TEST_SYS_SYSTM_H
            #include <stdint.h>
            #include <string.h>
            #endif
            """))

        harness = temp / "pmf_production.cpp"
        harness.write_text(build_harness())
        objects = []
        for source, name in ((OPENBSD / "crypto/aes.c", "aes.o"),
                             (OPENBSD / "crypto/cmac.c", "cmac.o")):
            obj = temp / name
            subprocess.run([
                c_compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra",
                "-Werror", "-I", str(shim), "-I", str(OPENBSD),
                "-c", str(source), "-o", str(obj),
            ], check=True)
            objects.append(obj)

        executable = temp / "pmf_production"
        subprocess.run([
            compiler, "-std=c++17", "-O1", "-g", "-Wall", "-Wextra",
            "-Werror", "-Wno-unused-function", "-Wno-unused-parameter",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", "-I", str(ROOT), "-I", str(OPENBSD),
            str(harness), *(str(obj) for obj in objects), "-o", str(executable),
        ], check=True)
        env = os.environ.copy()
        env.setdefault("ASAN_OPTIONS", "detect_leaks=0:halt_on_error=1")
        env.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
        subprocess.run([str(executable)], check=True, env=env)


if __name__ == "__main__":
    main()
