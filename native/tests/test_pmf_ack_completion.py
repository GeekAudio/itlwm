#!/usr/bin/env python3
"""Execute the production PMF ACK-completion and RSN-cancel bodies on host."""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap


ROOT = pathlib.Path(__file__).resolve().parents[2]
DRIVER = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
NODE = ROOT / "itl80211/openbsd/net80211/ieee80211_node.c"
IOCTL = ROOT / "itl80211/openbsd/net80211/ieee80211_ioctl.c"
CRYPTO = ROOT / "itl80211/openbsd/net80211/ieee80211_crypto.c"


def function_body(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.find("{", start)
    semicolon = source.find(";", start)
    while semicolon != -1 and semicolon < opening:
        start = source.index(marker, start + len(marker))
        opening = source.find("{", start)
        semicolon = source.find(";", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : end]
    raise AssertionError(f"unterminated production function: {marker}")


def production_bodies() -> dict[str, str]:
    return {
        "key_active": function_body(
            DRIVER.read_text(), "iwx_pmf_key_active(struct iwx_softc *sc,"),
        "completion": function_body(
            DRIVER.read_text(),
            "iwx_pmf_key_completion_task(struct iwx_softc *sc)"),
        "driver_cancel": function_body(
            DRIVER.read_text(),
            "iwx_pmf_cancel_keys_gated(struct ieee80211com *ic,"),
        "node_cancel": function_body(
            NODE.read_text(),
            "ieee80211_pmf_keys_cancel(struct ieee80211com *ic,"),
        "sta_cleanup": function_body(
            NODE.read_text(),
            "ieee80211_sta_security_cleanup(struct ieee80211com *ic,"),
        "group_cleanup": function_body(
            CRYPTO.read_text(),
            "ieee80211_crypto_clear_groupkeys(struct ieee80211com *ic)"),
        "disable_rsn": function_body(
            IOCTL.read_text(), "ieee80211_disable_rsn(struct ieee80211com *ic)"),
    }


HARNESS = r"""
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <sys/time.h>

#include "native/pmf_crypto_policy.h"

#define AIRPORT_TAHOE 1
#define IEEE80211_STA_ONLY 1
#define container_of(ptr, type, member) \
    reinterpret_cast<type *>(reinterpret_cast<char *>(ptr) - offsetof(type, member))
#define nitems(array) (sizeof(array) / sizeof((array)[0]))
#define __packed __attribute__((packed))
#define IEEE80211_NODE_RXPROT    0x0008U
#define IEEE80211_NODE_TXPROT    0x0010U
#define IEEE80211_NODE_RXMGMTPROT 0x0020U
#define IEEE80211_NODE_TXMGMTPROT 0x0040U
#define IEEE80211_NODE_MFP       0x0080U
#define IEEE80211_NODE_SA_QUERY  0x0800U
#define IEEE80211_NODE_SA_QUERY_FAILED 0x1000U
#define IEEE80211_NODE_TXRXPROT (IEEE80211_NODE_TXPROT | IEEE80211_NODE_RXPROT)
#define IEEE80211_NODE_PROT_MASK \
    (IEEE80211_NODE_TXMGMTPROT | IEEE80211_NODE_RXMGMTPROT)
#define IEEE80211_ADDR_LEN       6
#define IEEE80211_SA_QUERY_STA_MAX_ATTEMPTS 5
#define IEEE80211_KEY_FWPENDING  0x0001U
#define IEEE80211_KEY_FWACTIVE   0x0002U
#define IEEE80211_KEY_FWMFP      0x0004U
#define IEEE80211_KEY_GROUP      0x0008U
#define IEEE80211_KEY_IGTK       0x0010U
#define IEEE80211_KEY_TX         0x0020U
#define IEEE80211_KEY_SWCRYPTO   0x0040U
#define IEEE80211_CIPHER_NONE    0
#define IEEE80211_CIPHER_CCMP    1
#define IEEE80211_CIPHER_BIP     2
#define IEEE80211_GROUP_NKID     6
#define IEEE80211_M_STA          1
#define IEEE80211_F_RSNON        0x0001U
#define IEEE80211_F_PSK          0x0002U
#define IEEE80211_S_SCAN         1
#define IEEE80211_S_RUN          2
#define RSNA_SUPP_INITIALIZE     0
#define RNSA_SUPP_PTKDONE        7
#define IEEE80211_PMF_PENDING_GTK  0x01U
#define IEEE80211_PMF_PENDING_IGTK 0x02U
#define IWX_PMF_KEY_SLOT_COUNT   7
#define IWX_PMF_KEY_CMD_ADD_STA  1
#define IWX_PMF_KEY_CMD_IGTK     2
#define IWX_CMD_FAILED_MSK       0x40U
#define IWX_ADD_STA_SUCCESS      1U
#define IWX_DQA_CMD_QUEUE        0U
#define IWX_FLAG_STA_ACTIVE      0x01U
#define IWX_FLAG_SHUTDOWN        0x02U
#define LINK_STATE_UP            1

static constexpr uint64_t kNow = 9000000000ULL;
static uint64_t test_now = kNow;
static int test_arm_error;
static uint32_t test_reset_schedules;
static uint32_t test_link_up_calls;
static uint32_t test_state_changes;
static uint32_t test_sa_query_timeout_cancels;
static uint32_t test_eapol_timeout_cancels;
static uint32_t test_key_delete_calls;
static uint32_t test_pairwise_delete_calls;
static uint32_t test_group_delete_calls;
static void *tracked_sa_query_timeout;
static void *tracked_eapol_timeout;

struct ieee80211_key {
    uint32_t k_flags;
    uint8_t k_cipher;
    uint8_t k_id;
    uint8_t k_key[32];
};

struct ieee80211_ptk {
    uint8_t kck[16];
    uint8_t kek[16];
    uint8_t tk[32];
} __packed;

struct ieee80211_node {
    uint32_t ni_flags;
    uint32_t ni_pmf_key_epoch;
    struct ieee80211_key ni_pairwise_key;
    int ni_port_valid;
    uint8_t ni_pmf_link_pending;
    uint8_t ni_pmf_key_batch_ready;
    uint8_t ni_pmf_pending_key_ids;
    uint8_t ni_pmf_pending_gtk_kid;
    uint8_t ni_pmf_pending_igtk_kid;
    uint8_t ni_rsn_state;
    uint8_t ni_rsn_supp_state;
    uint32_t ni_assoc_fail;
    struct ieee80211_ptk ni_ptk;
    void *ni_eapol_to;
    void *ni_sa_query_to;
    int ni_sa_query_count;
    uint16_t ni_sa_query_trid;
    uint16_t ni_sa_query_trids[IEEE80211_SA_QUERY_STA_MAX_ATTEMPTS];
    uint8_t ni_sa_query_bssid[IEEE80211_ADDR_LEN];
    uint8_t ni_sa_query_local[IEEE80211_ADDR_LEN];
    struct timeval ni_sa_query_last_unprot;
    uint8_t ni_replaycnt_ok;
};

enum ieee80211_cipher { CIPHER_TEST_NONE = 0 };

struct ieee80211com;
using pmf_cancel_fn = void (*)(struct ieee80211com *, struct ieee80211_node *);
using key_delete_fn = void (*)(struct ieee80211com *, struct ieee80211_node *,
                               struct ieee80211_key *);

struct ieee80211com {
    struct ieee80211_node *ic_bss;
    struct ieee80211_key ic_nw_keys[6];
    uint32_t ic_flags;
    uint8_t ic_state;
    uint8_t ic_def_txkey;
    uint8_t ic_igtk_kid;
    uint8_t ic_psk[32];
    uint32_t ic_rsnprotos;
    uint32_t ic_rsnakms;
    enum ieee80211_cipher ic_rsngroupcipher;
    uint32_t ic_rsnciphers;
    int ic_opmode;
    void *ic_softc;
    pmf_cancel_fn ic_pmf_cancel_keys;
    key_delete_fn ic_delete_key;
};

struct iwx_pmf_key_cmd {
    struct ieee80211_node *node;
    struct ieee80211_key *key;
    void *response_pkt;
    size_t response_len;
    uint32_t generation;
    uint32_t node_epoch;
    uint32_t incarnation;
    uint32_t command_id;
    uint32_t response_command_id;
    uint8_t command_qid;
    uint8_t command_index;
    uint8_t igtk_status1_abi;
    uint8_t key_slot;
    uint8_t command_kind;
    uint8_t active;
    uint8_t completed;
    uint8_t timed_out;
    uint64_t timeout_deadline_ns;
};

struct iwx_softc {
    struct ieee80211com sc_ic;
    uint32_t sc_generation;
    uint32_t sc_pmf_key_incarnation[IWX_PMF_KEY_SLOT_COUNT];
    uint32_t sc_pmf_active_generation[IWX_PMF_KEY_SLOT_COUNT];
    uint32_t sc_pmf_active_incarnation[IWX_PMF_KEY_SLOT_COUNT];
    struct iwx_pmf_key_cmd sc_pmf_key_cmd[IWX_PMF_KEY_SLOT_COUNT];
    uint8_t sc_pmf_key_failed;
    uint8_t sc_pmf_timeout_fired;
    uint8_t sc_pmf_force_closed;
    uint8_t sc_pmf_igtk_status1_abi;
    uint32_t sc_flags;
    uint8_t sc_pmf_key_timeout;
};

struct iwx_cmd_header {
    uint8_t group_id;
    uint8_t command;
    uint16_t reserved;
};

struct iwx_cmd_response {
    uint32_t status;
};

struct iwx_rx_packet {
    uint32_t len_n_flags;
    struct iwx_cmd_header hdr;
    uint8_t data[16];
};

struct ItlIwx {
    struct iwx_softc com;
    uint32_t reset_calls;
    uint32_t cancel_reset_calls;

    bool tahoeP2pOnMainGate() const { return true; }
    void iwx_pmf_key_completion_task(struct iwx_softc *);
    void iwx_pmf_cancel_keys_gated(struct ieee80211com *,
                                   struct ieee80211_node *);
    void iwx_pmf_schedule_reset(struct iwx_softc *) { ++reset_calls; }
    void iwx_pmf_cancel_reset(struct iwx_softc *) { ++cancel_reset_calls; }
};

static inline uint32_t le32toh(uint32_t value) { return value; }
static inline uint32_t iwx_rx_packet_len(const struct iwx_rx_packet *packet) {
    return packet->len_n_flags & 0x3fffU;
}
static inline uint32_t iwx_rx_packet_payload_len(
    const struct iwx_rx_packet *packet) {
    return iwx_rx_packet_len(packet) - sizeof(packet->hdr);
}
static inline uint64_t iwx_pmf_monotonic_ns() { return test_now; }
static inline int iwx_pmf_arm_key_timeout(struct iwx_softc *) {
    return test_arm_error;
}
static inline int splnet() { return 0; }
static inline void splx(int) {}
static inline void timeout_del(void *timeout) {
    if (timeout == tracked_sa_query_timeout)
        ++test_sa_query_timeout_cancels;
    if (timeout == tracked_eapol_timeout)
        ++test_eapol_timeout_cancels;
}
static inline void test_explicit_bzero(void *memory, size_t length) {
    volatile uint8_t *bytes = static_cast<volatile uint8_t *>(memory);
    while (length-- != 0)
        *bytes++ = 0;
}
#define explicit_bzero test_explicit_bzero

static void ieee80211_new_state(struct ieee80211com *, int, int) {
    ++test_state_changes;
}
static void ieee80211_set_link_state(struct ieee80211com *, int state) {
    assert(state == LINK_STATE_UP);
    ++test_link_up_calls;
}

static bool iwx_pmf_key_active(struct iwx_softc *sc,
                               struct ieee80211_key *k,
                               uint8_t slot, bool requireMfp) {
KEY_ACTIVE_BODY
}

void ItlIwx::iwx_pmf_key_completion_task(struct iwx_softc *sc) {
COMPLETION_BODY
}

void ItlIwx::iwx_pmf_cancel_keys_gated(struct ieee80211com *ic,
                                       struct ieee80211_node *ni) {
DRIVER_CANCEL_BODY
}

void ieee80211_pmf_keys_cancel(struct ieee80211com *ic,
                               struct ieee80211_node *ni) {
NODE_CANCEL_BODY
}

void ieee80211_crypto_clear_groupkeys(struct ieee80211com *ic) {
GROUP_CLEANUP_BODY
}

#ifdef IEEE80211_STA_ONLY
void ieee80211_sta_security_cleanup(struct ieee80211com *ic,
                                    struct ieee80211_node *ni) {
STA_CLEANUP_BODY
}
#else
#error "STA security cleanup must be compiled for STA_ONLY"
#endif

void ieee80211_disable_rsn(struct ieee80211com *ic) {
DISABLE_RSN_BODY
}

static void cancel_bridge(struct ieee80211com *ic,
                          struct ieee80211_node *ni) {
    auto *sc = static_cast<struct iwx_softc *>(ic->ic_softc);
    auto *that = container_of(sc, ItlIwx, com);
    that->iwx_pmf_cancel_keys_gated(ic, ni);
}

static void test_delete_key(struct ieee80211com *ic,
                            struct ieee80211_node *ni,
                            struct ieee80211_key *key) {
    ++test_key_delete_calls;
    if (ni != nullptr && ni == ic->ic_bss &&
        key == &ni->ni_pairwise_key)
        ++test_pairwise_delete_calls;
    else if (ni == nullptr)
        ++test_group_delete_calls;
}

static bool bytes_are_zero(const void *memory, size_t length) {
    const auto *bytes = static_cast<const uint8_t *>(memory);
    for (size_t i = 0; i < length; ++i)
        if (bytes[i] != 0)
            return false;
    return true;
}

static struct iwx_rx_packet *make_packet(uint8_t kind, uint32_t status,
                                         bool failed,
                                         uint32_t payload_length = UINT32_MAX) {
    auto *packet = static_cast<struct iwx_rx_packet *>(
        std::calloc(1, sizeof(struct iwx_rx_packet)));
    assert(packet != nullptr);
    const uint32_t payload = payload_length == UINT32_MAX ? 4U :
        payload_length;
    packet->len_n_flags = sizeof(packet->hdr) + payload;
    packet->hdr.group_id = failed ? IWX_CMD_FAILED_MSK : 0;
    for (uint32_t i = 0; i < payload && i < sizeof(packet->data); ++i)
        packet->data[i] = i < sizeof(status) ?
            static_cast<uint8_t>(status >> (8U * i)) : 0xa5;
    return packet;
}

static struct ieee80211_key *key_for_slot(struct ieee80211com *ic,
                                          struct ieee80211_node *ni,
                                          uint8_t slot) {
    if (slot == 0)
        return &ni->ni_pairwise_key;
    assert(slot < IWX_PMF_KEY_SLOT_COUNT);
    return &ic->ic_nw_keys[slot - 1];
}

static struct iwx_pmf_key_cmd *add_command(ItlIwx *that, uint8_t slot,
                                            bool completed,
                                            uint8_t kind) {
    auto *sc = &that->com;
    auto *ni = sc->sc_ic.ic_bss;
    auto *pending = &sc->sc_pmf_key_cmd[slot];
    pending->node = ni;
    pending->key = key_for_slot(&sc->sc_ic, ni, slot);
    pending->generation = sc->sc_generation;
    pending->node_epoch = ni->ni_pmf_key_epoch;
    pending->incarnation = 100U + slot;
    pending->command_id = 0x440U + slot;
    pending->response_command_id = pending->command_id;
    pending->command_qid = IWX_DQA_CMD_QUEUE;
    pending->command_index = static_cast<uint8_t>(20 + slot);
    pending->igtk_status1_abi =
        kind == IWX_PMF_KEY_CMD_IGTK &&
        that->com.sc_pmf_igtk_status1_abi;
    pending->key_slot = slot;
    pending->command_kind = kind;
    pending->active = 1;
    pending->completed = completed;
    sc->sc_pmf_key_incarnation[slot] = pending->incarnation;
    pending->key->k_flags |= IEEE80211_KEY_FWPENDING;
    if (completed) {
        pending->response_pkt = make_packet(kind, IWX_ADD_STA_SUCCESS,
                                            false);
        auto *packet = static_cast<struct iwx_rx_packet *>(
            pending->response_pkt);
        pending->response_len = sizeof(packet->len_n_flags) +
            iwx_rx_packet_len(packet);
    }
    return pending;
}

static void setup(ItlIwx *that, bool completed = true) {
    std::memset(that, 0, sizeof(*that));
    auto *sc = &that->com;
    auto *ic = &sc->sc_ic;
    static struct ieee80211_node node;
    std::memset(&node, 0, sizeof(node));
    node.ni_flags = IEEE80211_NODE_MFP;
    node.ni_pmf_key_epoch = 22;
    node.ni_rsn_state = RNSA_SUPP_PTKDONE;
    node.ni_rsn_supp_state = RNSA_SUPP_PTKDONE;
    node.ni_pmf_key_batch_ready = 1;
    node.ni_pmf_pending_key_ids =
        IEEE80211_PMF_PENDING_GTK | IEEE80211_PMF_PENDING_IGTK;
    node.ni_pmf_pending_gtk_kid = 0;
    node.ni_pmf_pending_igtk_kid = 4;
    node.ni_pairwise_key.k_cipher = IEEE80211_CIPHER_CCMP;
    std::memset(node.ni_pairwise_key.k_key, 0xa1,
                sizeof(node.ni_pairwise_key.k_key));
    std::memset(&node.ni_ptk, 0xb2, sizeof(node.ni_ptk));
    node.ni_eapol_to = &test_link_up_calls;
    node.ni_sa_query_to = &test_now;
    node.ni_sa_query_count = 3;
    node.ni_sa_query_trid = 0x1234;
    std::memset(node.ni_sa_query_trids, 0x21,
                sizeof(node.ni_sa_query_trids));
    std::memset(node.ni_sa_query_bssid, 0x32,
                sizeof(node.ni_sa_query_bssid));
    std::memset(node.ni_sa_query_local, 0x43,
                sizeof(node.ni_sa_query_local));
    node.ni_sa_query_last_unprot.tv_sec = 17;
    node.ni_sa_query_last_unprot.tv_usec = 29;
    node.ni_replaycnt_ok = 1;
    tracked_eapol_timeout = &node.ni_eapol_to;
    tracked_sa_query_timeout = &node.ni_sa_query_to;
    ic->ic_bss = &node;
    ic->ic_flags = IEEE80211_F_RSNON;
    ic->ic_state = IEEE80211_S_RUN;
    ic->ic_def_txkey = 0;
    ic->ic_igtk_kid = 4;
    ic->ic_opmode = IEEE80211_M_STA;
    ic->ic_softc = sc;
    ic->ic_pmf_cancel_keys = cancel_bridge;
    ic->ic_delete_key = test_delete_key;
    for (uint8_t i = 0; i < 4; ++i) {
        ic->ic_nw_keys[i].k_cipher = IEEE80211_CIPHER_NONE;
        ic->ic_nw_keys[i].k_id = i;
        std::memset(ic->ic_nw_keys[i].k_key, 0x54 + i,
                    sizeof(ic->ic_nw_keys[i].k_key));
    }
    ic->ic_nw_keys[0].k_cipher = IEEE80211_CIPHER_CCMP;
    ic->ic_nw_keys[0].k_flags = IEEE80211_KEY_GROUP | IEEE80211_KEY_TX;
    ic->ic_nw_keys[4].k_cipher = IEEE80211_CIPHER_BIP;
    ic->ic_nw_keys[4].k_id = 4;
    ic->ic_nw_keys[4].k_flags = IEEE80211_KEY_GROUP | IEEE80211_KEY_IGTK;
    std::memset(ic->ic_nw_keys[4].k_key, 0x65,
                sizeof(ic->ic_nw_keys[4].k_key));
    std::memset(ic->ic_nw_keys[5].k_key, 0x76,
                sizeof(ic->ic_nw_keys[5].k_key));
    sc->sc_generation = 17;
    sc->sc_pmf_igtk_status1_abi = 1;
    add_command(that, 0, completed, IWX_PMF_KEY_CMD_ADD_STA);
    add_command(that, 1, completed, IWX_PMF_KEY_CMD_ADD_STA);
    add_command(that, 5, completed, IWX_PMF_KEY_CMD_IGTK);
}

static void seed_authorized(ItlIwx *that) {
    auto *ni = that->com.sc_ic.ic_bss;
    ni->ni_port_valid = 1;
    ni->ni_flags |= IEEE80211_NODE_PROT_MASK;
}

static void assert_closed(ItlIwx *that) {
    auto *ni = that->com.sc_ic.ic_bss;
    assert(ni->ni_port_valid == 0);
    assert((ni->ni_flags & IEEE80211_NODE_PROT_MASK) == 0);
}

static void set_igtk_response(ItlIwx *that, uint32_t payload_length,
                              uint32_t status, bool failed) {
    auto *pending = &that->com.sc_pmf_key_cmd[5];
    std::free(pending->response_pkt);
    pending->response_pkt = make_packet(IWX_PMF_KEY_CMD_IGTK, status,
                                        failed, payload_length);
    auto *packet = static_cast<struct iwx_rx_packet *>(pending->response_pkt);
    pending->response_len = sizeof(packet->len_n_flags) +
        iwx_rx_packet_len(packet);
    pending->completed = 1;
}

static void test_three_ack_barrier() {
    ItlIwx that{};
    setup(&that, true);
    auto *sc = &that.com;
    auto *ni = sc->sc_ic.ic_bss;
    auto *igtk = &sc->sc_pmf_key_cmd[5];
    std::free(igtk->response_pkt);
    igtk->response_pkt = nullptr;
    igtk->response_len = 0;
    igtk->completed = 0;

    that.iwx_pmf_key_completion_task(sc);
    assert(ni->ni_port_valid == 0);
    assert((ni->ni_flags & IEEE80211_NODE_PROT_MASK) == 0);
    assert((ni->ni_pairwise_key.k_flags & IEEE80211_KEY_FWACTIVE) != 0);
    assert((sc->sc_ic.ic_nw_keys[0].k_flags & IEEE80211_KEY_FWACTIVE) != 0);
    assert((sc->sc_ic.ic_nw_keys[4].k_flags & IEEE80211_KEY_FWACTIVE) == 0);

    igtk->response_pkt = make_packet(IWX_PMF_KEY_CMD_IGTK,
                                     IWX_ADD_STA_SUCCESS, false);
    auto *packet = static_cast<struct iwx_rx_packet *>(igtk->response_pkt);
    igtk->response_len = sizeof(packet->len_n_flags) +
        iwx_rx_packet_len(packet);
    assert(igtk->response_len == 12);
    igtk->completed = 1;
    that.iwx_pmf_key_completion_task(sc);
    assert(ni->ni_port_valid == 1);
    assert((ni->ni_flags & IEEE80211_NODE_PROT_MASK) ==
           IEEE80211_NODE_PROT_MASK);
    assert(test_link_up_calls != 0);
}

static void test_pending_failure_and_timeout_close() {
    ItlIwx pending{};
    setup(&pending, false);
    pending.iwx_pmf_key_completion_task(&pending.com);
    assert_closed(&pending);

    ItlIwx failure{};
    setup(&failure, true);
    seed_authorized(&failure);
    auto *bad = static_cast<struct iwx_rx_packet *>(
        failure.com.sc_pmf_key_cmd[1].response_pkt);
    uint32_t bad_status = 0;
    std::memcpy(bad->data, &bad_status, sizeof(bad_status));
    failure.iwx_pmf_key_completion_task(&failure.com);
    assert_closed(&failure);

    ItlIwx timeout{};
    setup(&timeout, false);
    seed_authorized(&timeout);
    timeout.com.sc_pmf_key_cmd[1].timeout_deadline_ns = test_now - 1;
    timeout.iwx_pmf_key_completion_task(&timeout.com);
    assert_closed(&timeout);
    assert(timeout.reset_calls == 1);
}

static void test_igtk_status_contract_rejects_bad_replies() {
    struct InvalidReply {
        uint32_t payload_length;
        uint32_t status;
        bool failed;
        bool pending_abi;
        bool current_abi;
        bool wrong_command;
    };
    const InvalidReply invalid[] = {
        {0, 1, false, true, true, false},   // bare response
        {1, 1, false, true, true, false},   // truncated
        {3, 1, false, true, true, false},   // truncated status word
        {5, 1, false, true, true, false},   // overlong
        {4, 0, false, true, true, false},   // non-success status
        {4, 1, true, true, true, false},    // CMD_FAILED
        {4, 1, false, false, true, false},  // unknown at submission
        {4, 1, false, true, false, false},  // identity no longer matches
        {4, 1, false, true, true, true},    // wrong command ID
    };
    for (const InvalidReply &reply : invalid) {
        ItlIwx that{};
        setup(&that, true);
        seed_authorized(&that);
        that.com.sc_pmf_igtk_status1_abi = reply.current_abi;
        that.com.sc_pmf_key_cmd[5].igtk_status1_abi = reply.pending_abi;
        set_igtk_response(&that, reply.payload_length, reply.status,
                          reply.failed);
        if (reply.wrong_command)
            ++that.com.sc_pmf_key_cmd[5].response_command_id;
        that.iwx_pmf_key_completion_task(&that.com);
        assert_closed(&that);
        assert((that.com.sc_ic.ic_nw_keys[4].k_flags &
                IEEE80211_KEY_FWACTIVE) == 0);
    }
}

static void test_stale_ack_does_not_authorize() {
    for (int stale = 0; stale != 3; ++stale) {
        ItlIwx that{};
        setup(&that, true);
        seed_authorized(&that);
        auto *sc = &that.com;
        auto *pending = &sc->sc_pmf_key_cmd[5];
        if (stale == 0)
            --pending->generation;
        else if (stale == 1)
            --pending->node_epoch;
        else
            ++sc->sc_pmf_key_incarnation[1];
        that.iwx_pmf_key_completion_task(sc);
        assert_closed(&that);
    }
}

static void test_disable_rsn_late_ack_cannot_reopen() {
    ItlIwx that{};
    setup(&that, true);
    seed_authorized(&that);
    auto *sc = &that.com;
    auto *ic = &sc->sc_ic;
    auto *ni = ic->ic_bss;
    const uint32_t epoch = ni->ni_pmf_key_epoch;
    ni->ni_flags |= IEEE80211_NODE_SA_QUERY |
        IEEE80211_NODE_SA_QUERY_FAILED | IEEE80211_NODE_PROT_MASK |
        IEEE80211_NODE_TXRXPROT;
    std::memset(ic->ic_psk, 0x5a, sizeof(ic->ic_psk));
    test_sa_query_timeout_cancels = 0;
    test_eapol_timeout_cancels = 0;
    test_key_delete_calls = 0;
    test_pairwise_delete_calls = 0;
    test_group_delete_calls = 0;

    ieee80211_disable_rsn(ic);
    assert(ni->ni_pmf_key_epoch != epoch);
    assert((ic->ic_flags & IEEE80211_F_RSNON) == 0);
    assert((ic->ic_flags & IEEE80211_F_PSK) == 0);
    assert(ic->ic_opmode == IEEE80211_M_STA);
    assert(test_sa_query_timeout_cancels == 1);
    assert(test_eapol_timeout_cancels == 1);
    assert(test_key_delete_calls == 3 && test_pairwise_delete_calls == 1 &&
           test_group_delete_calls == 2);
    assert(bytes_are_zero(&ni->ni_pairwise_key,
                          sizeof(ni->ni_pairwise_key)));
    assert(bytes_are_zero(&ni->ni_ptk, sizeof(ni->ni_ptk)));
    for (size_t i = 0; i < IEEE80211_GROUP_NKID; ++i)
        assert(bytes_are_zero(&ic->ic_nw_keys[i], sizeof(ic->ic_nw_keys[i])));
    assert(ni->ni_sa_query_count == 0 && ni->ni_sa_query_trid == 0);
    assert(bytes_are_zero(ni->ni_sa_query_trids,
                          sizeof(ni->ni_sa_query_trids)));
    assert(bytes_are_zero(ni->ni_sa_query_bssid,
                          sizeof(ni->ni_sa_query_bssid)));
    assert(bytes_are_zero(ni->ni_sa_query_local,
                          sizeof(ni->ni_sa_query_local)));
    assert(ni->ni_sa_query_last_unprot.tv_sec == 0 &&
           ni->ni_sa_query_last_unprot.tv_usec == 0);
    assert(ni->ni_replaycnt_ok == 0);
    assert(ni->ni_rsn_supp_state == RSNA_SUPP_INITIALIZE);
    assert(ic->ic_def_txkey == 0 && ic->ic_igtk_kid == 4);
    assert((ni->ni_flags & (IEEE80211_NODE_SA_QUERY |
                            IEEE80211_NODE_SA_QUERY_FAILED |
                            IEEE80211_NODE_TXRXPROT)) == 0);
    assert(bytes_are_zero(ic->ic_psk, sizeof(ic->ic_psk)));
    assert_closed(&that);

    /* These are valid ACK packets captured before disableRSN. Cancellation
     * advances the node/key incarnation before the completion body sees them. */
    that.iwx_pmf_key_completion_task(sc);
    assert_closed(&that);
}

int main() {
    test_three_ack_barrier();
    test_pending_failure_and_timeout_close();
    test_igtk_status_contract_rejects_bad_replies();
    test_stale_ack_does_not_authorize();
    test_disable_rsn_late_ack_cannot_reopen();
    std::puts("production PMF ACK completion scenarios passed");
    return 0;
}
"""


def test_pmf_completion_production_body_with_asan_ubsan() -> None:
    bodies = production_bodies()
    completion = bodies["completion"]

    # These structural checks keep the C++ harness tied to the authorization
    # edge itself, while the runtime cases exercise the parsed production body.
    assert "itl_pmf_authorize_port(" in completion
    assert "IEEE80211_NODE_TXMGMTPROT" in completion
    assert "IEEE80211_NODE_RXMGMTPROT" in completion
    authorize = completion.index("itl_pmf_authorize_port(")
    set_flags = completion.index("ni->ni_flags |=")
    port_open = completion.index("ni->ni_port_valid = 1")
    assert authorize < set_flags < port_open
    assert completion.count("IEEE80211_NODE_TXMGMTPROT") >= 2
    assert completion.count("IEEE80211_NODE_RXMGMTPROT") >= 2
    sta_cleanup = bodies["sta_cleanup"]
    disable_rsn = bodies["disable_rsn"]
    assert "ic->ic_opmode != IEEE80211_M_STA" in sta_cleanup
    assert "ieee80211_pmf_keys_cancel(ic, ni)" in sta_cleanup
    assert "timeout_del(&ni->ni_eapol_to)" in sta_cleanup
    assert "ni->ni_rsn_supp_state = RSNA_SUPP_INITIALIZE" in sta_cleanup
    assert "explicit_bzero(&ni->ni_ptk, sizeof(ni->ni_ptk))" in sta_cleanup
    assert "ieee80211_crypto_clear_groupkeys(ic)" in sta_cleanup
    assert "ic->ic_opmode == IEEE80211_M_STA" in disable_rsn
    assert "ieee80211_sta_security_cleanup(ic, ic->ic_bss)" in disable_rsn

    compiler = os.environ.get("CXX") or shutil.which("clang++") or shutil.which("c++")
    assert compiler, "a C++ compiler is required for the production-body harness"
    source = HARNESS
    for name, body in bodies.items():
        source = source.replace(
            {
                "key_active": "KEY_ACTIVE_BODY",
                "completion": "COMPLETION_BODY",
                "driver_cancel": "DRIVER_CANCEL_BODY",
                "node_cancel": "NODE_CANCEL_BODY",
                "group_cleanup": "GROUP_CLEANUP_BODY",
                "sta_cleanup": "STA_CLEANUP_BODY",
                "disable_rsn": "DISABLE_RSN_BODY",
            }[name], body)
    with tempfile.TemporaryDirectory(prefix="pmf-ack-completion-") as temp:
        temp_path = pathlib.Path(temp)
        cpp = temp_path / "pmf_ack_completion.cpp"
        binary = temp_path / "pmf_ack_completion"
        cpp.write_text(textwrap.dedent(source))
        preprocess_result = subprocess.run(
            [compiler, "-std=c++17", "-DIEEE80211_STA_ONLY=1", "-I",
             str(ROOT), "-E", str(cpp)],
            text=True,
            capture_output=True,
            check=False,
        )
        assert preprocess_result.returncode == 0, preprocess_result.stderr
        assert "void ieee80211_sta_security_cleanup" in preprocess_result.stdout
        compile_result = subprocess.run(
            [
                compiler,
                "-std=c++17",
                "-DIEEE80211_STA_ONLY=1",
                "-O1",
                "-g",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-I",
                str(ROOT),
                str(cpp),
                "-o",
                str(binary),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        assert compile_result.returncode == 0, compile_result.stderr
        run_result = subprocess.run(
            [str(binary)], text=True, capture_output=True, check=False,
            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"},
        )
        assert run_result.returncode == 0, run_result.stdout + run_result.stderr
        assert "production PMF ACK completion scenarios passed" in run_result.stdout


if __name__ == "__main__":
    test_pmf_completion_production_body_with_asan_ubsan()
    print("PMF ACK completion sanitizer test passed")
