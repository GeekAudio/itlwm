#!/usr/bin/env python3
"""Exercise the production AUTH caller and ADD_STA retry cleanup chain.

This compiles the actual iwx_auth() and iwx_add_sta_cmd() bodies. PHY, MAC,
binding, and command transport are deterministic firmware boundaries, while the
production flag commit, rm_binding cleanup, and retry decision stay intact.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


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


HARNESS_PREFIX = r"""
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

constexpr int EIO = 5;
constexpr int IEEE80211_M_MONITOR = 1;
constexpr int IEEE80211_M_STA = 2;
constexpr int IEEE80211_S_AUTH = 2;
constexpr int IEEE80211_S_ASSOC = 3;
constexpr int IEEE80211_CHAN_WIDTH_20_NOHT = 0;
constexpr int IEEE80211_CHAN_WIDTH_20 = 1;
constexpr int IEEE80211_CHAN_WIDTH_40 = 2;
constexpr int IEEE80211_CHAN_WIDTH_80 = 3;
constexpr int IEEE80211_CHAN_WIDTH_160 = 4;
constexpr int IEEE80211_CHAN_WIDTH_80P80 = 5;
constexpr uint32_t IEEE80211_NODE_HT = 1u << 0;
constexpr uint32_t IEEE80211_NODE_QOS = 1u << 1;
constexpr uint32_t IEEE80211_NODE_HT_SGI20 = 1u << 2;
constexpr uint32_t IEEE80211_NODE_HT_SGI40 = 1u << 3;
constexpr uint32_t IEEE80211_NODE_VHT = 1u << 4;
constexpr uint32_t IEEE80211_NODE_VHT_SGI80 = 1u << 5;
constexpr uint32_t IEEE80211_NODE_VHT_SGI160 = 1u << 6;
constexpr uint32_t IEEE80211_NODE_HE = 1u << 7;
constexpr int IEEE80211_DUR_TU = 100;
constexpr uint32_t IWX_FLAG_STA_ACTIVE = 1u << 0;
constexpr uint32_t IWX_FLAG_BINDING_ACTIVE = 1u << 1;
constexpr uint32_t IWX_FLAG_MAC_ACTIVE = 1u << 2;
constexpr uint32_t IWX_STATION_ID = 0;
constexpr uint32_t IWX_MONITOR_STA_ID = 2;
constexpr uint32_t IWX_STA_GENERAL_PURPOSE = 1;
constexpr uint32_t IWX_STA_LINK = 2;
constexpr uint32_t IWX_STA_FLG_FAT_EN_MSK = 1u << 0;
constexpr uint32_t IWX_STA_FLG_MIMO_EN_MSK = 1u << 1;
constexpr uint32_t IWX_STA_FLG_MAX_AGG_SIZE_MSK = 1u << 2;
constexpr uint32_t IWX_STA_FLG_AGG_MPDU_DENS_MSK = 1u << 3;
constexpr uint32_t IWX_STA_FLG_FAT_EN_160MHZ = 1u << 4;
constexpr uint32_t IWX_STA_FLG_FAT_EN_80MHZ = 1u << 5;
constexpr uint32_t IWX_STA_FLG_FAT_EN_40MHZ = 1u << 6;
constexpr uint32_t IWX_STA_FLG_FAT_EN_20MHZ = 1u << 7;
constexpr uint32_t IWX_STA_FLG_MIMO_EN_MIMO2 = 1u << 8;
constexpr uint32_t IWX_STA_FLG_MIMO_EN_SISO = 1u << 9;
constexpr uint32_t IWX_STA_FLG_MAX_AGG_SIZE_SHIFT = 12;
constexpr uint32_t IWX_STA_FLG_MAX_AGG_SIZE_4M = 9u << IWX_STA_FLG_MAX_AGG_SIZE_SHIFT;
constexpr uint32_t IWX_STA_FLG_MAX_AGG_SIZE_64K = 3u << IWX_STA_FLG_MAX_AGG_SIZE_SHIFT;
constexpr uint32_t IWX_STA_FLG_AGG_MPDU_DENS_2US = 1u << 13;
constexpr uint32_t IWX_STA_FLG_AGG_MPDU_DENS_4US = 2u << 13;
constexpr uint32_t IWX_STA_FLG_AGG_MPDU_DENS_8US = 3u << 13;
constexpr uint32_t IWX_STA_FLG_AGG_MPDU_DENS_16US = 4u << 13;
constexpr uint32_t IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK = 0x3;
constexpr uint32_t IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT = 0;
constexpr uint32_t IEEE80211_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_MASK = 0x3;
constexpr int IEEE80211_AMPDU_PARAM_SS = 0x3;
constexpr int IEEE80211_AMPDU_PARAM_SS_2 = 1;
constexpr int IEEE80211_AMPDU_PARAM_SS_4 = 2;
constexpr int IEEE80211_AMPDU_PARAM_SS_8 = 3;
constexpr int IEEE80211_AMPDU_PARAM_SS_16 = 4;
constexpr int IWX_ADD_STA = 10;
constexpr uint32_t IWX_ADD_STA_SUCCESS = 0;
constexpr uint32_t IWX_ADD_STA_STATUS_MASK = 0xff;
constexpr uint32_t IWX_FW_CTXT_ACTION_ADD = 1;
constexpr uint32_t IWX_FW_CTXT_ACTION_REMOVE = 2;
constexpr uint32_t IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD = 1u << 0;
constexpr int IWX_DQA_INJECT_MONITOR_QUEUE = 1;
constexpr int IWX_MGMT_TID = 0;

#define XYLog(...) ((void)0)
#define DEVNAME(sc) "test"
#define splassert(level) ((void)0)
#define IPL_NET 0
#define htole32(value) (value)
#define htole16(value) (value)
#define IWX_FW_CMD_ID_AND_COLOR(id, color) (((id) << 8) | (color))
#define IEEE80211_ADDR_COPY(dst, src) std::memcpy((dst), (src), 6)
#define min(a, b) ((a) < (b) ? (a) : (b))

static const uint8_t etheranyaddr[6] = {};
static unsigned gStaCommandCount = 0;
static unsigned gBindingAddCount = 0, gBindingRemoveCount = 0;
static unsigned gMacAddCount = 0, gMacRemoveCount = 0;
static unsigned gRmStaCount = 0, gMgmtQueueCount = 0, gStatsCount = 0;
static int gTransportError = 0;
static uint32_t gFirmwareStatus = IWX_ADD_STA_SUCCESS;

struct ieee80211_channel { int identity = 0; };
struct iwx_phy_ctxt { int identity = 0; };
struct ieee80211_he_cap_elem { uint8_t mac_cap_info[6]{}; };
struct ieee80211_node {
    uint32_t ni_flags = 0;
    int ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
    uint8_t ni_macaddr[6]{};
    uint16_t ni_intval = 0;
    ieee80211_channel *ni_chan = nullptr;
    uint32_t ni_rx_nss = 1, ni_vhtcaps = 0;
    ieee80211_he_cap_elem ni_he_cap_elem{};
};
struct iwx_node {
    ieee80211_node in_ni{}; // Production casts ic_bss back to iwx_node.
    uint8_t in_macaddr[6]{};
    uint32_t in_id = 0, in_color = 0;
    iwx_phy_ctxt *in_phyctxt = nullptr;
};
struct iwx_tx_ring { size_t ring_count = 16; };
struct ieee80211com {
    int ic_opmode = IEEE80211_M_STA, ic_state = IEEE80211_S_AUTH;
    int ic_ampdu_params = 0;
    ieee80211_node *ic_bss = nullptr;
    ieee80211_channel *ic_ibss_chan = nullptr;
};
struct iwx_softc {
    uint32_t sc_flags = 0;
    int sc_generation = 7;
    uint32_t sc_enabled_capa[1]{};
    iwx_phy_ctxt sc_phyctxt[1]{};
    iwx_tx_ring txq[2]{};
    ieee80211com sc_ic{};
};
struct iwx_add_sta_cmd {
    uint8_t sta_id = 0, station_type = 0;
    uint32_t mac_id_n_color = 0;
    uint8_t addr[6]{};
    uint8_t add_modify = 0;
    uint32_t station_flags_msk = 0, station_flags = 0;
    uint16_t tid_disable_tx = 0;
};

static uint32_t u8_get_bits(uint8_t value, uint32_t mask) { return value & mask; }
static bool iwx_mimo_enabled(iwx_softc *) { return false; }
static bool isset(const uint32_t *, uint32_t) { return false; }
static int iwx_send_cmd_pdu_status(iwx_softc *, uint32_t, size_t,
                                   const void *, uint32_t *status)
{
    ++gStaCommandCount;
    *status = gFirmwareStatus;
    return gTransportError;
}

struct ItlIwx {
    int iwx_auth(iwx_softc *);
    int iwx_add_sta_cmd(iwx_softc *, iwx_node *, int);
    int iwx_phy_ctxt_update(iwx_softc *, iwx_phy_ctxt *, ieee80211_channel *,
                            uint8_t, uint8_t, uint32_t) { return 0; }
    int iwx_mac_ctxt_cmd(iwx_softc *, iwx_node *, uint32_t, uint32_t);
    int iwx_binding_cmd(iwx_softc *, iwx_node *, uint32_t);
    int iwx_rm_sta_cmd(iwx_softc *, iwx_node *);
    int iwx_enable_txq(iwx_softc *, int, int, int, size_t) { return 0; }
    int iwx_enable_mgmt_queue(iwx_softc *) { ++gMgmtQueueCount; return 0; }
    int iwx_clear_statistics(iwx_softc *) { ++gStatsCount; return 0; }
    int iwx_schedule_protect_session(iwx_softc *, iwx_node *, uint32_t) { return 0; }
    int iwx_protect_session(iwx_softc *, iwx_node *, uint32_t, uint32_t) { return 0; }
};
"""


HARNESS_SUFFIX = r"""
int ItlIwx::iwx_mac_ctxt_cmd(iwx_softc *, iwx_node *, uint32_t action, uint32_t)
{
    if (action == IWX_FW_CTXT_ACTION_ADD) ++gMacAddCount;
    else if (action == IWX_FW_CTXT_ACTION_REMOVE) ++gMacRemoveCount;
    return 0;
}
int ItlIwx::iwx_binding_cmd(iwx_softc *, iwx_node *, uint32_t action)
{
    if (action == IWX_FW_CTXT_ACTION_ADD) ++gBindingAddCount;
    else if (action == IWX_FW_CTXT_ACTION_REMOVE) ++gBindingRemoveCount;
    return 0;
}
int ItlIwx::iwx_rm_sta_cmd(iwx_softc *, iwx_node *)
{
    ++gRmStaCount;
    return 0;
}

static void resetCounters()
{
    gStaCommandCount = gBindingAddCount = gBindingRemoveCount = 0;
    gMacAddCount = gMacRemoveCount = gRmStaCount = 0;
    gMgmtQueueCount = gStatsCount = 0;
}
static void setup(iwx_softc &sc, iwx_node &node, ieee80211_channel &channel)
{
    sc = {};
    node = {};
    sc.sc_generation = 7;
    sc.sc_ic.ic_opmode = IEEE80211_M_STA;
    sc.sc_ic.ic_state = IEEE80211_S_AUTH;
    sc.sc_ic.ic_bss = &node.in_ni;
    node.in_ni.ni_chan = &channel;
}

int main()
{
    ItlIwx driver;
    iwx_softc sc{};
    iwx_node node{};
    ieee80211_channel channel{};

    // Transport timeout: AUTH must unwind binding/MAC; the retry must issue
    // ADD_STA again rather than trusting a stale STA_ACTIVE software bit.
    resetCounters(); setup(sc, node, channel);
    gTransportError = 60;
    gFirmwareStatus = IWX_ADD_STA_SUCCESS;
    assert(driver.iwx_auth(&sc) == 60);
    assert((sc.sc_flags & IWX_FLAG_STA_ACTIVE) == 0);
    assert((sc.sc_flags & (IWX_FLAG_BINDING_ACTIVE | IWX_FLAG_MAC_ACTIVE)) == 0);
    assert(gStaCommandCount == 1 && gRmStaCount == 0);
    assert(gBindingAddCount == 1 && gBindingRemoveCount == 1);
    assert(gMacAddCount == 1 && gMacRemoveCount == 1);
    assert(gMgmtQueueCount == 0 && gStatsCount == 0);

    gTransportError = 0;
    assert(driver.iwx_auth(&sc) == 0);
    assert(gStaCommandCount == 2);
    assert((sc.sc_flags & IWX_FLAG_STA_ACTIVE) != 0);
    assert(gMgmtQueueCount == 1 && gStatsCount == 1);

    // A non-success status, including status bits outside the low byte, is a
    // firmware rejection. The failed AUTH path removes only resources whose
    // creation is proven and permits a fresh ADD_STA attempt.
    resetCounters(); setup(sc, node, channel);
    gTransportError = 0;
    gFirmwareStatus = 0x102;
    assert(driver.iwx_auth(&sc) == EIO);
    assert((sc.sc_flags & IWX_FLAG_STA_ACTIVE) == 0);
    assert((sc.sc_flags & (IWX_FLAG_BINDING_ACTIVE | IWX_FLAG_MAC_ACTIVE)) == 0);
    assert(gStaCommandCount == 1 && gRmStaCount == 0);
    assert(gBindingAddCount == 1 && gBindingRemoveCount == 1);
    assert(gMacAddCount == 1 && gMacRemoveCount == 1);
    assert(gMgmtQueueCount == 0 && gStatsCount == 0);

    gFirmwareStatus = IWX_ADD_STA_SUCCESS;
    assert(driver.iwx_auth(&sc) == 0);
    assert(gStaCommandCount == 2);
    assert((sc.sc_flags & IWX_FLAG_STA_ACTIVE) != 0);
    assert(gMgmtQueueCount == 1 && gStatsCount == 1);

    // Updating an already-active station must preserve its previously valid
    // active bit when transport or firmware reports failure, while still
    // sending the update command (update=1 bypasses the no-op fast path).
    resetCounters(); setup(sc, node, channel);
    sc.sc_flags |= IWX_FLAG_STA_ACTIVE;
    gTransportError = 60;
    gFirmwareStatus = IWX_ADD_STA_SUCCESS;
    assert(driver.iwx_add_sta_cmd(&sc, &node, 1) == 60);
    assert((sc.sc_flags & IWX_FLAG_STA_ACTIVE) != 0);
    assert(gStaCommandCount == 1);
    gTransportError = 0;
    gFirmwareStatus = 0x102;
    assert(driver.iwx_add_sta_cmd(&sc, &node, 1) == EIO);
    assert((sc.sc_flags & IWX_FLAG_STA_ACTIVE) != 0);
    assert(gStaCommandCount == 2);
    gFirmwareStatus = IWX_ADD_STA_SUCCESS;
    assert(driver.iwx_add_sta_cmd(&sc, &node, 1) == 0);
    assert((sc.sc_flags & IWX_FLAG_STA_ACTIVE) != 0);
    assert(gStaCommandCount == 3);

    std::puts("PASS: production AUTH cleanup and retry after ADD_STA transport/FW-status failure");
    return 0;
}
"""


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    auth = production_function(source, "int ItlIwx::\niwx_auth(")
    add_sta = production_function(source, "int ItlIwx::\niwx_add_sta_cmd(")
    compiler = shutil.which("clang++") or shutil.which("c++")
    if not compiler:
        raise SystemExit("No C++ compiler found")
    with tempfile.TemporaryDirectory(prefix="test082-auth-retry-") as directory:
        harness = Path(directory) / "test082_auth_retry_cleanup.cpp"
        binary = Path(directory) / "test082_auth_retry_cleanup"
        harness.write_text(
            HARNESS_PREFIX + "\n" + auth + "\n" + add_sta + "\n" + HARNESS_SUFFIX,
            encoding="utf-8",
        )
        result = subprocess.run(
            [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", str(harness), "-o", str(binary)],
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
