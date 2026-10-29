#!/usr/bin/env python3
"""Exercise the live AUTH session-protection call chain and wire payload.

The harness extracts iwx_auth(), iwx_schedule_protect_session(),
iwx_protect_session(), both packed command structs, the command-ID helper,
and constants from this working tree. Firmware send boundaries are replaced
with deterministic capture stubs; no firmware, RF, or interface is touched.

The cap-54 timing policy follows the OpenBSD direction in
openbsd/src commit a08da3bef5a4ce043b2281c6b0800e04855ac47e: 9 * beacon
interval TU, or 900 TU when the beacon interval is unavailable. This test
checks host-side construction only; it does not claim firmware acceptance.
"""

from __future__ import annotations

import ast
import operator
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
REG = ROOT / "itlwm/hal_iwx/if_iwxreg.h"
VAR = ROOT / "itlwm/hal_iwx/if_iwxvar.h"
IEEE = ROOT / "itl80211/openbsd/net80211/ieee80211.h"


def extract_function(source: str, marker: str) -> str:
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"missing production function: {marker}")
    opening = source.find("{", start)
    depth, index, state = 0, opening, "code"
    while index < len(source):
        ch = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state, index = "line", index + 2
                continue
            if ch == "/" and nxt == "*":
                state, index = "block", index + 2
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
                state, index = "code", index + 2
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


def packed_struct(header: str, name: str) -> str:
    marker = f"struct {name} {{"
    start = header.find(marker)
    end_marker = "} __packed;"
    end = header.find(end_marker, start)
    if start < 0 or end < 0:
        raise AssertionError(f"missing production packed struct: {name}")
    return header[start : end + len(end_marker)]


def macro_block(header: str, name: str) -> str:
    lines = header.splitlines()
    pattern = re.compile(rf"^\s*#define\s+{re.escape(name)}(?:\s|\()")
    for index, line in enumerate(lines):
        if pattern.match(line):
            block = [line]
            while block[-1].rstrip().endswith("\\"):
                index += 1
                block.append(lines[index])
            return "\n".join(block)
    raise AssertionError(f"missing production macro: {name}")


_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.BitOr: operator.or_,
    ast.BitAnd: operator.and_,
    ast.BitXor: operator.xor,
}
_UNARYOPS = {ast.UAdd: operator.pos, ast.USub: operator.neg, ast.Invert: operator.invert}


def _safe_int_expr(expression: str) -> int:
    tree = ast.parse(expression, mode="eval")

    def visit(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
            return _BINOPS[type(node.op)](visit(node.left), visit(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARYOPS:
            return _UNARYOPS[type(node.op)](visit(node.operand))
        raise AssertionError(f"unsupported numeric macro expression: {expression}")

    return visit(tree)


def macro_int(headers: tuple[str, ...], name: str, seen: frozenset[str] = frozenset()) -> int:
    if name in seen:
        raise AssertionError(f"recursive macro while resolving {name}")
    block = next((macro_block(header, name) for header in headers if re.search(
        rf"^\s*#define\s+{re.escape(name)}(?:\s|\()", header, re.MULTILINE
    )), None)
    if block is None:
        raise AssertionError(f"missing numeric macro: {name}")
    lines = block.replace("\\\n", " ").splitlines()
    expression = re.sub(r"^\s*#define\s+\w+\s*", "", lines[0], count=1)
    if len(lines) > 1:
        expression += " " + " ".join(lines[1:])
    expression = re.sub(r"/\*.*?\*/|//.*", "", expression).strip()
    expression = re.sub(r"\b(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]+\b", r"\1", expression)

    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", expression))
    for identifier in sorted(identifiers, key=len, reverse=True):
        if identifier == name:
            raise AssertionError(f"unsupported self-reference in macro {name}")
        has_definition = any(re.search(
            rf"^\s*#define\s+{re.escape(identifier)}(?:\s|\()", header, re.MULTILINE
        ) for header in headers)
        if has_definition:
            value = macro_int(headers, identifier, seen | {name})
            expression = re.sub(rf"\b{re.escape(identifier)}\b", str(value), expression)
        else:
            raise AssertionError(f"unresolved identifier {identifier} in {name}")
    return _safe_int_expr(expression)


def numeric_constants(reg: str, var: str, ieee: str) -> dict[str, int]:
    headers = (reg, var, ieee)
    names = {
        "IEEE80211_DUR_TU": headers,
        "IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK": headers,
        "IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT": headers,
        "IEEE80211_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_MASK": headers,
        "IEEE80211_AMPDU_PARAM_SS": headers,
        "IEEE80211_AMPDU_PARAM_SS_2": headers,
        "IEEE80211_AMPDU_PARAM_SS_4": headers,
        "IEEE80211_AMPDU_PARAM_SS_8": headers,
        "IEEE80211_AMPDU_PARAM_SS_16": headers,
        "IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD": headers,
        "IWX_ADD_STA": headers,
        "IWX_ADD_STA_SUCCESS": headers,
        "IWX_ADD_STA_STATUS_MASK": headers,
        "IWX_STATION_ID": headers,
        "IWX_STA_GENERAL_PURPOSE": headers,
        "IWX_STA_LINK": headers,
        "IWX_STA_FLG_FAT_EN_MSK": headers,
        "IWX_STA_FLG_MIMO_EN_MSK": headers,
        "IWX_STA_FLG_MAX_AGG_SIZE_MSK": headers,
        "IWX_STA_FLG_AGG_MPDU_DENS_MSK": headers,
        "IWX_STA_FLG_FAT_EN_160MHZ": headers,
        "IWX_STA_FLG_FAT_EN_80MHZ": headers,
        "IWX_STA_FLG_FAT_EN_40MHZ": headers,
        "IWX_STA_FLG_FAT_EN_20MHZ": headers,
        "IWX_STA_FLG_MIMO_EN_MIMO2": headers,
        "IWX_STA_FLG_MIMO_EN_SISO": headers,
        "IWX_STA_FLG_MAX_AGG_SIZE_SHIFT": headers,
        "IWX_STA_FLG_MAX_AGG_SIZE_4M": headers,
        "IWX_STA_FLG_MAX_AGG_SIZE_64K": headers,
        "IWX_STA_FLG_AGG_MPDU_DENS_2US": headers,
        "IWX_STA_FLG_AGG_MPDU_DENS_4US": headers,
        "IWX_STA_FLG_AGG_MPDU_DENS_8US": headers,
        "IWX_STA_FLG_AGG_MPDU_DENS_16US": headers,
        "IWX_FW_CTXT_ACTION_ADD": headers,
        "IWX_FW_CTXT_ACTION_REMOVE": headers,
        "IWX_MAC_CONF_GROUP": headers,
        "IWX_SESSION_PROTECTION_CMD": headers,
        "IWX_SESSION_PROTECT_CONF_ASSOC": headers,
        "IWX_TE_BSS_STA_AGGRESSIVE_ASSOC": headers,
        "IWX_TE_V2_FRAG_NONE": headers,
        "IWX_TE_V2_NOTIF_HOST_EVENT_START": headers,
        "IWX_TE_V2_NOTIF_HOST_EVENT_END": headers,
        "IWX_T2_V2_START_IMMEDIATELY": headers,
        "IWX_DQA_INJECT_MONITOR_QUEUE": headers,
        "IWX_MGMT_TID": headers,
        "IWX_MONITOR_STA_ID": headers,
        "IWX_FLAG_MAC_ACTIVE": headers,
        "IWX_FLAG_BINDING_ACTIVE": headers,
        "IWX_FLAG_STA_ACTIVE": headers,
        "IWX_FLAG_TE_ACTIVE": headers,
        "IWX_FW_CTXT_ID_POS": headers,
        "IWX_FW_CTXT_COLOR_POS": headers,
    }
    return {name: macro_int(source_headers, name) for name, source_headers in names.items()}


HARNESS = r"""
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#define __packed __attribute__((packed))
constexpr int IEEE80211_M_MONITOR = 1;
constexpr int IEEE80211_M_STA = 2;
constexpr int IEEE80211_CHAN_WIDTH_20_NOHT = 0;
constexpr uint32_t IEEE80211_NODE_HT = 1u << 0;
constexpr uint32_t IEEE80211_NODE_QOS = 1u << 1;
constexpr uint32_t IEEE80211_NODE_HT_SGI20 = 1u << 2;
constexpr uint32_t IEEE80211_NODE_HT_SGI40 = 1u << 3;
constexpr uint32_t IEEE80211_NODE_VHT = 1u << 4;
constexpr uint32_t IEEE80211_NODE_VHT_SGI80 = 1u << 5;
constexpr uint32_t IEEE80211_NODE_VHT_SGI160 = 1u << 6;
constexpr uint32_t IEEE80211_NODE_HE = 1u << 7;

@@CONSTANTS@@

#define IWX_FW_CTXT_ID_MSK (0xff << IWX_FW_CTXT_ID_POS)
#define IWX_FW_CTXT_COLOR_MSK (0xff << IWX_FW_CTXT_COLOR_POS)
@@ID_COLOR_MACRO@@

#define XYLog(...) ((void)0)
#define DEVNAME(sc) "test"
#define DPRINTFN(level, args) ((void)0)
#define splassert(level) ((void)0)
#define IPL_NET 0
#define DELAY(value) ((void)0)
#define IEEE80211_ADDR_COPY(dst, src) std::memcpy((dst), (src), 6)

static uint32_t host_to_le32(uint32_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return value;
#else
    return __builtin_bswap32(value);
#endif
}
static uint16_t host_to_le16(uint16_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return value;
#else
    return __builtin_bswap16(value);
#endif
}
#define htole32(value) host_to_le32(static_cast<uint32_t>(value))
#define htole16(value) host_to_le16(static_cast<uint16_t>(value))

@@CMD_ID_HELPER@@
@@SESSION_STRUCT@@
@@TIME_EVENT_STRUCT@@

struct ieee80211_channel { int marker = 0; };
struct iwx_phy_ctxt { int marker = 0; };
struct ieee80211_node {
    int ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
    uint32_t ni_flags = 0;
    uint8_t ni_macaddr[6]{};
    uint16_t ni_intval = 0;
    ieee80211_channel *ni_chan = nullptr;
};
struct iwx_node {
    ieee80211_node in_ni{}; // Production casts ic_bss back to iwx_node.
    uint8_t in_macaddr[6]{};
    uint32_t in_id = 0, in_color = 0;
    iwx_phy_ctxt *in_phyctxt = nullptr;
};
struct ieee80211com {
    int ic_opmode = IEEE80211_M_STA;
    int ic_state = 0;
    ieee80211_node *ic_bss = nullptr;
    ieee80211_channel *ic_ibss_chan = nullptr;
};
struct iwx_tx_ring { size_t ring_count = 16; };
struct iwx_softc {
    uint32_t sc_flags = 0;
    int sc_generation = 1;
    uint8_t sc_enabled_capa[16]{};
    iwx_phy_ctxt sc_phyctxt[1]{};
    iwx_tx_ring txq[3]{};
    ieee80211com sc_ic{};
};

static bool isset(const uint8_t *bits, uint32_t bit)
{ return (bits[bit / 8] & (1u << (bit % 8))) != 0; }
static void set_capability(uint8_t *bits, uint32_t bit, bool enabled)
{
    const uint8_t mask = static_cast<uint8_t>(1u << (bit % 8));
    if (enabled) bits[bit / 8] |= mask;
    else bits[bit / 8] &= static_cast<uint8_t>(~mask);
}
static uint32_t read_le32(const std::vector<uint8_t> &bytes, size_t offset)
{
    assert(offset + 4 <= bytes.size());
    return static_cast<uint32_t>(bytes[offset]) |
        (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
        (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
        (static_cast<uint32_t>(bytes[offset + 3]) << 24);
}
static uint16_t read_le16(const std::vector<uint8_t> &bytes, size_t offset)
{
    assert(offset + 2 <= bytes.size());
    return static_cast<uint16_t>(bytes[offset]) |
        (static_cast<uint16_t>(bytes[offset + 1]) << 8);
}

static unsigned gSessionSends = 0, gLegacySends = 0, gMgmtQueueStarts = 0;
static unsigned gMonitorQueueStarts = 0;
static uint32_t gSessionCommandId = 0, gSessionFlags = 0;
static uint16_t gSessionLength = 0;
static std::vector<uint8_t> gSessionPayload, gLegacyPayload;
static int gSessionTransportError = 0, gLegacyTransportError = 0;

class ItlIwx {
public:
    int iwx_auth(iwx_softc *);
    int iwx_schedule_protect_session(iwx_softc *, iwx_node *, uint32_t);
    void iwx_protect_session(iwx_softc *, iwx_node *, uint32_t, uint32_t);
    int iwx_send_cmd_pdu(iwx_softc *, uint32_t, uint32_t, uint16_t, const void *);
    int iwx_send_time_event_cmd(iwx_softc *, const iwx_time_event_cmd *);
    int iwx_phy_ctxt_update(iwx_softc *, iwx_phy_ctxt *, ieee80211_channel *,
                            uint8_t, uint8_t, uint32_t) { return 0; }
    int iwx_mac_ctxt_cmd(iwx_softc *, iwx_node *, uint32_t, uint32_t) { return 0; }
    int iwx_binding_cmd(iwx_softc *, iwx_node *, uint32_t) { return 0; }
    int iwx_add_sta_cmd(iwx_softc *, iwx_node *, int) { return 0; }
    int iwx_rm_sta_cmd(iwx_softc *, iwx_node *) { return 0; }
    int iwx_enable_txq(iwx_softc *, int sta, int qid, int tid, size_t)
    {
        assert(sta == IWX_MONITOR_STA_ID);
        assert(qid == IWX_DQA_INJECT_MONITOR_QUEUE);
        assert(tid == IWX_MGMT_TID);
        ++gMonitorQueueStarts;
        return 0;
    }
    int iwx_enable_mgmt_queue(iwx_softc *) { ++gMgmtQueueStarts; return 0; }
    int iwx_clear_statistics(iwx_softc *) { return 0; }
};

int ItlIwx::iwx_send_cmd_pdu(iwx_softc *, uint32_t commandId, uint32_t flags,
                            uint16_t length, const void *payload)
{
    ++gSessionSends;
    gSessionCommandId = commandId;
    gSessionFlags = flags;
    gSessionLength = length;
    const auto *bytes = static_cast<const uint8_t *>(payload);
    gSessionPayload.assign(bytes, bytes + length);
    return gSessionTransportError;
}
int ItlIwx::iwx_send_time_event_cmd(iwx_softc *, const iwx_time_event_cmd *cmd)
{
    ++gLegacySends;
    const auto *bytes = reinterpret_cast<const uint8_t *>(cmd);
    gLegacyPayload.assign(bytes, bytes + sizeof(*cmd));
    return gLegacyTransportError;
}

@@AUTH_FUNCTION@@
@@SESSION_HELPER@@
@@LEGACY_HELPER@@

static void reset_capture()
{
    gSessionSends = gLegacySends = gMgmtQueueStarts = gMonitorQueueStarts = 0;
    gSessionCommandId = gSessionFlags = 0;
    gSessionLength = 0;
    gSessionPayload.clear();
    gLegacyPayload.clear();
    gSessionTransportError = gLegacyTransportError = 0;
}
static void setup(iwx_softc &sc, iwx_node &node, ieee80211_channel &channel)
{
    sc = {};
    node = {};
    sc.sc_generation = 7;
    sc.sc_ic.ic_opmode = IEEE80211_M_STA;
    sc.sc_ic.ic_bss = &node.in_ni;
    sc.sc_ic.ic_ibss_chan = &channel;
    node.in_id = 0x12;
    node.in_color = 0x34;
    node.in_ni.ni_chan = &channel;
}

static void assert_session_payload(uint32_t durationTu)
{
    static_assert(sizeof(iwx_session_prot_cmd) == 24,
                  "production session-protection ABI must remain 24 bytes");
    assert(gSessionSends == 1 && gLegacySends == 0);
    assert(gSessionFlags == 0);
    assert(gSessionCommandId == iwx_cmd_id(IWX_SESSION_PROTECTION_CMD,
                                           IWX_MAC_CONF_GROUP, 0));
    assert(gSessionLength == 24 && gSessionPayload.size() == 24);
    assert(read_le32(gSessionPayload, 0) ==
           IWX_FW_CMD_ID_AND_COLOR(0x12, 0x34));
    assert(read_le32(gSessionPayload, 4) == IWX_FW_CTXT_ACTION_ADD);
    assert(read_le32(gSessionPayload, 8) == IWX_SESSION_PROTECT_CONF_ASSOC);
    assert(read_le32(gSessionPayload, 12) == durationTu);
    // The production ABI names both trailing words unused; they must stay zero.
    assert(read_le32(gSessionPayload, 16) == 0);
    assert(read_le32(gSessionPayload, 20) == 0);
}

static void run_cap54_case(ItlIwx &driver, uint16_t beaconInterval,
                           uint32_t expectedDuration)
{
    reset_capture();
    iwx_softc sc{};
    iwx_node node{};
    ieee80211_channel channel{};
    setup(sc, node, channel);
    node.in_ni.ni_intval = beaconInterval;
    set_capability(sc.sc_enabled_capa,
                   IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD, true);
    assert(driver.iwx_auth(&sc) == 0);
    assert(gMgmtQueueStarts == 1 && gMonitorQueueStarts == 0);
    assert_session_payload(expectedDuration);
}

static void run_legacy_case(ItlIwx &driver, uint16_t beaconInterval,
                            uint32_t expectedDuration, uint32_t expectedDelay)
{
    reset_capture();
    iwx_softc sc{};
    iwx_node node{};
    ieee80211_channel channel{};
    setup(sc, node, channel);
    node.in_ni.ni_intval = beaconInterval;
    assert(driver.iwx_auth(&sc) == 0);
    static_assert(sizeof(iwx_time_event_cmd) == 36,
                  "production legacy time-event ABI must remain 36 bytes");
    assert(gSessionSends == 0 && gLegacySends == 1);
    assert(gLegacyPayload.size() == 36);
    assert(read_le32(gLegacyPayload, 0) ==
           IWX_FW_CMD_ID_AND_COLOR(0x12, 0x34));
    assert(read_le32(gLegacyPayload, 4) == IWX_FW_CTXT_ACTION_ADD);
    assert(read_le32(gLegacyPayload, 8) == IWX_TE_BSS_STA_AGGRESSIVE_ASSOC);
    assert(read_le32(gLegacyPayload, 12) == 0);
    assert(read_le32(gLegacyPayload, 16) == expectedDelay);
    assert(read_le32(gLegacyPayload, 20) == 0);
    assert(read_le32(gLegacyPayload, 24) == 1);
    assert(read_le32(gLegacyPayload, 28) == expectedDuration);
    assert(gLegacyPayload[32] == 1);
    assert(gLegacyPayload[33] == IWX_TE_V2_FRAG_NONE);
    const uint16_t expectedPolicy =
        IWX_TE_V2_NOTIF_HOST_EVENT_START |
        IWX_TE_V2_NOTIF_HOST_EVENT_END | IWX_T2_V2_START_IMMEDIATELY;
    assert(read_le16(gLegacyPayload, 34) == expectedPolicy);
}

int main()
{
    ItlIwx driver;

    // Capability 54 path: TU values are copied to the real 24-byte command.
    run_cap54_case(driver, 0, 900);
    run_cap54_case(driver, 100, 900);
    run_cap54_case(driver, 120, 1080);
    run_cap54_case(driver, 65535, 589815);

    // Capability-off behavior stays on the legacy 36-byte time-event path.
    run_legacy_case(driver, 100, 200, 50);
    run_legacy_case(driver, 120, 240, 60);
    run_legacy_case(driver, 0, IEEE80211_DUR_TU, 0);

    // The production caller must return a transport failure from the helper.
    reset_capture();
    iwx_softc failedSc{};
    iwx_node failedNode{};
    ieee80211_channel failedChannel{};
    setup(failedSc, failedNode, failedChannel);
    failedNode.in_ni.ni_intval = 120;
    set_capability(failedSc.sc_enabled_capa,
                   IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD, true);
    gSessionTransportError = EIO;
    assert(driver.iwx_auth(&failedSc) == EIO);
    assert_session_payload(1080);

    // Monitor AUTH exits before either station-session protection mechanism.
    reset_capture();
    iwx_softc monitorSc{};
    iwx_node monitorNode{};
    ieee80211_channel monitorChannel{};
    setup(monitorSc, monitorNode, monitorChannel);
    monitorSc.sc_ic.ic_opmode = IEEE80211_M_MONITOR;
    monitorNode.in_ni.ni_intval = 100;
    set_capability(monitorSc.sc_enabled_capa,
                   IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD, true);
    assert(driver.iwx_auth(&monitorSc) == 0);
    assert(gSessionSends == 0 && gLegacySends == 0);
    assert(gMgmtQueueStarts == 0 && gMonitorQueueStarts == 1);

    std::puts("PASS: Test083 production AUTH/session helpers, 24-byte ABI, legacy path, and boundaries");
    return 0;
}
"""


def render_harness() -> str:
    driver = DRIVER.read_text(encoding="utf-8")
    reg = REG.read_text(encoding="utf-8")
    var = VAR.read_text(encoding="utf-8")
    ieee = IEEE.read_text(encoding="utf-8")
    all_constants = numeric_constants(reg, var, ieee)
    constant_names = (
        "IEEE80211_DUR_TU",
        "IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD",
        "IWX_FW_CTXT_ACTION_ADD",
        "IWX_FW_CTXT_ACTION_REMOVE",
        "IWX_MAC_CONF_GROUP",
        "IWX_SESSION_PROTECTION_CMD",
        "IWX_SESSION_PROTECT_CONF_ASSOC",
        "IWX_TE_BSS_STA_AGGRESSIVE_ASSOC",
        "IWX_TE_V2_FRAG_NONE",
        "IWX_TE_V2_NOTIF_HOST_EVENT_START",
        "IWX_TE_V2_NOTIF_HOST_EVENT_END",
        "IWX_T2_V2_START_IMMEDIATELY",
        "IWX_DQA_INJECT_MONITOR_QUEUE",
        "IWX_MGMT_TID",
        "IWX_MONITOR_STA_ID",
        "IWX_FLAG_MAC_ACTIVE",
        "IWX_FLAG_BINDING_ACTIVE",
        "IWX_FLAG_TE_ACTIVE",
        "IWX_FW_CTXT_ID_POS",
        "IWX_FW_CTXT_COLOR_POS",
    )
    constants = {name: all_constants[name] for name in constant_names}
    constant_lines = "\n".join(
        f"constexpr uint32_t {name} = {value}u;"
        for name, value in constants.items()
    )
    replacements = {
        "@@CONSTANTS@@": constant_lines,
        "@@ID_COLOR_MACRO@@": macro_block(reg, "IWX_FW_CMD_ID_AND_COLOR"),
        "@@CMD_ID_HELPER@@": extract_function(
            reg, "static inline uint32_t\niwx_cmd_id("
        ),
        "@@SESSION_STRUCT@@": packed_struct(reg, "iwx_session_prot_cmd"),
        "@@TIME_EVENT_STRUCT@@": packed_struct(reg, "iwx_time_event_cmd"),
        "@@AUTH_FUNCTION@@": extract_function(driver, "int ItlIwx::\niwx_auth("),
        "@@SESSION_HELPER@@": extract_function(
            driver, "int ItlIwx::\niwx_schedule_protect_session("
        ),
        "@@LEGACY_HELPER@@": extract_function(
            driver, "void ItlIwx::\niwx_protect_session("
        ),
    }
    output = HARNESS
    for marker, value in replacements.items():
        if marker not in output:
            raise AssertionError(f"missing harness marker: {marker}")
        output = output.replace(marker, value)
    return output


def run_build(compiler: str, source: Path, directory: Path, suffix: str,
              sanitizer: bool) -> tuple[bool, str]:
    binary = directory / f"session_protection_{suffix}"
    flags = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror"]
    if sanitizer:
        flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    flags += [str(source), "-o", str(binary)]
    built = subprocess.run(flags, capture_output=True, text=True)
    if built.returncode:
        return False, built.stderr or built.stdout
    run = subprocess.run([str(binary)], capture_output=True, text=True)
    if run.returncode:
        raise AssertionError(run.stdout + run.stderr)
    return True, run.stdout


def main() -> None:
    compiler = shutil.which("clang++") or shutil.which("c++")
    if not compiler:
        raise SystemExit("No C++ compiler found")
    with tempfile.TemporaryDirectory(prefix="test083-session-protection-") as temp:
        directory = Path(temp)
        harness = directory / "test083_session_protection.cpp"
        harness.write_text(render_harness(), encoding="utf-8")

        built, output = run_build(compiler, harness, directory, "plain", False)
        if not built:
            raise RuntimeError(output)
        print(output, end="")

        sanitized, sanitizer_output = run_build(
            compiler, harness, directory, "asan_ubsan", True
        )
        if sanitized:
            print("PASS: ASan/UBSan\n", end="")
        else:
            print("SKIP: ASan/UBSan compiler/runtime unavailable")
            if sanitizer_output.strip():
                print(sanitizer_output.splitlines()[0])


if __name__ == "__main__":
    main()
