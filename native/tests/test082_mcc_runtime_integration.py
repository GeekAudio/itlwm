#!/usr/bin/env python3
"""Extract and fault-inject the production Tahoe MCC callback, actions and request helper."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DRIVER = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
P2P_PROBE = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()


def function(source: str, marker: str) -> str:
    start = source.find(marker)
    if start < 0:
        raise RuntimeError(f"missing production function: {marker}")
    opening = source.find("{", start)
    depth = 0
    i = opening
    state = "code"
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block"
                i += 2
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
                    return source[start : i + 1]
        elif state == "line":
            if ch == "\n":
                state = "code"
        elif state == "block":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
                continue
        elif state in ("string", "char"):
            if ch == "\\":
                i += 2
                continue
            if (state == "string" and ch == '"') or (
                state == "char" and ch == "'"
            ):
                state = "code"
        i += 1
    raise RuntimeError(f"unterminated production function: {marker}")


FUNCTIONS = [
    function(DRIVER, "IOReturn ItlIwx::iwx_native_mcc_capture_action("),
    function(DRIVER, "IOReturn ItlIwx::iwx_native_mcc_apply_action("),
    function(DRIVER, "int ItlIwx::iwx_request_mcc_profile("),
    function(DRIVER, "void ItlIwx::iwx_native_mcc_refresh_task(void *arg)"),
    function(DRIVER, "void ItlIwx::tahoeMccScheduleIfReady(struct iwx_softc *sc)"),
    function(DRIVER, "static void tahoeRetireNativeMccNotice("),
    function(DRIVER, "void ItlIwx::\niwx_mcc_update("),
]

TICK = function(P2P_PROBE, "void ItlIwx::nativeP2pTick()")
assert "tahoeMccScheduleIfReady(&com);" in TICK
STOP = function(DRIVER, "iwx_stop(struct _ifnet *ifp, IwxResetTrace::ResetReason reason)")
assert STOP.index("taskq_try_pause_with_diagnostics") < STOP.index(
    "sc->sc_flags |= IWX_FLAG_SHUTDOWN"
)
assert STOP.index("sc->sc_flags |= IWX_FLAG_SHUTDOWN") < STOP.index(
    "iwx_del_task(sc, sc->sc_nswq, &sc->sc_native_mcc_task)"
) < STOP.index("iwx_stop_device(sc)")
DETACH = function(DRIVER, "detach(IOPCIDevice *device)")
assert DETACH.index("__atomic_store_n(&nativeLifecycleTearingDown_") < DETACH.index(
    "iwx_del_task(sc, sc->sc_nswq, &sc->sc_native_mcc_task)"
)

HARNESS = r"""
#define AIRPORT_TAHOE 1
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include "native/iwx_mcc_refresh_policy.hpp"

using namespace IwxMccRefreshPolicy;
using IOReturn = int;
constexpr int kIOReturnSuccess = 0, kIOReturnBadArgument = -1;
constexpr int kIOReturnNotReady = -2, kIOReturnError = -3;
constexpr int IWX_FLAG_SHUTDOWN = 0x800;
constexpr uint32_t IFF_UP = 1, IFF_RUNNING = 0x40;
constexpr uint32_t IWX_LONG_GROUP = 1, IWX_MCC_UPDATE_CMD = 0xc8;
constexpr uint32_t IWX_FW_CMD_VER_UNKNOWN = 0xff;
constexpr uint32_t IWX_UCODE_TLV_CAPA_MCC_UPDATE_11AX_SUPPORT = 89;
constexpr uint32_t IWX_CMD_WANT_RESP = 1, IWX_CMD_FAILED_MSK = 0x80;
constexpr size_t IWX_CMD_RESP_MAX = 512;
constexpr int IEEE80211_EVT_COUNTRY_CODE_UPDATE = 1;

struct OSObject {};
struct IOEthernetController {};
struct ItlIwx;
struct iwx_softc;
struct _ifnet { uint32_t if_flags = 0; };
struct ieee80211_channel { uint32_t ic_flags = 0, ic_freq = 0; };
struct ieee80211com {
    struct { _ifnet ac_if; } ic_ac;
    ieee80211_channel ic_channels[256] {};
    void (*ic_event_handler)(ieee80211com *, int, void *) = nullptr;
};
struct iwx_nvm { uint32_t lar_enabled = 0; };
struct task { bool queued = false; };
struct taskq { bool paused = false; int enterError = 0; int lockDepth = 0; unsigned adds = 0; };
struct iwx_mcc_chub_notif { uint16_t mcc; uint8_t source_id; };
struct iwx_mcc_update_cmd { uint16_t mcc; uint8_t source_id; uint8_t reserved[25]; };
struct iwx_rx_packet {
    struct { uint8_t group_id = 0; } hdr;
    const uint8_t *data = nullptr;
    size_t payloadLength = 0;
};
struct iwx_host_cmd {
    uint32_t id = 0, flags = 0;
    struct { void *data = nullptr; } data[2];
    size_t len[2] {};
    size_t resp_pkt_len = 0;
    iwx_rx_packet *resp_pkt = nullptr;
};

#define MCC_FIELDS \
    uint32_t sc_native_mcc_notice_generation = 0; \
    uint32_t sc_native_mcc_notice_code = 0; \
    uint32_t sc_native_mcc_notice_source = 0; \
    uint32_t sc_native_mcc_notice_valid = 0; \
    uint32_t sc_native_mcc_pending = 0; \
    uint32_t sc_native_mcc_request_sequence = 0; \
    uint32_t sc_native_mcc_request_mcc = 0; \
    uint32_t sc_native_mcc_request_notice_generation = 0; \
    uint32_t sc_native_mcc_request_firmware_generation = 0; \
    uint32_t sc_native_mcc_request_source = 0; \
    uint32_t sc_native_mcc_request_origin = 0; \
    uint32_t sc_native_mcc_command_version = 0; \
    uint32_t sc_native_mcc_command_version_present = 0; \
    uint32_t sc_native_mcc_notification_version = 0; \
    uint32_t sc_native_mcc_notification_version_present = 0; \
    uint32_t sc_native_mcc_response_format = 0; \
    uint32_t sc_native_mcc_11ax_capability = 0; \
    uint32_t sc_native_mcc_11ax_capability_present = 0; \
    uint32_t sc_native_mcc_response_present = 0; \
    uint32_t sc_native_mcc_response_notice_generation = 0; \
    uint32_t sc_native_mcc_response_firmware_generation = 0; \
    uint32_t sc_native_mcc_response_mcc = 0; \
    uint32_t sc_native_mcc_response_source = 0; \
    uint32_t sc_native_mcc_response_status = 0; \
    uint32_t sc_native_mcc_response_capabilities = 0; \
    uint32_t sc_native_mcc_response_time = 0; \
    uint32_t sc_native_mcc_response_geo_info = 0; \
    uint32_t sc_native_mcc_response_channel_count = 0; \
    uint32_t sc_native_mcc_response_profile149_flags = 0; \
    uint32_t sc_native_mcc_response_profile149_flags_present = 0; \
    uint32_t sc_native_mcc_applied_notice_generation = 0; \
    uint32_t sc_native_mcc_applied_firmware_generation = 0; \
    uint32_t sc_native_mcc_applied_channel149_flags = 0; \
    uint32_t sc_native_mcc_applied_channel149_flags_present = 0; \
    uint32_t sc_native_mcc_applied_channel149_frequency = 0; \
    uint32_t sc_native_mcc_applied_channel149_frequency_present = 0; \
    uint32_t sc_native_mcc_failed_notice_generation = 0; \
    uint32_t sc_native_mcc_failed_firmware_generation = 0; \
    uint32_t sc_native_mcc_failed_request_sequence = 0; \
    uint32_t sc_native_mcc_last_error = 0, sc_native_mcc_last_gate = 0;

struct iwx_softc {
    ieee80211com sc_ic;
    iwx_nvm sc_nvm;
    uint8_t sc_ucode_api[32] {}, sc_enabled_capa[32] {};
    uint32_t sc_flags = 0, sc_generation = 17;
    bool sc_uhb_supported = false;
    taskq *sc_nswq = nullptr;
    task sc_native_mcc_task;
    char sc_fw_mcc[3] {'Z', 'Z', 0};
    uint16_t sc_fw_mcc_int = 0;
    MCC_FIELDS
};
#undef MCC_FIELDS

struct NativeMccWork {
    ProfileResponse profile {};
    uint32_t requestMcc = 0, requestSource = 0, requestOrigin = 0;
    uint32_t retryAfterStale = 0;
    int error = 0;
};
struct IOCommandGate {
    using Action = IOReturn (*)(OSObject *, void *, void *, void *, void *);
    IOReturn runAction(Action, void *, void *, void *);
};
constexpr uint32_t kTahoeLifecycleMccTask = 1;
struct TahoeLifecycleGuard {
    struct ItlIwx *owner;
    explicit TahoeLifecycleGuard(struct ItlIwx *, uint32_t);
    explicit operator bool() const;
};
struct ItlIwx {
    iwx_softc com;
    uint32_t nativeLifecycleTearingDown_ = 0;
    bool mainGate = true, lifecycleAllowed = true;
    bool p2pBusy = false, p2pRetained = false;
    IOEthernetController controller;
    IOCommandGate commandGate;
    taskq queue;
    unsigned publishCalls = 0, mapCalls = 0;
    uint32_t lastMap149 = 0;
    static IOReturn iwx_native_mcc_capture_action(OSObject *, void *, void *, void *, void *);
    static IOReturn iwx_native_mcc_apply_action(OSObject *, void *, void *, void *, void *);
    static void iwx_native_mcc_refresh_task(void *);
    int iwx_request_mcc_profile(iwx_softc *, uint16_t, uint8_t, ProfileResponse *, bool);
    void iwx_mcc_update(iwx_softc *, iwx_mcc_chub_notif *);
    void tahoeMccScheduleIfReady(iwx_softc *);
    uint8_t iwx_lookup_cmd_ver(iwx_softc *, uint8_t, uint8_t) { return 1; }
    uint8_t iwx_lookup_notif_ver(iwx_softc *, uint8_t, uint8_t) { return 5; }
    bool tahoeP2pOnMainGate() const { return mainGate; }
    bool nativeP2pBusy() const { return p2pBusy; }
    bool nativeP2pResourcesRetained() const { return p2pRetained; }
    IOEthernetController *getController() { return &controller; }
    IOCommandGate *getMainCommandGate() { return &commandGate; }
    void tahoePublishMccSnapshot(IOEthernetController *) { ++publishCalls; }
    void iwx_init_channel_map(iwx_softc *, void *, const uint32_t *flags, int n)
    {
        assert(flags && n == 51);
        ++mapCalls;
        lastMap149 = flags[42];
        com.sc_ic.ic_channels[149].ic_flags = 0x20U;
        com.sc_ic.ic_channels[149].ic_freq = 5745U;
    }
};
#define container_of(ptr, type, member) reinterpret_cast<type *>(reinterpret_cast<char *>(ptr) - offsetof(type, member))

TahoeLifecycleGuard::TahoeLifecycleGuard(ItlIwx *value, uint32_t) : owner(value) {}
TahoeLifecycleGuard::operator bool() const { return owner && owner->lifecycleAllowed; }
IOReturn IOCommandGate::runAction(Action action, void *a, void *b, void *c)
{ return action(nullptr, a, b, c, nullptr); }

static unsigned g_countryEvents = 0, g_commands = 0, g_freeResponses = 0;
static uint32_t g_lastCommandId = 0;
static uint16_t g_lastCommandMcc = 0;
static uint8_t g_lastCommandSource = 0;
static int g_sendError = 0;
static bool g_capability89 = true;
static ItlIwx *g_injectOwner = nullptr;
static bool g_injectReplacementNotice = false;
static iwx_mcc_chub_notif g_replacementNotice {};
static std::vector<uint8_t> g_payload;
static uint8_t g_channels[51] {};
static iwx_rx_packet g_packet;

static uint16_t le16toh(uint16_t x) { return x; } // host test target is little-endian
static uint16_t htole16(uint16_t x) { return x; }
static int splnet() { return 0; }
static void splx(int) {}
static int taskq_enter_unpaused(taskq *q)
{
    if (!q || q->paused) return EBUSY;
    if (q->enterError) return q->enterError;
    ++q->lockDepth;
    return 0;
}
static void taskq_leave(taskq *q) { assert(q->lockDepth > 0); --q->lockDepth; }
static void task_add(taskq *q, task *t)
{
    assert(q && t);
    if (!t->queued) { t->queued = true; ++q->adds; }
}
static bool isset(const uint8_t *, uint32_t) { return g_capability89; }
static bool iwx_mcc_multi_source_supported(const iwx_softc *) { return true; }
static void iwx_free_resp(iwx_softc *, iwx_host_cmd *cmd)
{ ++g_freeResponses; cmd->resp_pkt = nullptr; }
static size_t iwx_rx_packet_payload_len(iwx_rx_packet *packet) { return packet->payloadLength; }
static int iwx_send_cmd(iwx_softc *, iwx_host_cmd *cmd)
{
    ++g_commands;
    g_lastCommandId = cmd->id;
    auto *request = static_cast<iwx_mcc_update_cmd *>(cmd->data[0].data);
    g_lastCommandMcc = request->mcc;
    g_lastCommandSource = request->source_id;
    if (g_injectReplacementNotice && g_injectOwner) {
        g_injectReplacementNotice = false;
        g_injectOwner->iwx_mcc_update(&g_injectOwner->com, &g_replacementNotice);
    }
    if (g_sendError) return g_sendError;
    g_packet.hdr.group_id = 0;
    g_packet.data = g_payload.data();
    g_packet.payloadLength = g_payload.size();
    cmd->resp_pkt = &g_packet;
    return 0;
}
static const uint8_t *iwx_mcc_channel_list(const iwx_softc *, size_t *count)
{ *count = sizeof(g_channels); return g_channels; }
static void countryEvent(ieee80211com *, int event, void *)
{ assert(event == IEEE80211_EVT_COUNTRY_CODE_UPDATE); ++g_countryEvents; }

"""

HARNESS_SUFFIX = r"""

static constexpr uint16_t kUS = static_cast<uint16_t>(('U' << 8) | 'S');
static constexpr uint16_t kCA = static_cast<uint16_t>(('C' << 8) | 'A');
static constexpr uint16_t kGB = static_cast<uint16_t>(('G' << 8) | 'B');
static void putLE16(std::vector<uint8_t> &b, size_t p, uint16_t v)
{ b[p] = static_cast<uint8_t>(v); b[p + 1] = static_cast<uint8_t>(v >> 8); }
static void putLE32(std::vector<uint8_t> &b, size_t p, uint32_t v)
{
    b[p] = static_cast<uint8_t>(v); b[p+1] = static_cast<uint8_t>(v >> 8);
    b[p+2] = static_cast<uint8_t>(v >> 16); b[p+3] = static_cast<uint8_t>(v >> 24);
}
static std::vector<uint8_t> response(uint16_t mcc, uint8_t source)
{
    std::vector<uint8_t> b(20 + 51 * 4, 0);
    putLE32(b, 0, 1); putLE16(b, 4, mcc); putLE16(b, 6, 0x1234);
    putLE16(b, 8, 30); putLE16(b, 10, 2); b[12] = source;
    putLE32(b, 16, 51);
    for (uint32_t i = 0; i < 51; ++i) putLE32(b, 20 + i*4, 0x10000U + i);
    putLE32(b, 20 + 42*4, 0x8800U);
    return b;
}
static void init(ItlIwx &o)
{
    o.com.sc_nvm.lar_enabled = 1;
    o.com.sc_generation = 17;
    o.com.sc_nswq = &o.queue;
    o.com.sc_ic.ic_ac.ac_if.if_flags = IFF_UP | IFF_RUNNING;
    o.com.sc_ic.ic_event_handler = countryEvent;
    o.com.sc_fw_mcc[0] = 'Z'; o.com.sc_fw_mcc[1] = 'Z'; o.com.sc_fw_mcc[2] = 0;
    o.com.sc_fw_mcc_int = htole16(static_cast<uint16_t>(('Z' << 8) | 'Z'));
    g_countryEvents = g_commands = g_freeResponses = 0; g_sendError = 0; g_capability89 = true;
    for (uint32_t i = 0; i < 51; ++i) g_channels[i] = static_cast<uint8_t>(i + 1);
    g_channels[42] = 149;
}
static NativeMccWork capture(ItlIwx &o)
{
    NativeMccWork w {};
    assert(ItlIwx::iwx_native_mcc_capture_action(nullptr, &o, &o.com, &w, nullptr) == kIOReturnSuccess);
    return w;
}
static int issue(ItlIwx &o, NativeMccWork &w, ProfileResponse *result)
{
    *result = w.profile;
    g_payload = response(kUS, 0x10);
    return o.iwx_request_mcc_profile(&o.com, static_cast<uint16_t>(w.requestMcc),
                                     static_cast<uint8_t>(w.requestSource), result, true);
}
static void runQueuedTask(ItlIwx &o)
{
    assert(o.com.sc_native_mcc_task.queued);
    o.com.sc_native_mcc_task.queued = false;
    ItlIwx::iwx_native_mcc_refresh_task(&o.com);
}

static void testCommandAndParserErrorsConsumeOnlyCurrentNotice()
{
    ItlIwx sendFailure {}; init(sendFailure);
    iwx_mcc_chub_notif n1 {kUS, 5};
    sendFailure.iwx_mcc_update(&sendFailure.com, &n1);
    g_sendError = ETIMEDOUT;
    runQueuedTask(sendFailure);
    assert(g_commands == 1);
    assert(sendFailure.com.sc_native_mcc_pending == 0);
    assert(sendFailure.com.sc_native_mcc_failed_notice_generation == 2);
    assert(sendFailure.com.sc_native_mcc_last_gate == 8);
    for (int i = 0; i < 3; ++i)
        sendFailure.tahoeMccScheduleIfReady(&sendFailure.com);
    assert(g_commands == 1 && sendFailure.queue.adds == 1);
    assert(!sendFailure.com.sc_native_mcc_task.queued);

    ItlIwx parseFailure {}; init(parseFailure);
    iwx_mcc_chub_notif n2 {kCA, 2};
    parseFailure.iwx_mcc_update(&parseFailure.com, &n2);
    g_payload.clear();
    runQueuedTask(parseFailure);
    assert(g_commands == 1);
    assert(parseFailure.com.sc_native_mcc_pending == 0);
    assert(parseFailure.com.sc_native_mcc_failed_notice_generation == 2);
    for (int i = 0; i < 3; ++i)
        parseFailure.tahoeMccScheduleIfReady(&parseFailure.com);
    assert(g_commands == 1 && parseFailure.queue.adds == 1);
    assert(!parseFailure.com.sc_native_mcc_task.queued);
}

static void testP2PBusyPreservesPendingUntilALaterTick()
{
    ItlIwx o {}; init(o);
    g_payload = response(kUS, 0x10);
    iwx_mcc_chub_notif notice {kUS, 5};
    o.iwx_mcc_update(&o.com, &notice);
    o.p2pBusy = true;
    runQueuedTask(o);
    assert(g_commands == 0 && o.com.sc_native_mcc_pending == 1);
    assert(o.com.sc_native_mcc_last_gate == 9);
    // nativeP2pTick invokes this production queue gate once per tick.
    o.tahoeMccScheduleIfReady(&o.com);
    assert(o.com.sc_native_mcc_task.queued && o.queue.adds == 2);
    o.p2pBusy = false;
    runQueuedTask(o);
    assert(g_commands == 1 && o.com.sc_native_mcc_pending == 0);

    iwx_mcc_chub_notif next {kCA, 2};
    o.iwx_mcc_update(&o.com, &next);
    o.p2pRetained = true;
    runQueuedTask(o);
    assert(g_commands == 1 && o.com.sc_native_mcc_pending == 1);
    assert(o.com.sc_native_mcc_last_gate == 9);
    o.tahoeMccScheduleIfReady(&o.com);
    assert(o.com.sc_native_mcc_task.queued);
    o.p2pRetained = false;
    runQueuedTask(o);
    assert(g_commands == 2 && o.com.sc_native_mcc_pending == 0);
}

static void testNewNoticeArrivingDuringFailedOldRequestIsNotConsumed()
{
    ItlIwx o {}; init(o);
    iwx_mcc_chub_notif oldNotice {kUS, 5};
    iwx_mcc_chub_notif newerNotice {kCA, 2};
    o.iwx_mcc_update(&o.com, &oldNotice);
    g_injectOwner = &o;
    g_replacementNotice = newerNotice;
    g_injectReplacementNotice = true;
    g_sendError = ETIMEDOUT;
    runQueuedTask(o);
    assert(g_commands == 1);
    assert(o.com.sc_native_mcc_notice_code == kCA);
    assert(o.com.sc_native_mcc_notice_source == 2);
    assert(o.com.sc_native_mcc_pending == 1);
    assert(o.com.sc_native_mcc_failed_notice_generation == 0);
    assert(o.com.sc_native_mcc_task.queued);
    assert(o.queue.adds == 2); // the replacement notice, not the old retry

    g_sendError = 0;
    g_payload = response(kUS, 0x10);
    runQueuedTask(o);
    assert(g_commands == 2);
    assert(g_lastCommandMcc == htole16(kCA));
    assert(g_lastCommandSource == 2);
    assert(o.com.sc_native_mcc_request_mcc == kCA);
    assert(o.com.sc_native_mcc_pending == 0);
}

static void testNoticeCaptureAndNarrowRequest()
{
    ItlIwx o {}; init(o);
    iwx_mcc_chub_notif invalid {kUS, 16};
    o.iwx_mcc_update(&o.com, &invalid);
    assert(o.com.sc_native_mcc_pending == 0 && o.com.sc_native_mcc_notice_valid == 0);
    assert(o.queue.adds == 0 && !o.com.sc_native_mcc_task.queued &&
           g_commands == 0 && g_countryEvents == 0);

    iwx_mcc_chub_notif notice {kUS, 5};
    o.iwx_mcc_update(&o.com, &notice);
    assert(o.com.sc_native_mcc_pending == 1);
    assert(o.com.sc_native_mcc_notice_code == kUS && o.com.sc_native_mcc_notice_source == 5);
    assert(o.queue.adds == 1 && o.com.sc_native_mcc_task.queued &&
           g_commands == 0 && g_countryEvents == 0);
    assert(strcmp(o.com.sc_fw_mcc, "ZZ") == 0);
    NativeMccWork w = capture(o);
    assert(w.requestMcc == kUS && w.requestSource == 5);
    assert(w.profile.requestMcc == kUS && w.profile.requestSource == 5);
    assert(o.com.sc_native_mcc_command_version == 1);
    assert(o.com.sc_native_mcc_notification_version == 5);
    assert(o.com.sc_native_mcc_response_format == kResponseFormatV4);
    assert(o.com.sc_native_mcc_11ax_capability == 1);

    ProfileResponse parsed {};
    assert(issue(o, w, &parsed) == 0);
    assert(g_commands == 1 && g_freeResponses == 1);
    assert(g_lastCommandId == IWX_MCC_UPDATE_CMD);
    assert(sizeof(iwx_mcc_update_cmd) == 28);
    assert(g_lastCommandMcc == htole16(kUS) && g_lastCommandSource == 5);
    assert(parsed.commandVersion == 1 && parsed.notificationVersion == 5);
    assert(parsed.responseFormat == kResponseFormatV4);
    assert(parsed.mcc == kUS && parsed.source == 0x10);
    assert(parsed.channelCount == 51 && parsed.profile149Present && parsed.profile149Flags == 0x8800);
    assert(g_payload[4] == 'S' && g_payload[5] == 'U'); // little-endian wire MCC "US"
}
static void testStaleNoticeAndErrorCannotApply()
{
    ItlIwx o {}; init(o);
    iwx_mcc_chub_notif a {kUS, 5}; o.iwx_mcc_update(&o.com, &a);
    NativeMccWork old = capture(o);
    ProfileResponse parsed {}; assert(issue(o, old, &parsed) == 0); old.profile = parsed;
    iwx_mcc_chub_notif b {kCA, 2}; o.iwx_mcc_update(&o.com, &b);
    assert(ItlIwx::iwx_native_mcc_apply_action(nullptr, &o, &o.com, &old, nullptr) == kIOReturnNotReady);
    assert(old.retryAfterStale == 1 && o.mapCalls == 0 && g_countryEvents == 0);
    assert(strcmp(o.com.sc_fw_mcc, "ZZ") == 0);
    NativeMccWork failed = capture(o); failed.error = EIO;
    assert(ItlIwx::iwx_native_mcc_apply_action(nullptr, &o, &o.com, &failed, nullptr) == kIOReturnError);
    assert(o.mapCalls == 0 && g_countryEvents == 0 && strcmp(o.com.sc_fw_mcc, "ZZ") == 0);
}
static void testResponseMccOwnsCountryAndEventDedup()
{
    ItlIwx o {}; init(o);
    iwx_mcc_chub_notif ca {kCA, 2}; o.iwx_mcc_update(&o.com, &ca);
    NativeMccWork w = capture(o);
    ProfileResponse parsed {}; assert(issue(o, w, &parsed) == 0);
    w.profile = parsed;
    assert(parsed.requestMcc == kCA && parsed.mcc == kUS); // firmware reply differs from notice
    assert(ItlIwx::iwx_native_mcc_apply_action(nullptr, &o, &o.com, &w, nullptr) == kIOReturnSuccess);
    assert(o.mapCalls == 1 && o.lastMap149 == 0x8800);
    assert(o.com.sc_native_mcc_response_profile149_flags == 0x8800);
    assert(o.com.sc_native_mcc_applied_channel149_flags == 0x20);
    assert(o.com.sc_native_mcc_applied_channel149_frequency == 5745);
    assert(o.com.sc_native_mcc_response_mcc == kUS && o.com.sc_native_mcc_response_source == 0x10);
    assert(strcmp(o.com.sc_fw_mcc, "US") == 0);
    assert(o.com.sc_fw_mcc_int == htole16(kUS) && g_countryEvents == 1);

    iwx_mcc_chub_notif gb {kGB, 5}; o.iwx_mcc_update(&o.com, &gb);
    NativeMccWork same = capture(o);
    ProfileResponse sameParsed {}; assert(issue(o, same, &sameParsed) == 0);
    same.profile = sameParsed;
    assert(ItlIwx::iwx_native_mcc_apply_action(nullptr, &o, &o.com, &same, nullptr) == kIOReturnSuccess);
    assert(strcmp(o.com.sc_fw_mcc, "US") == 0 && g_countryEvents == 1);
}
static void testP2PLeaseAndFirmwareRolloverFence()
{
    ItlIwx o {}; init(o);
    iwx_mcc_chub_notif n {kUS, 5}; o.iwx_mcc_update(&o.com, &n);
    NativeMccWork w = capture(o);
    ProfileResponse parsed {}; assert(issue(o, w, &parsed) == 0); w.profile = parsed;
    o.p2pBusy = true;
    assert(ItlIwx::iwx_native_mcc_apply_action(nullptr, &o, &o.com, &w, nullptr) == kIOReturnNotReady);
    assert(o.mapCalls == 0 && g_countryEvents == 0);
    o.p2pBusy = false;
    NativeMccWork old = capture(o);
    assert(issue(o, old, &parsed) == 0); old.profile = parsed;
    ++o.com.sc_generation;
    assert(ItlIwx::iwx_native_mcc_apply_action(nullptr, &o, &o.com, &old, nullptr) == kIOReturnNotReady);
    assert(o.mapCalls == 0 && g_countryEvents == 0);
}
static void testStopRetiresPendingNoticeAndStaleReply()
{
    ItlIwx o {}; init(o);
    iwx_mcc_chub_notif notice {kUS, 5};
    o.iwx_mcc_update(&o.com, &notice);
    NativeMccWork old = capture(o);
    ProfileResponse parsed {};
    assert(issue(o, old, &parsed) == 0);
    old.profile = parsed;
    const uint32_t before = o.com.sc_native_mcc_notice_generation;
    tahoeRetireNativeMccNotice(&o.com);
    assert(o.com.sc_native_mcc_notice_generation == before + 2);
    assert((o.com.sc_native_mcc_notice_generation & 1U) == 0);
    assert(o.com.sc_native_mcc_notice_valid == 0);
    assert(o.com.sc_native_mcc_pending == 0);
    assert(o.com.sc_native_mcc_last_gate == kGateRetiredByStop);
    assert(ItlIwx::iwx_native_mcc_apply_action(
        nullptr, &o, &o.com, &old, nullptr) == kIOReturnNotReady);
    assert(o.mapCalls == 0 && g_countryEvents == 0);
}
int main()
{
    testCommandAndParserErrorsConsumeOnlyCurrentNotice();
    testP2PBusyPreservesPendingUntilALaterTick();
    testNewNoticeArrivingDuringFailedOldRequestIsNotConsumed();
    testNoticeCaptureAndNarrowRequest();
    testStaleNoticeAndErrorCannotApply();
    testResponseMccOwnsCountryAndEventDedup();
    testP2PLeaseAndFirmwareRolloverFence();
    testStopRetiresPendingNoticeAndStaleReply();
    return 0;
}
"""

def main() -> None:
    source = HARNESS + "\n\n".join(FUNCTIONS) + HARNESS_SUFFIX
    with tempfile.TemporaryDirectory(prefix="test082-mcc-runtime-") as temp:
        cpp, binary = Path(temp) / "test.cpp", Path(temp) / "test"
        cpp.write_text(source)
        result = subprocess.run(
            ["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-function", "-Wno-missing-braces",
             "-I", str(ROOT), str(cpp), "-o", str(binary)],
            text=True, capture_output=True,
        )
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        result = subprocess.run([str(binary)], text=True, capture_output=True)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
print("PASS: extracted production MCC notification/capture/request/worker/apply/scheduler path; request replacement, same-notice failure backoff, P2P retention, response country/map behavior, and stop/detach task-retirement ordering")

if __name__ == "__main__":
    main()

