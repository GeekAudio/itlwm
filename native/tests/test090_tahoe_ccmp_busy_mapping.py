#!/usr/bin/env python3
"""Check CCMP key-install busy semantics against the production callback."""
from __future__ import annotations

import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
source = SOURCE.read_text()


def extract_function(text: str, marker: str) -> str:
    start = text.index(marker)
    opening = text.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


set_key = extract_function(
    source, "int ItlIwx::\niwx_set_key(struct ieee80211com *ic,"
)
set_key_impl = extract_function(source, "static int iwx_set_key_with_receipt(")
send_cmd = extract_function(source, "iwx_send_cmd(struct iwx_softc *sc,")

# EBUSY is the early ownership rejection before command-ring address/slot access.
guard = extract_function(send_cmd, "if (nativeP2pBusy() && !nativeP2pCommandAllowed())")
assert 'return EBUSY;' in guard
assert 'IWX_STA_SUBMIT_REJECTED_BEFORE_RING' in guard
ring_access = "struct iwx_tx_ring *ring = &sc->txq[IWX_DQA_CMD_QUEUE];"
assert send_cmd.index(guard) < send_cmd.index(ring_access)
assert send_cmd.count("return EBUSY;") == 1

HARNESS = r"""
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "native/iwx_sta_auth_trace.h"

#define IEEE80211_CIPHER_CCMP 1
#define IEEE80211_KEY_GROUP 0x01
#define IWX_STA_KEY_FLG_CCM 0x0100
#define IWX_STA_KEY_FLG_WEP_KEY_MAP 0x0200
#define IWX_STA_KEY_FLG_KEYID_POS 2
#define IWX_STA_KEY_FLG_KEYID_MSK 0x003c
#define IWX_STA_KEY_MULTICAST 0x0040
#define IWX_STATION_ID 0
#define IWX_CMD_ASYNC 0x01
#define IWX_ADD_STA_KEY 0x1234
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define htole16(v) static_cast<uint16_t>(v)
#define htole64(v) static_cast<uint64_t>(v)
#define container_of(ptr, type, member) reinterpret_cast<type *>(ptr)

static int gHardwareResult = 0;
static int gSoftwareResult = 0;
static unsigned gHardwareCalls = 0;
static unsigned gSoftwareCalls = 0;
static uint32_t gSubmittedCommand = 0;
static int gSubmittedFlags = 0;

struct iwx_softc { int sc_generation = 5; };
struct ieee80211com { iwx_softc *ic_softc = nullptr; };
struct ieee80211_node {};
struct ieee80211_key {
    int k_cipher = IEEE80211_CIPHER_CCMP;
    uint32_t k_flags = 0;
    uint8_t k_id = 0;
    uint8_t k_key[32]{};
    size_t k_len = 16;
    uint64_t k_tsc = 0;
};
struct iwx_add_sta_key_cmd {
    struct {
        uint16_t key_flags = 0;
        uint8_t key_offset = 0;
        uint8_t key[32]{};
        uint8_t sta_id = 0;
    } common;
    uint64_t transmit_seq_cnt = 0;
};

static int ieee80211_set_key(ieee80211com *, ieee80211_node *, ieee80211_key *) {
    ++gSoftwareCalls;
    return gSoftwareResult;
}

class ItlIwx {
public:
    iwx_softc com{};
    int iwx_send_cmd_pdu(iwx_softc *, uint32_t command, int flags,
                         size_t, void *, IwxStaAuthSubmitReceipt *receipt = nullptr) {
        ++gHardwareCalls;
        gSubmittedCommand = command;
        gSubmittedFlags = flags;
        if (receipt) {
            receipt->state = gHardwareResult == EBUSY ?
                IWX_STA_SUBMIT_REJECTED_BEFORE_RING :
                (gHardwareResult == 0 ? IWX_STA_SUBMIT_LOCAL_ENQUEUE : IWX_STA_SUBMIT_OTHER_ERROR);
            receipt->raw_command_result = gHardwareResult;
        }
        return gHardwareResult;
    }
    int iwx_set_key(ieee80211com *, ieee80211_node *, ieee80211_key *);
};

static_assert(offsetof(ItlIwx, com) == 0, "test container_of layout");

// PRODUCTION_SET_KEY

static int callSetKey(ItlIwx &owner, int cipher, int hwResult, int swResult) {
    ieee80211com ic{&owner.com};
    ieee80211_node node{};
    ieee80211_key key{};
    key.k_cipher = cipher;
    gHardwareResult = hwResult;
    gSoftwareResult = swResult;
    gHardwareCalls = gSoftwareCalls = 0;
    gSubmittedCommand = 0;
    gSubmittedFlags = 0;
    return owner.iwx_set_key(&ic, &node, &key);
}

int main() {
    ItlIwx owner{};
#ifdef AIRPORT_TAHOE
    assert(callSetKey(owner, IEEE80211_CIPHER_CCMP, EBUSY, 0) == EAGAIN);
#else
    assert(callSetKey(owner, IEEE80211_CIPHER_CCMP, EBUSY, 0) == EBUSY);
#endif
    assert(gHardwareCalls == 1 && gSoftwareCalls == 0);
    assert(gSubmittedCommand == IWX_ADD_STA_KEY);
    assert(gSubmittedFlags == IWX_CMD_ASYNC);

    assert(callSetKey(owner, IEEE80211_CIPHER_CCMP, 0, 0) == 0);
    assert(gHardwareCalls == 1 && gSoftwareCalls == 0);
    assert(callSetKey(owner, IEEE80211_CIPHER_CCMP, ENOMEM, 0) == ENOMEM);
    assert(gHardwareCalls == 1 && gSoftwareCalls == 0);

    // Software-crypto fallback keeps its independent legacy return contract.
    assert(callSetKey(owner, 99, 0, EBUSY) == EBUSY);
    assert(gHardwareCalls == 0 && gSoftwareCalls == 1);
    return 0;
}
"""


def run_case(tahoe: bool, directory: pathlib.Path) -> None:
    cpp = HARNESS.replace("// PRODUCTION_SET_KEY", set_key_impl + '\n' + set_key)
    source_path = directory / ("tahoe.cpp" if tahoe else "legacy.cpp")
    binary_path = directory / ("tahoe" if tahoe else "legacy")
    source_path.write_text(cpp)
    command = [
        "clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(ROOT),
    ]
    if tahoe:
        command += ["-DAIRPORT_TAHOE=1"]
    command += ["-o", str(binary_path), str(source_path)]
    subprocess.run(command, check=True)
    subprocess.run([str(binary_path)], check=True)


with tempfile.TemporaryDirectory(prefix="test091-ccmp-busy-") as temp:
    temp_path = pathlib.Path(temp)
    run_case(True, temp_path)
    run_case(False, temp_path)
print("CCMP key busy mapping host cases passed (ASan/UBSan)")
