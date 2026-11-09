#!/usr/bin/env python3
"""Compile the production MAC_CONTEXT remove wrapper against small stubs."""

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
HEADER = ROOT / "native/tahoe_p2p_mac_ack.hpp"


STUBS = r"""
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "__ACK_HEADER__"

enum { IWX_P2P_RESOURCE_ABSENT = 0, IWX_P2P_RESOURCE_ACTIVE = 1,
       IWX_P2P_RESOURCE_UNKNOWN = 2 };
enum { IWX_P2P_UNCERTAIN_NONE = 0, IWX_P2P_UNCERTAIN_MAC_CONTEXT = 1 };
enum { IWX_FW_CTXT_ACTION_REMOVE = 2, IWX_MAC_CONTEXT_CMD = 0x28,
       IWX_CMD_WANT_RESP = 1 };

struct iwx_cmd_header { uint8_t cmd, group_id, idx, qid; };
struct iwx_rx_packet {
    uint32_t len_n_flags;
    iwx_cmd_header hdr;
    uint8_t data[16];
    uint32_t testPacketLength;
};
struct iwx_cmd_response { uint32_t status; };
struct iwx_host_cmd {
    uint32_t id;
    uint16_t len[1];
    const void *data[1];
    uint32_t flags;
    size_t resp_pkt_len;
    iwx_rx_packet *resp_pkt;
};
struct iwx_mac_ctx_cmd { uint32_t action; };
struct iwx_p2p_context {
    uint8_t initialized, mac_state, binding_state, uncertain_kind,
        uncertain_action;
    uint32_t fw_generation;
};
struct iwx_p2p_roc_state { uint32_t token; };
struct iwx_softc {
    uint32_t sc_generation;
    iwx_p2p_context sc_p2p;
    iwx_p2p_roc_state sc_p2p_roc;
};

static class ItlIwx *gOwner;
static int gSendError;
static int gResponseMode;
static int gMutateEpochAfterSend;
static unsigned gSendCount;
static unsigned gFreeCount;
static uint32_t gLastFlags;

static uint8_t iwx_cmd_opcode(uint32_t command) { return command & 0xff; }
static uint8_t iwx_cmd_groupid(uint32_t command) { return (command >> 8) & 0xff; }
static uint32_t iwx_rx_packet_len(const iwx_rx_packet *packet)
{ return packet ? packet->testPacketLength : 0; }
static int iwx_p2p_check_fw_contract(ItlIwx *, iwx_softc *) { return 0; }
static void iwx_p2p_fill_mac_context(const iwx_p2p_context *, uint32_t action,
                                     iwx_mac_ctx_cmd *cmd)
{ cmd->action = action; }

class ItlIwx {
public:
    iwx_softc com{};
    uint32_t nativeP2pProbeGeneration_ = 0;
    bool nativeP2pCommandAllowed() const { return true; }
    int iwx_p2p_mac_context_remove_with_ack(
        iwx_softc *, TahoeP2PMacContextAckReceipt *);
};

static int iwx_send_cmd(iwx_softc *sc, iwx_host_cmd *command,
                        IwxStaAuthSubmitReceipt *receipt)
{
    ++gSendCount;
    gLastFlags = command->flags;
    receipt->state = IWX_STA_SUBMIT_LOCAL_ENQUEUE;
    receipt->command_id = command->id;
    receipt->driver_generation = sc->sc_generation;
    receipt->queue_id = 0;
    receipt->queue_index = 7;
    receipt->raw_command_result = gSendError;
    if (gResponseMode != 0) {
        command->resp_pkt = new iwx_rx_packet{};
        command->resp_pkt->hdr = {0x28, 0x01, 7, 0};
        command->resp_pkt->testPacketLength = gResponseMode == 1 ? 4 : 8;
        if (gResponseMode == 2)
            memset(command->resp_pkt->data, 0, 4);
    }
    if (gMutateEpochAfterSend && gOwner)
        ++gOwner->nativeP2pProbeGeneration_;
    return gSendError;
}

static void iwx_free_resp(iwx_softc *, iwx_host_cmd *command)
{
    ++gFreeCount;
    delete command->resp_pkt;
    command->resp_pkt = nullptr;
}

static void setup(ItlIwx &owner)
{
    owner = ItlIwx{};
    owner.com.sc_generation = 29;
    owner.com.sc_p2p.initialized = 1;
    owner.com.sc_p2p.mac_state = IWX_P2P_RESOURCE_ACTIVE;
    owner.com.sc_p2p.binding_state = IWX_P2P_RESOURCE_ABSENT;
    owner.com.sc_p2p.fw_generation = 29;
    owner.com.sc_p2p_roc.token = 17;
    owner.nativeP2pProbeGeneration_ = 17;
    gOwner = &owner;
    gSendError = 0;
    gResponseMode = 1;
    gMutateEpochAfterSend = 0;
    gSendCount = 0;
    gFreeCount = 0;
    gLastFlags = 0;
}

static TahoeP2PMacContextAckReceipt request()
{
    TahoeP2PMacContextAckReceipt r{};
    r.expectedP2PEpoch = 17;
    r.expectedRocToken = 17;
    r.expectedDriverGeneration = 29;
    return r;
}
"""


def extract_production_wrapper() -> str:
    source = SOURCE.read_text()
    start_marker = "int ItlIwx::\niwx_p2p_mac_context_remove_with_ack("
    end_marker = "\nint ItlIwx::\niwx_p2p_phy_lease("
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]


MAIN = r"""
int main()
{
    ItlIwx owner;
    TahoeP2PMacContextAckReceipt receipt;

    setup(owner);
    receipt = request();
    assert(owner.iwx_p2p_mac_context_remove_with_ack(&owner.com, &receipt) == 0);
    assert(owner.com.sc_p2p.mac_state == IWX_P2P_RESOURCE_ABSENT);
    assert(owner.com.sc_p2p.uncertain_kind == IWX_P2P_UNCERTAIN_NONE);
    assert(gSendCount == 1 && gFreeCount == 1);
    assert((gLastFlags & IWX_CMD_WANT_RESP) != 0);
    assert(receipt.accepted == 1);

    setup(owner);
    gResponseMode = 0;
    receipt = request();
    assert(owner.iwx_p2p_mac_context_remove_with_ack(&owner.com, &receipt) == EIO);
    assert(owner.com.sc_p2p.mac_state == IWX_P2P_RESOURCE_UNKNOWN);
    assert(gSendCount == 1 && gFreeCount == 0);
    assert(receipt.accepted == 0);

    setup(owner);
    gResponseMode = 2; // zero-filled generic 4-byte status payload
    receipt = request();
    assert(owner.iwx_p2p_mac_context_remove_with_ack(&owner.com, &receipt) == EIO);
    assert(owner.com.sc_p2p.mac_state == IWX_P2P_RESOURCE_UNKNOWN);
    assert(gSendCount == 1 && gFreeCount == 1);
    assert((receipt.rejectReason & TAHOE_P2P_MAC_ACK_REJECT_RESPONSE_PAYLOAD) != 0);

    setup(owner);
    gSendError = ETIMEDOUT;
    gResponseMode = 0;
    receipt = request();
    assert(owner.iwx_p2p_mac_context_remove_with_ack(&owner.com, &receipt) ==
           ETIMEDOUT);
    assert(owner.com.sc_p2p.mac_state == IWX_P2P_RESOURCE_UNKNOWN);
    assert(gSendCount == 1 && gFreeCount == 0);
    assert(receipt.transportResult == ETIMEDOUT);

    setup(owner);
    gMutateEpochAfterSend = 1;
    receipt = request();
    assert(owner.iwx_p2p_mac_context_remove_with_ack(&owner.com, &receipt) == EIO);
    assert(owner.com.sc_p2p.mac_state == IWX_P2P_RESOURCE_UNKNOWN);
    assert(gSendCount == 1 && gFreeCount == 1);
    assert((receipt.rejectReason & TAHOE_P2P_MAC_ACK_REJECT_P2P_EPOCH) != 0);

    setup(owner);
    receipt = request();
    receipt.expectedP2PEpoch = 18; // fail preflight; do not send or free
    assert(owner.iwx_p2p_mac_context_remove_with_ack(&owner.com, &receipt) ==
           ESTALE);
    assert(owner.com.sc_p2p.mac_state == IWX_P2P_RESOURCE_ACTIVE);
    assert(gSendCount == 0 && gFreeCount == 0);
    return 0;
}
"""


def main() -> None:
    compiler = shutil.which("c++") or shutil.which("clang++")
    if not compiler:
        raise SystemExit("no C++ compiler found")
    source = (STUBS.replace("__ACK_HEADER__", str(HEADER)) +
              "\n" + extract_production_wrapper() + "\n" + MAIN)
    with tempfile.TemporaryDirectory(prefix="tahoe-p2p-mac-ack-") as temp:
        cpp = Path(temp) / "wrapper_test.cpp"
        binary = Path(temp) / "wrapper_test"
        cpp.write_text(source)
        subprocess.run([
            compiler, "-std=gnu++17", "-Wall", "-Wextra", "-Werror",
            str(cpp), "-o", str(binary)
        ], check=True)
        subprocess.run([str(binary)], check=True)
    print("PASS: production remove wrapper stub scenarios")


if __name__ == "__main__":
    main()
