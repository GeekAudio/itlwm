#!/usr/bin/env python3
"""Compile the production IWX_TX_CMD case with Tahoe on and off.

The harness embeds the actual case text from ItlIwx.cpp. The legacy control is
made by mechanically restoring the Test072 #else boundary around the ordinary
fallback; no handler logic is duplicated or reimplemented by the test.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
START = "            case IWX_TX_CMD:\n"
END = "            case IWX_MISSED_BEACONS_NOTIFICATION:\n"
FALLBACK = "#endif\n                iwx_rx_tx_cmd(sc, pkt, data);\n"
LEGACY_BOUNDARY = (
    "#else\n                iwx_rx_tx_cmd(sc, pkt, data);\n#endif\n"
)


HARNESS_PREFIX = r'''#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

enum {
    IWX_TX_CMD = 1,
    IWX_MISSED_BEACONS_NOTIFICATION = 2,
    IWX_TX_PROGRESS_HAS_QID = 1u << 4,
    IWX_TX_PROGRESS_RESPONSE_DISPATCH = 1,
    IWX_TX_PROGRESS_RESPONSE_TX_RSP = 0,
    IWX_TX_PROGRESS_RESPONSE_P2P_CONSUMED = 2,
};

struct iwx_softc {};
struct iwx_rx_data {};
struct iwx_tx_resp { uint16_t tx_queue; };
struct iwx_rx_packet {
    alignas(8) uint8_t data[16]{};
    size_t payloadLength = sizeof(iwx_tx_resp);
};

class Driver;
static int ordinaryCalls = 0;
static int p2pCalls = 0;
static int responseEvents = 0;
static int consumedEvents = 0;

size_t iwx_rx_packet_payload_len(const iwx_rx_packet *pkt)
{
    return pkt->payloadLength;
}

uint16_t le16toh(uint16_t value) { return value; }

void iwx_rx_tx_cmd(iwx_softc *sc, iwx_rx_packet *pkt,
                   iwx_rx_data *data)
{
    (void)sc; (void)pkt; (void)data;
    ++ordinaryCalls;
}

void recordTxProgressEvent(iwx_softc *sc, uint32_t event,
    uint32_t reason, uint32_t presence, uint32_t qid, uint32_t index,
    uint32_t ringCount, uint32_t queued, uint32_t cur, uint32_t tail,
    bool isReset)
{
    (void)sc; (void)presence; (void)qid; (void)index; (void)ringCount;
    (void)queued; (void)cur; (void)tail; (void)isReset;
    if (event != IWX_TX_PROGRESS_RESPONSE_DISPATCH) return;
    if (reason == IWX_TX_PROGRESS_RESPONSE_TX_RSP) ++responseEvents;
    if (reason == IWX_TX_PROGRESS_RESPONSE_P2P_CONSUMED) ++consumedEvents;
}

bool iwx_tahoe_p2p_action_tx_response(Driver *owner, iwx_softc *sc,
    int *queue, int *action, iwx_rx_packet *pkt, iwx_rx_data *data);

class Driver {
public:
    iwx_softc softc{};
    iwx_rx_packet packet{};
    iwx_rx_data data{};
    int nativeP2pTxQueue_ = 0;
    int nativeP2pActionTx_ = 0;
    bool p2pResult = false;

    void dispatch()
    {
        iwx_softc *sc = &softc;
        iwx_rx_packet *pkt = &packet;
        iwx_rx_data *data = &this->data;
        const int code = IWX_TX_CMD;
        switch (code) {
'''


HARNESS_SUFFIX = r'''
            case IWX_MISSED_BEACONS_NOTIFICATION:
                break;
        }
    }
};

bool iwx_tahoe_p2p_action_tx_response(Driver *owner, iwx_softc *sc,
    int *queue, int *action, iwx_rx_packet *pkt, iwx_rx_data *data)
{
    (void)sc; (void)queue; (void)action; (void)pkt; (void)data;
    ++p2pCalls;
    return owner->p2pResult;
}

int main(int argc, char **argv)
{
    Driver driver;
    driver.p2pResult = argc > 1 && std::atoi(argv[1]) != 0;
    const uint16_t qid = 0x2345;
    std::memcpy(driver.packet.data + offsetof(iwx_tx_resp, tx_queue),
                &qid, sizeof(qid));
    driver.dispatch();
    std::printf("ordinary=%d p2p=%d response=%d consumed=%d\n",
                ordinaryCalls, p2pCalls, responseEvents, consumedEvents);

#ifdef AIRPORT_TAHOE
    if (p2pCalls != 1 || responseEvents != 1) return 10;
    if (driver.p2pResult) {
        if (ordinaryCalls != 0 || consumedEvents != 1) return 11;
    } else if (ordinaryCalls != 1 || consumedEvents != 0) {
        return 12;
    }
#else
    if (p2pCalls != 0 || responseEvents != 0 || consumedEvents != 0 ||
        ordinaryCalls != 1) return 20;
#endif
    return 0;
}
'''


def compiler_command():
    xcrun = shutil.which("xcrun")
    compiler = shutil.which("clang++") or shutil.which("c++")
    if xcrun and compiler:
        return [xcrun, "clang++"]
    if compiler:
        return [compiler]
    raise SystemExit("No C++ compiler found (clang++ or c++)")


def compile_case(temp: Path, name: str, case: str, tahoe: bool) -> Path:
    source = temp / f"{name}.cpp"
    binary = temp / name
    source.write_text(HARNESS_PREFIX + case + HARNESS_SUFFIX)
    command = compiler_command() + [
        "-std=c++14", "-Wall", "-Wextra", "-Werror",
        str(source), "-o", str(binary),
    ]
    if tahoe:
        command.insert(-3, "-DAIRPORT_TAHOE=1")
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    return binary


def run(binary: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(binary), *args], capture_output=True, text=True)


def main() -> None:
    source = SOURCE.read_text()
    start = source.index(START)
    end = source.index(END, start + len(START))
    production_case = source[start:end]
    if production_case.count(FALLBACK) != 1:
        raise AssertionError("production case does not have one post-Tahoe fallback")
    if "#else\n                iwx_rx_tx_cmd(sc, pkt, data);" in production_case:
        raise AssertionError("ordinary fallback is still isolated in the Tahoe #else")

    # This is the prior Test072 conditional shape restored around the exact
    # current production case. Only the preprocessor boundary changes.
    old_case, replacements = production_case.replace(FALLBACK, LEGACY_BOUNDARY), 1
    if production_case.replace(FALLBACK, "", 1) == production_case:
        raise AssertionError("could not derive the Test072 baseline boundary")
    if old_case.count(LEGACY_BOUNDARY) != replacements:
        raise AssertionError("baseline did not restore exactly one old #else boundary")

    with tempfile.TemporaryDirectory(prefix="test073-tx-response-") as directory:
        temp = Path(directory)
        tahoe = compile_case(temp, "production_tahoe", production_case, True)
        non_tahoe = compile_case(temp, "production_non_tahoe", production_case, False)
        old_tahoe = compile_case(temp, "legacy_test072_tahoe", old_case, True)

        ordinary_fallback = run(tahoe, "0")
        assert ordinary_fallback.returncode == 0, ordinary_fallback.stdout + ordinary_fallback.stderr
        assert "ordinary=1 p2p=1 response=1 consumed=0" in ordinary_fallback.stdout

        p2p_consumed = run(tahoe, "1")
        assert p2p_consumed.returncode == 0, p2p_consumed.stdout + p2p_consumed.stderr
        assert "ordinary=0 p2p=1 response=1 consumed=1" in p2p_consumed.stdout

        non_tahoe_fallback = run(non_tahoe)
        assert non_tahoe_fallback.returncode == 0, non_tahoe_fallback.stdout + non_tahoe_fallback.stderr
        assert "ordinary=1 p2p=0 response=0 consumed=0" in non_tahoe_fallback.stdout

        old_behavior = run(old_tahoe, "0")
        assert old_behavior.returncode == 12, (
            "legacy Test072 did not reproduce the skipped ordinary handler: "
            + old_behavior.stdout + old_behavior.stderr
        )
        assert "ordinary=0 p2p=1 response=1 consumed=0" in old_behavior.stdout

    print("PASS: production Tahoe fallback runs once after P2P false")
    print("PASS: production P2P true consumes and records consumed trace")
    print("PASS: production non-Tahoe ordinary handler runs once")
    print("PASS: legacy Test072 macro boundary reproduces fallback regression")


if __name__ == "__main__":
    main()
