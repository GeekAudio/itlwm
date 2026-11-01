#!/usr/bin/env python3
"""Offline host fixture; compiles exact local ABI declarations and hook bodies.

No ioreg, sockets, devices, firmware commands or RF. Kernel/controller interfaces
are fakes. Pass a fresh output directory; existing output is never overwritten.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def function(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[start:index + 1]
    raise AssertionError(marker)


def declaration(source, name):
    start = source.index("struct " + name + " {")
    end = source.index("} __packed;", start) + len("} __packed;")
    return source[start:end]


def main():
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
    reg = (ROOT / "itlwm/hal_iwx/if_iwxreg.h").read_text()
    frame = (ROOT / "itl80211/openbsd/net80211/ieee80211.h").read_text()
    preamble = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <unordered_map>
#define __packed __attribute__((packed))
#define IEEE80211_ADDR_LEN 6
using u_int8_t = uint8_t;
using __le16 = uint16_t;
using __le32 = uint32_t;
using __le64 = uint64_t;
static uint16_t le16toh(uint16_t x) { return x; }
static uint32_t le32toh(uint32_t x) { return x; }
struct iwx_rx_packet { uint8_t data[64]; };
struct IOEthernetController {
    std::unordered_map<std::string, uint64_t> values;
    std::string failKey;
    bool setProperty(const char *key, uint64_t value, unsigned) {
        if (failKey == key) return false;
        values[key] = value; return true;
    }
};
'''
    names = ["iwx_dram_sec_info", "iwx_tx_cmd_gen2", "iwx_tx_cmd_gen3",
             "iwx_agg_tx_status", "iwx_tx_resp", "iwx_fw_cmd_version"]
    parts = [preamble, declaration(frame, "ieee80211_frame")]
    parts += [declaration(reg, name) for name in names]
    parts.append("""
#define IWX_FW_CMD_VER_UNKNOWN 0xff
struct iwx_softc { int n_cmd_versions; const iwx_fw_cmd_version *cmd_versions; };
class ItlIwx { public: uint8_t iwx_lookup_notif_ver(iwx_softc *, uint8_t, uint8_t); };
""".replace("\n+", "\n"))
    parts.append(function(source, "uint8_t ItlIwx::\niwx_lookup_notif_ver("))
    a = source.index("// BEGIN TX_RSP local prefix ABI assertions")
    b = source.index("// END TX_RSP local prefix ABI assertions.", a)
    parts.append(source[a:b])
    markers = ["static void txCompletionSetTxRspFacts(",
               "static void txCompletionSetTxRspPrefixFacts(",
               "static bool publishCompletionSnapshot("]
    parts += [function(source, marker) for marker in markers]
    generated = "\n\n".join(parts) + "\n"
    (out / "tx_rsp_prefix_production.inc").write_text(generated)
    tests = ["iwx_tx_rsp_prefix_observation_test",
             "iwx_tx_completion_observation_test",
             "iwx_tx_completion_publish_test",
             "iwx_tx_rsp_retry_observation_test"]
    commands = []
    for test in tests:
        binary = out / test
        cmd = ["xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
               "-Wextra", "-Werror", "-fsanitize=address,undefined",
               "-fno-omit-frame-pointer", "-pthread", "-I", str(ROOT),
               "-I", str(out), str(ROOT / "native/tests" / (test + ".cpp")),
               "-o", str(binary)]
        subprocess.run(cmd, check=True)
        subprocess.run([str(binary)], check=True)
        commands.append(cmd)
    subprocess.run([sys.executable, str(ROOT / "native/tests/test103_tx_rsp_retry_hook.py")],
                   check=True)
    (out / "receipt.json").write_text(json.dumps({
        "schema": "tx-rsp-prefix-private-fixture/v1",
        "tests_passed": tests + ["test103_tx_rsp_retry_hook.py"],
        "commands": commands,
        "generated_production_sha256": hashlib.sha256(generated.encode()).hexdigest(),
        "hardware_operations": False,
        "kernel_full_translation_unit_compiled": False,
        "abi_scope": "local extracted declarations; not firmware compatibility proof"
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
