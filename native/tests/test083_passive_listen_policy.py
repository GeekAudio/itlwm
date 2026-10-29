#!/usr/bin/env python3
"""Test the production RX149 ROC policy in feature-on and feature-off builds."""

from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def extract(path: str, marker: str) -> str:
    source = (ROOT / path).read_text()
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unterminated production function: {path}: {marker}")


def production_functions() -> str:
    markers = [
        ("itlwm/hal_iwx/ItlIwxP2PRoc.cpp",
         "static bool\ntahoeP2pRocIsReceiveObservationOnly("),
        ("itlwm/hal_iwx/ItlIwxP2PRoc.cpp",
         "static TahoeP2PRocObservationPolicy::Channel\ntahoeP2pRocObservationChannel("),
        ("itlwm/hal_iwx/ItlIwxP2PRoc.cpp",
         "static bool\ntahoeP2pRocObservation149PrepareAllowed("),
        ("itlwm/hal_iwx/ItlIwxP2PRoc.cpp",
         "static bool\ntahoeP2pRocObservation149SubmitAllowed("),
    ]
    return "\n\n".join(extract(path, marker) for path, marker in markers)


SHIM = r"""
#include <cassert>
#include <cstddef>
#include <cstdint>
#define IEEE80211_CHAN_DFS (1U << 19)
#define IEEE80211_CHAN_PASSIVE (1U << 9)
#define IEEE80211_CHAN_5GHZ (1U << 8)
#define IEEE80211_CHAN_2GHZ (1U << 7)
#define IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV 2
#if defined(TEST_FEATURE_ON)
#define ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332 1
#endif
#define IEEE80211_IS_CHAN_5GHZ(c) (((c)->ic_flags & IEEE80211_CHAN_5GHZ) != 0)
#define IEEE80211_IS_CHAN_2GHZ(c) (((c)->ic_flags & IEEE80211_CHAN_2GHZ) != 0)
typedef unsigned int u_int;
struct ieee80211_channel {
    uint16_t ic_freq;
    uint32_t ic_flags;
};
struct iwx_p2p_roc_state {
    uint8_t receive_observation_only;
    ieee80211_channel *roc_channel;
};
#include "itlwm/hal_iwx/tahoe_p2p_roc_observation_policy.hpp"
"""

CASES = r"""
int main() {
    ieee80211_channel passive{5745, IEEE80211_CHAN_5GHZ | 1U |
                                      IEEE80211_CHAN_PASSIVE};
    const uint32_t originalFlags = passive.ic_flags;
    iwx_p2p_roc_state roc{1, &passive};

#if defined(TEST_FEATURE_ON)
    assert(tahoeP2pRocObservation149PrepareAllowed(&passive, 149, 2, true));
    assert(tahoeP2pRocObservation149SubmitAllowed(roc, 2, 100, 149));
    assert(!tahoeP2pRocObservation149SubmitAllowed(roc, 2, 99, 149));
    assert(!tahoeP2pRocObservation149SubmitAllowed(roc, 2, 900, 149));
    assert(!tahoeP2pRocObservation149PrepareAllowed(&passive, 149, 3, true));
    assert(!tahoeP2pRocObservation149SubmitAllowed(roc, 3, 100, 149));
    assert(!tahoeP2pRocObservation149PrepareAllowed(&passive, 148, 2, true));
    assert(tahoeP2pRocObservation149PrepareAllowed(&passive, 149, 2, false));
    assert(tahoeP2pRocObservation149SubmitAllowed(
        iwx_p2p_roc_state{0, &passive}, 2, 900, 149));
#else
    assert(!tahoeP2pRocObservation149PrepareAllowed(&passive, 149, 2, true));
    assert(!tahoeP2pRocObservation149SubmitAllowed(roc, 2, 100, 149));
    assert(tahoeP2pRocObservation149PrepareAllowed(&passive, 149, 2, false));
    assert(tahoeP2pRocObservation149SubmitAllowed(
        iwx_p2p_roc_state{0, &passive}, 2, 100, 149));
#endif

    assert(passive.ic_flags == originalFlags);

    passive.ic_flags = 0;
    assert(!tahoeP2pRocObservation149PrepareAllowed(&passive, 149, 2, true));
    passive.ic_flags = IEEE80211_CHAN_5GHZ | 1U | IEEE80211_CHAN_DFS;
    assert(!tahoeP2pRocObservation149PrepareAllowed(&passive, 149, 2, true));
    passive.ic_flags = IEEE80211_CHAN_2GHZ | 1U;
    assert(!tahoeP2pRocObservation149PrepareAllowed(&passive, 149, 2, true));
    passive.ic_flags = IEEE80211_CHAN_5GHZ | 1U;
    passive.ic_freq = 5740;
    assert(!tahoeP2pRocObservation149PrepareAllowed(&passive, 149, 2, true));
    return 0;
}
"""


def check_source_contract() -> None:
    source = (ROOT / "itlwm/hal_iwx/ItlIwxP2PRoc.cpp").read_text()
    prepare = extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp",
                      "int ItlIwx::\ntahoeP2pRocPrepare(")
    submit = extract("itlwm/hal_iwx/ItlIwxP2PRoc.cpp",
                     "int ItlIwx::\ntahoeP2pRocSubmit(")
    assert "!receiveObservation149 && sta->in_ni.ni_chan != channel" in prepare
    assert "tahoeP2pRocObservation149PrepareAllowed" in prepare
    assert "tahoeP2pRocObservation149SubmitAllowed" in submit
    assert "durationMs != kTahoeRocDurationMs" in submit
    assert "channel->ic_flags =" not in prepare
    assert "channel->ic_flags =" not in submit
    assert "IEEE80211_CHAN_PASSIVE" in source


def main() -> None:
    check_source_contract()
    functions = production_functions()
    compiler = os.environ.get("CXX", "clang++")
    with tempfile.TemporaryDirectory(prefix="test083-passive-policy-") as tmp:
        for feature_on in (True, False):
            source = Path(tmp) / ("feature-on.cpp" if feature_on else "feature-off.cpp")
            executable = source.with_suffix("")
            feature = "-DTEST_FEATURE_ON" if feature_on else ""
            source.write_text(SHIM + "\n" + functions + "\n" + CASES)
            command = [
                compiler, "-std=c++14", "-O1", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-fno-sanitize-recover=all", "-I", str(ROOT),
            ]
            if feature:
                command.append(feature)
            command.extend([str(source), "-o", str(executable)])
            subprocess.run(command, check=True)
            environment = dict(os.environ)
            environment.setdefault("ASAN_OPTIONS", "detect_leaks=0:halt_on_error=1")
            environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
            subprocess.run([str(executable)], check=True, env=environment)
    print("PASS: production RX149 policy accepts retained PASSIVE only in the compiled explicit listen route")


if __name__ == "__main__":
    main()
