#!/usr/bin/env python3
"""Compile the production QM HIGH_PRI selector and profile guard."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp").read_text()
REG_SOURCE = (ROOT / "itlwm/hal_iwx/if_iwxreg.h").read_text()


def production_guard():
    start = SOURCE.index("#ifndef ITL_NATIVE_AWDL_QM_NORMAL_PRIORITY_25G332")
    end = SOURCE.index("\n\nnamespace {", start)
    return SOURCE[start:end]


def production_flags_expression():
    function = SOURCE.index("int iwx_tahoe_p2p_action_tx_submit(")
    start = SOURCE.index("    const uint32_t txFlags =", function)
    end = SOURCE.index("#endif", start) + len("#endif")
    return SOURCE[start:end]


def compile_guard(guard, defines):
    source = guard + "\nint main() { return 0; }\n"
    return subprocess.run(
        ["c++", "-std=c++11", "-fsyntax-only", "-x", "c++", "-", *defines],
        input=source, capture_output=True, text=True, check=False,
    )


def run_flags_selector(guard, expression, defines):
    source = r"""
#include <cassert>
#include <cstdint>
#define IWX_TX_FLAGS_CMD_RATE (1U << 0)
#define IWX_TX_FLAGS_ENCRYPT_DIS (1U << 1)
#define IWX_TX_FLAGS_HIGH_PRI (1U << 2)
""" + guard + r"""
static uint32_t selectedFlags(bool qm, bool window, bool mdnsGroup) {
    const bool qmWireSnapshotCandidate = qm;
    const bool estimatedWindowValid = window;
    const bool ipv6DestinationIsAirdropMdns = mdnsGroup;
""" + expression + r"""
    (void)qmWireSnapshotCandidate;
    (void)estimatedWindowValid;
    (void)ipv6DestinationIsAirdropMdns;
    return txFlags;
}
int main() {
    for (unsigned mask = 0; mask < 8; ++mask) {
        const bool qm = (mask & 1U) != 0;
        const bool window = (mask & 2U) != 0;
        const bool mdnsGroup = (mask & 4U) != 0;
        const bool eligible = qm && window && mdnsGroup;
        const uint32_t expected =
            (ITL_NATIVE_AWDL_QM_NORMAL_PRIORITY_25G332 && eligible)
                ? 0x3U : 0x7U;
        const uint32_t actual = selectedFlags(qm, window, mdnsGroup);
        assert(actual == expected);
        assert((actual & (IWX_TX_FLAGS_CMD_RATE | IWX_TX_FLAGS_ENCRYPT_DIS)) == 0x3U);
        assert(actual == 0x3U || actual == 0x7U);
        if (ITL_NATIVE_AWDL_QM_NORMAL_PRIORITY_25G332 && eligible)
            assert((0x7U ^ actual) == IWX_TX_FLAGS_HIGH_PRI);
    }
}
"""
    with tempfile.TemporaryDirectory(prefix="itl-p2p-qm-priority-") as temp:
        cpp = Path(temp) / "qm_priority.cpp"
        binary = Path(temp) / "qm_priority"
        cpp.write_text(source)
        subprocess.run(
            ["c++", "-std=c++11", "-Wall", "-Wextra", "-Werror",
             str(cpp), *defines, "-o", str(binary)],
            check=True,
        )
        subprocess.run([str(binary)], check=True)


def main():
    assert "#define IWX_TX_FLAGS_HIGH_PRI        (1 << 2)" in REG_SOURCE
    guard = production_guard()
    expression = production_flags_expression()
    assert "#define ITL_NATIVE_AWDL_QM_NORMAL_PRIORITY_25G332 0" in guard
    assert "qmWireSnapshotCandidate && estimatedWindowValid &&" in expression
    assert "ipv6DestinationIsAirdropMdns) ? 0u : IWX_TX_FLAGS_HIGH_PRI" in expression

    # The default build compiles as the original flags-7 path.
    run_flags_selector(guard, expression, [])

    candidate = [
        "-DITL_NATIVE_AWDL_QM_NORMAL_PRIORITY_25G332=1",
        "-DITL_NATIVE_AWDL_RESIDENT_25G332=1",
        "-DITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332=1",
    ]
    assert compile_guard(guard, candidate).returncode == 0
    run_flags_selector(guard, expression, candidate)

    # Discovery RX input remains compatible with the same restricted candidate.
    assert compile_guard(guard, candidate + [
        "-DITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332=1",
    ]).returncode == 0

    unsupported = {
        "ordinary_wifi": ["-DITL_NATIVE_AWDL_QM_NORMAL_PRIORITY_25G332=1"],
        "resident_only": [
            "-DITL_NATIVE_AWDL_QM_NORMAL_PRIORITY_25G332=1",
            "-DITL_NATIVE_AWDL_RESIDENT_25G332=1",
        ],
        "multicast_admission": candidate + [
            "-DITL_NATIVE_AWDL_MULTICAST_ADMISSION_25G332=1",
        ],
        "rx149_observation": candidate + [
            "-DITL_NATIVE_AWDL_RX149_OBSERVATION_25G332=1",
        ],
        "rx149_data_input": candidate + [
            "-DITL_NATIVE_AWDL_RX149_OBSERVATION_25G332=1",
            "-DITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332=1",
        ],
        "directed_data_tx": candidate + [
            "-DITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332=1",
        ],
    }
    for profile, defines in unsupported.items():
        result = compile_guard(guard, defines)
        assert result.returncode != 0, profile
        assert "QM priority candidate requires" in result.stderr, profile

    print("production QM priority selector and profile guard passed")


if __name__ == "__main__":
    main()
