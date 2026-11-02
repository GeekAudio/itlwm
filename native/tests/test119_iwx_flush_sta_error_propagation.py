#!/usr/bin/env python3
"""Exercise the production iwx_flush_sta function for Tahoe and legacy builds."""
from __future__ import annotations

import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def extract_function(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


production = extract_function(
    SOURCE.read_text(), "int ItlIwx::\niwx_flush_sta("
)
assert "#ifdef AIRPORT_TAHOE\n    if (err)" in production
assert "err = iwx_drain_sta(sc, in, 0);" in production
assert "#ifndef AIRPORT_TAHOE\n    if (err == ENXIO)" in production
assert "sc->sc_flags &= ~IWX_FLAG_TXFLUSH;" in production


HARNESS = r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <vector>

#define IPL_NET 0
#define IWX_FLAG_TXFLUSH 0x20u
#define IWX_STATION_ID 7
#define splassert(level) ((void)(level))
#define XYLog(...) ((void)0)

struct iwx_softc { uint32_t sc_flags = 0; };
struct iwx_node {};

class ItlIwx {
public:
    int iwx_flush_sta(struct iwx_softc *, struct iwx_node *);
};

static int firstDrainError = 0;
static int flushError = 0;
static int secondDrainError = 0;
static std::vector<int> calls;

static int iwx_drain_sta(struct iwx_softc *, struct iwx_node *, int drain)
{
    calls.push_back(drain ? 1 : 3);
    return drain ? firstDrainError : secondDrainError;
}

static int iwx_flush_sta_tids(struct iwx_softc *, int sta, uint16_t tids)
{
    assert(sta == IWX_STATION_ID);
    assert(tids == 0xffff);
    calls.push_back(2);
    return flushError;
}

""" + production + r"""

static int run(int first, int flush, int second,
               const std::vector<int> &expectedCalls)
{
    firstDrainError = first;
    flushError = flush;
    secondDrainError = second;
    calls.clear();

    iwx_softc sc{};
    sc.sc_flags = 0x80u;
    iwx_node node{};
    const int result = ItlIwx{}.iwx_flush_sta(&sc, &node);
    assert(calls == expectedCalls);
    assert((sc.sc_flags & IWX_FLAG_TXFLUSH) == 0);
    assert(sc.sc_flags == 0x80u);
    return result;
}

int main()
{
    assert(run(0, 0, 0, {1, 2, 3}) == 0);
    assert(run(0, EBUSY, 0, {1, 2}) == EBUSY);
    assert(run(0, 0, ENXIO, {1, 2, 3}) == ENXIO);

#ifdef AIRPORT_TAHOE
    /* A failed first drain must not issue flush or the second drain. */
    assert(run(EIO, 0, 0, {1}) == EIO);
    assert(run(ENXIO, 0, 0, {1}) == ENXIO);
    /* The final drain's non-ENXIO errors must not be replaced with success. */
    assert(run(0, 0, EIO, {1, 2, 3}) == EIO);
#else
    /* Preserve the pre-existing non-Tahoe behavior exactly. */
    assert(run(EIO, 0, 0, {1, 2, 3}) == 0);
    assert(run(ENXIO, 0, 0, {1}) == ENXIO);
    assert(run(0, 0, EIO, {1, 2, 3}) == 0);
#endif
    return 0;
}
"""


def build_and_run(output: pathlib.Path, tahoe: bool) -> None:
    cpp = output.with_suffix(".cpp")
    cpp.write_text(HARNESS)
    command = [
        "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
    ]
    if tahoe:
        command.append("-DAIRPORT_TAHOE=1")
    command.extend([str(cpp), "-o", str(output)])
    subprocess.run(command, check=True)
    subprocess.run([str(output)], check=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="test119-flush-error-") as temp:
        directory = pathlib.Path(temp)
        build_and_run(directory / "tahoe-test", True)
        build_and_run(directory / "legacy-test", False)
    print(
        "PASS: extracted iwx_flush_sta preserves Tahoe drain errors and "
        "retains legacy behavior (ASan/UBSan)"
    )


if __name__ == "__main__":
    main()
