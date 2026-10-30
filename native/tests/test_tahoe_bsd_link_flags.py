#!/usr/bin/env python3
"""Exercise the production BSD setLinkState() body with a tiny KPI shim."""
from __future__ import annotations

import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "AirportItlwm/AirportItlwmEthernetInterface.cpp"


def extract_function(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise RuntimeError(f"missing function: {signature}")
    opening = source.find("{", start + len(signature))
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise RuntimeError("unterminated production function")


PRODUCTION = extract_function(
    SOURCE.read_text(),
    "bool AirportItlwmEthernetInterface::\nsetLinkState(IO80211LinkState state)",
)

HARNESS = r'''#include <cassert>
#include <cstdint>
#include <cstring>

using u_int16_t = uint16_t;
using ifnet_t = struct FakeIf *;
enum { IFF_UP = 0x1, IFF_RUNNING = 0x40 };
enum IO80211LinkState { kIO80211NetworkLinkDown = 0, kIO80211NetworkLinkUp = 1 };

struct FakeIf { u_int16_t flags; };
static FakeIf fakeIf{};
static u_int16_t lastNewFlags = 0;
static u_int16_t lastMask = 0;
static unsigned calls = 0;

static u_int16_t ifnet_flags(ifnet_t ifp) { return ifp->flags; }
static int ifnet_set_flags(ifnet_t ifp, u_int16_t newFlags, u_int16_t mask) {
    ++calls;
    lastNewFlags = newFlags;
    lastMask = mask;
    ifp->flags = (ifp->flags & ~mask) | (newFlags & mask);
    return 0;
}

class AirportItlwmEthernetInterface {
public:
    bool setLinkState(IO80211LinkState state);
    ifnet_t getIfnet() { return &fakeIf; }
};

// PRODUCTION_FUNCTION

int main(int argc, char **argv) {
    assert(argc == 2);
    AirportItlwmEthernetInterface interface;
    const char *scenario = argv[1];
    if (!std::strcmp(scenario, "admin-up-down")) {
        fakeIf.flags = IFF_UP | IFF_RUNNING;
        assert(interface.setLinkState(kIO80211NetworkLinkDown));
        assert(fakeIf.flags == IFF_UP);
#ifdef AIRPORT_TAHOE
        assert(lastMask == IFF_RUNNING && lastNewFlags == 0);
#endif
    } else if (!std::strcmp(scenario, "admin-down-down")) {
        fakeIf.flags = 0;
        assert(interface.setLinkState(kIO80211NetworkLinkDown));
        assert(fakeIf.flags == 0);
#ifdef AIRPORT_TAHOE
        assert(lastMask == IFF_RUNNING && lastNewFlags == 0);
#endif
    } else if (!std::strcmp(scenario, "initial-link-up")) {
        fakeIf.flags = 0;
        assert(interface.setLinkState(kIO80211NetworkLinkUp));
        assert(fakeIf.flags == (IFF_UP | IFF_RUNNING));
        assert(lastMask == (IFF_UP | IFF_RUNNING));
    } else if (!std::strcmp(scenario, "reconnect")) {
        fakeIf.flags = IFF_UP | IFF_RUNNING;
        assert(interface.setLinkState(kIO80211NetworkLinkDown));
        assert(fakeIf.flags == IFF_UP);
        assert(interface.setLinkState(kIO80211NetworkLinkUp));
        assert(fakeIf.flags == (IFF_UP | IFF_RUNNING));
    } else if (!std::strcmp(scenario, "legacy-link-down-call-unchanged")) {
#ifdef AIRPORT_TAHOE
        assert(!"legacy-only test compiled for Tahoe");
#else
        fakeIf.flags = IFF_UP | IFF_RUNNING;
        assert(interface.setLinkState(kIO80211NetworkLinkDown));
        assert(calls == 1 && lastMask == 0 && lastNewFlags == 0);
#endif
    } else {
        assert(!"unknown scenario");
    }
    return 0;
}
'''


def compile_harness(tahoe: bool, binary: pathlib.Path) -> None:
    source = HARNESS.replace("// PRODUCTION_FUNCTION", PRODUCTION)
    with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False) as stream:
        stream.write(source)
        path = pathlib.Path(stream.name)
    try:
        command = ["clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror"]
        if tahoe:
            command += ["-DAIRPORT_TAHOE=1"]
        command += [str(path), "-o", str(binary)]
        subprocess.run(command, check=True)
    finally:
        path.unlink(missing_ok=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="itl-tahoe-ifflags-") as temp:
        temp_path = pathlib.Path(temp)
        tahoe = temp_path / "tahoe"
        legacy = temp_path / "legacy"
        compile_harness(True, tahoe)
        for case in ("admin-up-down", "admin-down-down", "initial-link-up", "reconnect"):
            subprocess.run([str(tahoe), case], check=True)
        compile_harness(False, legacy)
        subprocess.run([str(legacy), "legacy-link-down-call-unchanged"], check=True)
    print("Tahoe BSD link flag tests passed; legacy down branch unchanged")


if __name__ == "__main__":
    main()
