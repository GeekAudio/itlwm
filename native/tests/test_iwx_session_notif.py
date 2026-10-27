#!/usr/bin/env python3
"""Run the production Session Protection RX switch branch with a host shim."""
from pathlib import Path
import subprocess
import tempfile


root = Path(__file__).resolve().parents[2]
source = (root / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
marker = (
    "case IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_SESSION_PROTECTION_NOTIF): {"
)
start = source.index(marker)
opening = source.index("{", start)
end, depth = opening + 1, 1
while depth:
    depth += (source[end] == "{") - (source[end] == "}")
    end += 1
branch = source[start:end]

fixture = r"""
#include "intel_roc_event_state.hpp"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>

#define AIRPORT_TAHOE 1
#define IWX_MAC_CONF_GROUP 3
#define IWX_SESSION_PROTECTION_NOTIF 0xfb
#define IWX_STATION_ID 0
#define IWX_FLAG_TE_ACTIVE 0x40u
#define IWX_WIDE_ID(group, command) (((group) << 8) | (command))
#define SYNC_RESP_STRUCT(variable, packet, type) \
    do { (variable) = reinterpret_cast<type>((packet)->data); } while (0)
#define XYLog(...) do { } while (0)

struct iwx_session_prot_notif {
    uint32_t mac_id;
    uint32_t status;
    uint32_t start;
    uint32_t conf_id;
} __attribute__((packed));
static_assert(sizeof(iwx_session_prot_notif) == 16, "API v2 notif size");

struct iwx_rx_packet {
    alignas(4) uint8_t data[32]{};
    size_t payload_length = 16;
};
static size_t iwx_rx_packet_payload_len(const iwx_rx_packet *packet)
{
    return packet->payload_length;
}
struct iwx_softc { uint32_t sc_flags = 0; };

struct ItlIwx {
    unsigned taps = 0;
    uint32_t tapMac = 0, tapStatus = 0, tapStart = 0, tapConf = 0;

    void tahoeP2pTapSessionEvent(iwx_softc *, const uint8_t *bytes,
                                 size_t length)
    {
        assert(length == sizeof(iwx_session_prot_notif));
        ++taps;
        tapMac = uint32_t(bytes[0]) | uint32_t(bytes[1]) << 8 |
                 uint32_t(bytes[2]) << 16 | uint32_t(bytes[3]) << 24;
        tapStatus = uint32_t(bytes[4]) | uint32_t(bytes[5]) << 8 |
                    uint32_t(bytes[6]) << 16 | uint32_t(bytes[7]) << 24;
        tapStart = uint32_t(bytes[8]) | uint32_t(bytes[9]) << 8 |
                   uint32_t(bytes[10]) << 16 | uint32_t(bytes[11]) << 24;
        tapConf = uint32_t(bytes[12]) | uint32_t(bytes[13]) << 8 |
                  uint32_t(bytes[14]) << 16 | uint32_t(bytes[15]) << 24;
    }

    void dispatch(iwx_softc *sc, iwx_rx_packet *pkt)
    {
        switch (IWX_WIDE_ID(IWX_MAC_CONF_GROUP,
                            IWX_SESSION_PROTECTION_NOTIF)) {
            BRANCH
        }
    }
};

static void notify(ItlIwx &driver, iwx_softc &sc, iwx_rx_packet &packet,
                   uint32_t mac, uint32_t status, uint32_t start,
                   uint32_t conf, size_t length = 16)
{
    iwx_session_prot_notif n{mac, status, start, conf};
    std::memset(packet.data, 0, sizeof(packet.data));
    std::memcpy(packet.data, &n, sizeof(n));
    packet.payload_length = length;
    driver.dispatch(&sc, &packet);
}

int main()
{
    // P2P conf2 is tapped for its own tracker and cannot clear STA state.
    {
        ItlIwx d; iwx_softc sc; iwx_rx_packet p;
        sc.sc_flags = IWX_FLAG_TE_ACTIVE;
        notify(d, sc, p, 1, 1, 0, 2);
        assert(d.taps == 1 && d.tapMac == 1 && d.tapConf == 2);
        assert(sc.sc_flags & IWX_FLAG_TE_ACTIVE);
    }
    // The existing STA association failure and END paths retain their effect.
    {
        ItlIwx d; iwx_softc sc; iwx_rx_packet p;
        sc.sc_flags = IWX_FLAG_TE_ACTIVE;
        notify(d, sc, p, 0, 0, 1, 0);
        assert(d.taps == 1 && !(sc.sc_flags & IWX_FLAG_TE_ACTIVE));
    }
    {
        ItlIwx d; iwx_softc sc; iwx_rx_packet p;
        sc.sc_flags = IWX_FLAG_TE_ACTIVE;
        notify(d, sc, p, 0, 1, 0, 0);
        assert(d.taps == 1 && !(sc.sc_flags & IWX_FLAG_TE_ACTIVE));
    }
    // Notifications for another MAC or configuration never mutate STA state.
    for (const auto &value : {uint32_t(1), uint32_t(2)}) {
        ItlIwx d; iwx_softc sc; iwx_rx_packet p;
        sc.sc_flags = IWX_FLAG_TE_ACTIVE;
        notify(d, sc, p, value == 1 ? 1 : 0, 1, 0,
               value == 1 ? 0 : 2);
        assert(d.taps == 1);
        assert(sc.sc_flags & IWX_FLAG_TE_ACTIVE);
    }
    // Exact-size but unknown boolean fields are tapped, never treated as STA.
    {
        ItlIwx d; iwx_softc sc; iwx_rx_packet p;
        sc.sc_flags = IWX_FLAG_TE_ACTIVE;
        notify(d, sc, p, 0, 2, 1, 0);
        assert(d.taps == 1 && sc.sc_flags == IWX_FLAG_TE_ACTIVE);
        assert(!IntelROCEvent::isStationSessionNotification(p.data, 16, 0));
    }
    // Both truncation and an oversized API payload are rejected before tap/cast.
    for (size_t length : {size_t(0), size_t(12), size_t(15), size_t(17), size_t(24)}) {
        ItlIwx d; iwx_softc sc; iwx_rx_packet p;
        sc.sc_flags = IWX_FLAG_TE_ACTIVE;
        notify(d, sc, p, 1, 1, 0, 2, length);
        assert(d.taps == 0 && sc.sc_flags == IWX_FLAG_TE_ACTIVE);
    }
    // The helper used by the real branch accepts only a valid STA conf0 event.
    {
        uint8_t bytes[16]{};
        auto put = [&](unsigned offset, uint32_t v) {
            for (unsigned i = 0; i < 4; ++i) bytes[offset+i] = uint8_t(v >> (i*8));
        };
        put(0, 0); put(4, 1); put(8, 0); put(12, 0);
        assert(IntelROCEvent::isStationSessionNotification(bytes, 16, 0));
        put(12, 2);
        assert(!IntelROCEvent::isStationSessionNotification(bytes, 16, 0));
    }
}
"""

fixture = fixture.replace("BRANCH", branch)
with tempfile.TemporaryDirectory(prefix="itlwm-session-notif-") as directory:
    cpp = Path(directory) / "session_notif_test.cpp"
    binary = Path(directory) / "session_notif_test"
    cpp.write_text(fixture)
    subprocess.run([
        "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer", "-I", str(root / "native"),
        str(cpp), str(root / "native/intel_roc_event_state.cpp"),
        "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True)

print("PASS: actual Session Protection RX branch and STA/P2P routing")
