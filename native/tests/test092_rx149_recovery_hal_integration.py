#!/usr/bin/env python3
"""Host-test the production HAL gate for Test092 RX149 recovery."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def extract_action() -> str:
    source = SOURCE.read_text()
    start = source.index("IOReturn ItlIwx::tahoeRx149RecoverInputAction(")
    end = source.index("\nvoid ItlIwx::tahoeRx149RecoverInput()", start)
    return source[start:end].strip()


PRELUDE = r"""
#include <cassert>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <string>

using IOReturn = int;
constexpr IOReturn kIOReturnNotReady = -1;
constexpr IOReturn kIOReturnBusy = -2;
constexpr IOReturn kIOReturnSuccess = 0;
constexpr uint32_t IFF_UP = 1u << 0;
constexpr uint32_t IFF_RUNNING = 1u << 1;
constexpr uint32_t IWX_FLAG_HW_ERR = 1u << 0;
constexpr uint32_t IWX_FLAG_SHUTDOWN = 1u << 1;
constexpr uint32_t IWX_FLAG_RFKILL = 1u << 2;
constexpr uint32_t IEEE80211_S_RUN = 4;
constexpr uint32_t IWX_P2P_ROC_IDLE = 0;
constexpr uint32_t IWX_P2P_ROC_COMPLETE = 13;
constexpr uint32_t IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN = 8;
constexpr uint32_t IWX_P2P_ROC_SESSION_ACKED = 9;
constexpr uint32_t IWX_P2P_ROC_QUARANTINED = 14;

struct OSObject {};

namespace IntelROCEvent {
struct SessionSnapshot {
    bool submitted = false;
    bool cleanupAllowed = false;
    bool outcomeUnknown = false;
};
}

struct TimelineSnapshot {
    bool active = false;
    bool ownerPresent = false;
    bool producerClosed = false;
    uint32_t pendingDrainCount = 0;
    uint32_t untrackedPendingDrainCount = 0;
    uint32_t untrackedPendingIdentityOverflowCount = 0;
};
struct ProbeSnapshot { uint32_t resourceMayExist = 0; };
struct Lease { bool active = false; };
struct NetworkIf { uint32_t if_flags = IFF_UP | IFF_RUNNING; };
struct Ieee80211Com {
    uint32_t ic_state = IEEE80211_S_RUN;
    NetworkIf ic_if;
    int ic_tahoe_init_error = 0;
    uint32_t ic_tahoe_init_stage = 14;
};
struct RocState { uint32_t phase = IWX_P2P_ROC_IDLE; };
struct Softc {
    Ieee80211Com sc_ic;
    int sc_generation = 42;
    uint32_t sc_flags = 0;
    RocState sc_p2p_roc;
};

namespace NativeAwdlBSD {
struct Rx149RecoveryAuthority {
    uint32_t faultSerial = 0;
    uint32_t powerGeneration = 0;
    bool fullInitializationSucceeded = false;
    bool faultSourceClear = false;
};
enum class Rx149RecoveryResult : uint32_t {
    Recovered = 0, NotBlocked = 1, InvalidAuthority = 2,
    StaleFaultSerial = 3, BridgeUnavailable = 4,
    WrongPowerGeneration = 5, CurrentOwnerActive = 6,
    VersionExhausted = 7, WorkerActive = 8,
    InputTicketActive = 9, PermitQueueNotDrained = 10, FaultRaced = 11
};
inline bool blocked = true;
inline uint32_t faultSerial = 7;
inline unsigned recoverCalls = 0;
inline Rx149RecoveryAuthority lastAuthority{};
inline Rx149RecoveryResult recoverResult = Rx149RecoveryResult::Recovered;
inline bool rx149DataInputBlocked() { return blocked; }
inline uint32_t rx149DataInputFaultSerial() { return faultSerial; }
inline Rx149RecoveryResult recoverRx149DataInput(
    const Rx149RecoveryAuthority &authority) {
    ++recoverCalls;
    lastAuthority = authority;
    return recoverResult;
}
}

struct IOEthernetController {
    std::map<std::string, uint64_t> properties;
    bool setProperty(const char *key, uint64_t value, unsigned) {
        properties[key] = value;
        return true;
    }
};

struct ItlIwx;
struct RocAdapter {
    ItlIwx *owner;
    IntelROCEvent::SessionSnapshot snapshot() const;
};
struct TimelineAdapter {
    ItlIwx *owner;
    TimelineSnapshot snapshot() const;
};
struct ProbeAdapter {
    ItlIwx *owner;
    ProbeSnapshot snapshot() const;
};
struct TahoeLifecycleGuard {
    TahoeLifecycleGuard(ItlIwx *, bool, bool, bool *) {}
    explicit operator bool() const { return true; }
};

struct ItlIwx {
    Softc com;
    uint64_t nativeRx149InitProof_ = (uint64_t{42} << 32) | 7;
    uint32_t nativeRx149RecoveryCount_ = 0;
    IntelROCEvent::SessionSnapshot rocSnapshot{};
    TimelineSnapshot timelineSnapshot{};
    ProbeSnapshot probeSnapshot{};
    RocAdapter nativeP2pRocEvents_{this};
    TimelineAdapter nativeAwdlRxEventTimeline_{this};
    ProbeAdapter nativeP2pProbe_{this};
    Lease tahoe_p2p_rx_lease_{};
    bool nativeP2pProbeQueued_ = false;
    void *nativeP2pProbeOwner_ = nullptr;
    bool nativeP2pNswqPaused_ = false;
    bool nativeP2pManualArmRequested_ = false;
    bool probeBusy = false;
    bool resourcesRetained = false;
    IOEthernetController controller;

    bool tahoeP2pOnMainGate() const { return true; }
    bool nativeP2pBusy() const { return probeBusy; }
    bool nativeP2pResourcesRetained() const { return resourcesRetained; }
    IOEthernetController *getController() { return &controller; }
    static IOReturn tahoeRx149RecoverInputAction(
        OSObject *, void *, void *, void *, void *);
};

inline IntelROCEvent::SessionSnapshot RocAdapter::snapshot() const {
    return owner->rocSnapshot;
}
inline TimelineSnapshot TimelineAdapter::snapshot() const {
    return owner->timelineSnapshot;
}
inline ProbeSnapshot ProbeAdapter::snapshot() const {
    return owner->probeSnapshot;
}

#define ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332 1
"""


POSTLUDE = r"""
static void resetBridge() {
    NativeAwdlBSD::blocked = true;
    NativeAwdlBSD::faultSerial = 7;
    NativeAwdlBSD::recoverCalls = 0;
    NativeAwdlBSD::recoverResult = NativeAwdlBSD::Rx149RecoveryResult::Recovered;
}

static IOReturn run(ItlIwx &owner) {
    bool flush = false;
    return ItlIwx::tahoeRx149RecoverInputAction(
        nullptr, &owner, &flush, nullptr, nullptr);
}

int main() {
    // Restore is pre-ARM and does not require a fresh ROC START or owner.
    resetBridge();
    ItlIwx ready{};
    assert(run(ready) == kIOReturnSuccess);
    assert(NativeAwdlBSD::recoverCalls == 1);
    assert(NativeAwdlBSD::lastAuthority.faultSerial == 7);
    assert(NativeAwdlBSD::lastAuthority.powerGeneration == 42);
    assert(NativeAwdlBSD::lastAuthority.fullInitializationSucceeded);
    assert(NativeAwdlBSD::lastAuthority.faultSourceClear);

    // A proof from another generation or a newly asserted hardware fault is
    // stale and must not reach the bridge recovery API.
    resetBridge();
    ItlIwx staleGeneration{};
    ++staleGeneration.com.sc_generation;
    assert(run(staleGeneration) == kIOReturnNotReady);
    assert(NativeAwdlBSD::recoverCalls == 0);
    assert(staleGeneration.controller.properties.at(
        "NativeP2PRx149RecoveryBlockers") == 1u);

    resetBridge();
    ItlIwx hardwareFault{};
    hardwareFault.com.sc_flags |= IWX_FLAG_HW_ERR;
    assert(run(hardwareFault) == kIOReturnNotReady);
    assert(NativeAwdlBSD::recoverCalls == 0);
    assert(hardwareFault.controller.properties.at(
        "NativeP2PRx149RecoveryBlockers") == 2u);

    // Even a matching packed proof must be rejected if the signed driver
    // generation is invalid after an exhaustion/wrap boundary.
    resetBridge();
    ItlIwx negativeGeneration{};
    negativeGeneration.com.sc_generation = -1;
    negativeGeneration.nativeRx149InitProof_ =
        (uint64_t{0xffffffffu} << 32) | 7u;
    assert(run(negativeGeneration) == kIOReturnNotReady);
    assert(NativeAwdlBSD::recoverCalls == 0);
    assert(negativeGeneration.controller.properties.at(
        "NativeP2PRx149RecoveryBlockers") == 1u);

    // Active or quarantined firmware ROC phases must not reopen the gate.
    for (uint32_t phase : {IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN,
                           IWX_P2P_ROC_SESSION_ACKED,
                           IWX_P2P_ROC_QUARANTINED}) {
        resetBridge();
        ItlIwx owner{};
        owner.com.sc_p2p_roc.phase = phase;
        assert(run(owner) == kIOReturnNotReady);
        assert(NativeAwdlBSD::recoverCalls == 0);
        assert(owner.controller.properties.at(
            "NativeP2PRx149RecoveryBlockers") == 8u);
    }
    for (uint32_t phase : {IWX_P2P_ROC_IDLE, IWX_P2P_ROC_COMPLETE}) {
        resetBridge();
        ItlIwx owner{};
        owner.com.sc_p2p_roc.phase = phase;
        assert(run(owner) == kIOReturnSuccess);
        assert(NativeAwdlBSD::recoverCalls == 1);
    }

    // Untracked owner identity overflow means quiescence is unproven.
    resetBridge();
    ItlIwx overflow{};
    overflow.timelineSnapshot.untrackedPendingIdentityOverflowCount = 1;
    assert(run(overflow) == kIOReturnNotReady);
    assert(NativeAwdlBSD::recoverCalls == 0);
    assert(overflow.controller.properties.at(
        "NativeP2PRx149RecoveryBlockers") == 8u);

    resetBridge();
    ItlIwx closed{};
    closed.timelineSnapshot.ownerPresent = true;
    closed.timelineSnapshot.producerClosed = true;
    assert(run(closed) == kIOReturnSuccess);
    assert(NativeAwdlBSD::recoverCalls == 1);
    return 0;
}
"""


def main() -> None:
    source = PRELUDE + "\n" + extract_action() + "\n" + POSTLUDE
    with tempfile.TemporaryDirectory(prefix="itl-test092-") as directory:
        cpp = pathlib.Path(directory) / "test.cpp"
        binary = pathlib.Path(directory) / "test"
        cpp.write_text(source)
        subprocess.run(
            ["clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
             str(cpp), "-o", str(binary)],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
    print("Test092 HAL recovery-gate integration passed")


if __name__ == "__main__":
    main()
