#!/usr/bin/env python3
"""Compile the production P2P-retention guard and exercise Test108 cold-start cases."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
ITL = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
ACTION = (ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp").read_text()
DATA_HEADER = (ROOT / "itlwm/hal_iwx/ItlIwxP2PData.hpp").read_text()


def extract(source: str, marker: str) -> str:
    start = source.index(marker)
    while True:
        opening = source.find("{", start)
        semicolon = source.find(";", start)
        if opening < 0:
            raise ValueError(f"definition body not found for {marker!r}")
        if semicolon < 0 or opening < semicolon:
            break
        start = source.find(marker, semicolon + 1)
        if start < 0:
            raise ValueError(f"definition body not found after declaration: {marker!r}")
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


GUARD = extract(ITL, "bool ItlIwx::nativeP2pResourcesRetained()")
SUBMIT = extract(ACTION, "static int directedDataTxSubmitOnMainGate(")

assert DATA_HEADER.count("mayOwnResource") == 2  # field plus constructor zero
assert "reason(TahoeP2PDirectedDataReason::kNone), mayOwnResource(0)" in DATA_HEADER
assert ACTION.count("mayOwnResource") == 1
assert "__atomic_store_n(&context->mayOwnResource" in ACTION
assert ITL.count("mayOwnResource") == 1
assert "__atomic_load_n(\n        &nativeP2pDirectedDataTx_.mayOwnResource, __ATOMIC_ACQUIRE)" in ITL

submit_flat = " ".join(SUBMIT.split())
may_own_publish = submit_flat.index(
    "directedDataSetMayOwnResource(context, true)",
    submit_flat.index("context->expectedNextSsn"),
)
doorbell_flag = submit_flat.index("context->doorbellIssued = true;")
doorbell_write = submit_flat.index("IWX_WRITE(sc, IWX_HBUS_TARG_WRPTR")
assert may_own_publish < doorbell_flag < doorbell_write

submit_lines = SUBMIT.splitlines()
for line_number, line in enumerate(submit_lines):
    if "context->state = TahoeP2PDirectedDataState::kQuarantined;" in line:
        preceding = "\n".join(submit_lines[max(0, line_number - 4):line_number])
        assert "directedDataSetMayOwnResource(context, true)" in preceding, \
            f"quarantine path at line {line_number + 1} did not publish mayOwn first"

HARNESS = r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_map>

#define ITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332 1
#define IOLog(...) ((void)0)

using IOInterruptState = unsigned long;
struct IOSimpleLock {};
static IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *) { return 0; }
static void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *, IOInterruptState) {}

class IOEthernetController {
public:
    void setProperty(const char *key, uint32_t value, unsigned) {
        properties[key] = value;
    }
    std::unordered_map<std::string, uint32_t> properties;
};

enum class TahoeP2PResourceState : uint8_t {
    kAbsent, kPending, kActive, kRemoving, kReleasing, kUnknown
};
static constexpr uint32_t IWX_P2P_RESOURCE_ABSENT = 0;
struct TahoeP2PTxQueueLease {
    TahoeP2PResourceState state {TahoeP2PResourceState::kAbsent};
    uint16_t queueId {0};
    uint32_t generation {0};
    void *pendingRing {nullptr};
    bool submissionBusy {false};
};
struct TahoeP2PStationLease {
    TahoeP2PResourceState state {TahoeP2PResourceState::kAbsent};
    uint8_t stationId {0};
    uint32_t generation {0};
};

enum TahoeP2PDirectedDataState : uint32_t {
    kIdle, kArmed, kTicketBound, kPermitIssued, kInFlight,
    kCompleted, kQuarantined, kClosed
};
enum TahoeP2PDirectedDataReason : uint32_t { kNone, kDrainMismatch };
struct TahoeP2PDirectedDataContext {
    uint32_t mayOwnResource {0};
};
struct TahoeP2PDirectedDataSnapshot {
    TahoeP2PDirectedDataState state {kIdle};
    TahoeP2PDirectedDataReason reason {kNone};
    bool originTicketBound {false};
    bool originClosed {false};
    bool doorbellIssued {false};
    bool completionObserved {false};
    bool mbufHeldByRing {false};
    bool completionArmed {false};
    bool hardStopDrained {false};
};

struct P2PFields {
    uint32_t mac_state {0};
    uint32_t binding_state {0};
    bool phy_leased {false};
    uint32_t fw_generation {0};
};
struct iwx_softc {
    int sc_generation {0};
    P2PFields sc_p2p;
};

class ItlIwx;
static unsigned gSnapshotCalls = 0;
static bool gSnapshotValid = true;
static int gSnapshotGateResult = 0;
static TahoeP2PDirectedDataSnapshot gSnapshot;
static constexpr int kIOReturnBusy = -536870187;
static constexpr int kIOReturnNotReady = -536870184;

static bool iwx_tahoe_p2p_directed_data_snapshot(
    ItlIwx *, const TahoeP2PDirectedDataContext *,
    TahoeP2PDirectedDataSnapshot *snapshot, bool, int *gateResultOut);

class ItlIwx {
public:
    iwx_softc com;
    TahoeP2PTxQueueLease nativeP2pTxQueue_;
    TahoeP2PStationLease nativeP2pStation_;
    IOSimpleLock txLock_;
    IOSimpleLock *nativeP2pTxLock_ {&txLock_};
    TahoeP2PDirectedDataContext nativeP2pDirectedDataTx_;
    uint64_t nativeP2pStopRejectFingerprint_ {0};
    IOEthernetController controller_;
    bool busy {false};

    bool nativeP2pBusy() const { return busy; }
    IOEthernetController *getController() { return &controller_; }
    bool nativeP2pResourcesRetained();
};

static bool iwx_tahoe_p2p_directed_data_snapshot(
    ItlIwx *, const TahoeP2PDirectedDataContext *,
    TahoeP2PDirectedDataSnapshot *snapshot, bool, int *gateResultOut)
{
    ++gSnapshotCalls;
    if (gateResultOut) *gateResultOut = gSnapshotGateResult;
    if (!gSnapshotValid) return false;
    *snapshot = gSnapshot;
    return true;
}
"""

TEST = r"""
static void resetSnapshot() {
    gSnapshotCalls = 0;
    gSnapshotValid = true;
    gSnapshotGateResult = 0;
    gSnapshot = TahoeP2PDirectedDataSnapshot{};
}
static void assertGenericBlock(ItlIwx &owner) {
    resetSnapshot();
    assert(owner.nativeP2pResourcesRetained());
    assert(gSnapshotCalls == 0); // no data snapshot when mayOwnResource is clear
}

int main() {
    // Cold start: no P2P data owner exists. A busy/unavailable command gate
    // must not turn an unarmed context into a false quarantine.
    {
        ItlIwx owner;
        owner.nativeP2pDirectedDataTx_.mayOwnResource = 0;
        gSnapshotValid = false;
        gSnapshotGateResult = kIOReturnBusy;
        assert(!owner.nativeP2pResourcesRetained());
        assert(gSnapshotCalls == 0);
        assert(owner.controller_.properties.empty());
    }
    // A missing/unavailable gate (NotReady) is also harmless before this
    // context has ever owned a resource.
    {
        ItlIwx owner;
        owner.nativeP2pDirectedDataTx_.mayOwnResource = 0;
        gSnapshotValid = false;
        gSnapshotGateResult = kIOReturnNotReady;
        assert(!owner.nativeP2pResourcesRetained());
        assert(gSnapshotCalls == 0);
        assert(owner.controller_.properties.empty());
    }
    // Once ownership may exist, the same unavailable snapshot is fail-closed.
    {
        ItlIwx owner;
        owner.nativeP2pDirectedDataTx_.mayOwnResource = 1;
        resetSnapshot();
        gSnapshotValid = false;
        gSnapshotGateResult = kIOReturnBusy;
        assert(owner.nativeP2pResourcesRetained());
        assert(gSnapshotCalls == 1);
        const auto &p = owner.controller_.properties;
        assert(p.at("NativeP2PStopBlockReason") & (1u << 6));
        assert(p.at("NativeP2PStopDataMayOwnResource") == 1);
        assert(p.at("NativeP2PStopDataSnapshotAttempted") == 1);
        assert(p.at("NativeP2PStopDataSnapshotValid") == 0);
        assert(p.at("NativeP2PStopDataSnapshotGateResult") ==
               static_cast<uint32_t>(kIOReturnBusy));
        assert(p.at("NativeP2PStopDataContextFlags") & (1u << 31));
    }
    // The same missing gate remains fail-closed after ownership was published.
    {
        ItlIwx owner;
        owner.nativeP2pDirectedDataTx_.mayOwnResource = 1;
        resetSnapshot();
        gSnapshotValid = false;
        gSnapshotGateResult = kIOReturnNotReady;
        assert(owner.nativeP2pResourcesRetained());
        assert(gSnapshotCalls == 1);
        const auto &p = owner.controller_.properties;
        assert(p.at("NativeP2PStopBlockReason") & (1u << 6));
        assert(p.at("NativeP2PStopDataSnapshotAttempted") == 1);
        assert(p.at("NativeP2PStopDataSnapshotValid") == 0);
        assert(p.at("NativeP2PStopDataSnapshotGateResult") ==
               static_cast<uint32_t>(kIOReturnNotReady));
    }
    // Every firmware-owning directed-data phase remains a stop/init blocker.
    for (TahoeP2PDirectedDataState state : {
             kArmed, kTicketBound, kPermitIssued, kInFlight, kQuarantined}) {
        ItlIwx owner;
        owner.nativeP2pDirectedDataTx_.mayOwnResource = 1;
        resetSnapshot();
        gSnapshot.state = state;
        assert(owner.nativeP2pResourcesRetained());
        assert(gSnapshotCalls == 1);
        assert(owner.controller_.properties.at("NativeP2PStopBlockReason") &
               (1u << 6));
    }
    // A doorbelled buffer with uncertain completion is protected even when
    // the snapshot is otherwise well formed.
    {
        ItlIwx owner;
        owner.nativeP2pDirectedDataTx_.mayOwnResource = 1;
        resetSnapshot();
        gSnapshot.state = kQuarantined;
        gSnapshot.reason = kDrainMismatch;
        gSnapshot.originTicketBound = true;
        gSnapshot.originClosed = true;
        gSnapshot.doorbellIssued = true;
        gSnapshot.mbufHeldByRing = true;
        assert(owner.nativeP2pResourcesRetained());
    }
    // A completed exact-close with no mbuf/unfinished completion is safe.
    {
        ItlIwx owner;
        owner.nativeP2pDirectedDataTx_.mayOwnResource = 1;
        resetSnapshot();
        gSnapshot.state = kClosed;
        gSnapshot.originTicketBound = true;
        gSnapshot.originClosed = true;
        gSnapshot.doorbellIssued = true;
        gSnapshot.completionObserved = true;
        assert(!owner.nativeP2pResourcesRetained());
    }
    // Existing generic P2P protections remain independent of the new data
    // summary and continue to block with an unarmed data context.
    {
        ItlIwx owner; owner.busy = true; assertGenericBlock(owner);
    }
    {
        ItlIwx owner;
        owner.nativeP2pTxQueue_.state = TahoeP2PResourceState::kUnknown;
        assertGenericBlock(owner);
    }
    {
        ItlIwx owner; int ring = 0;
        owner.nativeP2pTxQueue_.pendingRing = &ring;
        assertGenericBlock(owner);
    }
    {
        ItlIwx owner;
        owner.nativeP2pStation_.state = TahoeP2PResourceState::kUnknown;
        assertGenericBlock(owner);
    }
    {
        ItlIwx owner; owner.com.sc_p2p.mac_state = 1; assertGenericBlock(owner);
    }
    {
        ItlIwx owner; owner.com.sc_p2p.binding_state = 1; assertGenericBlock(owner);
    }
    {
        ItlIwx owner; owner.com.sc_p2p.phy_leased = true; assertGenericBlock(owner);
    }
}
"""


def compile_and_run() -> None:
    source = HARNESS + "\n" + GUARD + "\n" + TEST
    with tempfile.TemporaryDirectory(prefix="itlwm-test108-cold-start-") as temp:
        cpp = Path(temp) / "cold_start_guard.cpp"
        binary = Path(temp) / "cold_start_guard"
        cpp.write_text(source)
        subprocess.run([
            "xcrun", "clang++", "-std=c++14", "-O1", "-Wall", "-Wextra",
            "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", str(cpp), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    compile_and_run()
    print("PASS: Test108 production retention guard covers cold start, uncertainty, and legacy leases")
