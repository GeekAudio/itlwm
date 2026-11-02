#!/usr/bin/env python3
"""Compile actual Test115 arm/bind/producer snippets against the policy helper."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
ACTION = (ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp").read_text()
PROBE = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()
DATA = (ROOT / "itlwm/hal_iwx/ItlIwxP2PData.hpp").read_text()


def block(source: str, marker: str) -> str:
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
    raise RuntimeError(f"unterminated source block: {marker}")


def source_slice(source: str, start: str, end: str, from_index: int = 0) -> str:
    first = source.index(start, from_index)
    last = source.index(end, first)
    return source[first:last]


binding_type = block(DATA, "struct TahoeP2PDirectedDataBinding {")
state_type = block(DATA, "enum class TahoeP2PDirectedDataState : uint8_t {")
ticket_alias = source_slice(
    DATA,
    "using TahoeP2PDirectedDataOriginTicket =",
    ";",
) + ";"

arm_method = ACTION.index("int iwx_tahoe_p2p_directed_data_arm(")
arm_seed = source_slice(
    ACTION,
    "    ++context->armSerialHighWater;",
    "    memset(&context->originTicket",
    arm_method,
)
arm_flags = source_slice(
    ACTION,
    "    context->ticketBound = false;",
    "    context->permitIssued = false;",
    arm_method,
)
arm_state_and_copy = source_slice(
    ACTION,
    "    context->state = TahoeP2PDirectedDataState::kArmed;",
    "    return 0;",
    arm_method,
)
probe_arm = block(PROBE, "static bool tahoeP2pArmDirectedDataRoc(")
probe_copy = "probe->directedDataBinding = run.binding;"
if probe_copy not in probe_arm:
    raise RuntimeError("arm-time probe binding copy was not found")

window_action_type = block(ACTION, "struct DirectedDataWindowAction {")
window_action = block(
    ACTION, "static IOReturn directedDataBindOriginWindowAction(")
roc_action = block(PROBE, "IOReturn ItlIwx::tahoeP2pRocEventAction(")
producer_start = roc_action.index(
    "                const auto &halData=owner->nativeP2pDirectedDataTx_;"
)
producer_end = roc_action.index("                uint32_t actualChannel=0;", producer_start)
producer = roc_action[producer_start:producer_end]

prefix = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "native/p2p_directed_data_control.hpp"

using TahoeP2PDirectedDataEpochs=NativeAwdlDirectedOriginTx::Epochs;
'''
support = r'''
struct TahoeP2PDirectedDataArm {};
struct TahoeP2PDirectedDataPermit {};
enum class TahoeP2PDirectedDataReason : uint8_t { kNone };
struct TahoeP2PDirectedDataContext {
    TahoeP2PDirectedDataBinding binding{};
    TahoeP2PDirectedDataArm arm{};
    TahoeP2PDirectedDataOriginTicket originTicket{};
    TahoeP2PDirectedDataPermit permit{};
    TahoeP2PDirectedDataReason reason=TahoeP2PDirectedDataReason::kNone;
    TahoeP2PDirectedDataState state=TahoeP2PDirectedDataState::kIdle;
    uint64_t armSerialHighWater=0;
    void *workerThread=nullptr;
    bool ticketBound=false;
    bool originWindowBound=false;
    bool originClosed=true;
};
struct TestSoftc {
    struct { uint32_t fw_generation=0; } sc_p2p;
};
struct FakeCom {
    uint32_t sc_generation=0;
    struct { uint32_t fw_generation=0; } sc_p2p;
    struct { uint64_t token=0; } sc_p2p_roc;
};
struct ItlIwx {
    FakeCom com{};
    TahoeP2PDirectedDataContext nativeP2pDirectedDataTx_{};
    uint64_t nativeAwdlRxEventOwnerSerial_=0;
    bool gate=true;
    bool tahoeP2pOnMainGate() { return gate; }
};
struct P2PProbeRun {
    TahoeP2PDirectedDataBinding directedDataBinding{};
    TahoeP2PDirectedDataOriginTicket directedDataOriginTicket{};
    uint32_t contextGeneration=0;
    uint32_t powerGeneration=0;
    uint32_t stationGeneration=0;
    bool directedDataTicketBound=false;
};
struct ArmRun { TahoeP2PDirectedDataBinding binding{}; };
struct RocEventRun {
    struct { uint32_t generation=0; uint64_t startObservedMonotonicUs=0; } snapshot;
};
struct RxLease { uint64_t startUs=0; uint64_t deadlineUs=0; };
struct ReadyHandshakeEvidence {
    bool rocSessionCurrent=false;
    bool originWindowBound=false;
};
struct OSObject {};
using IOReturn=int;
constexpr IOReturn kIOReturnBadArgument=-1;
constexpr IOReturn kIOReturnSuccess=0;
static uint64_t testNowUs=0;
static uint64_t directedDataMonotonicUs() { return testNowUs; }
'''

arm_function = r'''
static void productionArm(TahoeP2PDirectedDataContext *context,
                          TahoeP2PDirectedDataBinding *bindingOut,
                          const TahoeP2PDirectedDataArm *arm,
                          void *workerThread, uint64_t ownerSerial,
                          const TahoeP2PDirectedDataEpochs *epochs,
                          uint32_t generation, TestSoftc *sc) {
'''.replace("\n", "\n") + arm_seed + arm_flags + arm_state_and_copy + "}\n"

probe_copy_function = (
    "static void productionProbeCopy(P2PProbeRun *probe, const ArmRun &run) {\n"
    "    " + probe_copy + "\n}\n"
)

producer_function = r'''
static bool productionReadyProducer(ItlIwx *owner, P2PProbeRun *probe,
                                    RocEventRun *action, RxLease rxLease,
                                    uint64_t nowUs) {
    ReadyHandshakeEvidence evidence{};
    evidence.rocSessionCurrent=true;
''' + producer + r'''
    return evidence.originWindowBound;
}
'''

fixture_code = r'''
static void populateTicket(NativeAwdlDirectedOriginTx::Ticket *ticket) {
    ticket->ticketSerial=12;
    ticket->ownerSerial=22;
    ticket->runSerial=1;
    ticket->interfaceIncarnation=4;
    ticket->rocStartUs=100000;
    ticket->deadlineUs=200000;
    ticket->ifindex=7;
    ticket->sourceMac[0]=2;
    ticket->sourceMac[5]=1;
    ticket->epochs={37,8,19,37};
}

struct Fixture {
    ItlIwx owner{};
    P2PProbeRun probe{};
    RocEventRun action{};
    RxLease lease{100000,200000};
};

static Fixture startedFixture() {
    Fixture f{};
    f.owner.com.sc_generation=8;
    f.owner.com.sc_p2p.fw_generation=9;
    f.owner.com.sc_p2p_roc.token=37;
    f.owner.nativeAwdlRxEventOwnerSerial_=22;
    f.probe.contextGeneration=37;
    f.probe.powerGeneration=8;
    f.probe.stationGeneration=19;
    f.action.snapshot.generation=37;
    f.action.snapshot.startObservedMonotonicUs=100000;

    TestSoftc softc{};
    softc.sc_p2p.fw_generation=9;
    const TahoeP2PDirectedDataEpochs epochs{37,8,19,37};
    TahoeP2PDirectedDataBinding returned{};
    TahoeP2PDirectedDataArm arm{};
    productionArm(&f.owner.nativeP2pDirectedDataTx_, &returned, &arm,
                  reinterpret_cast<void *>(0x1000), 22, &epochs, 8,
                  &softc);
    ArmRun run{};
    run.binding=returned;
    productionProbeCopy(&f.probe, run);
    assert(f.probe.directedDataBinding.rocToken==0);
    assert(f.probe.directedDataBinding.rocStartUs==0);
    assert(f.probe.directedDataBinding.deadlineUs==0);
    assert(f.owner.nativeP2pDirectedDataTx_.state==
           TahoeP2PDirectedDataState::kArmed);

    DirectedDataWindowAction window{
        &f.owner.nativeP2pDirectedDataTx_, 37, 100000, 200000, EBUSY};
    assert(directedDataBindOriginWindowAction(
        nullptr, &f.owner, &window, nullptr, nullptr)==kIOReturnSuccess);
    assert(window.result==0);
    assert(f.owner.nativeP2pDirectedDataTx_.originWindowBound);
    assert(f.owner.nativeP2pDirectedDataTx_.binding.rocToken==37);
    assert(f.owner.nativeP2pDirectedDataTx_.binding.rocStartUs==100000);
    assert(f.owner.nativeP2pDirectedDataTx_.binding.deadlineUs==200000);
    assert(f.probe.directedDataBinding.rocStartUs==0);

    // The ticket bind completes the real lifecycle state used by the Ready
    // witness. Its detailed validation remains covered by existing HAL tests.
    populateTicket(&f.owner.nativeP2pDirectedDataTx_.originTicket);
    f.probe.directedDataOriginTicket=
        f.owner.nativeP2pDirectedDataTx_.originTicket;
    f.owner.nativeP2pDirectedDataTx_.state=
        TahoeP2PDirectedDataState::kTicketBound;
    f.owner.nativeP2pDirectedDataTx_.ticketBound=true;
    f.owner.nativeP2pDirectedDataTx_.originClosed=false;
    f.probe.directedDataTicketBound=true;
    return f;
}

static bool oldProbeCopyExpression(const Fixture &f) {
    return f.probe.directedDataBinding.rocToken==
            f.probe.contextGeneration&&
        f.probe.directedDataBinding.rocStartUs==f.lease.startUs&&
        f.probe.directedDataBinding.deadlineUs==f.lease.deadlineUs;
}

int main() {
    testNowUs=150000;
    auto f=startedFixture();
    assert(!oldProbeCopyExpression(f));
    assert(productionReadyProducer(&f.owner,&f.probe,&f.action,
                                   f.lease,testNowUs));

    auto foreignOwner=startedFixture();
    ++foreignOwner.owner.nativeAwdlRxEventOwnerSerial_;
    assert(!productionReadyProducer(&foreignOwner.owner,&foreignOwner.probe,
        &foreignOwner.action,foreignOwner.lease,testNowUs));

    auto foreignEpoch=startedFixture();
    ++foreignEpoch.probe.directedDataBinding.epochs.station;
    assert(!productionReadyProducer(&foreignEpoch.owner,&foreignEpoch.probe,
        &foreignEpoch.action,foreignEpoch.lease,testNowUs));

    auto foreignTicket=startedFixture();
    ++foreignTicket.probe.directedDataOriginTicket.ticketSerial;
    assert(!productionReadyProducer(&foreignTicket.owner,&foreignTicket.probe,
        &foreignTicket.action,foreignTicket.lease,testNowUs));

    auto expired=startedFixture();
    testNowUs=expired.lease.deadlineUs;
    assert(!productionReadyProducer(&expired.owner,&expired.probe,
        &expired.action,expired.lease,testNowUs));

    std::cout << "actual arm/copy -> HAL window bind -> Ready producer passed; "
                 "old arm-copy check failed; foreign owner/epoch/ticket and "
                 "expired window rejected\n";
}
'''

source = "\n".join([
    prefix,
    binding_type + ";",
    ticket_alias,
    state_type + ";",
    support,
    window_action_type + ";",
    arm_function,
    window_action,
    probe_copy_function,
    producer_function,
    fixture_code,
])

with tempfile.TemporaryDirectory(prefix="test115-ready-window-") as tmp:
    source_path = Path(tmp) / "ready_window_lifecycle.cpp"
    binary_path = Path(tmp) / "ready_window_lifecycle"
    source_path.write_text(source)
    compiled = subprocess.run(
        ["xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
         "-Wextra", "-Werror", "-fsanitize=address,undefined",
         "-fno-sanitize-recover=all", "-fno-omit-frame-pointer", "-I",
         str(ROOT), str(source_path), "-o", str(binary_path)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if compiled.returncode:
        raise SystemExit(compiled.stdout)
    result = subprocess.run(
        [str(binary_path)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode:
        raise SystemExit(result.stdout)
    print(result.stdout, end="")
