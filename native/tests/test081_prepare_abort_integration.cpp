// Test body for test081_prepare_abort_integration.py. The Python runner
// injects the existing low-level firmware shim and extracts real production
// functions into the marked location below.
#include <cstdio>
#include <string>

using NativeP2PProbe::BlockedReason;
using NativeP2PProbe::ExerciseRecoveryProof;

struct P2PProbeRun {
    ItlIwx *owner = nullptr;
    bool rx149ObservationOnly = true;
    bool txProbeEnabled = false;
    bool awdlPsfProbeEnabled = false;
    bool awdlMifFollowupEnabled = false;
    bool prepareTraceBaselineValid = false;
    bool sessionSubmitReached = false;
    bool canceled = false;
    uint32_t contextGeneration = 53;
    uint32_t powerGeneration = 41;
    uint32_t stationGeneration = 59;
    uint32_t scGeneration = 41;
    uint32_t p2pFirmwareGeneration = 0;
    uint32_t prepareTraceSerialBefore = 0;
    uint32_t prepareTraceSerialExpected = 0;
    void *workerThread = nullptr;
    uint8_t address[6]{};
};

struct P2PExerciseRecoveryAction {
    P2PProbeRun *run;
    int32_t exerciseErrno;
    ExerciseRecoveryProof *proof;
    bool snapshotRead;
};

enum RocEventOperation {
    kRocArm,
    kRocCommandReturned,
    kRocRead,
    kRocExpire,
    kRocCloseRx149
};

namespace IntelROCEvent {
struct SessionSnapshot {
    bool endSeen = false;
    bool outcomeUnknown = false;
    bool cleanupAllowed = false;
    bool observedScheduledPair = false;
    uint32_t configuration = 0;
};
}
struct P2PTxDiagnosticSnapshot {};

struct RocEventRun {
    P2PProbeRun *probe = nullptr;
    RocEventOperation operation = kRocArm;
    uint32_t firmwareGeneration = 0;
    uint32_t macIdAndColor = 0;
    uint32_t configuration = 0;
    int commandResult = 0;
    bool armed = false;
    bool consumeRxAfterRead = false;
    IntelROCEvent::SessionSnapshot snapshot{};
    P2PTxDiagnosticSnapshot txSnapshot{};
    bool txSnapshotValid = false;
    bool rxDrainComplete = false;
};

static bool rx149ArmModeSelected(ItlIwx *) { return true; }
static bool rx149ObservationOnlyRequested(IOEthernetController *) { return true; }
static bool rx149ActualRocChannel(struct iwx_softc *);
static NativeP2PRx149Observation::ProfileStatus rx149ProfileStatus(
    ItlIwx *, IOEthernetController *)
{
    return NativeP2PRx149Observation::ProfileStatus::kSelected;
}
static bool rx149TxHistoryQuiescent(
    ItlIwx *owner, P2PTxDiagnosticSnapshot *)
{
    return owner && owner->txHistoryQuiescent_;
}
static int readRocState(P2PProbeRun *, RocEventRun *, bool = false)
{
    return ENOTSUP;
}
static NativeP2PRx149Observation::RocEvidence rx149RocEvidence(
    P2PProbeRun *probe, const IntelROCEvent::SessionSnapshot &)
{
    if (probe && probe->owner)
        (void)rx149ActualRocChannel(&probe->owner->com);
    return {};
}
static void IOSleep(unsigned) {}
static int exerciseTxProbe(P2PProbeRun *) { return ENOTSUP; }

class OSObject {};
using IOReturn = int;
constexpr IOReturn kIOReturnSuccess = 0;
constexpr IOReturn kIOReturnBadArgument = -1;

class IOEthernetController {
public:
    void setProperty(const char *, uint32_t, unsigned) {}
};

using IOAction = IOReturn (*)(OSObject *, void *, void *, void *, void *);
class IOCommandGate {
public:
    IOReturn runAction(IOAction action, void *argument)
    {
        if (!action)
            return kIOReturnBadArgument;
        return action(nullptr, argument, nullptr, nullptr, nullptr);
    }
};

class IOWorkLoop {
public:
    bool onThread() const { return false; }
    bool inGate() const { return false; }
};

IOEthernetController *ItlIwx::tahoeP2pController()
{
    return controller_;
}
IOCommandGate *ItlIwx::getMainCommandGate()
{
    return commandGate_;
}
IOCommandGate *ItlIwx::tahoeP2pCommandGate()
{
    return commandGate_;
}
IOWorkLoop *ItlIwx::getMainWorkLoop()
{
    return workLoop_;
}
bool ItlIwx::tahoeP2pOnMainGate() const
{
    return onMainGate_;
}
bool ItlIwx::nativeP2pBusy() const
{
    return probeBusy_;
}

bool ItlIwx::tahoeP2pArmRoc(
    void *, uint32_t, uint32_t, uint32_t)
{
    return false; // The version/Prepare failures under test never arm a ROC.
}

IOReturn ItlIwx::tahoeP2pRocEventAction(
    OSObject *, void *, void *, void *, void *)
{
    return kIOReturnBadArgument; // Unreachable in Prepare-failure fixtures.
}

// __TEST081_PRODUCTION_METHODS__

struct Fixture {
    ItlIwx owner;
    IOEthernetController controller;
    IOCommandGate gate;
    IOWorkLoop workLoop;
    iwx_node station;
    P2PProbeRun run;
    uint32_t configureCalls = 0;
    uint32_t addCalls = 0;
    uint32_t removeCalls = 0;
    uint32_t publishCalls = 0;
    bool publishedMayExist = false;
    bool failOuterRemove = false;
};

static void require(bool condition, const char *message)
{
    if (!condition) {
        std::fprintf(stderr, "Test081 assertion failed: %s\n", message);
        std::abort();
    }
}

static void setupFixture(Fixture &fixture)
{
    ItlIwx &owner = fixture.owner;
    auto *sc = &owner.com;
    owner.commandGate_ = &fixture.gate;
    owner.workLoop_ = &fixture.workLoop;
    owner.controller_ = &fixture.controller;
    owner.allowed = true;
    owner.probeBusy_ = true;
    owner.onMainGate_ = true;
    owner.txHistoryQuiescent_ = true;
    owner.nativeP2pPowerGeneration_ = fixture.run.powerGeneration;
    owner.nativeP2pProbeGeneration_ = fixture.run.contextGeneration;
    owner.nativeP2pProbeOwner_ = &fixture.run;
    owner.fixtureRunPowerGeneration_ = &fixture.run.powerGeneration;

    sc->sc_generation = static_cast<int>(fixture.run.scGeneration);
    sc->sc_tx_rate_generation = fixture.run.stationGeneration;
    sc->sc_flags = IWX_FLAG_MAC_ACTIVE | IWX_FLAG_BINDING_ACTIVE;
    sc->sc_ic.ic_state = IEEE80211_S_RUN;
    sc->sc_enabled_capa[IWX_UCODE_TLV_CAPA_BINDING_CDB_SUPPORT / 8] |=
        static_cast<uint8_t>(1U <<
            (IWX_UCODE_TLV_CAPA_BINDING_CDB_SUPPORT % 8));
    sc->sc_enabled_capa[IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD / 8] |=
        static_cast<uint8_t>(1U <<
            (IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD % 8));

    auto *stationChannel = &sc->sc_ic.ic_channels[36];
    *stationChannel = ieee80211_channel{36, false};
    auto *originalP2pChannel = &sc->sc_ic.ic_channels[1];
    *originalP2pChannel = ieee80211_channel{1, true};
    auto *rx149Channel = &sc->sc_ic.ic_channels[149];
    *rx149Channel = ieee80211_channel{149, false};

    fixture.station.in_phyctxt = &sc->sc_phyctxt[0];
    fixture.station.in_id = 0;
    fixture.station.in_ni.ni_chan = stationChannel;
    fixture.station.ni_chan = stationChannel;
    sc->sc_ic.ic_bss = &fixture.station;
    sc->sc_phyctxt[0].id = 0;
    sc->sc_phyctxt[0].color = 3;
    sc->sc_phyctxt[0].channel = stationChannel;
    sc->sc_phyctxt[1].id = 1;
    sc->sc_phyctxt[1].color = 4;
    sc->sc_phyctxt[1].channel = originalP2pChannel;
    sc->sc_phyctxt[2].id = 2;
    sc->sc_phyctxt[2].color = 5;
    sc->sc_phyctxt[2].channel = originalP2pChannel;

    fixture.run.owner = &owner;
    fixture.run.workerThread = &fixture.run;
    fixture.run.rx149ObservationOnly = true;
    fixture.run.txProbeEnabled = false;
    fixture.run.awdlPsfProbeEnabled = false;
    fixture.run.awdlMifFollowupEnabled = false;
    fixture.run.prepareTraceBaselineValid = false;
    fixture.run.sessionSubmitReached = false;
    fixture.run.canceled = false;
    fixture.run.scGeneration = static_cast<uint32_t>(sc->sc_generation);
    fixture.run.p2pFirmwareGeneration = 0;
}

static NativeP2PProbe::Admission admissionFor(const P2PProbeRun &run)
{
    return NativeP2PProbe::Admission{
        true, true, true, true, true, true, true, true, true, true, true,
        true, true, true, run.contextGeneration, run.powerGeneration,
        run.stationGeneration
    };
}

static BlockedReason revalidate(void *opaque, uint32_t powerGeneration,
                                uint32_t stationGeneration)
{
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner || powerGeneration != run->powerGeneration ||
        stationGeneration != run->stationGeneration ||
        run->owner->nativeP2pPowerGeneration_ != powerGeneration ||
        run->owner->com.sc_tx_rate_generation != stationGeneration)
        return NativeP2PProbe::kGenerationChanged;
    return NativeP2PProbe::kNotBlocked;
}

static int configure(void *opaque)
{
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner)
        return EINVAL;
    ++run->owner->fixtureConfigureCalls_;
    return 0;
}

static int add(void *opaque)
{
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner)
        return EINVAL;
    ItlIwx *owner = run->owner;
    ++owner->fixtureAddCalls_;
    owner->com.sc_p2p.initialized = 1;
    owner->com.sc_p2p.mac_state = IWX_P2P_RESOURCE_ACTIVE;
    owner->com.sc_p2p.binding_state = IWX_P2P_RESOURCE_ABSENT;
    owner->com.sc_p2p.mac_id = 1;
    owner->com.sc_p2p.fw_generation =
        static_cast<uint32_t>(owner->com.sc_generation);
    run->p2pFirmwareGeneration = owner->com.sc_p2p.fw_generation;
    return 0;
}

static int remove(void *opaque)
{
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner)
        return EINVAL;
    ItlIwx *owner = run->owner;
    ++owner->fixtureRemoveCalls_;
    if (owner->nativeP2pProbeOwner_ != run->workerThread)
        return EBUSY;
    if (owner->fixtureFailOuterRemove_)
        return EIO;
    owner->com.sc_p2p.mac_state = IWX_P2P_RESOURCE_ABSENT;
    return 0;
}

static bool publishLease(void *opaque, bool resourceMayExist)
{
    auto run = static_cast<P2PProbeRun *>(opaque);
    if (!run || !run->owner)
        return false;
    ++run->owner->fixturePublishCalls_;
    run->owner->fixturePublishedMayExist_ = resourceMayExist;
    return true;
}

static NativeP2PProbe::RunResult execute(Fixture &fixture)
{
    auto &run = fixture.run;
    auto &probe = fixture.owner.nativeP2pProbe_;
    require(probe.tryQueue(admissionFor(run)), "probe admission rejected");
    NativeP2PProbe::Operations operations{
        &run, revalidate, configure, add, remove, publishLease,
        ItlIwx::tahoeP2pExerciseRoc,
        ItlIwx::tahoeP2pExerciseRecovery
    };
    return probe.executeOnce(operations);
}

static iwx_p2p_roc_prepare_trace_snapshot traceSnapshot(Fixture &fixture)
{
    iwx_p2p_roc_prepare_trace_snapshot trace{};
    require(iwx_p2p_roc_prepare_trace_read_snapshot(
        &fixture.owner.com.sc_p2p_roc_prepare_trace, &trace) == 0,
        "Prepare trace was not stable");
    return trace;
}

struct VersionCase {
    const char *name;
    uint8_t sessionCapability;
    uint8_t phyCommandVersion;
    uint8_t bindingCommandVersion;
    uint8_t bindingNotificationVersion;
    uint8_t sessionCommandVersion;
    uint8_t sessionNotificationVersion;
    uint32_t expectedReason;
};

static const VersionCase kVersionCases[] = {
    // __TEST081_VERSION_CASES__
};

static void assertCleanPrepareFailure(Fixture &fixture, int expectedErrno,
                                     uint32_t expectedReason,
                                     uint32_t expectedStep =
                                         IWX_P2P_PREPARE_STEP_FIRMWARE_CAPABILITY,
                                     uint32_t expectedFrequency = 5745)
{
    auto &owner = fixture.owner;
    const auto trace = traceSnapshot(fixture);
    const auto snapshot = fixture.owner.nativeP2pProbe_.snapshot();
    if (static_cast<int32_t>(trace.prepareErrno) != expectedErrno ||
        trace.reason != expectedReason) {
        std::fprintf(stderr,
            "Prepare trace errno=%d reason=%u step=%u expected errno=%d reason=%u\n",
            static_cast<int32_t>(trace.prepareErrno), trace.reason, trace.step,
            expectedErrno, expectedReason);
    }
    require(static_cast<int32_t>(trace.prepareErrno) == expectedErrno,
            "trace lost original Prepare errno");
    require(static_cast<int32_t>(trace.cleanupErrno) == 0,
            "pre-resource failure reported cleanup error");
    require(trace.reason == expectedReason,
            "Prepare errno was not uniquely attributed");
    require(trace.step == expectedStep,
            "firmware gate failed at an unexpected Prepare step");
    require(trace.featureCompiled == 1 && trace.receiveObservation149 == 1,
            "RX149 feature/request fields were not recorded");
    require(trace.requestedChannelPresent == 1 && trace.channelIndex == 149 &&
            trace.ieeeChannelNumber == 149 &&
            trace.channelFrequency == expectedFrequency,
            "channel table index, IEEE channel or frequency was misreported");
    require(trace.configuration == 2 && trace.token == fixture.run.contextGeneration,
            "configuration or owner token was not recorded");
    require(trace.originalChannelDetailsCaptured == 1 &&
            trace.restoredChannelDetailsCaptured == 1 &&
            trace.originalChannelFrequency != 0 &&
            trace.restoredChannelFrequency == trace.originalChannelFrequency,
            "clean pre-resource rejection lacked a verified channel identity pair");
    require(trace.scGenerationEntry == fixture.run.scGeneration &&
            trace.scGenerationExit == fixture.run.scGeneration &&
            trace.p2pFirmwareGenerationEntry ==
                fixture.run.p2pFirmwareGeneration &&
            trace.p2pFirmwareGenerationExit ==
                fixture.run.p2pFirmwareGeneration &&
            trace.stationEpochEntry == fixture.run.stationGeneration &&
            trace.stationEpochExit == fixture.run.stationGeneration,
            "firmware, P2P firmware and station epochs were conflated");
    require(trace.phyLeaseAttempted == 0 && trace.phyRemoveAttempted == 0 &&
            trace.phyAddAttempted == 0 && trace.bindingAddAttempted == 0,
            "firmware resource command ran before firmware gate passed");
    require(owner.pduSends == 0 && owner.statusSends == 0,
            "pre-resource firmware gate emitted ROC commands");
    require(snapshot.exerciseResult == expectedErrno &&
            snapshot.exerciseRecoveryAttempted == 1 &&
            snapshot.exerciseRecoveryProofAccepted == 1,
            "Controller did not retain failure and accept actual clean proof");
    require(snapshot.state == NativeP2PProbe::kExerciseFailedCleaned &&
            snapshot.blocked == NativeP2PProbe::kExerciseFailureRecovered &&
            snapshot.resourceMayExist == 0,
            "Controller did not reach failed-but-cleaned terminal state");
    require(owner.fixtureAddCalls_ == 1 && owner.fixtureRemoveCalls_ == 1,
            "outer MAC lease was not removed exactly once");
}

static void testVersionGates()
{
    for (const auto &test : kVersionCases) {
        Fixture fixture;
        setupFixture(fixture);
        ItlIwx &owner = fixture.owner;
        auto *sc = &owner.com;
        owner.phyVer = test.phyCommandVersion;
        owner.bindingVer = test.bindingCommandVersion;
        owner.bindingNotif = test.bindingNotificationVersion;
        owner.sessionVer = test.sessionCommandVersion;
        owner.sessionNotif = test.sessionNotificationVersion;
        if (!test.sessionCapability)
            sc->sc_enabled_capa[IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD / 8] &=
                static_cast<uint8_t>(~(1U <<
                    (IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD % 8)));
        const auto result = execute(fixture);
        require(result == NativeP2PProbe::RunResult::kExerciseFailedCleaned,
                test.name);
        assertCleanPrepareFailure(fixture, EOPNOTSUPP, test.expectedReason);
        const auto trace = traceSnapshot(fixture);
        require(trace.sessionCapabilityPresent == test.sessionCapability &&
                trace.phyContextCommandVersion == test.phyCommandVersion &&
                trace.bindingContextCommandVersion == test.bindingCommandVersion &&
                trace.bindingContextNotificationVersion ==
                    test.bindingNotificationVersion &&
                trace.sessionProtectionCommandVersion == test.sessionCommandVersion &&
                trace.sessionProtectionNotificationVersion ==
                    test.sessionNotificationVersion,
                "firmware capability/version inputs were not preserved");
    }
}

static void testRx149ChannelPolicyRejectsCleanly()
{
    Fixture fixture;
    setupFixture(fixture);
    fixture.owner.com.sc_ic.ic_channels[149].ic_freq = 5740;
    require(execute(fixture) == NativeP2PProbe::RunResult::kExerciseFailedCleaned,
            "invalid RX149 channel profile did not fail closed cleanly");
    assertCleanPrepareFailure(
        fixture, EOPNOTSUPP,
        IWX_P2P_PREPARE_REASON_RX149_CHANNEL_NOT_ALLOWED,
        IWX_P2P_PREPARE_STEP_RX149_POLICY, 5740);
    require(traceSnapshot(fixture).channelFrequency == 5740,
            "invalid channel frequency input was not preserved in trace");
}

static void testUnexpectedPhyLeaseSlotIsAttributed()
{
    Fixture fixture;
    setupFixture(fixture);
    fixture.owner.com.sc_phyctxt[1].id = 2;
    const auto result = execute(fixture);
    require(result == NativeP2PProbe::RunResult::kExerciseFailedCleaned,
            "verified slot-2 lease/release without firmware mutation should clean");
    const auto trace = traceSnapshot(fixture);
    const auto snapshot = fixture.owner.nativeP2pProbe_.snapshot();
    require(trace.reason == IWX_P2P_PREPARE_REASON_UNEXPECTED_PHY_ID &&
            trace.step == IWX_P2P_PREPARE_STEP_PHY_ID &&
            static_cast<int32_t>(trace.prepareErrno) == EOPNOTSUPP &&
            static_cast<int32_t>(trace.cleanupErrno) == 0,
            "unexpected PHY slot rejection was not uniquely attributed");
    require(trace.phyLeaseAttempted == 1 && trace.phyLeaseResult == 0 &&
            trace.phyLeaseId == 2 && trace.phyReleaseAttempted == 1 &&
            trace.phyReleaseResult == 0 &&
            trace.originalChannelDetailsCaptured == 1 &&
            trace.restoredChannelDetailsCaptured == 1 &&
            trace.originalChannelFrequency == 2412 &&
            trace.restoredChannelFrequency == 2412 &&
            fixture.owner.pduSends == 0 && fixture.owner.statusSends == 0,
            "PHY lease slot/release evidence was not recorded exactly");
    require(trace.knownNotSubmittedSafeToAbort == 1 && trace.fullyRestored == 1 &&
            snapshot.exerciseRecoveryProofAccepted == 1 &&
            snapshot.state == NativeP2PProbe::kExerciseFailedCleaned &&
            snapshot.resourceMayExist == 0 && fixture.owner.fixtureRemoveCalls_ == 1,
            "verified no-command slot mismatch did not clean only its outer MAC lease");
}

static void assertUncapturedIdentityQuarantines(Fixture &fixture,
                                                const char *message)
{
    require(execute(fixture) == NativeP2PProbe::RunResult::kQuarantined,
            message);
    const auto trace = traceSnapshot(fixture);
    const auto snapshot = fixture.owner.nativeP2pProbe_.snapshot();
    require(trace.reason == IWX_P2P_PREPARE_REASON_SESSION_COMMAND_VERSION &&
            static_cast<int32_t>(trace.prepareErrno) == EOPNOTSUPP &&
            trace.sessionProtectionCommandVersion != 1 &&
            trace.phyLeaseAttempted == 0 && trace.sessionSubmitAttempted == 0 &&
            fixture.owner.pduSends == 0 && fixture.owner.statusSends == 0,
            "uncaptured identity case did not remain a pre-resource rejection");
    require(snapshot.exerciseRecoveryAttempted == 1 &&
            snapshot.exerciseRecoveryProofAccepted == 0 &&
            snapshot.state == NativeP2PProbe::kQuarantined &&
            snapshot.resourceMayExist == 1 &&
            fixture.owner.fixtureRemoveCalls_ == 0,
            "uncaptured identity authorized outer MAC removal");
}

static void testUncapturedChannelIdentityCannotAuthorizeCleanup()
{
    {
        Fixture fixture;
        setupFixture(fixture);
        ieee80211_channel foreignStationChannel{36, false};
        fixture.station.in_ni.ni_chan = &foreignStationChannel;
        fixture.station.ni_chan = &foreignStationChannel;
        fixture.owner.com.sc_phyctxt[0].channel = &foreignStationChannel;
        fixture.owner.sessionVer = 99;
        assertUncapturedIdentityQuarantines(
            fixture, "foreign STA channel pointer bypassed safe-owner proof");
        const auto trace = traceSnapshot(fixture);
        require(trace.stationDetailsCapturedEntry == 1 &&
                trace.stationChannelDetailsCapturedEntry == 0 &&
                trace.stationChannelDetailsCapturedExit == 0,
                "foreign STA channel was reported as a verified table member");
    }
    {
        Fixture fixture;
        setupFixture(fixture);
        fixture.owner.com.sc_ic.ic_channels[36].ic_freq = 0;
        fixture.owner.sessionVer = 99;
        assertUncapturedIdentityQuarantines(
            fixture, "zero-frequency STA channel bypassed safe-owner proof");
        const auto trace = traceSnapshot(fixture);
        require(trace.stationChannelDetailsCapturedEntry == 0 &&
                trace.stationChannelDetailsCapturedExit == 0 &&
                trace.stationChannelFrequencyEntry == 0 &&
                trace.stationChannelFrequencyExit == 0,
                "zero-frequency STA channel used an empty 0==0 identity proof");
    }
    {
        Fixture fixture;
        setupFixture(fixture);
        fixture.owner.com.sc_ic.ic_channels[1].ic_freq = 0;
        fixture.owner.sessionVer = 99;
        assertUncapturedIdentityQuarantines(
            fixture, "zero-frequency original PHY channel bypassed safe proof");
        const auto trace = traceSnapshot(fixture);
        require(trace.originalChannelDetailsCaptured == 0 &&
                trace.restoredChannelDetailsCaptured == 0,
                "zero-frequency original PHY channel was marked captured");
    }
}

static void testCommandUnknownQuarantines()
{
    for (unsigned failedCommand = 1; failedCommand <= 2; ++failedCommand) {
        Fixture fixture;
        setupFixture(fixture);
        fixture.owner.pduFailAt = static_cast<int>(failedCommand);
        require(execute(fixture) == NativeP2PProbe::RunResult::kQuarantined,
                "PHY transport error did not quarantine");
        const auto trace = traceSnapshot(fixture);
        const auto snapshot = fixture.owner.nativeP2pProbe_.snapshot();
        require(trace.reason == (failedCommand == 1
                    ? IWX_P2P_PREPARE_REASON_PHY_REMOVE_FAILED
                    : IWX_P2P_PREPARE_REASON_PHY_ADD_FAILED),
                "PHY error attribution was not stage-specific");
        require(static_cast<int32_t>(trace.prepareErrno) == ETIMEDOUT &&
                static_cast<int32_t>(trace.cleanupErrno) == 0,
                "PHY transport failure errno was not kept separate");
        require(trace.sessionSubmitAttempted == 0 &&
                snapshot.exerciseResult == ETIMEDOUT &&
                snapshot.exerciseRecoveryAttempted == 1 &&
                snapshot.exerciseRecoveryProofAccepted == 0,
                "unknown PHY outcome was mistaken for a safe rejection");
        require(snapshot.state == NativeP2PProbe::kQuarantined &&
                snapshot.resourceMayExist == 1 &&
                fixture.owner.fixtureRemoveCalls_ == 0,
                "outer MAC was removed while PHY firmware outcome was unknown");
    }
}

static void testBindingUnknownQuarantines()
{
    Fixture fixture;
    setupFixture(fixture);
    fixture.owner.statusResult = ETIMEDOUT;
    require(execute(fixture) == NativeP2PProbe::RunResult::kQuarantined,
            "unknown Binding ADD outcome did not quarantine");
    const auto trace = traceSnapshot(fixture);
    const auto snapshot = fixture.owner.nativeP2pProbe_.snapshot();
    require(trace.reason == IWX_P2P_PREPARE_REASON_BINDING_ADD_UNKNOWN &&
            trace.bindingAddAttempted == 1 && trace.bindingAddReturned == 1,
            "Binding timeout was not attributed as unknown");
    require(trace.bindingKnownAbsent == 0 && trace.fullyRestored == 0 &&
            trace.restoreRemoveAttempted == 0 && trace.restoreAddAttempted == 0,
            "unknown Binding outcome incorrectly triggered restore");
    require(snapshot.exerciseResult == ETIMEDOUT &&
            snapshot.exerciseRecoveryProofAccepted == 0 &&
            fixture.owner.fixtureRemoveCalls_ == 0,
            "unknown Binding outcome authorized outer MAC removal");
}

static void testDecodedBindingRejectionRestores()
{
    for (unsigned failure = 0; failure < 3; ++failure) {
        Fixture fixture;
        setupFixture(fixture);
        fixture.owner.status = 1; // A decoded firmware rejection, not timeout.
        if (failure == 1)
            fixture.owner.pduFailAt = 3; // Actual RestorePhy REMOVE.
        else if (failure == 2)
            fixture.owner.pduFailAt = 4; // Actual RestorePhy ADD.

        const auto result = execute(fixture);
        const auto trace = traceSnapshot(fixture);
            const auto snapshot = fixture.owner.nativeP2pProbe_.snapshot();
        if (failure == 0 &&
            result != NativeP2PProbe::RunResult::kExerciseFailedCleaned) {
            std::fprintf(stderr,
                "Binding reject diag result=%u state=%u blocked=%u accepted=%u "
                "prepare=%d cleanup=%d reason=%u step=%u serial=%u valid=%u "
                "owner=%u known=%u restored=%u bindAbsent=%u phyFree=%u "
                "phaseIdle=%u orig=%u back=%u p2pgen=%u runp2p=%u scgen=%u power=%u runpower=%u station=%u runstation=%u\n",
                static_cast<unsigned>(result), snapshot.state, snapshot.blocked,
                snapshot.exerciseRecoveryProofAccepted,
                static_cast<int32_t>(trace.prepareErrno),
                static_cast<int32_t>(trace.cleanupErrno), trace.reason,
                trace.step, trace.serial, trace.valid, trace.ownerEpochsUnchanged,
                trace.knownNotSubmittedSafeToAbort, trace.fullyRestored,
                trace.bindingKnownAbsent, trace.phyKnownUnleased,
                trace.phaseKnownIdle, trace.originalChannelFrequency,
                trace.restoredChannelFrequency,
                fixture.owner.com.sc_p2p.fw_generation,
                fixture.run.p2pFirmwareGeneration,
                fixture.owner.com.sc_generation, snapshot.powerGeneration,
                fixture.run.powerGeneration,
                fixture.owner.com.sc_tx_rate_generation,
                fixture.run.stationGeneration);
            std::fprintf(stderr,
                "owner pieces sc=%u p2p=%u mac=%u macId=%u macColor=%u "
                "bss=%u staCaptured=%u/%u staChanCaptured=%u/%u "
                "staId=%u/%u phyId=%u/%u phyColor=%u/%u "
                "phyChan=%u/%u staChan=%u/%u flags=%u/%u\n",
                trace.ownerScGenerationUnchanged,
                trace.ownerP2pFirmwareGenerationUnchanged,
                trace.ownerP2pMacContextUnchanged,
                trace.p2pMacIdEntry, trace.p2pMacColorEntry,
                trace.ownerBssIdentityUnchanged,
                trace.stationDetailsCapturedEntry,
                trace.stationDetailsCapturedExit,
                trace.stationChannelDetailsCapturedEntry,
                trace.stationChannelDetailsCapturedExit,
                trace.stationIdEntry, trace.stationIdExit,
                trace.stationPhyIdEntry, trace.stationPhyIdExit,
                trace.stationPhyColorEntry, trace.stationPhyColorExit,
                trace.stationChannelFrequencyEntry,
                trace.stationChannelFrequencyExit,
                trace.channelIndex, trace.ieeeChannelNumber,
                trace.p2pMacStateEntry, trace.p2pMacStateExit);
        }
        require(trace.bindingStatusValid == 1 && trace.bindingRejected == 1 &&
                trace.bindingRawStatus == 1,
                "decoded Binding rejection was not distinguished from timeout");
        if (static_cast<int32_t>(trace.bindingAddResult) != EIO) {
            std::fprintf(stderr,
                "binding errno diag result=%u prep=%d cleanup=%d reason=%u step=%u "
                "binding=%u/%u/%u status=%u/%u/%u restore=%u/%d/%u/%d release=%u/%d\n",
                static_cast<unsigned>(result),
                static_cast<int32_t>(trace.prepareErrno),
                static_cast<int32_t>(trace.cleanupErrno), trace.reason, trace.step,
                trace.bindingAddAttempted, trace.bindingAddReturned,
                static_cast<int32_t>(trace.bindingAddResult),
                trace.bindingStatusValid, trace.bindingRejected,
                trace.bindingRawStatus, trace.restoreRemoveAttempted,
                static_cast<int32_t>(trace.restoreRemoveResult),
                trace.restoreAddAttempted,
                static_cast<int32_t>(trace.restoreAddResult),
                trace.phyReleaseAttempted,
                static_cast<int32_t>(trace.phyReleaseResult));
        }
        require(static_cast<int32_t>(trace.bindingAddResult) == EIO,
                "decoded Binding rejection errno was overwritten");

        if (failure == 0) {
            require(result == NativeP2PProbe::RunResult::kExerciseFailedCleaned,
                    "successful production RestorePhy did not permit safe outer cleanup");
            require(trace.reason == IWX_P2P_PREPARE_REASON_BINDING_ADD_DECODED_REJECT &&
                    trace.restoreRemoveAttempted == 1 &&
                    trace.restoreRemoveResult == 0 &&
                    trace.restoreAddAttempted == 1 && trace.restoreAddResult == 0 &&
                    trace.phyReleaseAttempted == 1 && trace.phyReleaseResult == 0,
                    "successful RestorePhy command chain was not recorded");
            require(trace.cleanupErrno == 0 && trace.fullyRestored == 1 &&
                    trace.bindingKnownAbsent == 1 && trace.phyKnownUnleased == 1 &&
                    trace.phaseKnownIdle == 1,
                    "real RestorePhy did not prove all resources absent");
            require(static_cast<int32_t>(trace.prepareErrno) == EIO &&
                    snapshot.exerciseResult == EIO &&
                    snapshot.exerciseRecoveryProofAccepted == 1 &&
                    snapshot.state == NativeP2PProbe::kExerciseFailedCleaned &&
                    fixture.owner.fixtureRemoveCalls_ == 1,
                    "Controller did not clean only the same owner's outer MAC lease");
        } else {
            const uint32_t expectedReason = failure == 1
                ? IWX_P2P_PREPARE_REASON_RESTORE_REMOVE_FAILED
                : IWX_P2P_PREPARE_REASON_RESTORE_ADD_FAILED;
            require(result == NativeP2PProbe::RunResult::kQuarantined &&
                    trace.reason == expectedReason,
                    "RestorePhy failure was not stage-attributed/quarantined");
            require(static_cast<int32_t>(trace.cleanupErrno) == ETIMEDOUT &&
                    static_cast<int32_t>(trace.prepareErrno) == ETIMEDOUT &&
                    snapshot.exerciseResult == ETIMEDOUT &&
                    snapshot.exerciseRecoveryProofAccepted == 0 &&
                    snapshot.state == NativeP2PProbe::kQuarantined &&
                    snapshot.resourceMayExist == 1 &&
                    fixture.owner.fixtureRemoveCalls_ == 0,
                    "cleanup error overwrote Prepare errno or removed uncertain owner");
        }
    }
}

static void testReleaseFailureKeepsPrepareErrnoSeparate()
{
    Fixture fixture;
    setupFixture(fixture);
    fixture.owner.status = 1;
    fixture.owner.disableAllowedAfterPdu = 4;
    require(execute(fixture) == NativeP2PProbe::RunResult::kQuarantined,
            "PHY release error after real restore did not quarantine");
    const auto trace = traceSnapshot(fixture);
    const auto snapshot = fixture.owner.nativeP2pProbe_.snapshot();
    require(trace.reason == IWX_P2P_PREPARE_REASON_PHY_RELEASE_FAILED &&
            static_cast<int32_t>(trace.bindingAddResult) == EIO &&
            static_cast<int32_t>(trace.prepareErrno) == EBUSY &&
            static_cast<int32_t>(trace.cleanupErrno) == EBUSY &&
            trace.restoreRemoveResult == 0 && trace.restoreAddResult == 0 &&
            trace.phyReleaseAttempted == 1 &&
            static_cast<int32_t>(trace.phyReleaseResult) == EBUSY,
            "Prepare and cleanup errors were not kept in separate trace fields");
    require(snapshot.exerciseResult == EBUSY &&
            snapshot.exerciseRecoveryProofAccepted == 0 &&
            snapshot.state == NativeP2PProbe::kQuarantined &&
            fixture.owner.fixtureRemoveCalls_ == 0,
            "incomplete PHY release authorized outer MAC removal");
}

static void testEpochChangeQuarantines()
{
    enum class Mutation {
        Station,
        Context,
        Firmware,
        P2pFirmware,
        Power
    };
    const Mutation mutations[] = {
        Mutation::Station, Mutation::Context, Mutation::Firmware,
        Mutation::P2pFirmware, Mutation::Power
    };
    for (const Mutation mutation : mutations) {
        Fixture fixture;
        setupFixture(fixture);
        fixture.owner.status = 1;
        switch (mutation) {
            case Mutation::Station:
                fixture.owner.changeStationEpochOnBindingAdd = true;
                break;
            case Mutation::Context:
                fixture.owner.changeContextGenerationOnBindingAdd = true;
                break;
            case Mutation::Firmware:
                fixture.owner.changeScGenerationOnBindingAdd = true;
                break;
            case Mutation::P2pFirmware:
                fixture.owner.changeP2pFirmwareGenerationOnBindingAdd = true;
                break;
            case Mutation::Power:
                fixture.owner.changeCapturedPowerGenerationOnBindingAdd = true;
                break;
        }
        require(execute(fixture) == NativeP2PProbe::RunResult::kQuarantined,
                "generation change did not quarantine");
        const auto trace = traceSnapshot(fixture);
        const auto snapshot = fixture.owner.nativeP2pProbe_.snapshot();
        require(fixture.owner.fixtureRemoveCalls_ == 0 &&
                snapshot.state == NativeP2PProbe::kQuarantined,
                "changed generation authorized outer MAC removal");
        if (mutation == Mutation::Power) {
            require(snapshot.exerciseRecoveryProofAccepted == 0 &&
                    snapshot.blocked == NativeP2PProbe::kExerciseOutcomeUnknown,
                    "captured power-epoch mismatch escaped the recovery proof");
        } else if (mutation == Mutation::Context) {
            require(snapshot.exerciseRecoveryProofAccepted == 0 &&
                    trace.bindingRejected == 1 && trace.fullyRestored == 1,
                    "context epoch change escaped the production recovery gate");
        } else {
            require(snapshot.exerciseRecoveryProofAccepted == 0 &&
                    trace.reason == IWX_P2P_PREPARE_REASON_OWNER_CHANGED &&
                    trace.ownerEpochsUnchanged == 0 &&
                    trace.restoreRemoveAttempted == 0,
                    "firmware/station epoch change was not isolated before restore");
        }
    }
}

static void testRecoveryCallbackGenerationDomains()
{
    Fixture fixture;
    setupFixture(fixture);
    fixture.owner.status = 1;
    // The production contract derives HAL power generation from sc_generation
    // and Prepare requires p2pFirmwareGeneration == scGeneration. Context and
    // station epochs remain independent numeric domains.
    require(fixture.run.contextGeneration != fixture.run.powerGeneration &&
            fixture.run.powerGeneration == fixture.run.scGeneration &&
            fixture.run.stationGeneration != fixture.run.scGeneration,
            "generation fixture violates production epoch relationships");
    fixture.owner.changeCapturedPowerGenerationOnBindingAdd = true;
    require(execute(fixture) == NativeP2PProbe::RunResult::kQuarantined,
            "mismatched captured power epoch did not quarantine");
    const auto snapshot = fixture.owner.nativeP2pProbe_.snapshot();
    require(snapshot.exerciseRecoveryAttempted == 1 &&
            snapshot.exerciseRecoveryProofAccepted == 0 &&
            snapshot.blocked == NativeP2PProbe::kExerciseOutcomeUnknown &&
            fixture.owner.fixtureRemoveCalls_ == 0,
            "power snapshot mismatch authorized outer MAC removal");
}

static void testLegacyPrepareRemainsAvailable()
{
    Fixture fixture;
    setupFixture(fixture);
    // Model the same post-ADD context used by the controller before an
    // observation-only run. The legacy channel-6 GO_NEG path stays unchanged.
    auto *sc = &fixture.owner.com;
    sc->sc_p2p.initialized = 1;
    sc->sc_p2p.mac_state = IWX_P2P_RESOURCE_ACTIVE;
    sc->sc_p2p.binding_state = IWX_P2P_RESOURCE_ABSENT;
    sc->sc_p2p.mac_id = 1;
    sc->sc_p2p.fw_generation = static_cast<uint32_t>(sc->sc_generation);
    auto *social6 = &sc->sc_ic.ic_channels[6];
    *social6 = ieee80211_channel{6, true};
    require(fixture.owner.tahoeP2pRocPrepare(
                sc, social6, 83, IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION,
                false) == 0,
            "legacy non-RX149 channel-6 Prepare regressed");
    require(sc->sc_p2p_roc.receive_observation_only == 0 &&
            sc->sc_p2p_roc.phase == IWX_P2P_ROC_PREPARED,
            "legacy Prepare was incorrectly routed through RX149-only mode");
    require(fixture.owner.tahoeP2pRocAbortPrepared(
                sc, 83, IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION, true) == 0,
            "legacy prepared ROC did not restore through its existing abort path");
    require(sc->sc_p2p_roc.phase == IWX_P2P_ROC_COMPLETE &&
            !sc->sc_p2p.phy_leased &&
            sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT,
            "legacy ROC cleanup left firmware resources behind");
}

int main()
{
    testVersionGates();
    testRx149ChannelPolicyRejectsCleanly();
    testUnexpectedPhyLeaseSlotIsAttributed();
    testUncapturedChannelIdentityCannotAuthorizeCleanup();
    testCommandUnknownQuarantines();
    testBindingUnknownQuarantines();
    testDecodedBindingRejectionRestores();
    testReleaseFailureKeepsPrepareErrnoSeparate();
    testEpochChangeQuarantines();
    testRecoveryCallbackGenerationDomains();
    testLegacyPrepareRemainsAvailable();
    std::puts("Test081 production caller-chain Prepare/recovery integration passed");
}
