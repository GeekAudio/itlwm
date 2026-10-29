#!/usr/bin/env python3
"""Exercise Tahoe RX149 packaging gates and the actual outer arm setter."""
from argparse import Namespace
import importlib.util
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "test080_build_tahoe", ROOT / "scripts/build_tahoe.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_builder_isolation():
    builder = load_builder()
    boolean_options = (
        "p2p_probe", "p2p_roc_probe", "p2p_tx_probe", "p2p_manual_trigger",
        "p2p_awdl_psf_observation_only", "p2p_awdl_mif_followup",
        "p2p_gp2_observation", "native_awdl_init_observation_only",
        "native_awdl_lifecycle_observation_only", "native_awdl_resident_data",
        "native_awdl_tx_evidence", "native_awdl_discovery_experiment",
        "native_awdl_discovery_mif_current_slot",
        "native_awdl_discovery_current_aw_fallback",
        "native_awdl_rx149_observation_only",
    )
    base = {name: False for name in boolean_options}
    base.update(p2p_probe=True, p2p_manual_trigger=True,
                native_awdl_resident_data=True,
                native_awdl_rx149_observation_only=True)
    assert builder.receive149_profile_errors(Namespace(**base)) == []

    for option in (
            "p2p_roc_probe", "p2p_tx_probe",
            "p2p_awdl_psf_observation_only", "p2p_awdl_mif_followup",
            "p2p_gp2_observation", "native_awdl_init_observation_only",
            "native_awdl_lifecycle_observation_only", "native_awdl_tx_evidence",
            "native_awdl_discovery_experiment",
            "native_awdl_discovery_mif_current_slot",
            "native_awdl_discovery_current_aw_fallback"):
        args = Namespace(**{**base, option: True})
        assert builder.receive149_profile_errors(args), option

    for missing in ("p2p_probe", "p2p_manual_trigger", "native_awdl_resident_data"):
        args = Namespace(**{**base, missing: False})
        assert builder.receive149_profile_errors(args), missing

    args = Namespace(**base)
    flags = builder.resident_build_flags(args)
    assert "-DITL_NATIVE_AWDL_RX149_OBSERVATION_25G332=1" in flags
    # The implementations are compiled for ABI/link compatibility, while
    # runtime personality enables only the manual RX149 profile.
    assert "-DITL_NATIVE_AWDL_TX_EVIDENCE_25G332=1" in flags
    assert "-DITL_NATIVE_AWDL_DISCOVERY_EXPERIMENT_25G332=1" in flags
    personality = {}
    builder.apply_artifact_profile(personality, args)
    assert personality["NativeP2PRx149ObservationOnly"] is True
    for name in (
            "NativeP2PRocProbe", "NativeP2PTxProbe",
            "NativeP2PAwdlPsfObservationOnly", "NativeP2PAwdlMifFollowup",
            "NativeP2PGp2Observation", "NativeAwdlInitObservationOnly",
            "NativeAwdlLifecycleObservationOnly", "NativeAwdlTxEvidenceEnabled",
            "NativeAwdlDiscoveryExperimentEnabled",
            "NativeAwdlDiscoveryMifCurrentSlotEnabled",
            "NativeAwdlDiscoveryCurrentAwFallbackEnabled"):
        assert personality[name] is False, name


SHIM = r"""
#include <cassert>
#include <cstddef>
#include <map>
#include <string>
#include <vector>

using IOReturn = int;
static constexpr IOReturn kIOReturnSuccess = 0;
static constexpr IOReturn kIOReturnUnsupported = -1;
static constexpr IOReturn kIOReturnBadArgument = -2;
static constexpr IOReturn kIOReturnNotReady = -3;
[[maybe_unused]] static constexpr IOReturn kIOReturnNotPrivileged = -4;
static constexpr int kIOClientPrivilegeAdministrator = 1;

class OSObject {
public:
    virtual ~OSObject() = default;
};
class OSBoolean final : public OSObject {
public:
    explicit OSBoolean(bool value) : value(value) {}
    bool value;
};
static OSBoolean trueBoolean(true);
[[maybe_unused]] static OSBoolean falseBoolean(false);
static OSObject *const kOSBooleanTrue = &trueBoolean;
[[maybe_unused]] static OSObject *const kOSBooleanFalse = &falseBoolean;

class OSDictionary final : public OSObject {
public:
    std::map<std::string, OSObject *> entries;
    OSObject *getObject(const char *key) {
        auto it = entries.find(key);
        return it == entries.end() ? nullptr : it->second;
    }
    unsigned getCount() const { return static_cast<unsigned>(entries.size()); }
    void add(const char *key, OSObject *value) { entries[key] = value; }
};

#define OSDynamicCast(type, object) dynamic_cast<type *>(object)

static int gAdmin = kIOReturnSuccess;
class IOUserClient {
public:
    static IOReturn clientHasPrivilege(void *, int) { return gAdmin; }
};
static void *current_task() { return nullptr; }

class BaseService {
public:
    unsigned parentCalls = 0;
    IOReturn parentResult = kIOReturnSuccess;
    IOReturn setProperties(OSObject *) { ++parentCalls; return parentResult; }
};
#define super BaseService

class NativeHal {
public:
    unsigned armCalls = 0;
    IOReturn armResult = kIOReturnSuccess;
    IOReturn nativeP2pArmProbe() { ++armCalls; return armResult; }
};

class AirportItlwm : public BaseService {
public:
    NativeHal *fHalService = nullptr;
    std::map<std::string, OSObject *> properties;
    OSObject *getProperty(const char *key) {
        auto it = properties.find(key);
        return it == properties.end() ? nullptr : it->second;
    }
    IOReturn setProperties(OSObject *properties);
};
"""


def test_outer_setter(rx_macro_enabled: bool):
    source = (ROOT / "AirportItlwm/AirportItlwmV2.cpp").read_text()
    actual = function_body(source, "IOReturn AirportItlwm::setProperties(")
    macro = "#define AIRPORT_TAHOE 1\n"
    if rx_macro_enabled:
        macro += "#define ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332 1\n"

    body = r"""
static IOReturn invoke(AirportItlwm &driver, OSDictionary &request) {
    return driver.setProperties(&request);
}
static OSDictionary oneKey(const char *name, OSObject *value = kOSBooleanTrue) {
    OSDictionary request; request.add(name, value); return request;
}

int main() {
    const std::vector<const char *> protectedKeys = {
        "NativeP2PManualTrigger", "NativeP2PManualArmed",
        "NativeP2PProbe", "NativeP2PRocProbe", "NativeP2PTxProbe",
        "NativeP2PAwdlPsfObservationOnly", "NativeP2PAwdlMifFollowup",
        "NativeP2PGp2Observation", "NativeP2PRx149ObservationOnly",
        "NativeP2PRx149ProfileEnabled", "NativeP2PRx149Selected",
        "NativeP2PRx149HostTxBlocked", "NativeP2PTxProbeEverDoorbelled",
        "NativeP2PAwdlActionFramesSubmitted",
        "NativeP2PAwdlPsfFrameSubmitted",
        "NativeP2PAwdlMifFrameSubmitted",
        "NativeP2PAwdlMifBootstrapSubmitted"
    };
    for (const char *key : protectedKeys) {
        AirportItlwm driver; NativeHal hal; driver.fHalService = &hal;
        auto request = oneKey(key);
        assert(invoke(driver, request) == kIOReturnUnsupported);
        assert(driver.parentCalls == 0 && hal.armCalls == 0);
    }

    AirportItlwm driver; NativeHal hal; driver.fHalService = &hal;
    driver.properties["NativeP2PRx149ObservationOnly"] = kOSBooleanTrue;
    auto legacyArm = oneKey("NativeP2PArmOnce");
    assert(invoke(driver, legacyArm) == kIOReturnUnsupported);
    assert(hal.armCalls == 0 && driver.parentCalls == 0);

    auto newArm = oneKey("NativeP2PRx149ArmOnce");
#if defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332)
    gAdmin = kIOReturnNotPrivileged;
    assert(invoke(driver, newArm) == kIOReturnNotPrivileged);
    assert(hal.armCalls == 0);
    gAdmin = kIOReturnSuccess;
    assert(invoke(driver, newArm) == kIOReturnSuccess);
    assert(hal.armCalls == 1 && driver.parentCalls == 0);
    auto bothArms = oneKey("NativeP2PRx149ArmOnce");
    bothArms.add("extra", kOSBooleanTrue);
    assert(invoke(driver, bothArms) == kIOReturnBadArgument);
    auto falseArm = oneKey("NativeP2PRx149ArmOnce", kOSBooleanFalse);
    assert(invoke(driver, falseArm) == kIOReturnBadArgument);
#else
    gAdmin = kIOReturnSuccess;
    assert(invoke(driver, newArm) == kIOReturnUnsupported);
    assert(hal.armCalls == 0);
#endif

    AirportItlwm legacy; NativeHal legacyHal; legacy.fHalService = &legacyHal;
    auto rejectedNewAlias = oneKey("NativeP2PRx149ArmOnce");
    assert(invoke(legacy, rejectedNewAlias) == kIOReturnUnsupported);
    assert(legacyHal.armCalls == 0 && legacy.parentCalls == 0);
    auto allowedLegacyAlias = oneKey("NativeP2PArmOnce");
    assert(invoke(legacy, allowedLegacyAlias) == kIOReturnSuccess);
    assert(legacyHal.armCalls == 1 && legacy.parentCalls == 0);

    AirportItlwm notReady;
    auto notReadyArm = oneKey("NativeP2PArmOnce");
    assert(invoke(notReady, notReadyArm) == kIOReturnNotReady);

    AirportItlwm ordinary;
    OSDictionary unrelated; unrelated.add("OtherProperty", kOSBooleanTrue);
    assert(invoke(ordinary, unrelated) == kIOReturnSuccess);
    assert(ordinary.parentCalls == 1);
}
"""
    with tempfile.TemporaryDirectory(prefix="itlwm-test080-outer-") as directory:
        cpp = Path(directory) / "outer_manual_alias.cpp"
        exe = Path(directory) / "outer_manual_alias"
        cpp.write_text(SHIM + "\n" + macro + actual + "\n" + body)
        subprocess.run([
            "xcrun", "clang++", "-std=c++14", "-O1", "-Wall", "-Wextra",
            "-Werror", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            str(cpp), "-o", str(exe),
        ], check=True)
        subprocess.run([str(exe)], check=True)


def main():
    test_builder_isolation()
    test_outer_setter(False)
    test_outer_setter(True)
    print("PASS: RX149 build/runtime isolation and outer manual aliases")


if __name__ == "__main__":
    main()
