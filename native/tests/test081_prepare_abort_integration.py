#!/usr/bin/env python3
"""Exercise the production RX149 Prepare/recovery caller chain under ASan/UBSan.

The harness reuses the existing ROC HAL firmware shim, then extracts the real
Prepare, RestorePhy, RX149 caller, recovery callback and Controller methods.
Only the OS work-loop boundary and firmware I/O are modeled; no policy,
Prepare, restore or recovery proof is reimplemented in the test.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE_HARNESS = HERE / "test_iwx_p2p_roc_hal.py"
FIXTURE = HERE / "test081_prepare_abort_cases.json"
CPP_HARNESS = HERE / "test081_prepare_abort_integration.cpp"


def source_function(path: str, marker: str) -> str:
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


def base_shim_and_hal_markers() -> tuple[str, list[tuple[str, str]]]:
    tree = ast.parse(BASE_HARNESS.read_text(), filename=str(BASE_HARNESS))
    shim = None
    actual = None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if shim is None and any(isinstance(target, ast.Name) and target.id == "shim"
                                for target in node.targets):
            shim = ast.literal_eval(node.value)
        if any(isinstance(target, ast.Name) and target.id == "actual"
               for target in node.targets):
            actual = node.value
    if not isinstance(shim, str) or not isinstance(actual, ast.Call):
        raise AssertionError("existing ROC HAL shim/extraction list changed")
    if not (isinstance(actual.func, ast.Attribute) and
            actual.func.attr == "join" and actual.args and
            isinstance(actual.args[0], ast.List)):
        raise AssertionError("existing production HAL extraction list changed")
    markers: list[tuple[str, str]] = []
    for expression in actual.args[0].elts:
        if not (isinstance(expression, ast.Call) and
                isinstance(expression.func, ast.Name) and
                expression.func.id == "extract" and len(expression.args) == 2):
            raise AssertionError("unexpected entry in existing HAL extraction list")
        path = ast.literal_eval(expression.args[0])
        marker = ast.literal_eval(expression.args[1])
        markers.append((path, marker))
    return shim, markers


def extend_shim(shim: str) -> str:
    shim = shim.replace(
        '#include "native/iwx_p2p_roc_prepare_trace.h"',
        '#include "native/iwx_p2p_roc_prepare_trace.h"\n'
        '#include "native/p2p_hal_probe.hpp"',
        1,
    )
    shim = shim.replace(
        "struct ItlIwx {\n iwx_softc com{}; bool allowed=true;",
        """class IOEthernetController;
class IOCommandGate;
class IOWorkLoop;
class OSObject;
using IOReturn = int;

struct ItlIwx {
 iwx_softc com{}; bool allowed=true;
 IOEthernetController *controller_=nullptr;
 IOCommandGate *commandGate_=nullptr;
 IOWorkLoop *workLoop_=nullptr;
 NativeP2PProbe::Controller nativeP2pProbe_{};
 void *nativeP2pProbeOwner_=nullptr;
 uint32_t nativeP2pProbeGeneration_=0;
 uint32_t nativeP2pPowerGeneration_=0;
 uint32_t nativeP2pRocStage_=0,nativeP2pRocChannel_=0;
 uint32_t nativeP2pRocDurationMs_=0,nativeP2pRocConfiguration_=0;
 uint32_t nativeP2pRocResult_=0,nativeP2pRocGeneration_=0;
 uint32_t nativeP2pProbeGenerationForFixture_=0;
 bool probeBusy_=false,onMainGate_=true,txHistoryQuiescent_=true;
 bool changeStationEpochOnBindingAdd=false;
 bool changeCapturedPowerGenerationOnBindingAdd=false;
 uint32_t *fixtureRunPowerGeneration_=nullptr;
 int disableAllowedAfterPdu=0;
 bool changeContextGenerationOnBindingAdd=false;
 bool changeScGenerationOnBindingAdd=false;
 bool changeP2pFirmwareGenerationOnBindingAdd=false;
 uint32_t fixtureConfigureCalls_=0,fixtureAddCalls_=0,fixtureRemoveCalls_=0;
 uint32_t fixturePublishCalls_=0;
 bool fixturePublishedMayExist_=false,fixtureFailOuterRemove_=false;""",
        1,
    )
    if "NativeP2PProbe::Controller nativeP2pProbe_{};" not in shim:
        raise AssertionError("could not extend shared HAL shim class")

    shim = shim.replace(
        "struct iwx_node { iwx_phy_ctxt *in_phyctxt=nullptr; uint16_t in_id=0; ieee80211_node in_ni{}; };",
        "struct iwx_node { iwx_phy_ctxt *in_phyctxt=nullptr; uint16_t in_id=0; ieee80211_node in_ni{}; ieee80211_channel *ni_chan=nullptr; };",
        1,
    )

    shim = shim.replace(
        " if(changeStationEpochOnBindingRemove&&id==IWX_BINDING_CONTEXT_CMD&&\n"
        "     len>=sizeof(iwx_binding_cmd)) {\n"
        "   const auto *binding=static_cast<const iwx_binding_cmd*>(data);\n"
        "   if(binding->action==IWX_FW_CTXT_ACTION_REMOVE)\n"
        "    ++sc->sc_tx_rate_generation;\n"
        "  }\n",
        """ if(id==IWX_BINDING_CONTEXT_CMD&&len>=sizeof(iwx_binding_cmd)) {
   const auto *binding=static_cast<const iwx_binding_cmd*>(data);
   if(binding->action==IWX_FW_CTXT_ACTION_REMOVE&&changeStationEpochOnBindingRemove)
    ++sc->sc_tx_rate_generation;
   if(binding->action==IWX_FW_CTXT_ACTION_ADD) {
    if(changeStationEpochOnBindingAdd) ++sc->sc_tx_rate_generation;
    if(changeCapturedPowerGenerationOnBindingAdd && fixtureRunPowerGeneration_)
     ++*fixtureRunPowerGeneration_;
    if(changeContextGenerationOnBindingAdd) ++nativeP2pProbeGeneration_;
    if(changeScGenerationOnBindingAdd) ++sc->sc_generation;
    if(changeP2pFirmwareGenerationOnBindingAdd) ++sc->sc_p2p.fw_generation;
   }
  }
""",
        1,
    )
    if "changeContextGenerationOnBindingAdd" not in shim:
        raise AssertionError("could not extend binding response fault injection")

    shim = shim.replace(
        "  if(pduFailAt==static_cast<int>(pduSends))return ETIMEDOUT;\n"
        "  return pduDefault;\n",
        "  if(pduFailAt==static_cast<int>(pduSends))return ETIMEDOUT;\n"
        "  if(disableAllowedAfterPdu==static_cast<int>(pduSends))allowed=false;\n"
        "  return pduDefault;\n",
        1,
    )
    if "disableAllowedAfterPdu==static_cast<int>(pduSends)" not in shim:
        raise AssertionError("could not add PHY release fault injection")

    shim = shim.replace(
        " int tahoeP2pRocAbortPrepared(iwx_softc*,uint32_t,uint32_t,bool);\n};",
        """ int tahoeP2pRocAbortPrepared(iwx_softc*,uint32_t,uint32_t,bool);
 IOEthernetController *tahoeP2pController();
 IOCommandGate *getMainCommandGate();
 IOCommandGate *tahoeP2pCommandGate();
 IOWorkLoop *getMainWorkLoop();
 bool tahoeP2pOnMainGate() const;
 bool nativeP2pBusy() const;
 static bool tahoeP2pArmRoc(void*,uint32_t,uint32_t,uint32_t);
 static IOReturn tahoeP2pRocEventAction(OSObject*,void*,void*,void*,void*);
 static int tahoeP2pExerciseRoc(void*);
 static bool tahoeP2pExerciseRecovery(void*,int32_t,
     NativeP2PProbe::ExerciseRecoveryProof*);
 static IOReturn tahoeP2pExerciseRecoveryAction(OSObject*,void*,void*,void*,void*);
};""",
        1,
    )
    return shim


def version_case_source(fixture: dict) -> str:
    names = {
        "SESSION_CAPABILITY_MISSING": "IWX_P2P_PREPARE_REASON_SESSION_CAPABILITY_MISSING",
        "PHY_COMMAND_VERSION": "IWX_P2P_PREPARE_REASON_PHY_COMMAND_VERSION",
        "BINDING_COMMAND_VERSION": "IWX_P2P_PREPARE_REASON_BINDING_COMMAND_VERSION",
        "BINDING_NOTIFICATION_VERSION": "IWX_P2P_PREPARE_REASON_BINDING_NOTIFICATION_VERSION",
        "SESSION_COMMAND_VERSION": "IWX_P2P_PREPARE_REASON_SESSION_COMMAND_VERSION",
        "SESSION_NOTIFICATION_VERSION": "IWX_P2P_PREPARE_REASON_SESSION_NOTIFICATION_VERSION",
    }
    rows = []
    for case in fixture["firmware_gates"]:
        try:
            reason = names[case["reason"]]
        except KeyError as error:
            raise AssertionError(f"unmapped fixture reason: {error}") from error
        rows.append(
            "    {\"%s\", %du, %du, %du, %du, %du, %du, %s}" % (
                case["name"], case["session_capability"],
                case["phy_command_version"], case["binding_command_version"],
                case["binding_notification_version"],
                case["session_command_version"],
                case["session_notification_version"], reason,
            )
        )
    return ",\n".join(rows)


def verify_production_binding() -> None:
    source = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()
    start = source.index("NativeP2PProbe::Operations operations{")
    end = source.index("owner->nativeP2pProbe_.executeOnce(operations)", start)
    operations = source[start:end]
    if "operations.exercise = tahoeP2pExerciseRoc;" not in operations:
        raise AssertionError("production worker is not bound to the RX149 caller")
    if "operations.exerciseRecovery = tahoeP2pExerciseRecovery;" not in operations:
        raise AssertionError("production worker is not bound to recovery proof")


def main() -> None:
    verify_production_binding()
    fixture = json.loads(FIXTURE.read_text())
    profile = fixture["profile"]
    if profile != {
        "ieee_channel": 149,
        "frequency_mhz": 5745,
        "configuration": 2,
        "duration_ms": 100,
    }:
        raise AssertionError("Test081 RX149 profile fixture changed unexpectedly")

    base_shim, low_level_markers = base_shim_and_hal_markers()
    shim = extend_shim(base_shim)
    production_markers = low_level_markers + [
        ("itlwm/hal_iwx/ItlIwxP2PProbe.cpp", "static bool readPrepareTraceSnapshot("),
        ("itlwm/hal_iwx/ItlIwxP2PProbe.cpp", "static void publishPrepareTraceSnapshot("),
        ("itlwm/hal_iwx/ItlIwxP2PProbe.cpp", "static int exerciseRx149Observation("),
        ("itlwm/hal_iwx/ItlIwxP2PProbe.cpp", "int ItlIwx::tahoeP2pExerciseRoc("),
        ("itlwm/hal_iwx/ItlIwxP2PProbe.cpp", "bool ItlIwx::tahoeP2pExerciseRecovery("),
        ("itlwm/hal_iwx/ItlIwxP2PProbe.cpp", "IOReturn ItlIwx::tahoeP2pExerciseRecoveryAction("),
    ]
    production = "\n\n".join(
        source_function(path, marker) for path, marker in production_markers
    )
    cpp = CPP_HARNESS.read_text()
    marker = "// __TEST081_PRODUCTION_METHODS__"
    if cpp.count(marker) != 1:
        raise AssertionError("Test081 production insertion marker missing or duplicated")
    cpp = cpp.replace(marker, production, 1)
    cases_marker = "// __TEST081_VERSION_CASES__"
    if cpp.count(cases_marker) != 1:
        raise AssertionError("Test081 fixture insertion marker missing or duplicated")
    cpp = cpp.replace(cases_marker, version_case_source(fixture), 1)

    with tempfile.TemporaryDirectory(prefix="test081-prepare-abort-") as tmp:
        source_path = Path(tmp) / "test081_prepare_abort.cpp"
        executable = Path(tmp) / "test081_prepare_abort"
        source_path.write_text(shim + "\n" + cpp)
        compiler = os.environ.get("CXX", "clang++")
        subprocess.run(
            [
                compiler,
                "-std=c++14",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-parameter",
                "-Wno-sign-compare",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-fno-sanitize-recover=all",
                "-I",
                str(ROOT),
                str(source_path),
                str(ROOT / "native/p2p_hal_probe.cpp"),
                "-o",
                str(executable),
            ],
            check=True,
        )
        environment = dict(os.environ)
        environment.setdefault("ASAN_OPTIONS", "detect_leaks=0:halt_on_error=1")
        environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
        subprocess.run([str(executable)], check=True, env=environment)


if __name__ == "__main__":
    main()
