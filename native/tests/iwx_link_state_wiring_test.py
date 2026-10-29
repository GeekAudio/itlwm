#!/usr/bin/env python3
"""Keep reset pairing and splnet-safe terminal trace wiring explicit."""
from pathlib import Path


root = Path(__file__).resolve().parents[2]
source = (root / "itlwm/hal_iwx/ItlIwx.cpp").read_text(encoding="utf-8")
header = (root / "itlwm/hal_iwx/ItlIwx.hpp").read_text(encoding="utf-8")
trace_header = (root / "native/iwx_link_state_trace.hpp").read_text(
    encoding="utf-8")


def section(start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


observation_class = section(
    "class NativeNewstateObservation {", "class NativeDeauthObservation {")
destructor = observation_class[
    observation_class.index("~NativeNewstateObservation()"):
    observation_class.index("// Called before splx(s)")]
assert "sc_->sc_ic" not in destructor
assert "sc_->sc_ic" in observation_class[
    observation_class.index("void finish()"):
    observation_class.index("// 0..65535")]

newstate_task = section(
    "void ItlIwx::\niwx_newstate_task(void *psc)",
    "\nint ItlIwx::\niwx_newstate(")
after_observation = newstate_task[
    newstate_task.index("NativeNewstateObservation stateObservation"):
]
for before_unlock in after_observation.split("splx(s);")[:-1]:
    assert "stateObservation.finish();" in before_unlock, (
        "every post-observation splx(s) needs an in-splnet finish()")

stop = section(
    "int ItlIwx::\niwx_stop(struct _ifnet *ifp, IwxResetTrace::ResetReason reason)",
    "\nint ItlIwx::\niwx_resume(")
assert stop.index("s = splnet();") < stop.index("tahoeRecordReset(reason, sc)")
assert "const uint32_t linkResetSequence = tahoeRecordReset(reason, sc);" in stop
complete = stop.index("IwxLinkStateTrace::Event::kResetComplete")
assert "linkResetSequence" in stop[complete:complete + 280]
assert "linkResetSequence, true" in stop[complete:complete + 360]
assert complete < stop.rindex("splx(s);")

init_task = section(
    "void ItlIwx::\niwx_init_task(void *arg1)",
    "\nint ItlIwx::\niwx_resume(")
assert init_task.index("int s = splnet();") < init_task.index("that->tahoeRecordReset(")
assert "const uint32_t linkResetSequence = that->tahoeRecordReset(" in init_task
skipped = init_task.index("IwxLinkStateTrace::Event::kResetSkipped")
assert "linkResetSequence" in init_task[skipped:skipped + 300]
assert "linkResetSequence, true" in init_task[skipped:skipped + 360]
assert "IwxLinkStateTrace::Event::kResetComplete" not in init_task
assert "uint32_t tahoeRecordReset(" in header
assert "nativeLinkTransitionResetOldState_" not in header + source
assert "nativeLinkTransitionResetReason_" not in header + source
assert "kResetSkipped = 7" in trace_header

print("PASS: reset events are sequence-bound and every observed newstate exit finishes under splnet")
