from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROBE = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise AssertionError("unclosed function: " + signature)


class Rx149LiveStartLifecycleTests(unittest.TestCase):
    def test_reset_retirement_is_serialized_before_any_stop_early_return(self):
        body = function_body(PROBE, "int ItlIwx::tahoeP2pStopBeforeReset(")
        invalidation = body.index("invalidateRx149LiveStartOnMainGate(this)")
        retained_gate = body.index("nativeP2pResourcesRetained()")
        self.assertLess(invalidation, retained_gate)
        self.assertIn("if (invalidateError)\n        return invalidateError;", body)

        retire = function_body(PROBE, "static int invalidateRx149LiveStartOnMainGate(")
        self.assertIn("owner->tahoeP2pOnMainGate()", retire)
        self.assertIn("owner->tahoeP2pCommandGate()", retire)
        self.assertIn("gate->runAction(invalidateRx149LiveStartAction, owner)", retire)
        action = function_body(PROBE, "static IOReturn invalidateRx149LiveStartAction(")
        self.assertIn("removeRx149LiveStartPublication(owner)", action)

    def test_retirement_clears_run_identity_and_current_permit(self):
        body = function_body(PROBE, "static void removeRx149LiveStartPublication(")
        self.assertIn('removeProperty("NativeP2PRx149LiveStartSnapshot")', body)
        self.assertIn('removeProperty("NativeP2PRx149RunToken")', body)
        self.assertIn("memset(owner->nativeP2pRx149RunToken_", body)
        self.assertIn("nativeP2pRx149LiveSnapshotOwnerSerial_ = 0", body)
        self.assertIn("nativeP2pRx149LiveSnapshotValid_ = 0", body)

    def test_owner_mismatch_and_session_terminal_paths_fail_closed(self):
        event = function_body(PROBE, "IOReturn ItlIwx::tahoeP2pRocEventAction(")
        self.assertIn("if (!currentOwner)", event)
        mismatch = event[event.index("if (!currentOwner)"):event.index("auto &tracker")]
        self.assertIn("publishRx149LiveStartSnapshot(owner, probe, stale, true)", mismatch)
        self.assertIn("return kIOReturnNotReady", mismatch)
        tap = function_body(PROBE, "void ItlIwx::tahoeP2pTapSessionEvent(")
        self.assertIn("!getMainWorkLoop()->inGate()", tap)
        self.assertIn("if ((canonicalStart || canonicalEnd) && rx149ArmModeSelected(this))", tap)
        self.assertIn("publishRx149LiveStartSnapshot(\n                this, nullptr, after, true)", tap)

    def test_cancel_finish_and_start_publication_remain_main_gate_scoped(self):
        cancel = function_body(PROBE, "IOReturn ItlIwx::tahoeP2pCancelAction(")
        self.assertIn("removeRx149LiveStartPublication(owner)", cancel)
        finish = function_body(PROBE, "IOReturn ItlIwx::tahoeP2pFinishAction(")
        self.assertIn("if (run->rx149ObservationOnly && owner->tahoeP2pOnMainGate())", finish)
        self.assertIn("publishRx149LiveStartSnapshot(\n            owner, run, owner->nativeP2pRocEvents_.snapshot(), true)", finish)
        publish = function_body(PROBE, "static bool publishRx149LiveStartSnapshot(")
        self.assertIn("!owner->tahoeP2pOnMainGate()", publish)
        self.assertIn("OSData *payload = OSData::withBytes", publish)


if __name__ == "__main__":
    unittest.main()
