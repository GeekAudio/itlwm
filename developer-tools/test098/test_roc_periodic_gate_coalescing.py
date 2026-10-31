#!/usr/bin/env python3
"""Source guards for the Test098 periodic single-gate ROC publication path."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
DRIVER = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
P2P = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()
FEATURE = "ITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332"


def function(source: str, marker: str) -> str:
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
    raise AssertionError(f"unterminated function {marker}")


TICK = function(P2P, "void ItlIwx::nativeP2pTick()")
PERIODIC_TICK = function(
    DRIVER, "void ItlIwx::tahoeRxRocCorrelationPeriodicTick("
)
PERIODIC_ACTION = function(
    DRIVER, "IOReturn ItlIwx::tahoeRxRocCorrelationPeriodicAction("
)
PUBLISH_ACTION = function(
    DRIVER, "IOReturn ItlIwx::tahoeRxRocCorrelationPublishAction("
)
PUBLISH = function(DRIVER, "void ItlIwx::tahoeRxRocCorrelationPublish(")


class RocPeriodicGateTests(unittest.TestCase):
    def test_only_opt_in_periodic_tick_uses_combined_path(self):
        feature_at = TICK.index(f"#if defined({FEATURE})")
        fallback_at = TICK.index("#else", feature_at)
        endif_at = TICK.index("#endif", fallback_at)
        feature_branch = TICK[feature_at:fallback_at]
        fallback_branch = TICK[fallback_at:endif_at]
        self.assertEqual(feature_branch.count(
            "tahoeRxRocCorrelationPeriodicTick(rocController)"), 1)
        self.assertIn("tahoeP2pRxDrain()", fallback_branch)
        self.assertNotIn("tahoeRxRocCorrelationPeriodicTick", fallback_branch)
        self.assertEqual(TICK.count("tahoeRxRocCorrelationPublish("), 0)
        self.assertEqual(TICK.count("tahoeP2pRxDrain()"), 2)

    def test_periodic_path_drains_then_publishes_inside_one_gate(self):
        self.assertIn("if (tahoeP2pOnMainGate())", PERIODIC_TICK)
        direct = PERIODIC_TICK[PERIODIC_TICK.index(
            "if (tahoeP2pOnMainGate())"):]
        self.assertLess(direct.index("tahoeP2pRxDrain();"),
                        direct.index("tahoeRxRocCorrelationPublish(controller);"))
        self.assertEqual(PERIODIC_TICK.count("attemptAction("), 1)
        self.assertIn("getMainCommandGate()", PERIODIC_TICK)
        self.assertIn("tahoeRxRocCorrelationPeriodicAction", PERIODIC_TICK)
        self.assertNotIn("runAction", PERIODIC_TICK)
        self.assertIn("!owner->tahoeP2pOnMainGate()", PERIODIC_ACTION)
        self.assertIn("owner->getController() != controller", PERIODIC_ACTION)
        self.assertLess(PERIODIC_ACTION.index("owner->tahoeP2pRxDrain();"),
                        PERIODIC_ACTION.index(
                            "owner->tahoeRxRocCorrelationPublish(controller);"))
        self.assertIn("getController() != controller", PUBLISH_ACTION)

    def test_failed_attempt_cannot_drain_or_enter_publisher(self):
        # `attemptAction` invokes the action only when the try-lock succeeds;
        # this guard checks the production implementation remains nonblocking
        # and the only drain for the opt-in periodic path lives in that action.
        off_gate = PERIODIC_TICK[PERIODIC_TICK.index(
            "IOCommandGate *gate = getMainCommandGate();"):]
        self.assertNotIn("tahoeP2pRxDrain", off_gate)
        self.assertIn("gate->attemptAction(", off_gate)
        self.assertIn("owner->tahoeP2pRxDrain();", PERIODIC_ACTION)
        self.assertNotIn("tahoeP2pRxDrain", PUBLISH)
        self.assertNotIn("tahoeP2pRxDrain", PUBLISH_ACTION)


if __name__ == "__main__":
    unittest.main()
