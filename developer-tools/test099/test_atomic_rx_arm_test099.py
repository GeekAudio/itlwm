from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
V2_SOURCE = ROOT / "AirportItlwm/AirportItlwmV2.cpp"
HELPER_SOURCE = Path(__file__).with_name("arm_p2p_rx149_test099.swift")


def function_body(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise AssertionError("unterminated C++ function")


class AtomicRx149ArmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v2 = V2_SOURCE.read_text(encoding="utf-8")
        cls.helper = HELPER_SOURCE.read_text(encoding="utf-8")

    def test_v2_requires_combined_arm_and_run_token_on_main_gate(self):
        setter = function_body(self.v2, "IOReturn AirportItlwm::setProperties(")
        action = function_body(self.v2, "IOReturn armNativeRx149OnMainGate(")

        self.assertIn("request->getCount() != 2", setter)
        self.assertIn("validRx149RunToken(rxToken)", setter)
        self.assertIn("_fCommandGate->runAction(", setter)
        self.assertIn("hal->tahoeP2pCommandGate() != _fCommandGate", action)
        self.assertIn("setProperty(\"NativeP2PRx149RunToken\"", action)
        self.assertLess(action.index("setProperty(\"NativeP2PRx149RunToken\""),
                        action.index("nativeP2pArmProbe()"))

    def test_user_helper_uses_one_combined_registry_request(self):
        arm_path = self.helper[self.helper.index("let armRequest:"):]
        self.assertEqual(arm_path.count("IORegistryEntrySetCFProperties("), 1)
        self.assertNotIn("IORegistryEntrySetCFProperty(", arm_path)
        self.assertIn('"NativeP2PRx149ArmOnce": true', arm_path)
        self.assertIn('"NativeP2PRx149RunToken": expectedRunToken', arm_path)
        self.assertNotIn('number("NativeP2PManualArmed")', arm_path)


if __name__ == "__main__":
    unittest.main()
