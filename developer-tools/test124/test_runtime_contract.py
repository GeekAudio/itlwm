"""Real packet codec and sender contract regressions, without device access."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


R = load("test124_runtime_contract", ROOT / "rx149_runtime.py")
F = load("test124_sender_fixtures", ROOT / "test123/router-status/test_dual_sender_protocol_test123.py")


class RuntimeContractTests(unittest.TestCase):
    def setUp(self):
        self.raw, self.construction = F.PACKETSET.encode_packet_set(
            F.SOURCE, F.TARGET, "test124-offline", wire_nonce_hex=F.NONCE,
            wifi_sequence_base=4094, awdl_sequence_base=65534)
        self.packet = R.ValidatedPacketSet.from_bytes(
            self.raw, self.construction, F.PACKETSET.validate_packet_set)
        self.run = R.BoundRun(F.TOKEN, self.packet, F.PROTOCOL)
        self.record = F.sender_result(self.packet.manifest())

    def test_real_builder_manifest_cannot_be_used_as_validated_contract(self):
        self.assertNotIn("valid", self.construction)
        with self.assertRaisesRegex(F.PROTOCOL.SenderProtocolError,
                                    "send_timing_packetset_binding_mismatch"):
            F.PROTOCOL.validate_result(self.record, F.TOKEN,
                expected_wire_nonce_hex=F.NONCE, packet_set_manifest=self.construction)
        self.assertTrue(self.run.validate_result(self.record)["send_complete"])
        self.assertEqual(self.run.classify_result(self.record)["status"],
                         "local_sender_record_validated")

    def test_mutating_construction_or_returned_view_does_not_rebind_run(self):
        self.construction["wire_nonce_hex"] = "a" * 16
        view = self.packet.manifest()
        view["frames"][0]["sequence_control"] = 0
        self.assertTrue(self.run.validate_result(self.record)["send_complete"])
        self.assertNotIn(F.NONCE, str(self.run.audit()))
        self.assertNotIn(F.TOKEN, str(self.run.audit()))

    def test_hash_frame_identity_and_type_mismatches_are_rejected(self):
        mutations = [lambda m: m.update(packet_set_sha256="0" * 64),
                     lambda m: m["frames"][0].update(sequence_control=0),
                     lambda m: m["identities"]["source"].update(mac=F.TARGET["mac"]),
                     lambda m: m.update(frame_count=True)]
        for mutate in mutations:
            value = copy.deepcopy(self.construction)
            mutate(value)
            with self.subTest(value=value), self.assertRaises(R.RuntimeContractError):
                R.ValidatedPacketSet.from_bytes(self.raw, value, F.PACKETSET.validate_packet_set)

    def test_wrong_session_token_does_not_self_validate(self):
        self.record["run_token"] = "a" * 32
        with self.assertRaises(F.PROTOCOL.SenderProtocolError):
            self.run.classify_result(self.record)


class NativeTerminalTests(unittest.TestCase):
    def setUp(self):
        self.args = dict(run_token="a" * 32, boot_epoch=123, expected_loaded_uuid="uuid")
        row = {"current_owner_and_epochs": {key: 1 for key in ("NativeP2PProbeContextGeneration", "NativeP2PProbePowerGeneration", "NativeP2PProbeStationGeneration", "NativeP2PRocGeneration", "NativeP2PRxTraceOwnerSerial")},
               "native_p2p_probe_lifecycle": {
                   "Selected": 1, "Attempted": 1, "State": 10, "EndSeen": 1,
                   "RecoveryAttempted": 1, "ProofAccepted": 1, "RemoveResult": 0,
                   "ResourceMayExist": 0, "ExerciseResult": 100}}
        self.capture = {"arm_run_token": "a" * 32, "boot_epoch": 123,
                        "expected_loaded_uuid": "uuid", "boot_attempt_claim_consumed": True,
                        "post_samples": [copy.deepcopy(row) for _ in range(3)]}

    def test_failed_but_cleaned_is_neither_delivery_nor_permission_to_retry(self):
        actual = R.native_terminal(self.capture, **self.args)
        self.assertEqual(actual["cleanup"], "verified")
        self.assertEqual(actual["exercise"], "failed")
        self.assertFalse(actual["functional_delivery_proven"])
        self.assertFalse(actual["retry_allowed"])

    def test_mixed_owner_or_resource_may_exist_is_unknown(self):
        for mutate in (
                lambda c: c["post_samples"][1]["current_owner_and_epochs"].update(NativeP2PRxTraceOwnerSerial=2),
                lambda c: c["post_samples"][2]["current_owner_and_epochs"].update(NativeP2PRxTraceOwnerSerial=True),
                lambda c: c["post_samples"][2]["native_p2p_probe_lifecycle"].update(ResourceMayExist=1),
                lambda c: c.update(arm_run_token="b" * 32)):
            value = copy.deepcopy(self.capture)
            mutate(value)
            self.assertEqual(R.native_terminal(value, **self.args)["cleanup"], "unknown")


if __name__ == "__main__":
    unittest.main()
