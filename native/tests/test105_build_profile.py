#!/usr/bin/env python3
"""Keep the optional reply shadow distinct from runtime or firmware TX permission."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    'test105_inbound_profile', ROOT / 'native/tests/test086_build_profile.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
builder = base.builder


def shadow(**changes):
    return base.inbound(native_awdl_reply_shadow=True, **changes)


class ReplyShadowBuildIsolation(unittest.TestCase):
    def test_cannot_bypass_existing_rx_profile_requirements(self):
        self.assertEqual(builder.receive149_profile_errors(shadow()), [])
        for flag in ('native_awdl_rx149_data_input', 'native_awdl_rx149_observation_only',
                     'native_awdl_resident_data', 'p2p_probe', 'p2p_manual_trigger'):
            with self.subTest(flag=flag):
                self.assertTrue(builder.receive149_profile_errors(shadow(**{flag: False})))

    def test_legacy_transmit_profiles_remain_incompatible(self):
        for flag in ('p2p_tx_probe', 'p2p_roc_probe', 'native_awdl_tx_evidence',
                     'native_awdl_discovery_experiment', 'p2p_awdl_mif_followup'):
            with self.subTest(flag=flag):
                self.assertTrue(builder.receive149_profile_errors(shadow(**{flag: True})))

    def test_compiling_shadow_keeps_rx_only_and_does_not_enable_runtime(self):
        flags = builder.resident_build_flags(shadow())
        self.assertIn('-DITL_NATIVE_AWDL_REPLY_SHADOW_25G332=1', flags)
        self.assertIn('-DITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332=1', flags)
        profile = {'NativeAwdlReplyShadowEnabled': True, 'NativeP2PTxProbe': True}
        builder.apply_artifact_profile(profile, shadow())
        self.assertTrue(profile['NativeAwdlReplyShadowCompiled'])
        self.assertFalse(profile['NativeAwdlReplyShadowEnabled'])
        self.assertFalse(profile['NativeP2PTxProbe'])
        self.assertFalse(profile['NativeAwdlTxEvidenceEnabled'])
        self.assertFalse(profile['NativeAwdlDiscoveryExperimentEnabled'])

    def test_normal_and_existing_rx_builds_clear_stale_shadow_flags(self):
        for args in (base.base.args(), base.inbound()):
            profile = {'NativeAwdlReplyShadowCompiled': True,
                       'NativeAwdlReplyShadowEnabled': True}
            builder.apply_artifact_profile(profile, args)
            self.assertFalse(profile['NativeAwdlReplyShadowCompiled'])
            self.assertFalse(profile['NativeAwdlReplyShadowEnabled'])
            self.assertNotIn('ITL_NATIVE_AWDL_REPLY_SHADOW_',
                             builder.resident_build_flags(args))


if __name__ == '__main__':
    unittest.main()
