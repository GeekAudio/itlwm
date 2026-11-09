#!/usr/bin/env python3
"""Prevent an A artifact or incompatible profile from silently enabling B."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('base_profile', ROOT/'native/tests/test080_build_profile.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
builder = base.builder


class QmPriorityProfile(unittest.TestCase):
    def test_default_a_does_not_inherit_b(self):
        profile = {'NativeAwdlQmNormalPriorityCompiled': True}
        args = base.discovery_rx()
        self.assertEqual(builder.receive149_profile_errors(args), [])
        builder.apply_artifact_profile(profile, args)
        self.assertFalse(profile['NativeAwdlQmNormalPriorityCompiled'])
        self.assertTrue(profile['NativeAwdlDiscoveryRxInputEnabled'])
        self.assertTrue(profile['NativeP2PManualTrigger'])
        self.assertNotIn('QM_NORMAL_PRIORITY', builder.resident_build_flags(args))

    def test_b_is_explicit_and_scoped(self):
        args = base.discovery_rx()
        args.native_awdl_qm_normal_priority = True
        self.assertEqual(builder.receive149_profile_errors(args), [])
        profile = {}
        builder.apply_artifact_profile(profile, args)
        self.assertTrue(profile['NativeAwdlQmNormalPriorityCompiled'])
        self.assertIn('ITL_NATIVE_AWDL_QM_NORMAL_PRIORITY_25G332=1', builder.resident_build_flags(args))
        for name in ('native_awdl_resident_data', 'native_awdl_discovery_experiment',
                     'native_awdl_tx_evidence', 'p2p_manual_trigger'):
            with self.subTest(missing=name):
                setattr(args, name, False)
                self.assertTrue(builder.receive149_profile_errors(args))
                setattr(args, name, True)
        for name in ('native_awdl_rx149_observation_only', 'native_awdl_rx149_data_input',
                     'native_awdl_directed_prepare', 'native_awdl_directed_data_tx',
                     'native_awdl_reply_shadow', 'native_awdl_multicast_admission'):
            with self.subTest(excluded=name):
                setattr(args, name, True)
                self.assertTrue(builder.receive149_profile_errors(args))
                setattr(args, name, False)


if __name__ == '__main__':
    unittest.main()
