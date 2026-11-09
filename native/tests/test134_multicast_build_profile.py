#!/usr/bin/env python3
"""Ensure a no-doorbell admission artifact cannot silently enable RF profiles."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('base_profile', ROOT/'native/tests/test080_build_profile.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
builder = base.builder


def admission(**changes):
    values = dict(p2p_tx_probe=True, p2p_manual_trigger=True,
                  native_awdl_resident_data=True, native_awdl_multicast_admission=True)
    values.update(changes)
    return base.args(**values)


class MulticastAdmissionProfile(unittest.TestCase):
    def test_requires_manual_resident_control(self):
        self.assertEqual(builder.receive149_profile_errors(admission()), [])
        for flag in ('p2p_tx_probe', 'p2p_manual_trigger', 'native_awdl_resident_data'):
            with self.subTest(flag=flag):
                self.assertTrue(builder.receive149_profile_errors(admission(**{flag: False})))

    def test_cannot_mix_with_frame_paths(self):
        for flag in ('p2p_awdl_psf_observation_only', 'p2p_awdl_mif_followup',
                     'p2p_gp2_observation', 'native_awdl_tx_evidence',
                     'native_awdl_discovery_experiment', 'native_awdl_discovery_mif_current_slot',
                     'native_awdl_discovery_current_aw_fallback', 'native_awdl_discovery_rx_input',
                     'native_awdl_rx149_observation_only', 'native_awdl_rx149_data_input',
                     'native_rx_preowner_observation', 'native_awdl_reply_shadow',
                     'native_awdl_directed_prepare', 'native_awdl_directed_data_tx',
                     'native_awdl_init_observation_only', 'native_awdl_lifecycle_observation_only'):
            with self.subTest(flag=flag):
                self.assertTrue(builder.receive149_profile_errors(admission(**{flag: True})))

    def test_switch_is_explicit_and_cleared_in_other_artifacts(self):
        profile = {'NativeP2PMulticastAdmissionEnabled': True}
        builder.apply_artifact_profile(profile, base.args())
        self.assertFalse(profile['NativeP2PMulticastAdmissionEnabled'])
        builder.apply_artifact_profile(profile, admission())
        self.assertTrue(profile['NativeP2PMulticastAdmissionEnabled'])
        self.assertTrue(profile['NativeP2PManualTrigger'])
        for flag in ('NativeP2PAwdlPsfObservationOnly', 'NativeP2PAwdlMifFollowup',
                     'NativeP2PDirectedDataEnabled', 'NativeAwdlDiscoveryExperimentEnabled',
                     'NativeAwdlDiscoveryRxInputEnabled', 'NativeP2PRx149DataInputExperiment'):
            self.assertFalse(profile[flag])
        flags = builder.resident_build_flags(admission())
        self.assertIn('ITL_NATIVE_AWDL_MULTICAST_ADMISSION_25G332=1', flags)
        self.assertNotIn('DIRECTED_DATA_TX', flags)
        self.assertNotIn('DISCOVERY_EXPERIMENT', flags)
        self.assertNotIn('TX_EVIDENCE', flags)


if __name__ == '__main__':
    unittest.main()
