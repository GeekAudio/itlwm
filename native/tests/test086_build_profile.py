#!/usr/bin/env python3
"""Check that the inbound-data artifact cannot acquire a host TX profile."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('base_profile', ROOT/'native/tests/test080_build_profile.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
builder = base.builder


def inbound(**changes):
    args = base.receive()
    args.native_awdl_rx149_data_input = True
    for key, value in changes.items():
        setattr(args, key, value)
    return args


class InboundProfileIsolation(unittest.TestCase):
    def test_requires_the_isolated_manual_resident_receive_profile(self):
        self.assertEqual(builder.receive149_profile_errors(inbound()), [])
        for key in ('p2p_probe', 'p2p_manual_trigger', 'native_awdl_resident_data',
                    'native_awdl_rx149_observation_only'):
            with self.subTest(key=key):
                self.assertTrue(builder.receive149_profile_errors(inbound(**{key: False})))

    def test_cannot_mix_any_legacy_send_or_discovery_mode(self):
        for key in ('p2p_roc_probe', 'p2p_tx_probe', 'p2p_awdl_psf_observation_only',
                    'p2p_awdl_mif_followup', 'p2p_gp2_observation',
                    'native_awdl_init_observation_only', 'native_awdl_lifecycle_observation_only',
                    'native_awdl_tx_evidence', 'native_awdl_discovery_experiment',
                    'native_awdl_discovery_mif_current_slot',
                    'native_awdl_discovery_current_aw_fallback'):
            with self.subTest(key=key):
                self.assertTrue(builder.receive149_profile_errors(inbound(**{key: True})))

    def test_compile_capability_requires_its_own_flag(self):
        macro = 'ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332=1'
        self.assertIn(macro, builder.resident_build_flags(inbound()))
        self.assertNotIn(macro, builder.resident_build_flags(base.receive()))
        self.assertNotIn(macro, builder.resident_build_flags(base.args()))

    def test_signed_profile_does_not_inherit_host_tx(self):
        profile = {key: True for key in ('NativeP2PTxProbe', 'NativeP2PRocProbe',
            'NativeP2PAwdlPsfObservationOnly', 'NativeP2PAwdlMifFollowup',
            'NativeP2PGp2Observation', 'NativeAwdlTxEvidenceEnabled',
            'NativeAwdlDiscoveryExperimentEnabled')}
        builder.apply_artifact_profile(profile, inbound())
        self.assertTrue(profile['NativeP2PRx149DataInputExperiment'])
        self.assertTrue(profile['NativeP2PRx149ObservationOnly'])
        self.assertTrue(profile['NativeAwdlResidentEnabled'])
        self.assertTrue(profile['NativeP2PManualTrigger'])
        for key in ('NativeP2PTxProbe', 'NativeP2PRocProbe',
                    'NativeP2PAwdlPsfObservationOnly', 'NativeP2PAwdlMifFollowup',
                    'NativeP2PGp2Observation', 'NativeAwdlTxEvidenceEnabled',
                    'NativeAwdlDiscoveryExperimentEnabled'):
            self.assertFalse(profile[key], key)

    def test_normal_and_old_receive_artifacts_clear_stale_data_capability(self):
        for args in (base.args(), base.receive()):
            profile = {'NativeP2PRx149DataInputExperiment': True}
            builder.apply_artifact_profile(profile, args)
            self.assertIs(profile['NativeP2PRx149DataInputExperiment'], False)


if __name__ == '__main__':
    unittest.main()
