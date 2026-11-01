#!/usr/bin/env python3
"""Keep the directed prepare candidate isolated and administrator-armed."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    'directed_prepare_base_profile', ROOT / 'native/tests/test086_build_profile.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
builder = base.builder


def directed(**changes):
    args = base.inbound(native_awdl_directed_prepare=True, **changes)
    return args


class DirectedPrepareBuildIsolation(unittest.TestCase):
    def test_requires_the_manual_resident_rx149_data_input_profile(self):
        self.assertEqual(builder.receive149_profile_errors(directed()), [])
        for key in ('native_awdl_rx149_data_input',
                    'native_awdl_rx149_observation_only',
                    'native_awdl_resident_data', 'p2p_probe',
                    'p2p_manual_trigger'):
            with self.subTest(key=key):
                self.assertTrue(builder.receive149_profile_errors(
                    directed(**{key: False})))

    def test_cannot_mix_legacy_transmit_or_discovery_profiles(self):
        for key in ('p2p_roc_probe', 'p2p_tx_probe',
                    'p2p_awdl_psf_observation_only',
                    'p2p_awdl_mif_followup', 'p2p_gp2_observation',
                    'native_awdl_tx_evidence',
                    'native_awdl_discovery_experiment',
                    'native_awdl_discovery_mif_current_slot',
                    'native_awdl_discovery_current_aw_fallback'):
            with self.subTest(key=key):
                self.assertTrue(builder.receive149_profile_errors(
                    directed(**{key: True})))

    def test_macro_and_artifact_profile_are_explicit(self):
        flags = builder.resident_build_flags(directed())
        self.assertIn('-DITL_NATIVE_AWDL_DIRECTED_PREPARE_25G332=1', flags)
        self.assertIn('-DITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332=1', flags)
        self.assertIn('-DITL_NATIVE_AWDL_RX149_OBSERVATION_25G332=1', flags)

        profile = {
            'NativeP2PDirectedPrepareEnabled': False,
            'NativeP2PDirectedPrepareCompiled': False,
            'NativeP2PTxProbe': True,
            'NativeAwdlTxEvidenceEnabled': True,
            'NativeAwdlDiscoveryExperimentEnabled': True,
        }
        builder.apply_artifact_profile(profile, directed())
        self.assertTrue(profile['NativeP2PDirectedPrepareCompiled'])
        self.assertTrue(profile['NativeP2PDirectedPrepareEnabled'])
        self.assertTrue(profile['NativeP2PRx149DataInputExperiment'])
        self.assertTrue(profile['NativeP2PRx149ObservationOnly'])
        self.assertTrue(profile['NativeP2PManualTrigger'])
        for key in ('NativeP2PTxProbe', 'NativeAwdlTxEvidenceEnabled',
                    'NativeAwdlDiscoveryExperimentEnabled'):
            self.assertFalse(profile[key], key)

    def test_non_candidate_builds_clear_stale_profile_properties(self):
        for args in (base.base.args(), base.base.receive(), base.inbound()):
            profile = {
                'NativeP2PDirectedPrepareEnabled': True,
                'NativeP2PDirectedPrepareCompiled': True,
            }
            builder.apply_artifact_profile(profile, args)
            self.assertFalse(profile['NativeP2PDirectedPrepareEnabled'])
            self.assertFalse(profile['NativeP2PDirectedPrepareCompiled'])
            self.assertNotIn('ITL_NATIVE_AWDL_DIRECTED_PREPARE_25G332=1',
                             builder.resident_build_flags(args))


if __name__ == '__main__':
    unittest.main()
