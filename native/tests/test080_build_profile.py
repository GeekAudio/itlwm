#!/usr/bin/env python3
"""Artifact isolation tests; no build, code signing or system operation."""
import argparse
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('tahoe_builder', ROOT/'scripts/build_tahoe.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
FIELDS = ('p2p_probe p2p_roc_probe p2p_tx_probe p2p_manual_trigger '
          'p2p_awdl_psf_observation_only p2p_awdl_mif_followup p2p_gp2_observation '
          'native_awdl_init_observation_only native_awdl_lifecycle_observation_only '
          'native_awdl_resident_data native_awdl_tx_evidence native_awdl_discovery_experiment '
          'native_awdl_discovery_mif_current_slot native_awdl_discovery_current_aw_fallback '
          'native_awdl_discovery_rx_input native_awdl_rx149_observation_only '
          'native_awdl_rx149_data_input').split()

def args(**changes):
    values = dict.fromkeys(FIELDS, False)
    values.update(changes)
    return argparse.Namespace(**values)

def receive():
    return args(p2p_probe=True, p2p_manual_trigger=True, native_awdl_resident_data=True,
                native_awdl_rx149_observation_only=True)

def discovery_rx():
    return args(p2p_probe=True, p2p_tx_probe=True, p2p_manual_trigger=True,
                p2p_awdl_psf_observation_only=True,
                p2p_awdl_mif_followup=True, p2p_gp2_observation=True,
                native_awdl_resident_data=True, native_awdl_tx_evidence=True,
                native_awdl_discovery_experiment=True,
                native_awdl_discovery_mif_current_slot=True,
                native_awdl_discovery_rx_input=True)

class ProfileIsolation(unittest.TestCase):
    def test_rx_cannot_inherit_old_signed_tx_switches(self):
        profile = dict.fromkeys(('NativeP2PRocProbe', 'NativeP2PTxProbe',
            'NativeP2PAwdlPsfObservationOnly', 'NativeP2PAwdlMifFollowup',
            'NativeP2PGp2Observation', 'NativeAwdlTxEvidenceEnabled',
            'NativeAwdlDiscoveryExperimentEnabled'), True)
        builder.apply_artifact_profile(profile, receive())
        self.assertTrue(profile['NativeP2PRx149ObservationOnly'])
        self.assertTrue(profile['NativeP2PManualTrigger'])
        self.assertTrue(profile['NativeAwdlResidentEnabled'])
        self.assertFalse(any(value for key,value in profile.items()
            if key not in ('NativeP2PRx149ObservationOnly','NativeP2PManualTrigger',
                           'NativeP2PProbe','NativeAwdlResidentEnabled')))

    def test_incompatible_cli_combinations_fail_before_build(self):
        self.assertEqual(builder.receive149_profile_errors(receive()), [])
        for name in FIELDS:
            if name in ('p2p_probe','p2p_manual_trigger','native_awdl_resident_data',
                        'native_awdl_rx149_observation_only',
                        'native_awdl_rx149_data_input'):
                continue
            bad = receive()
            setattr(bad, name, True)
            with self.subTest(name=name):
                self.assertTrue(builder.receive149_profile_errors(bad))
        for name in ('p2p_probe','p2p_manual_trigger','native_awdl_resident_data'):
            bad = receive()
            setattr(bad, name, False)
            self.assertTrue(builder.receive149_profile_errors(bad))

    def test_plain_artifact_disables_receive_and_legacy_probes(self):
        profile = {'NativeP2PRx149ObservationOnly': True, 'NativeP2PTxProbe': True}
        builder.apply_artifact_profile(profile, args())
        self.assertFalse(any(profile.values()))

    def test_legacy_compilation_does_not_gain_receive_permission(self):
        legacy = args(native_awdl_resident_data=True, native_awdl_tx_evidence=True,
                      native_awdl_discovery_experiment=True)
        self.assertNotIn('ITL_NATIVE_AWDL_RX149', builder.resident_build_flags(legacy))
        self.assertIn('ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332=1',
                      builder.resident_build_flags(receive()))

    def test_discovery_rx_requires_manual_resident_mif_profile_and_excludes_rx149(self):
        self.assertEqual(builder.receive149_profile_errors(discovery_rx()), [])
        for name in ('p2p_manual_trigger', 'native_awdl_resident_data',
                     'native_awdl_discovery_experiment',
                     'native_awdl_discovery_mif_current_slot'):
            bad = discovery_rx()
            setattr(bad, name, False)
            with self.subTest(name=name):
                self.assertTrue(builder.receive149_profile_errors(bad))

        for name in ('native_awdl_rx149_observation_only',
                     'native_awdl_rx149_data_input'):
            bad = discovery_rx()
            setattr(bad, name, True)
            with self.subTest(name=name):
                self.assertTrue(builder.receive149_profile_errors(bad))

    def test_discovery_rx_macro_and_artifact_switch_are_opt_in_and_separate(self):
        args_value = discovery_rx()
        flags = builder.resident_build_flags(args_value)
        self.assertIn('-DITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332=1', flags)
        self.assertNotIn('ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332', flags)
        self.assertNotIn('ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332', flags)

        profile = {
            'NativeP2PRx149ObservationOnly': True,
            'NativeP2PRx149DataInputExperiment': True,
        }
        builder.apply_artifact_profile(profile, args_value)
        self.assertTrue(profile['NativeAwdlDiscoveryRxInputEnabled'])
        self.assertTrue(profile['NativeAwdlDiscoveryExperimentEnabled'])
        self.assertTrue(profile['NativeAwdlDiscoveryMifCurrentSlotEnabled'])
        self.assertTrue(profile['NativeAwdlResidentEnabled'])
        self.assertTrue(profile['NativeP2PManualTrigger'])
        self.assertFalse(profile['NativeP2PRx149ObservationOnly'])
        self.assertFalse(profile['NativeP2PRx149DataInputExperiment'])

        for args_value in (args(), receive()):
            profile = {
                'NativeAwdlDiscoveryRxInputEnabled': True,
                'NativeAwdlDiscoveryMifCurrentSlotEnabled': True,
            }
            builder.apply_artifact_profile(profile, args_value)
            self.assertFalse(profile['NativeAwdlDiscoveryRxInputEnabled'])
            self.assertFalse(profile['NativeAwdlDiscoveryMifCurrentSlotEnabled'])
            self.assertNotIn('ITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332',
                             builder.resident_build_flags(args_value))

    def test_syntax_profile_is_separate_from_rx149(self):
        verify_spec = importlib.util.spec_from_file_location(
            'tahoe_compile_profiles', ROOT/'scripts/verify_tahoe_compile_profiles.py')
        verify_profiles = importlib.util.module_from_spec(verify_spec)
        verify_spec.loader.exec_module(verify_profiles)
        self.assertEqual(verify_profiles.PROFILES['discovery_rx_input'],
            ('LIFECYCLE', 'RESIDENT', 'TX_EVIDENCE', 'DISCOVERY_EXPERIMENT',
             'DISCOVERY_RX_INPUT'))
        self.assertFalse(any('RX149' in name
                             for name in verify_profiles.PROFILES['discovery_rx_input']))

if __name__ == '__main__': unittest.main()
