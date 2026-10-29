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
          'native_awdl_rx149_observation_only').split()

def args(**changes):
    values = dict.fromkeys(FIELDS, False)
    values.update(changes)
    return argparse.Namespace(**values)

def receive():
    return args(p2p_probe=True, p2p_manual_trigger=True, native_awdl_resident_data=True,
                native_awdl_rx149_observation_only=True)

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
                        'native_awdl_rx149_observation_only'):
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

if __name__ == '__main__': unittest.main()
