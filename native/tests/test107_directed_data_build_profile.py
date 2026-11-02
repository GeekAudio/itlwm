#!/usr/bin/env python3
"""Check the opt-in data TX profile's exclusion of normal and legacy paths."""
import importlib.util
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('prepare_profile', ROOT/'native/tests/test105_directed_prepare_build_profile.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
builder = p.builder

def candidate(**changes):
    args = p.directed(native_awdl_directed_data_tx=True)
    for name, value in changes.items(): setattr(args, name, value)
    return args

class DataProfile(unittest.TestCase):
    def test_all_prerequisites(self):
        self.assertEqual(builder.receive149_profile_errors(candidate()), [])
        for name in ('native_awdl_directed_prepare', 'native_awdl_rx149_data_input',
                     'native_awdl_rx149_observation_only', 'native_awdl_resident_data',
                     'p2p_probe', 'p2p_manual_trigger'):
            with self.subTest(name=name):
                self.assertTrue(builder.receive149_profile_errors(candidate(**{name: False})))
    def test_legacy_paths_excluded(self):
        for name in ('p2p_roc_probe','p2p_tx_probe','p2p_awdl_psf_observation_only',
                     'p2p_awdl_mif_followup','native_awdl_tx_evidence',
                     'native_awdl_discovery_experiment','native_awdl_reply_shadow'):
            with self.subTest(name=name):
                self.assertTrue(builder.receive149_profile_errors(candidate(**{name: True})))
    def test_default_off_and_explicit_enable(self):
        for args in (p.base.base.args(), p.base.base.receive(), p.base.inbound(), p.directed()):
            profile={'NativeP2PDirectedDataCompiled': True, 'NativeP2PDirectedDataEnabled': True}
            builder.apply_artifact_profile(profile,args)
            self.assertFalse(profile['NativeP2PDirectedDataCompiled'])
            self.assertFalse(profile['NativeP2PDirectedDataEnabled'])
            self.assertNotIn('-DITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332=1',builder.resident_build_flags(args))
        profile={};builder.apply_artifact_profile(profile,candidate())
        self.assertTrue(profile['NativeP2PDirectedDataCompiled'])
        self.assertTrue(profile['NativeP2PDirectedDataEnabled'])
        self.assertTrue(profile['NativeP2PManualTrigger'])
        self.assertFalse(profile['NativeP2PTxProbe'])
        self.assertFalse(profile['NativeAwdlDiscoveryExperimentEnabled'])
        self.assertIn('-DITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332=1',builder.resident_build_flags(candidate()))

if __name__=='__main__': unittest.main()
