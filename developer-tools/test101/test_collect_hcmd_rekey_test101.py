import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).with_name("collect_hcmd_rekey_test101.py")
SPEC = importlib.util.spec_from_file_location("collect_hcmd_rekey_test101", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TestHcmdRekeySidecar(unittest.TestCase):
    def test_event_serials_include_ring_and_latest_slot(self):
        decoded = {
            "add_sta_key_status_events": [{"serial": 7}, {"serial": 8}],
            "key_response_slot": {"event": {"serial": 9}},
        }
        self.assertEqual(MODULE._event_serials(decoded), {7, 8, 9})

    def test_event_serials_ignore_missing_and_invalid_values(self):
        decoded = {
            "add_sta_key_status_events": [{"serial": 0}, {"serial": "9"}, None],
            "key_response_slot": {"event": {"serial": None}},
        }
        self.assertEqual(MODULE._event_serials(decoded), set())

    def test_selected_decode_keeps_status_not_claims(self):
        selected = MODULE._selected_decode({"decoded": {
            "schema": "test101-hcmd-rx-observation/v1",
            "status": "stable_complete_cut",
            "snapshot_stable": True,
            "snapshot_complete": True,
            "publish_revision": 4,
            "header": {"version_begin": 2, "version_end": 2, "stable": 1,
                       "complete": 1, "row_count": 0},
            "key_response_slot": {"status": "latest_target_event", "event": {
                "serial": 9, "firmware_status_state": "raw_status_present",
                "firmware_status_raw_le32": 0,
                "status_interpreted_as_key_install_success": False,
                "peer_ack_proven": False,
            }},
            "add_sta_key_status_events": [],
            "key_install_success_proven": False,
            "peer_ack_proven": False,
            "wifi_stability_proven": False,
        }})
        self.assertEqual(selected["key_response_slot"]["event"]["firmware_status_raw_le32"], 0)
        self.assertFalse(selected["key_install_success_proven"])
        self.assertFalse(selected["peer_ack_proven"])
        self.assertFalse(selected["wifi_stability_proven"])
        self.assertNotIn("rows", selected)
        self.assertNotIn("blob", selected)


if __name__ == "__main__":
    unittest.main()
