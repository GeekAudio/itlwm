#!/usr/bin/env python3
"""Offline strict-contract tests for the Test103 unicast listener protocol."""
from __future__ import annotations

import json
import unittest

import listener_protocol_test103 as listener


RUN_TOKEN = "0123456789abcdef0123456789abcdef"


def fixture_binding():
    return listener.expected_binding({
        "identities": {
            "source": {"ipv6_link_local": "fe80::1122"},
            "destination_awdl0": {"ipv6_link_local": "fe80::aabb"},
        }
    }, 31)


def ready(binding):
    return {
        "event": "LISTENER_READY", "schema": listener.SCHEMA,
        "interface": "awdl0", "ifindex": binding["ifindex"], "family": 6,
        "port": listener.PORT, "source_port": listener.SOURCE_PORT,
        "hop_limit": listener.HOP_LIMIT, "payload": listener.MARKER,
        "timeout_ms": listener.TIMEOUT_MS, "bound_if": True,
        "destination_assigned": True, "pktinfo_enabled": True,
        "hoplimit_enabled": True, "recv_anyif_requested": True,
        "recv_anyif_set": True, "recv_anyif_errno": 0,
        "source_identity_tag_fnv1a64": binding["source_identity_tag_fnv1a64"],
        "destination_identity_tag_fnv1a64": binding["destination_identity_tag_fnv1a64"],
        "peer_address_serialized": False, "run_token": RUN_TOKEN,
    }


def result(binding, *, source_tag=None, destination_tag=None, **overrides):
    if source_tag is None:
        source_tag = binding["source_identity_tag_fnv1a64"]
    if destination_tag is None:
        destination_tag = binding["destination_identity_tag_fnv1a64"]
    value = {
        "event": "LISTENER_RESULT", "schema": listener.SCHEMA,
        "status": "marker_received", "interface": "awdl0",
        "ifindex": binding["ifindex"], "datagrams": 1,
        "marker_match": True, "source_address_match": True,
        "destination_address_match": True, "source_port_match": True,
        "destination_port_match": True, "hop_limit_present": True,
        "hop_limit_match": True, "pktinfo_present": True,
        "pktinfo_ifindex_match": True, "payload_length": len(listener.MARKER),
        "payload_match": True, "payload_truncated": False,
        "control_truncated": False, "wrong_source_datagrams": 0,
        "wrong_destination_datagrams": 0, "other_unmatched_datagrams": 0,
        "receive_error": 0, "source_identity_tag_fnv1a64": source_tag,
        "destination_identity_tag_fnv1a64": destination_tag,
        "peer_address_serialized": False, "recv_anyif_requested": True,
        "recv_anyif_set": True, "recv_anyif_errno": 0, "run_token": RUN_TOKEN,
    }
    value.update(overrides)
    return value


class Test103ListenerProtocolTests(unittest.TestCase):
    def setUp(self):
        self.binding = fixture_binding()

    @staticmethod
    def line(value):
        return json.dumps(value, separators=(",", ":"))

    def test_ready_binds_same_dynamic_awdl_identity_and_ifindex(self):
        parsed = listener.parse_ready(self.line(ready(self.binding)),
                                      run_token=RUN_TOKEN, expected=self.binding)
        self.assertEqual(parsed["ifindex"], 31)
        self.assertFalse(parsed["peer_address_serialized"])

    def test_exact_unicast_source_destination_and_transport_is_positive(self):
        parsed = listener.parse_result(self.line(result(self.binding)),
                                       run_token=RUN_TOKEN, expected=self.binding)
        self.assertEqual(parsed["status"], "marker_received")
        self.assertTrue(parsed["source_address_match"])
        self.assertTrue(parsed["destination_address_match"])

    def test_wrong_source_is_never_a_positive_match(self):
        wrong_source = listener.identity_tag("fe80::9999")
        value = result(self.binding, source_tag=wrong_source,
                       status="timeout_or_unmatched", marker_match=False,
                       source_address_match=False, source_port_match=True,
                       wrong_source_datagrams=1)
        parsed = listener.parse_result(self.line(value), run_token=RUN_TOKEN,
                                       expected=self.binding)
        self.assertFalse(parsed["marker_match"])
        self.assertEqual(parsed["wrong_source_datagrams"], 1)

    def test_wrong_destination_including_legacy_multicast_is_never_positive(self):
        wrong_destination = listener.identity_tag("fe80::9998")
        value = result(self.binding, destination_tag=wrong_destination,
                       status="timeout_or_unmatched", marker_match=False,
                       destination_address_match=False,
                       wrong_destination_datagrams=1)
        parsed = listener.parse_result(self.line(value), run_token=RUN_TOKEN,
                                       expected=self.binding)
        self.assertFalse(parsed["marker_match"])
        self.assertEqual(parsed["wrong_destination_datagrams"], 1)
        legacy = result(self.binding)
        legacy["group"] = "ff02::1"
        with self.assertRaisesRegex(listener.ListenerProtocolError, "field_set_mismatch"):
            listener.parse_result(self.line(legacy), run_token=RUN_TOKEN,
                                  expected=self.binding)

    def test_rejects_wrong_ifindex_hoplimit_ports_and_truncation(self):
        wrong_ifindex = ready(self.binding)
        wrong_ifindex["ifindex"] = 32
        with self.assertRaisesRegex(listener.ListenerProtocolError, "ready_contract_mismatch"):
            listener.parse_ready(self.line(wrong_ifindex), run_token=RUN_TOKEN,
                                 expected=self.binding)
        for override in (
            {"hop_limit_match": False},
            {"source_port_match": False},
            {"payload_truncated": True},
            {"control_truncated": True},
        ):
            with self.assertRaisesRegex(listener.ListenerProtocolError,
                                        "positive_contract_mismatch"):
                listener.parse_result(self.line(result(self.binding, **override)),
                                      run_token=RUN_TOKEN, expected=self.binding)

    def test_rejects_flags_that_conflict_with_manifest_identity_tags(self):
        value = result(self.binding, source_address_match=False)
        with self.assertRaisesRegex(listener.ListenerProtocolError,
                                    "source_identity_conflict"):
            listener.parse_result(self.line(value), run_token=RUN_TOKEN,
                                  expected=self.binding)


if __name__ == "__main__":
    unittest.main()
