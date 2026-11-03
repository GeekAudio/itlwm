"""Offline protocol and real-C nonce checks; never opens a network socket."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import listener_protocol_test123 as listener

CODEC_PATH = HERE.parent / "test122/router-status/packetset_correlated_test122.py"
spec = importlib.util.spec_from_file_location("test123_listener_packetset", CODEC_PATH)
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)

TOKEN = "0123456789abcdef0123456789abcdef"
NONCE = "01000203feff0405"  # embedded NUL and non-ASCII bytes must be compared in full


def fixture():
    _, manifest = codec.encode_packet_set(
        {"mac": "02:11:22:33:44:55", "ipv6_link_local": "fe80::1122"},
        {"mac": "02:aa:bb:cc:dd:ee", "ipv6_link_local": "fe80::aabb"},
        "listener-offline", wire_nonce_hex=NONCE,
        wifi_sequence_base=4094, awdl_sequence_base=65534)
    return listener.expected_binding(manifest, 31), manifest


def ready(binding):
    return dict(
        event="LISTENER_READY", schema=listener.SCHEMA,
        interface="awdl0", ifindex=31, family=6, port=49153, source_port=49152,
        hop_limit=1, payload=NONCE, payload_encoding="hex", wire_nonce_hex=NONCE,
        timeout_ms=15000, bound_if=True, destination_assigned=True,
        pktinfo_enabled=True, hoplimit_enabled=True, recv_anyif_requested=True,
        recv_anyif_set=True, recv_anyif_errno=0,
        source_identity_tag_fnv1a64=binding["source_identity_tag_fnv1a64"],
        destination_identity_tag_fnv1a64=binding["destination_identity_tag_fnv1a64"],
        peer_address_serialized=False, run_token=TOKEN, tool_test="Test123",
        running_kernel_test="Test122", clock_domain="CLOCK_MONOTONIC",
        clock_host="mac", ready_ns=1000)


def received(binding, **changes):
    value = dict(
        event="LISTENER_RESULT", schema=listener.SCHEMA, status="marker_received",
        interface="awdl0", ifindex=31, datagrams=1, marker_match=True,
        source_address_match=True, destination_address_match=True,
        source_port_match=True, destination_port_match=True,
        hop_limit_present=True, hop_limit_match=True, pktinfo_present=True,
        pktinfo_ifindex_match=True, payload_length=8, payload_match=True,
        payload_truncated=False, control_truncated=False,
        wrong_source_datagrams=0, wrong_destination_datagrams=0,
        other_unmatched_datagrams=0, receive_error=0,
        source_identity_tag_fnv1a64=binding["source_identity_tag_fnv1a64"],
        destination_identity_tag_fnv1a64=binding["destination_identity_tag_fnv1a64"],
        peer_address_serialized=False, recv_anyif_requested=True,
        recv_anyif_set=True, recv_anyif_errno=0, run_token=TOKEN,
        wire_nonce_hex=NONCE, received_payload_hex=NONCE, payload_encoding="hex",
        distinct_ordinals_proven=False, tool_test="Test123",
        running_kernel_test="Test122", clock_domain="CLOCK_MONOTONIC",
        clock_host="mac", time_semantics="userspace_recvmsg_return",
        ready_ns=1000, observed_ns=2000, finished_ns=3000)
    value.update(changes)
    return value


class ListenerTests(unittest.TestCase):
    def setUp(self):
        self.binding, self.manifest = fixture()
        event = listener.parse_ready(json.dumps(ready(self.binding)),
                                     run_token=TOKEN, expected=self.binding)
        self.binding["ready_ns"] = event["ready_ns"]

    def parse(self, value):
        return listener.parse_result(json.dumps(value), run_token=TOKEN,
                                     expected=self.binding)

    def test_v2_packetset_nonce_reaches_expected_binding_and_argv(self):
        args = listener.listener_argv("/fixture/listener", run_token=TOKEN,
                                      expected=self.binding)
        self.assertEqual(args[1:3], ["--listen-nonce", NONCE])
        self.assertNotIn("T086RX01", args)
        self.assertEqual(self.binding["payload"], NONCE)
        self.assertTrue(self.parse(received(self.binding))["marker_match"])

    def test_wrong_nonce_is_rejected_even_with_right_control_token(self):
        for field in ("wire_nonce_hex", "received_payload_hex"):
            value = received(self.binding)
            value[field] = "abcdef0123456789"
            with self.assertRaises(listener.ListenerProtocolError):
                self.parse(value)

    def test_legacy_marker_version_and_mixed_packetset_rejected(self):
        for replacement in (
            {"schema": "test104-runtime-packet-set/v1"},
            {"wire_nonce_hex": "0" * 16},
            {"packet_set_length": 528},
            {"frames": [{"ordinal": i, "payload_hex": "5430383652583031"}
                        for i in range(4)]}):
            value = dict(self.manifest)
            value.update(replacement)
            with self.assertRaises(listener.ListenerProtocolError):
                listener.expected_binding(value, 31)

    def test_nonce_does_not_override_identity_transport_or_truncation(self):
        for field, wrong in (
            ("ifindex", 32), ("hop_limit_match", False),
            ("source_port_match", False), ("destination_port_match", False),
            ("pktinfo_ifindex_match", False), ("payload_truncated", True),
            ("control_truncated", True), ("receive_error", 6),
            ("source_identity_tag_fnv1a64", listener.identity_tag("fe80::99"))):
            with self.subTest(field=field):
                with self.assertRaises(listener.ListenerProtocolError):
                    self.parse(received(self.binding, **{field: wrong}))

    def test_other_source_with_same_nonce_is_nonpositive(self):
        value = received(self.binding, status="timeout_or_unmatched",
                         marker_match=False, source_address_match=False,
                         wrong_source_datagrams=1,
                         source_identity_tag_fnv1a64=listener.identity_tag("fe80::99"))
        self.assertFalse(self.parse(value)["marker_match"])

    def test_repeat_payloads_never_prove_distinct_ordinals(self):
        value = self.parse(received(self.binding, datagrams=4))
        self.assertFalse(value["distinct_ordinals_proven"])
        with self.assertRaises(listener.ListenerProtocolError):
            self.parse(received(self.binding, distinct_ordinals_proven=True))

    def test_listener_instance_clock_and_types_bound(self):
        for replacement in (
            {"ready_ns": 999}, {"ready_ns": True}, {"observed_ns": 0},
            {"observed_ns": 999}, {"finished_ns": 1999},
            {"clock_host": "router"}, {"clock_domain": "mach_absolute_time"},
            {"finished_ns": 20_000_001_000}):
            with self.subTest(replacement=replacement):
                with self.assertRaises(listener.ListenerProtocolError):
                    self.parse(received(self.binding, **replacement))
        no_ready = dict(self.binding)
        no_ready.pop("ready_ns")
        with self.assertRaises(listener.ListenerProtocolError):
            listener.parse_result(json.dumps(received(self.binding)),
                                  run_token=TOKEN, expected=no_ready)

    def test_no_datagram_keeps_payload_unknown(self):
        value = received(self.binding, status="timeout_or_unmatched",
                         datagrams=0, observed_ns=0, marker_match=False,
                         source_address_match=False, destination_address_match=False,
                         source_port_match=False, destination_port_match=False,
                         hop_limit_present=False, hop_limit_match=False,
                         pktinfo_present=False, pktinfo_ifindex_match=False,
                         payload_length=0, payload_match=False,
                         source_identity_tag_fnv1a64=None,
                         destination_identity_tag_fnv1a64=None,
                         received_payload_hex=None)
        self.assertFalse(self.parse(value)["marker_match"])

    def test_duplicate_json_field_rejected(self):
        line = json.dumps(received(self.binding))
        line = line[:-1] + ',"wire_nonce_hex":"' + NONCE + '"}'
        with self.assertRaises(listener.ListenerProtocolError):
            listener.parse_result(line, run_token=TOKEN, expected=self.binding)

    def test_real_c_nonce_bytes_and_output_contract_without_sockets(self):
        source = HERE / "awdl0_unicast_listener_test123.c"
        with tempfile.TemporaryDirectory(prefix="test123-listener-host-") as td:
            harness = Path(td) / "harness.c"
            binary = Path(td) / "harness"
            harness.write_text(
                '#define main unused_listener_entry\n#include "' + str(source) +
                '"\n#undef main\n#include <assert.h>\nint main(void) {\n'
                'assert(!parse_nonce("0000000000000000"));\n'
                'assert(!parse_nonce("01000203FEFF0405"));\n'
                'assert(!parse_nonce("T086RX01"));\n'
                'assert(parse_nonce("' + NONCE + '"));\n'
                'unsigned char good[8]={1,0,2,3,254,255,4,5};\n'
                'assert(payload_matches_nonce(good,8,0));\n'
                'assert(!payload_matches_nonce(good,7,0));\n'
                'assert(!payload_matches_nonce(good,8,1));\n'
                'unsigned char bad[8]={1,0,2,3,254,255,4,6};\n'
                'assert(!payload_matches_nonce(bad,8,0));\n'
                'memcpy(run_token,"' + TOKEN + '",33);\n'
                'recv_anyif_requested=1; recv_anyif_set=1; ready_ns=1000;\n'
                'emit_ready(31,"' + self.binding["source_identity_tag_fnv1a64"] +
                '","' + self.binding["destination_identity_tag_fnv1a64"] + '");\n'
                'remember_payload(good,8,0); observed_ns=2000; finished_ns=3000;\n'
                'emit_result(31,1,1,1,1,1,1,1,1,1,1,8,1,0,0,0,0,0,0,"' +
                self.binding["source_identity_tag_fnv1a64"] + '","' +
                self.binding["destination_identity_tag_fnv1a64"] + '"); return 0;}\n')
            subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            str(harness), "-o", str(binary)], check=True,
                           capture_output=True, text=True)
            run = subprocess.run([str(binary)], check=True, capture_output=True,
                                 text=True, timeout=5)
            lines = run.stdout.splitlines()
            self.assertEqual(len(lines), 2)
            parsed = listener.parse_ready(lines[0], run_token=TOKEN,
                                           expected=self.binding)
            self.binding["ready_ns"] = parsed["ready_ns"]
            result = listener.parse_result(lines[1], run_token=TOKEN,
                                            expected=self.binding)
            self.assertEqual(result["received_payload_hex"], NONCE)
            self.assertTrue(result["marker_match"])
            self.assertFalse(result["distinct_ordinals_proven"])


if __name__ == "__main__":
    unittest.main()
