#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


TOOL_PATH = Path(__file__).with_name("router_status_tail_test122.py")
SPEC = importlib.util.spec_from_file_location("router_status_tail_test122_under_test", TOOL_PATH)
TOOL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TOOL
SPEC.loader.exec_module(TOOL)

TOKEN = "0123456789abcdef0123456789abcdef"
WIRE_NONCE = "a1b2c3d4e5f67890"
SOURCE = {"mac": "02:00:00:00:10:01", "ipv6_link_local": "fe80::1001"}
TARGET = {"mac": "02:00:00:00:20:02", "ipv6_link_local": "fe80::2002"}
PACKETSET = TOOL._load_packetset()


def packet_set(*, wire_nonce: str = WIRE_NONCE,
               wifi_sequence_base: int = 1,
               awdl_sequence_base: int = 10) -> bytes:
    value, _ = PACKETSET.encode_packet_set(
        SOURCE, TARGET, "offline-wrapper-test", wire_nonce_hex=wire_nonce,
        wifi_sequence_base=wifi_sequence_base,
        awdl_sequence_base=awdl_sequence_base)
    return value


def _frame(packetset: bytes, ordinal: int = 0) -> tuple[dict, bytes]:
    decoded = PACKETSET.decode_packet_set(packetset)
    row = decoded["frames"][ordinal]
    offset = PACKETSET.HEADER_LEN + ordinal * PACKETSET.PACKET_LEN
    packet = packetset[offset:offset + PACKETSET.PACKET_LEN]
    return row, packet[PACKETSET.RADIOTAP_LEN:]


def _status_radiotap(mpdu: bytes, *, tx_flags: int = 0, retries: int = 0) -> bytes:
    present = (1 << 15) | (1 << 17)  # TX_FLAGS and DATA_RETRIES
    header = (b"\x00\x00\x0b\x00" + struct.pack("<I", present) +
              struct.pack("<H", tx_flags) + bytes((retries,)))
    assert len(header) == 11
    return header + mpdu


def status_sample(packetset: bytes, *, ordinal: int = 0, tx_flags: int = 0,
                  retries: int = 0, observed_ns: int = 1_500_000_000,
                  mpdu: bytes | None = None) -> dict:
    row, expected_mpdu = _frame(packetset, ordinal)
    mpdu = expected_mpdu if mpdu is None else mpdu
    raw = _status_radiotap(mpdu, tx_flags=tx_flags, retries=retries)
    sequence_control = struct.unpack_from("<H", mpdu, 22)[0]
    return {
        "ordinal": ordinal,
        "packet_type": 3,
        "ifindex": 4,
        "msg_flags": 0,
        "received_len": len(raw),
        "bytes_retained": len(raw),
        "raw_prefix_truncated": False,
        "exact_match": mpdu == expected_mpdu,
        "has_tx_flags": True,
        "tx_flags": tx_flags,
        "has_data_retries": True,
        "data_retries": retries,
        "ieee80211_sequence": sequence_control >> 4,
        "ieee80211_sequence_control": sequence_control,
        "awdl_sequence": struct.unpack_from("<H", mpdu, 34)[0],
        "observed_ns": observed_ns,
        "raw_prefix_hex": raw.hex(),
    }


def nonmatch_sample(*, parse_status: str = "invalid",
                    observed_ns: int = 1_500_000_000,
                    raw: bytes = b"\x00\x00\xff\xffbad!",
                    packet_type_present: bool = True, packet_type: int | None = 3,
                    ifindex_present: bool = True, ifindex: int | None = 4) -> dict:
    return {
        "observed_ns": observed_ns,
        "parse_status": parse_status,
        "packet_type_present": packet_type_present,
        "packet_type": packet_type if packet_type_present else None,
        "ifindex_present": ifindex_present,
        "ifindex": ifindex if ifindex_present else None,
        "msg_flags": 0,
        "received_len": len(raw) + 8,
        "copied_len": len(raw),
        "raw_prefix_truncated": True,
        "raw_prefix_hex": raw.hex(),
    }


def monitor(*, kernel_stats: bool = True, truncated: int = 0,
            status_sample_row: dict | None = None,
            nonmatch_row: dict | None = None) -> dict:
    status_samples = [status_sample_row] if status_sample_row else []
    nonmatches = [nonmatch_row] if nonmatch_row else []
    sample_rows = []
    if status_sample_row:
        sample_rows.append({
            "exact_ordinal": status_sample_row["ordinal"],
            "packet_type_present": True, "packet_type": status_sample_row["packet_type"],
            "ifindex_present": True, "ifindex": status_sample_row["ifindex"],
            "msg_flags": status_sample_row["msg_flags"],
            "received_len": status_sample_row["received_len"],
            "copied_len": status_sample_row["bytes_retained"],
            "parse_supported": True, "exact_match": status_sample_row["exact_match"],
            "outgoing_echo": False, "host_driver_completion_candidate": True,
            "has_tx_flags": True, "tx_flags": status_sample_row["tx_flags"],
            "has_data_retries": True, "data_retries": status_sample_row["data_retries"],
            "ieee80211_sequence": status_sample_row["ieee80211_sequence"],
            "ieee80211_sequence_control": status_sample_row["ieee80211_sequence_control"],
            "awdl_sequence": status_sample_row["awdl_sequence"],
            "observed_ns": status_sample_row["observed_ns"],
        })
    packets = len(sample_rows) + len(nonmatches) + truncated
    exact_counts = [0, 0, 0, 0]
    non_outgoing_counts = [0, 0, 0, 0]
    status_counts = [0, 0, 0, 0]
    if status_sample_row:
        ordinal = status_sample_row["ordinal"]
        exact_counts[ordinal] += 1
        non_outgoing_counts[ordinal] += 1
        status_counts[ordinal] += 1
    return {
        "schema": TOOL.MONITOR_SCHEMA,
        "clock_domain": "CLOCK_MONOTONIC",
        "observation_time_semantics": "userspace_recvmsg_return",
        "started_ns": 1_000_000_000,
        "ended_ns": 3_040_000_000,
        "actual_horizon_ns": TOOL.CAPTURE_WINDOW_NS,
        "capture_window_ns": TOOL.CAPTURE_WINDOW_NS,
        "status_tail_began_ns": 1_040_000_000,
        "capture_finished": True,
        "capture_limit_reached": False,
        "read_attempts": packets,
        "packets_received": packets,
        "exact_samples_recorded": len(sample_rows),
        "exact_samples_overflow": 0,
        "receive_error": 0,
        "kernel_stats_available": kernel_stats,
        "kernel_packets": packets if kernel_stats else None,
        "kernel_dropped_packets": 0 if kernel_stats else None,
        "capture_loss_free": False if truncated else (True if kernel_stats else None),
        "classification_complete": not nonmatches and not truncated,
        "identity_complete": True,
        "radiotap_invalid": sum(1 for row in nonmatches if row["parse_status"] == "invalid"),
        "radiotap_unsupported": sum(1 for row in nonmatches if row["parse_status"] == "unsupported"),
        "unmatched_valid_packets": sum(1 for row in nonmatches if row["parse_status"] == "valid_unmatched"),
        "truncated_packets": truncated,
        "exact_identity_unavailable": 0,
        "socket_topology": "distinct_tx_and_observer",
        "observer_bound_ifindex": 4,
        "outgoing_tap_is_rf_proof": False,
        "exact_match_by_ordinal": exact_counts,
        "outgoing_exact_by_ordinal": [0, 0, 0, 0],
        "non_outgoing_exact_by_ordinal": non_outgoing_counts,
        "tx_status_candidate_by_ordinal": status_counts,
        "other_exact_by_ordinal": [0, 0, 0, 0],
        "samples": sample_rows,
        "status_candidate_matches_by_ordinal": status_counts,
        "status_candidate_samples_recorded": len(status_samples),
        "status_candidate_samples_overflow": 0,
        "status_candidate_identity_unavailable": 0,
        "status_candidate_samples": status_samples,
        "nonmatch_samples_recorded": len(nonmatches),
        "nonmatch_samples_overflow": 0,
        "nonmatch_samples": nonmatches,
    }


def result(*, capture: dict | None = None) -> dict:
    start = 1_000_000_000
    go = start - 1_000_000
    pset = packet_set()
    decoded = PACKETSET.decode_packet_set(pset)
    send_rows = []
    for index in range(4):
        before = start + index * 10_000_000
        frame = decoded["frames"][index]
        send_rows.append({
            "ordinal": index, "ieee80211_sequence": frame["wifi_sequence"],
            "ieee80211_sequence_control": frame["sequence_control"],
            "awdl_sequence": frame["awdl_sequence"], "before_ns": before,
            "after_ns": before + 100_000, "return_bytes": 106, "errno": 0,
        })
    ended = start + TOOL.CAPTURE_WINDOW_NS
    return {
        "event": "SENDER_RESULT", "schema": TOOL.SENDER_SCHEMA,
        "clock_domain": "CLOCK_MONOTONIC", "status": "send_complete",
        "wire_nonce_hex": WIRE_NONCE,
        "run_token": TOKEN, "run_token_in_frame": False, "go_received_ns": go,
        "frames_requested": 4, "frames_attempted": 4, "frames_completed": 4,
        "send_complete": True, "packet_bytes": 106, "radiotap_bytes": 10,
        "mpdu_bytes": 96, "elapsed_ms": 30, "deadline_hit": False,
        "error_count": 0, "last_errno": 0, "stop_reason": "complete",
        "tx_flags_requested": "NOSEQNO", "noack_requested": False,
        "ack_policy": "normal_unicast_requested", "hardware_honoring": "unknown",
        "raw_txs": "unknown", "mac_ack": "unknown", "interval_ms": 10,
        "send_budget_ns": TOOL.SEND_BUDGET_NS, "status_tail_ns": TOOL.STATUS_TAIL_NS,
        "capture_window_ns": TOOL.CAPTURE_WINDOW_NS, "started_ns": start,
        "send_deadline_ns": start + TOOL.SEND_BUDGET_NS,
        "observer_deadline_ns": start + TOOL.CAPTURE_WINDOW_NS,
        "finished_ns": ended, "go_to_start_ns": start - go,
        "go_to_start_max_ns": TOOL.GO_TO_START_MAX_NS, "first_send_ns": start,
        "pre_capture_queue_drain": {
            "read_attempts": 1, "packets_drained": 0, "receive_error": 0,
            "drain_complete": True, "kernel_stats_available": True,
            "kernel_packets": 0, "kernel_dropped_packets": 0,
        },
        "send_timing": send_rows,
        "monitor_observation": capture if capture is not None else monitor(),
        "radio_transmission_proven": False, "rf_transmission_proven": False,
        "firmware_tx_status_proven": False, "peer_receipt_proven": False,
        "airdrop_proven": False, "intel_arm_invoked": False, "boot_claim_used": False,
    }


class RouterStatusTailTest122Tests(unittest.TestCase):
    def test_default_is_side_effect_free_plan_and_has_no_host_address(self):
        self.assertEqual(TOOL.main([]), 0)

    def test_explicit_run_requires_persistent_nonce_ledger(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                TOOL.main([
                    "--run", "--host", "router-test", "--control-path", "/tmp/fake.sock",
                    "--binary", "/tmp/sender", "--binary-sha256", "a" * 64,
                    "--packet-set", "/tmp/packetset", "--packet-set-sha256", "b" * 64,
                    "--output", "/tmp/report.json",
                ])
        self.assertEqual(raised.exception.code, 2)

    def test_ready_requires_exact_scope_wire_nonce_and_explicit_noack_false(self):
        line = "READY wire_nonce_hex=" + WIRE_NONCE + " " + " ".join(
            f"{key}={value}" for key, value in TOOL.READY_VALUES.items())
        parsed = TOOL.parse_ready(line)
        self.assertEqual(parsed["wire_nonce_hex"], WIRE_NONCE)
        self.assertFalse(parsed["noack_requested"])
        self.assertFalse(parsed["intel_arm_invoked"])
        self.assertIn("send_budget_ms=40", line)
        with self.assertRaises(TOOL.RouterStatusTailError):
            TOOL.parse_ready(line.replace("noack_requested=false", "noack_requested=true"))
        with self.assertRaises(TOOL.RouterStatusTailError):
            TOOL.parse_ready(line.replace(WIRE_NONCE, "bad"))

    def test_packetset_valid_is_only_a_nontransmitting_verification(self):
        line = ('PACKET_SET_VALID {"event":"PACKET_SET_VALID",'
                '"schema":"test122-correlated-packet-set/v2","wire_nonce_hex":"' + WIRE_NONCE + '",'
                '"frames":4,"interval_ms":10,"budget_ms":40,"noack_requested":false,'
                '"transmission_capability":false,"rf_transmission_proven":false}')
        self.assertFalse(TOOL.parse_packetset_valid(line)["transmission_capability"])
        self.assertFalse(TOOL.parse_packetset_valid(line)["rf_transmission_proven"])
        with self.assertRaises(TOOL.RouterStatusTailError):
            TOOL.parse_packetset_valid(line.replace('"rf_transmission_proven":false',
                                                    '"rf_transmission_proven":true'))

    def test_duplicate_json_fields_are_rejected(self):
        line = ('PACKET_SET_VALID {"event":"PACKET_SET_VALID",'
                '"event":"PACKET_SET_VALID","schema":"test122-correlated-packet-set/v2",'
                '"wire_nonce_hex":"' + WIRE_NONCE + '","frames":4,"interval_ms":10,'
                '"budget_ms":40,"noack_requested":false,"transmission_capability":false,'
                '"rf_transmission_proven":false}')
        with self.assertRaises(TOOL.RouterStatusTailError):
            TOOL.parse_packetset_valid(line)

    def test_started_and_result_validate_40ms_send_and_full_tail(self):
        started_ns = 1_000_000_000
        started = {
            "event": "SENDER_STARTED", "schema": TOOL.SENDER_SCHEMA,
            "clock_domain": "CLOCK_MONOTONIC", "run_token": TOKEN,
            "wire_nonce_hex": WIRE_NONCE,
            "go_received_ns": started_ns - 1_000_000, "started_ns": started_ns,
            "send_deadline_ns": started_ns + TOOL.SEND_BUDGET_NS,
            "observer_deadline_ns": started_ns + TOOL.CAPTURE_WINDOW_NS,
            "go_to_start_ns": 1_000_000, "go_to_start_max_ns": TOOL.GO_TO_START_MAX_NS,
            "send_budget_ns": TOOL.SEND_BUDGET_NS, "status_tail_ns": TOOL.STATUS_TAIL_NS,
            "frames_requested": 4, "interval_ms": 10, "tx_flags_requested": "NOSEQNO",
            "noack_requested": False, "intel_arm_invoked": False, "boot_claim_used": False,
        }
        self.assertEqual(TOOL.validate_started(started, TOKEN), started)
        good = TOOL.validate_result(result(), TOKEN)
        self.assertTrue(good["send_complete"])
        self.assertEqual(good["monitor_observation"]["actual_horizon_ns"],
                         TOOL.CAPTURE_WINDOW_NS)
        self.assertFalse(good["rf_transmission_proven"])
        self.assertEqual(good["mac_ack"], "unknown")
        self.assertEqual(good["wire_nonce_hex"], WIRE_NONCE)

    def test_truncation_is_known_loss_even_when_kernel_statistics_are_unavailable(self):
        observation = monitor(kernel_stats=False, truncated=1)
        observation["capture_loss_free"] = False
        value = result(capture=observation)
        checked = TOOL.validate_result(value, TOKEN)
        self.assertFalse(checked["monitor_observation"]["capture_loss_free"])
        observation["capture_loss_free"] = None
        with self.assertRaisesRegex(TOOL.RouterStatusTailError,
                                    "monitor_loss_classification_invalid"):
            TOOL.validate_result(value, TOKEN)

    def test_status_sample_correlates_by_current_wire_nonce_and_full_sequence_pair(self):
        pset = packet_set()
        observation = monitor(status_sample_row=status_sample(pset, ordinal=0, tx_flags=1))
        checked = TOOL.validate_result(result(capture=observation), TOKEN)
        correlation = TOOL.correlate_status_samples({"sender_result": checked}, pset)
        self.assertEqual(correlation["wire_nonce_hex"], WIRE_NONCE)
        self.assertEqual(correlation["matched_status_samples"], 1)
        self.assertEqual(correlation["samples"][0]["ordinal"], 0)
        self.assertTrue(correlation["samples"][0]["host_tx_fail_bit"])
        self.assertFalse(correlation["rf_transmission_proven"])

    def test_wrong_frame_nonce_is_rejected_by_correlation(self):
        pset = packet_set()
        _, mpdu = _frame(pset, 0)
        altered = bytearray(mpdu)
        altered[88:96] = bytes.fromhex("1020304050607081")
        sample = status_sample(pset, ordinal=0, mpdu=bytes(altered))
        observation = monitor(status_sample_row=sample)
        checked = TOOL.validate_result(result(capture=observation), TOKEN)
        with self.assertRaisesRegex(TOOL.RouterStatusTailError,
                                    "status_raw_packetset_identity_mismatch"):
            TOOL.correlate_status_samples({"sender_result": checked}, pset)

    def test_wrong_sequence_control_is_not_correlated_even_with_current_nonce(self):
        pset = packet_set()
        _, mpdu = _frame(pset, 0)
        altered = bytearray(mpdu)
        struct.pack_into("<H", altered, 22, (777 << 4))
        sample = status_sample(pset, ordinal=0, mpdu=bytes(altered))
        observation = monitor(status_sample_row=sample)
        checked = TOOL.validate_result(result(capture=observation), TOKEN)
        with self.assertRaisesRegex(TOOL.RouterStatusTailError,
                                    "status_raw_packetset_identity_mismatch"):
            TOOL.correlate_status_samples({"sender_result": checked}, pset)

    def test_correlator_rejects_result_nonce_mismatch(self):
        pset = packet_set()
        checked = TOOL.validate_result(result(), TOKEN)
        checked["wire_nonce_hex"] = "1020304050607081"
        with self.assertRaisesRegex(TOOL.RouterStatusTailError, "result_wire_nonce_mismatch"):
            TOOL.correlate_status_samples({"sender_result": checked}, pset)

    def test_sample_time_outside_window_is_rejected(self):
        pset = packet_set()
        sample = status_sample(pset, observed_ns=3_040_000_001)
        observation = monitor(status_sample_row=sample)
        with self.assertRaisesRegex(TOOL.RouterStatusTailError,
                                    "sample_observation_time_invalid"):
            TOOL.validate_result(result(capture=observation), TOKEN)

    def test_correlator_also_rechecks_sample_time_bounds(self):
        pset = packet_set()
        observation = monitor(status_sample_row=status_sample(pset))
        checked = TOOL.validate_result(result(capture=observation), TOKEN)
        checked["monitor_observation"]["status_candidate_samples"][0]["observed_ns"] = (
            checked["monitor_observation"]["ended_ns"] + 1)
        with self.assertRaisesRegex(TOOL.RouterStatusTailError,
                                    "sample_observation_time_invalid"):
            TOOL.correlate_status_samples({"sender_result": checked}, pset)

    def test_invalid_radiotap_raw_prefix_is_preserved_as_nonmatch_evidence(self):
        invalid = nonmatch_sample(parse_status="invalid", raw=b"\x00\x00\xff\xffbad!")
        observation = monitor(nonmatch_row=invalid)
        checked = TOOL.validate_result(result(capture=observation), TOKEN)
        nonmatches = checked["monitor_observation"]["nonmatch_samples"]
        self.assertEqual(len(nonmatches), 1)
        self.assertEqual(nonmatches[0]["parse_status"], "invalid")
        self.assertEqual(nonmatches[0]["raw_prefix_hex"], invalid["raw_prefix_hex"])
        self.assertFalse(checked["monitor_observation"]["classification_complete"])

    def test_missing_sockaddr_identity_is_preserved_as_unknown_without_false_loss(self):
        unknown = nonmatch_sample(
            parse_status="invalid", packet_type_present=False, packet_type=None,
            ifindex_present=False, ifindex=None)
        checked = TOOL.validate_result(
            result(capture=monitor(nonmatch_row=unknown)), TOKEN)
        observed = checked["monitor_observation"]
        self.assertEqual(observed["nonmatch_samples_recorded"], 1)
        self.assertEqual(observed["nonmatch_samples"][0]["packet_type"], None)
        self.assertEqual(observed["nonmatch_samples"][0]["ifindex"], None)
        self.assertFalse(observed["nonmatch_samples"][0]["packet_type_present"])
        self.assertFalse(observed["nonmatch_samples"][0]["ifindex_present"])
        self.assertEqual(observed["nonmatch_samples"][0]["raw_prefix_hex"], unknown["raw_prefix_hex"])
        self.assertEqual(observed["exact_match_by_ordinal"], [0, 0, 0, 0])
        self.assertEqual(observed["status_candidate_matches_by_ordinal"], [0, 0, 0, 0])
        self.assertTrue(observed["capture_loss_free"])
        self.assertFalse(observed["classification_complete"])

    def test_nonmatch_parse_statuses_are_bounded_and_unknown_values_rejected(self):
        for parse_status in ("unsupported", "valid_unmatched"):
            with self.subTest(parse_status=parse_status):
                row = nonmatch_sample(parse_status=parse_status, raw=b"\x00\x00\x0b\x00x")
                checked = TOOL.validate_result(
                    result(capture=monitor(nonmatch_row=row)), TOKEN)
                self.assertEqual(
                    checked["monitor_observation"]["nonmatch_samples"][0]["parse_status"],
                    parse_status)
        unknown = nonmatch_sample(parse_status="unknown")
        with self.assertRaisesRegex(TOOL.RouterStatusTailError, "nonmatch_sample_invalid"):
            TOOL.validate_result(result(capture=monitor(nonmatch_row=unknown)), TOKEN)
        too_large = nonmatch_sample(parse_status="invalid", raw=b"x" * 257)
        with self.assertRaisesRegex(TOOL.RouterStatusTailError, "nonmatch_sample_invalid"):
            TOOL.validate_result(result(capture=monitor(nonmatch_row=too_large)), TOKEN)

    def test_duplicate_wire_nonce_claim_is_rejected(self):
        import tempfile
        pset = packet_set()
        digest = hashlib.sha256(pset).hexdigest()
        with tempfile.TemporaryDirectory() as raw_dir:
            ledger = Path(raw_dir) / "nonce-ledger"
            first = TOOL.claim_wire_nonce(ledger, WIRE_NONCE, digest, TOKEN)
            self.assertTrue(first.exists())
            self.assertEqual(first.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(TOOL.RouterStatusTailError, "wire_nonce_already_claimed"):
                TOOL.claim_wire_nonce(ledger, WIRE_NONCE, digest, "f" * 32)

    def test_remote_script_stages_and_verifies_packetset_before_monitor_and_go(self):
        binary = b"fake-test122-sender"
        pset = packet_set()
        script = TOOL.build_remote_script(
            binary=binary, binary_sha256=hashlib.sha256(binary).hexdigest(),
            packet_set=pset, packet_set_sha256=hashlib.sha256(pset).hexdigest(),
            run_token=TOKEN)
        self.assertIn('"$BIN" --verify-only --packet-set "$PSET"', script)
        self.assertIn('"$BIN" --send --packet-set "$PSET" --interface "$MON"', script)
        self.assertEqual(TOOL.validate_packetset_shape(pset)["wire_nonce_hex"], WIRE_NONCE)
        self.assertLess(script.index("--verify-only"), script.index('interface add "$MON"'))
        self.assertIn("/tmp/iwn-test122-tail-$RUN_TOKEN", script)
        self.assertIn("MON=iwtail122", script)
        self.assertNotIn("uci commit", script)
        self.assertNotIn('iw dev "$AP" set', script)

    def test_exception_after_private_run_setup_still_writes_private_report(self):
        binary = b"fake-test122-sender"
        pset = packet_set()
        with unittest.TestCase().subTest():
            import tempfile
            with tempfile.TemporaryDirectory() as raw_dir:
                base = Path(raw_dir)
                private = base / "private"
                private.mkdir(mode=0o700)
                private.chmod(0o700)
                binary_path = private / "sender"
                binary_path.write_bytes(binary)
                binary_path.chmod(0o700)
                pset_path = private / "packet-set.bin"
                pset_path.write_bytes(pset)
                pset_path.chmod(0o600)
                output = private / "run-private.json"
                args = SimpleNamespace(
                    host="router-test", control_path=Path("/private/tmp/fake.sock"),
                    binary=binary_path, binary_sha256=hashlib.sha256(binary).hexdigest(),
                    packet_set=pset_path, packet_set_sha256=hashlib.sha256(pset).hexdigest(),
                    nonce_ledger_dir=private / "nonce-ledger",
                    output=output)

                class FakeRunner:
                    @staticmethod
                    def build_bootstrap_argv(host, control_path):
                        return ["fake-ssh"]

                    @staticmethod
                    def remote_script_bytes(script):
                        return b"script\n"

                with mock.patch.object(TOOL, "_load_router_runner", return_value=FakeRunner), \
                     mock.patch.object(TOOL.subprocess, "Popen", side_effect=RuntimeError("start failed")):
                    report = TOOL.run(args)
                self.assertEqual(report["status"], "router_only_incomplete")
                self.assertEqual(report["error"], "RuntimeError")
                self.assertTrue(output.exists())
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                stored = json.loads(output.read_text())
                self.assertFalse(stored["rf_transmission_proven"])
                self.assertEqual(stored["error"], "RuntimeError")

    def test_invalid_sender_result_is_preserved_unvalidated_before_rejection(self):
        invalid = {
            "event": "SENDER_RESULT", "schema": TOOL.SENDER_SCHEMA,
            "status": "send_complete", "wire_nonce_hex": WIRE_NONCE,
        }
        line = json.dumps(invalid, separators=(",", ":"))
        report = {
            "transcript": [], "event_order": [], "wire_nonce_hex": WIRE_NONCE,
            "sender_result": None, "go_sent": True,
        }
        with self.assertRaisesRegex(TOOL.RouterStatusTailError,
                                    "sender_result_field_set_invalid"):
            TOOL._record_line(report, line, TOKEN)
        self.assertEqual(report["sender_result_unvalidated"], invalid)
        self.assertIsNone(report["sender_result"])
        self.assertEqual(report["transcript"], [line])


if __name__ == "__main__":
    unittest.main()
