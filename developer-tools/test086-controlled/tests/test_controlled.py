#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import dataclasses
import selectors
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3] / "developer-tools/test086-controlled"
spec = importlib.util.spec_from_file_location(
    "test086_controlled", ROOT / "test086_controlled.py")
protocol = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = protocol
spec.loader.exec_module(protocol)
runner_spec = importlib.util.spec_from_file_location(
    "test086_controlled_runner", ROOT / "run_controlled_probe_once.py")
runner = importlib.util.module_from_spec(runner_spec)
sys.modules[runner_spec.name] = runner
runner_spec.loader.exec_module(runner)


def sender_result(**changes):
    value = {
        "event": "SENDER_RESULT", "status": "aborted",
        "frames_attempted": 0, "frames_completed": 0, "sent": 0,
        "payload_bytes": 96, "mpdu_bytes": 96, "radiotap_bytes": 10,
        "packet_bytes": 106, "udp_payload_bytes": 8, "elapsed_ms": 0,
        "deadline_hit": False, "error_count": 0, "last_errno": 0,
        "stop_reason": "aborted_before_go", "tx_flags_requested": "NOACK|NOSEQNO",
        "hardware_honoring": "unknown",
    }
    value.update(changes)
    return json.dumps(value, separators=(",", ":"))


def listener_ready(token="0123456789abcdef0123456789abcdef", **changes):
    value = {
        "event": "LISTENER_READY", "interface": "awdl0", "ifindex": 8,
        "family": 6, "port": 49153, "group": "ff02::1", "timeout_ms": 15000,
        "bound_if": True, "pktinfo_enabled": True,
        "recv_anyif_requested": True, "recv_anyif_set": True,
        "recv_anyif_errno": 0, "run_token": token,
    }
    value.update(changes)
    return json.dumps(value, separators=(",", ":"))


def listener_result(token="0123456789abcdef0123456789abcdef", **changes):
    value = {
        "event": "LISTENER_RESULT", "status": "marker_received", "interface": "awdl0",
        "ifindex": 8, "datagrams": 1, "marker_match": True,
        "pktinfo_present": True, "pktinfo_ifindex_match": True,
        "destination_group_match": True, "source_link_local": True,
        "source_port_match": True, "payload_length": 8,
        "peer_address_serialized": False, "recv_anyif_requested": True,
        "recv_anyif_set": True, "recv_anyif_errno": 0, "run_token": token,
    }
    value.update(changes)
    return json.dumps(value, separators=(",", ":"))


def metadata_fixture():
    sha = "a" * 64
    return {
        "schema": "test086-controlled-probe-private/v1",
        "candidate": protocol.BUILD,
        "source_ready_kind": protocol.SOURCE_KIND,
        "requires_phone_ready": False, "armed": False,
        "status": "prepared_disarmed", "retry_allowed": False,
        "expected_loaded_uuid": protocol.EXPECTED_UUID,
        "profile": protocol.PROFILE, "diagnostic_duration_ms": 100,
        "receiver_gated": True, "atomic_boot_claim_required": True,
        "host_management_or_data_tx_allowed": False,
        "owner_epoch_fields": list(protocol.OWNER_EPOCH_FIELDS),
        "required_zero_host_tx_counters": ["tx_a", "tx_b"],
        "source_binding": {
            "build_receipt_sha256": sha, "source_file_count": 396,
            "source_sha256_map_sha256": sha, "expected_binary_sha256": sha,
            "expected_info_plist_sha256": sha,
        },
        "sender": {"frames_max": 16, "interval_ms": 50, "max_elapsed_seconds": 2},
    }, sha


class ProtocolTests(unittest.TestCase):
    def test_sender_ready_exact_contract(self):
        ready = protocol.parse_sender_ready(
            "READY frames=16 interval_ms=50 mpdu_bytes=96 radiotap_bytes=10 "
            "packet_bytes=106 udp_payload_bytes=8 tx_flags=NOACK|NOSEQNO "
            "hardware_honoring=unknown")
        self.assertEqual(ready["send_started"], False)
        with self.assertRaises(protocol.ControlledProbeError):
            protocol.parse_sender_ready(
                "READY frames=16 interval_ms=5 mpdu_bytes=96 radiotap_bytes=10 "
                "packet_bytes=106 udp_payload_bytes=8 tx_flags=NOACK|NOSEQNO "
                "hardware_honoring=unknown")

    def test_monitor_channel_direct_and_same_phy_fallback(self):
        fallback = (
            "MONITOR_READY mode=same_phy_active_ap_single_channel "
            "monitor_direct_channel_known=false monitor_wiphy=1 monitor_channel=0 "
            "monitor_frequency_mhz=0 ap_wiphy=1 ap_channel=149 "
            "ap_frequency_mhz=5745 ap_width_mhz=80 "
            "phy_single_channel_constraints_count=1 active_same_phy_channel_count=1 "
            "active_same_phy_channels=149 active_same_phy_frequencies_mhz=5745")
        self.assertEqual(protocol.parse_monitor_ready(fallback)["mode"],
                         "same_phy_active_ap_single_channel")
        direct = fallback.replace(
            "mode=same_phy_active_ap_single_channel monitor_direct_channel_known=false "
            "monitor_wiphy=1 monitor_channel=0 monitor_frequency_mhz=0",
            "mode=monitor_direct_channel monitor_direct_channel_known=true "
            "monitor_wiphy=2 monitor_channel=149 monitor_frequency_mhz=5745")
        self.assertEqual(protocol.parse_monitor_ready(direct)["monitor_wiphy"], 2)
        for rejected in (
            fallback.replace("monitor_wiphy=1", "monitor_wiphy=2"),
            fallback.replace("phy_single_channel_constraints_count=1",
                             "phy_single_channel_constraints_count=0"),
            fallback.replace("active_same_phy_channels=149",
                             "active_same_phy_channels=36"),
            fallback.replace("active_same_phy_frequencies_mhz=5745",
                             "active_same_phy_frequencies_mhz=5180"),
            fallback.replace("active_same_phy_channel_count=1",
                             "active_same_phy_channel_count=2").replace(
                                 "active_same_phy_channels=149",
                                 "active_same_phy_channels=149,36").replace(
                                     "active_same_phy_frequencies_mhz=5745",
                                     "active_same_phy_frequencies_mhz=5745,5180"),
            direct.replace("monitor_channel=149", "monitor_channel=36"),
        ):
            with self.subTest(rejected=rejected):
                with self.assertRaises(protocol.ControlledProbeError):
                    protocol.parse_monitor_ready(rejected)

    def test_sender_abort_and_status_are_strict(self):
        parsed = protocol.parse_sender_result(sender_result())
        self.assertTrue(protocol.validate_readiness_abort(parsed))
        with self.assertRaises(protocol.ControlledProbeError):
            protocol.parse_sender_result(sender_result(sent=1, frames_attempted=1,
                                                       frames_completed=1))
        with self.assertRaises(protocol.ControlledProbeError):
            protocol.parse_sender_result(sender_result(status="complete"))
        with self.assertRaises(protocol.ControlledProbeError):
            protocol.parse_sender_result(sender_result(status="aborted", extra_address="x"))
        failed = sender_result(status="failed", stop_reason="send_errno", error_count=1,
                               last_errno=5)
        self.assertEqual(protocol.parse_sender_result(failed)["status"], "failed")

    def test_cleanup_contract_rejects_mismatched_token(self):
        token = "0123456789abcdef0123456789abcdef"
        line = "CLEANUP " + json.dumps({
            "event": "MONITOR_CLEANUP", "run_token": token,
            "monitor_removed": True, "ap_unchanged": True,
            "temporary_files_removed": True,
        }, separators=(",", ":"))
        self.assertTrue(protocol.parse_cleanup(line, run_token=token)["monitor_removed"])
        with self.assertRaises(protocol.ControlledProbeError):
            protocol.parse_cleanup(line, run_token="f" * 32)

    def test_listener_ready_and_marker_receipt(self):
        token = "0123456789abcdef0123456789abcdef"
        self.assertEqual(protocol.parse_listener_ready(
            listener_ready(token), run_token=token)["ifindex"], 8)
        self.assertTrue(protocol.parse_listener_result(
            listener_result(token), run_token=token)["marker_match"])
        with self.assertRaises(protocol.ControlledProbeError):
            protocol.parse_listener_ready(listener_ready(token, recv_anyif_set=False),
                                          run_token=token)
        with self.assertRaises(protocol.ControlledProbeError):
            protocol.parse_listener_result(
                listener_result(token, peer_address_serialized=True), run_token=token)
        with self.assertRaises(protocol.ControlledProbeError):
            protocol.parse_listener_result(
                listener_result(token, marker_match=False), run_token=token)

    def test_fresh_boot_and_private_metadata_gates(self):
        metadata, receipt = metadata_fixture()
        errors = protocol.validate_private_metadata(
            metadata, boot_epoch=protocol.MINIMUM_BOOT_EPOCH_EXCLUSIVE + 1,
            expected_receipt_sha256=receipt, actual_receipt_sha256=receipt)
        self.assertEqual(errors, [])
        errors = protocol.validate_private_metadata(
            metadata, boot_epoch=protocol.MINIMUM_BOOT_EPOCH_EXCLUSIVE,
            expected_receipt_sha256=receipt, actual_receipt_sha256=receipt)
        self.assertIn("fresh_boot_required", errors)

    def test_pre_go_negative_gates(self):
        metadata, receipt = metadata_fixture()
        kwargs = dict(
            template=metadata,
            boot_epoch=protocol.MINIMUM_BOOT_EPOCH_EXCLUSIVE + 3,
            expected_receipt_sha256=receipt, actual_receipt_sha256=receipt,
            shared_boot_claim_available=True,
            host_tx_counters={"tx_a": 0, "tx_b": 0},
            router_sender_ready=True, native_preflight_ready=True,
            listener_ready=True)
        self.assertEqual(protocol.validate_full_run_gates(**kwargs), [])
        self.assertIn("fresh_boot_required", protocol.validate_full_run_gates(
            **{**kwargs, "boot_epoch": protocol.MINIMUM_BOOT_EPOCH_EXCLUSIVE}))
        self.assertIn("shared_boot_claim_unavailable", protocol.validate_full_run_gates(
            **{**kwargs, "shared_boot_claim_available": False}))
        self.assertIn("host_tx_nonzero_or_missing:tx_a", protocol.validate_full_run_gates(
            **{**kwargs, "host_tx_counters": {"tx_a": 1, "tx_b": 0}}))
        missing = protocol.validate_full_run_gates(**{**kwargs, "listener_ready": False})
        self.assertIn("listener_ready", missing)

    def test_remote_readiness_script_is_bounded_and_syntax_valid(self):
        binary = b"offline fixture only"
        digest = hashlib.sha256(binary).hexdigest()
        script = protocol.build_remote_monitor_sender_script(
            binary=binary, binary_sha256=digest,
            run_token="0123456789abcdef0123456789abcdef")
        result = subprocess.run(["sh", "-n"], input=script, text=True,
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--wait-go", script)
        self.assertNotIn('printf \'GO', script)
        self.assertNotIn("uci set", script)
        self.assertNotIn("set channel", script)
        self.assertNotIn("sysctl", script)
        self.assertIn("iw dev \"$MON\" del", script)
        fd_dup = script.index("exec 3<&0")
        sender_wait = script.index("--wait-go <&3 &")
        self.assertLess(fd_dup, sender_wait)
        self.assertNotIn("--wait-go <&0 &", script)
        self.assertIn("exec 3<&-", script)
        with self.assertRaises(protocol.ControlledProbeError):
            protocol.build_remote_monitor_sender_script(
                binary=binary, binary_sha256="0" * 64,
                run_token="0123456789abcdef0123456789abcdef")

    def test_openwrt_ash_stdin_reproduction_when_available(self):
        script = ROOT / "tests/test_openwrt_ash_stdin.sh"
        completed = subprocess.run(["sh", str(script)], text=True,
                                   capture_output=True, check=False)
        if completed.returncode == 77:
            self.skipTest(completed.stdout.strip())
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("ASH_ASYNC_STDIN_FD3_OK", completed.stdout)

    def test_bootstrap_uses_shared_transport_without_duplicate_host(self):
        original = runner.validate_transport
        runner.validate_transport = lambda host, path: ["ssh", "-S", path, host,
                                                        "sh -c bootstrap"]
        try:
            argv = runner.build_bootstrap_argv("root@router", "/tmp/control.sock")
        finally:
            runner.validate_transport = original
        self.assertEqual(argv[-2:], ["root@router", "sh -c bootstrap"])

    def test_control_socket_owner_is_workspace_owner_not_caller(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "router.sock"
            control_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                control_socket.bind(str(path))
                workspace_uid = path.lstat().st_uid
                fake_workspace = SimpleNamespace(
                    stat=lambda: SimpleNamespace(st_uid=workspace_uid))
                with mock.patch.object(runner, "ROOT", fake_workspace), \
                        mock.patch.object(runner.os, "getuid", return_value=workspace_uid + 1), \
                        mock.patch.object(runner, "load_openwrt_transport",
                                          return_value=SimpleNamespace(
                                              build_ssh_argv=lambda host, socket_path:
                                              ["ssh", "-S", socket_path, host])):
                    argv = runner.validate_transport("root@router", str(path))
                self.assertEqual(argv[-1], "root@router")

                third_party_workspace = SimpleNamespace(
                    stat=lambda: SimpleNamespace(st_uid=workspace_uid + 2))
                with mock.patch.object(runner, "ROOT", third_party_workspace), \
                        self.assertRaises(protocol.ControlledProbeError) as caught:
                    runner.validate_transport("root@router", str(path))
                self.assertEqual(caught.exception.code, "UNSAFE_CONTROL_SOCKET")
            finally:
                control_socket.close()

    def test_actual_openwrt_helper_module_load(self):
        module_name = "test086_openwrt_transport"
        previous = sys.modules.pop(module_name, None)
        try:
            transport = runner.load_openwrt_transport()
            self.assertIs(sys.modules[module_name], transport)
            self.assertTrue(dataclasses.is_dataclass(transport.ExpectedAP))
            argv = transport.build_ssh_argv("root@192.168.5.1", "/tmp/test-control.sock")
            self.assertEqual(argv[-2], "root@192.168.5.1")
        finally:
            sys.modules.pop(module_name, None)
            if previous is not None:
                sys.modules[module_name] = previous

    def test_multi_line_pipe_tail_survives_child_eof(self):
        process = subprocess.Popen(
            [sys.executable, "-c",
             "print('NATIVE_ARMED {\\\"claim_consumed\\\":true}'); "
             "print('NATIVE_RESULT {\\\"report_saved\\\":true}')"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        state = {"buffer": b""}
        try:
            deadline = __import__("time").monotonic() + 2
            first = runner._read_protocol_line(selector, process, state, deadline)
            second = runner._read_protocol_line(selector, process, state, deadline)
            self.assertEqual(first, 'NATIVE_ARMED {"claim_consumed":true}')
            self.assertEqual(second, 'NATIVE_RESULT {"report_saved":true}')
            self.assertEqual(process.wait(timeout=1), 0)
        finally:
            selector.close()
            process.stdout.close()

    def test_default_invocation_is_plan_only(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "run_controlled_probe_once.py")],
            text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0)
        report = json.loads(completed.stdout)
        self.assertEqual(report["mode"], "plan")
        self.assertFalse(report["full_run_supported"])


if __name__ == "__main__":
    unittest.main()
