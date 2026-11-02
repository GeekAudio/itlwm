# SPDX-License-Identifier: GPL-2.0-only
"""Offline-only tests for the Test111 local coordinator."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import shlex
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import coordinate_test111 as coordinator


UUID = "00000000-0000-4000-8000-000000000001"
TOKEN = "0102030405060708090a0b0c0d0e0f10"
IDENTITY = {
    "run_token": TOKEN,
    "nonce": "0102030405060708",
    "local_mac": "02:00:00:00:00:01",
    "peer_mac": "02:00:00:00:00:02",
    "local_ipv6": "fe80::1",
    "peer_ipv6": "fe80::2",
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def make_config(root):
    root = Path(root)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    os.chmod(runtime, 0o700)
    artifacts = {}
    for name, contents in (
        ("helper", b"mock-helper"),
        ("helper-source", b"mock-helper-source"),
        ("remote-script-source", b"mock-remote-script"),
        ("peer-binary", b"mock-peer-binary"),
    ):
        path = runtime / name
        path.write_bytes(contents)
        os.chmod(path, 0o600)
        artifacts[name] = path
    return {
        "ssh_target": "root@192.168.5.1",
        "ssh_socket": "/tmp/test111-mock-ssh.sock",
        "remote_dir": f"/tmp/iw111echo-{TOKEN}",
        "output_dir": str(runtime / f"run-{TOKEN}"),
        "expected_boot": 1793599665,
        "expected_uuid": UUID,
        "expected_build": "25G332-Test111",
        "expected_reset_count": 5,
        "helper_path": str(artifacts["helper"]),
        "helper_sha256": sha(artifacts["helper"]),
        "helper_source_path": str(artifacts["helper-source"]),
        "helper_source_sha256": sha(artifacts["helper-source"]),
        "remote_script_path": str(artifacts["remote-script-source"]),
        "remote_script_sha256": sha(artifacts["remote-script-source"]),
        "peer_binary_path": str(artifacts["peer-binary"]),
        "peer_sha256": sha(artifacts["peer-binary"]),
        "identity": IDENTITY,
        "_artifacts": artifacts,
    }


def make_snapshot(attempted=0, doorbell=0, reset=5):
    props = {
        "NativeTestBuild": "25G332-Test111",
        "NativePowerReady": 1,
        "NativeP2PManualTrigger": True,
        "NativeP2PDirectedDataEnabled": True,
        "NativeP2PDirectedDataCompiled": True,
        "NativeP2PProbeAttempted": attempted,
        "NativeP2PDirectedDataDoorbellIssued": doorbell,
        "NativePowerResetCount": reset,
    }
    return {
        "boot": b"{ sec = 1793599665, usec = 2000 }\n",
        "boot_exit": b"0",
        "loaded": (f"org.geekaudio.AirportItlwm (Test111) {UUID}\n").encode(),
        "loaded_exit": b"0",
        "ioreg": plistlib.dumps([props]),
        "ioreg_exit": b"0",
        "en1": b"en1: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX>\n\tinet 192.0.2.10 netmask 0xffffff00\n",
        "en1_exit": b"0",
        "awdl0": b"awdl0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX>\n\tether 02:00:00:00:00:01\n\tinet6 fe80::1%awdl0 prefixlen 64\n",
        "awdl0_exit": b"0",
    }


def ready_line(identity):
    normalized = coordinator.normalize_identity(identity)
    now_ns = 1_000_000_000
    event = {
        "schema": "test110-openwrt-echo-peer/v1",
        "event": "READY",
        "window_ms": 16000,
        "ifindex": 8,
        "monotonic_start_ns": now_ns,
        "monotonic_deadline_ns": now_ns + 16_000_000_000,
        "token_bytes_hex": normalized["run_token"],
        **normalized,
        **coordinator.READY_FIXED,
    }
    return json.dumps(event, separators=(",", ":")).encode() + b"\n"


class FakeCaptureProcess:
    def __init__(self, data):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, data)
        os.close(write_fd)
        self.stdout = os.fdopen(read_fd, "rb", buffering=0)

    def poll(self):
        return None


class FakeStream:
    def close(self):
        pass


class FakePopenProcess:
    def __init__(self, stdout):
        self.stdout = FakeStream() if stdout == subprocess.PIPE else None
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def kill(self):
        self.returncode = -9


class FakePeerSession:
    def __init__(self, directory, line):
        self.result_line = json.dumps({
            "schema": "test110-openwrt-echo-peer/v1",
            "event": "RESULT",
            "observed_frames": 0,
            "request_matched": False,
            "reply_local_send": False,
            "over_air_delivery_proven": False,
            "airdrop_proven": False,
            "stopped": True,
        }, separators=(",", ":")).encode() + b"\n"
        self.ready_process = FakeCaptureProcess(line + self.result_line)
        self.directory = Path(directory)
        self.finished = False
        self.returncode = None
        self.line = line
        coordinator._write_private(self.directory / "peer.stdout.raw", line)

    def collect(self, timeout=25.0):
        self.finished = True
        self.returncode = 0
        self.ready_process.stdout.close()
        with (self.directory / "peer.stdout.raw").open("ab") as stream:
            stream.write(self.result_line)
        coordinator._write_private(self.directory / "peer.stdout.remaining.raw", b"")
        coordinator._write_private_json(self.directory / "peer.result.json", {"returncode": 0})
        return 0

    def stop_local(self):
        self.finished = True


class OfflineDeps:
    def __init__(self, directory, config):
        self.directory = Path(directory)
        self.config = config
        self.commands = []
        self.remote_restores = 0
        self.peer = None
        self.geteuid = lambda: 0
        self.verify_socket = lambda _path: None
        self.snapshot = lambda: make_snapshot()
        self.monotonic = time.monotonic
        self.popen = subprocess.Popen
        self.capture_ready = coordinator.capture_ready

    def run(self, argv, **kwargs):
        argv = list(argv)
        self.commands.append(argv)
        if "/usr/bin/ssh" in argv:
            remote_command = argv[-1]
            if "sha256sum" in remote_command:
                output = (
                    self.config["remote_script_sha256"] + "  /tmp/iw111echo-" + TOKEN + "/monitor_window111.sh\n" +
                    self.config["peer_sha256"] + "  /tmp/iw111echo-" + TOKEN + "/openwrt_echo110\n"
                ).encode()
                return subprocess.CompletedProcess(argv, 0, output, b"")
            if "--prepare" in remote_command:
                return subprocess.CompletedProcess(argv, 0, b"prepared\n", b"")
            if "--restore" in remote_command:
                self.remote_restores += 1
                return subprocess.CompletedProcess(argv, 0, b"restored\n", b"")
            if "--run" in remote_command:
                raise AssertionError("remote --run must be a live Popen, not run()")
        if "--expect-build" in argv:
            raise subprocess.TimeoutExpired(argv, 12, output=b'{"phase":"wait_matching_return"}\n', stderr=b"helper timeout")
        raise AssertionError("unexpected command")

    def start_peer(self, config, directory):
        self.peer = FakePeerSession(directory, ready_line(config["identity"]))
        return self.peer


class TestCoordinateTest111(unittest.TestCase):
    def test_default_plan_hashes_only_and_does_not_run_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            config_path = Path(temp) / "config.json"
            config_path.write_text(json.dumps({k: v for k, v in config.items() if not k.startswith("_")}))
            os.chmod(config_path, 0o600)
            output = io.StringIO()
            with mock.patch("sys.argv", ["coordinate_test111.py", "--config", str(config_path)]), \
                    mock.patch("subprocess.run", side_effect=AssertionError("plan ran a command")), \
                    contextlib.redirect_stdout(output):
                status = coordinator.main()
            self.assertEqual(status, 0)
            summary = json.loads(output.getvalue())
            self.assertEqual(summary["mode"], "plan")
            self.assertFalse(summary["hardware_action"])
            self.assertFalse(summary["ssh_attempted"])
            self.assertFalse(Path(config["output_dir"]).exists())

    def test_live_ready_is_captured_and_helper_failure_still_restores(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            deps = OfflineDeps(temp, config)
            deps.start_peer = lambda cfg, directory: FakePeerSession(directory, ready_line(cfg["identity"]))
            result = coordinator.execute_run(config, deps)
            self.assertFalse(result["orchestration_completed"])
            self.assertEqual(deps.remote_restores, 1)
            self.assertTrue(result.get("live_ready_captured"))
            self.assertFalse(result["airdrop_proven"])
            output_dir = Path(config["output_dir"])
            receipt_path = output_dir / f"peer-ready-{TOKEN}.json"
            receipt = json.loads(receipt_path.read_text())
            self.assertEqual(receipt["router_ready_sha256"], hashlib.sha256(ready_line(IDENTITY)).hexdigest())
            self.assertTrue((output_dir / "peer.stdout.raw").read_bytes().startswith(ready_line(IDENTITY)))
            self.assertTrue(result["hardware_action"])
            self.assertTrue(result["router_mutation_attempted"])
            self.assertTrue(result["rf_window_attempted"])
            self.assertEqual((output_dir / "helper.stdout.raw").read_bytes(), b'{"phase":"wait_matching_return"}\n')
            self.assertTrue((output_dir / "remote-restore.result.json").exists())
            self.assertTrue((output_dir / "before-ioreg.plist").exists())
            self.assertTrue((output_dir / "after-ioreg.plist").exists())
            self.assertEqual(result["peer_result"]["event"], "RESULT")
            self.assertFalse(result["peer_result"]["over_air_delivery_proven"])
            self.assertTrue((output_dir / "peer.stdout.raw").read_bytes().startswith(ready_line(IDENTITY)))

    def test_preflight_rejects_cfnumber_for_boolean_flag(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            raw = make_snapshot()
            properties = plistlib.loads(raw["ioreg"])[0]
            properties["NativeP2PDirectedDataEnabled"] = 1
            raw["ioreg"] = plistlib.dumps([properties])
            summary = coordinator.inspect_snapshot(raw, {**config, "identity": coordinator.normalize_identity(config["identity"])})
            with self.assertRaisesRegex(coordinator.CoordinatorError, "data_enabled"):
                coordinator.validate_preflight(summary, {**config, "identity": coordinator.normalize_identity(config["identity"])})

    def test_missing_doorbell_is_zero_but_present_boolean_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            identity_config = {**config, "identity": coordinator.normalize_identity(config["identity"])}
            raw = make_snapshot()
            properties = plistlib.loads(raw["ioreg"])[0]
            del properties["NativeP2PDirectedDataDoorbellIssued"]
            raw["ioreg"] = plistlib.dumps([properties])
            summary = coordinator.inspect_snapshot(raw, identity_config)
            self.assertEqual(summary["doorbell_issued"], 0)
            coordinator.validate_preflight(summary, identity_config)
            properties["NativeP2PDirectedDataDoorbellIssued"] = True
            raw["ioreg"] = plistlib.dumps([properties])
            summary = coordinator.inspect_snapshot(raw, identity_config)
            with self.assertRaisesRegex(coordinator.CoordinatorError, "doorbell_issued"):
                coordinator.validate_preflight(summary, identity_config)

    def test_peer_arguments_use_colon_mac_and_remote_script_name(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            normalized, _ = coordinator.validate_config(config)
            argv = coordinator._peer_remote_args(normalized)
            self.assertEqual(argv[0], f"/tmp/iw111echo-{TOKEN}/monitor_window111.sh")
            self.assertEqual(argv[argv.index("--local-mac") + 1], IDENTITY["local_mac"])
            self.assertEqual(argv[argv.index("--peer-mac") + 1], IDENTITY["peer_mac"])
            self.assertEqual(coordinator.REMOTE_SCRIPT_NAME, "monitor_window111.sh")

    def test_peer_result_parser_skips_ready_event(self):
        raw = ready_line(IDENTITY) + b'{"event":"RESULT","observed_frames":1}\n'
        result = coordinator._parse_peer_result(raw)
        self.assertEqual(result, {"event": "RESULT", "observed_frames": 1})

    def test_real_start_peer_adapter_injects_deps_and_formats_command(self):
        with tempfile.TemporaryDirectory() as temp:
            config = make_config(temp)
            normalized, _ = coordinator.validate_config(config)
            output_dir = Path(config["output_dir"])
            output_dir.mkdir(mode=0o700)
            ssh_process = FakePopenProcess(subprocess.PIPE)
            tee_process = FakePopenProcess(subprocess.PIPE)
            with mock.patch.object(coordinator.RealDeps, "popen", side_effect=[ssh_process, tee_process]) as popen:
                session = coordinator.RealDeps.start_peer(normalized, output_dir)
            self.assertEqual(popen.call_count, 2)
            ssh_args = popen.call_args_list[0].args[0]
            tee_args = popen.call_args_list[1].args[0]
            self.assertIn("/usr/bin/ssh", ssh_args)
            peer_args = shlex.split(ssh_args[-1])
            self.assertEqual(peer_args[0], f"/tmp/iw111echo-{TOKEN}/monitor_window111.sh")
            self.assertEqual(peer_args[peer_args.index("--local-mac") + 1], "02:00:00:00:00:01")
            self.assertEqual(peer_args[peer_args.index("--peer-mac") + 1], "02:00:00:00:00:02")
            self.assertEqual(tee_args[0], "/usr/bin/tee")
            self.assertIs(popen.call_args_list[1].kwargs["stdin"], ssh_process.stdout)
            session.stop_local()


if __name__ == "__main__":
    unittest.main()
