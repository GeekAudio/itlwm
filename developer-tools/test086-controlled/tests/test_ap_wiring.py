from __future__ import annotations

import contextlib
import base64
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
TOOL_DIR = ROOT / "developer-tools/test086-controlled"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


protocol = load_module("test086_controlled", TOOL_DIR / "test086_controlled.py")
router = load_module("test086_controlled_runner", TOOL_DIR / "run_controlled_probe_once.py")
coordinator = load_module(
    "test086_controlled_full_coordinator", TOOL_DIR / "controlled_run_coordinator.py")

TOKEN = "0123456789abcdef0123456789abcdef"
MONITOR_LINE = (
    "MONITOR_READY mode=same_phy_active_ap_single_channel monitor_direct_channel_known=false "
    "monitor_wiphy=7 monitor_channel=0 monitor_frequency_mhz=0 "
    "ap_wiphy=7 ap_channel=149 ap_frequency_mhz=5745 ap_width_mhz=80 "
    "phy_single_channel_constraints_count=1 active_same_phy_channel_count=1 "
    "active_same_phy_channels=149 active_same_phy_frequencies_mhz=5745")
SENDER_LINE = (
    "READY frames=16 interval_ms=80 mpdu_bytes=96 radiotap_bytes=10 "
    "packet_bytes=106 udp_payload_bytes=8 tx_flags=NOACK|NOSEQNO "
    "hardware_honoring=unknown")


class FakeSelector:
    def register(self, *_args):
        pass

    def close(self):
        pass


class FakeProcess:
    def __init__(self):
        self.stdin = io.BytesIO()
        self.stdout = object()

    @staticmethod
    def poll():
        return None

    @staticmethod
    def wait(timeout=None):
        return 0


class DynamicApWiringTests(unittest.TestCase):
    def test_router_session_passes_live_wlan7_to_script_and_phy_derivation(self):
        binary = b"synthetic sender for offline test"
        digest = hashlib.sha256(binary).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            sender = Path(temporary) / "sender"
            sender.write_bytes(binary)
            process = FakeProcess()
            with mock.patch.object(router.subprocess, "Popen", return_value=process), \
                    mock.patch.object(router.selectors, "DefaultSelector",
                                      return_value=FakeSelector()), \
                    mock.patch.object(router, "build_bootstrap_argv",
                                      return_value=["ssh", "fake"]), \
                    mock.patch.object(router, "_read_protocol_line",
                                      side_effect=[MONITOR_LINE, SENDER_LINE]):
                session, monitor, ready = router.RouterSenderSession.start(
                    host="root@router", control_path="/tmp/control.sock",
                    sender_binary=sender, sender_sha256=digest,
                    run_token=TOKEN, ap="wlan7")

            script = base64.b64decode(process.stdin.getvalue()).decode("utf-8")
            self.assertIn("AP=wlan7", script)
            self.assertIn('iw dev "$AP" info', script)
            self.assertIn('iw phy "phy$AP_PHY" interface add', script)
            self.assertIn('[ "$AP_CHANNEL" != 149 ]', script)
            self.assertEqual(monitor["ap_wiphy"], 7)
            self.assertEqual(monitor["ap_channel"], 149)
            self.assertEqual(ready["frames"], 16)
            self.assertEqual(session.run_token, TOKEN)

    def test_readiness_cli_forwards_ap_without_starting_a_real_session(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            base.chmod(0o700)
            report = base / "readiness.json"
            result = {"schema": "test086-controlled-readiness-private/v1",
                      "success": True, "transmit_started": False,
                      "local_send_calls": 0}
            output = io.StringIO()
            with mock.patch.object(router, "run_readiness_only",
                                   return_value=result) as run_mock, \
                    contextlib.redirect_stdout(output):
                code = router.main([
                    "--readiness-only", "--host", "root@router",
                    "--control-path", "/tmp/control.sock",
                    "--sender-binary", str(base / "sender"),
                    "--sender-sha256", "a" * 64,
                    "--ap", "wlan7", "--report", str(report)])
            self.assertEqual(code, 0)
            self.assertEqual(run_mock.call_args.kwargs["ap"], "wlan7")
            self.assertTrue(report.is_file())
            self.assertIn("READINESS_ONLY_OK", output.getvalue())

    def test_readiness_cli_rejects_unsafe_ap_name_before_report_or_ssh(self):
        output = io.StringIO()
        with mock.patch.object(router, "run_readiness_only") as run_mock, \
                contextlib.redirect_stderr(output):
            code = router.main(["--readiness-only", "--ap", "wlan7;reboot"])
        self.assertEqual(code, 2)
        run_mock.assert_not_called()
        self.assertIn("INVALID_INTERFACE_NAME", output.getvalue())

    def test_full_run_api_rejects_unsafe_ap_before_transport_preflight(self):
        with mock.patch.object(router, "validate_transport") as transport_mock:
            with self.assertRaises(coordinator.CoordinatorError) as raised:
                coordinator.run_controlled_once(
                    host="root@router", control_path="/tmp/control.sock",
                    metadata_path=Path("/unused"), sender_binary=Path("/unused"),
                    sender_sha256="a" * 64, output_dir=Path("/unused"),
                    ap="wlan7;reboot")
        self.assertEqual(raised.exception.code, "INVALID_INTERFACE_NAME")
        transport_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
