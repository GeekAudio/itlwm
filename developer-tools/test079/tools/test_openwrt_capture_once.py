#!/usr/bin/env python3
"""Offline tests for the bounded OpenWrt capture coordinator."""

from __future__ import annotations

import base64
import hashlib
import contextlib
import io
import importlib.util
import os
import re
import socket
import subprocess
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from pathlib import Path
from unittest import mock
import json


MODULE_PATH = Path(__file__).with_name("openwrt_capture_once.py")
SPEC = importlib.util.spec_from_file_location("openwrt_capture_once", MODULE_PATH)
assert SPEC and SPEC.loader
capture = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = capture
SPEC.loader.exec_module(capture)


AP_ARGS = ("--host", "root@router", "--control-path", "/tmp/mock-control",
           "--ap", "wlan0", "--ap", "wlan1",
           "--expect-ap", "wlan0:0:6:2437:20",
           "--expect-ap", "wlan1:1:36:5180:160",
           "--interface", "wlan1")
AP_INFO = {
    "wlan0": ("101", "0", "6", "2437", "20"),
    "wlan1": ("102", "1", "36", "5180", "160"),
}
PCAP_HEADER = (b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" +
               b"\x00\x00\x00\x00\x00\x00\x00\x00" +
               b"\x00\x08\x00\x00\x7f\x00\x00\x00")


def write_executable(path: Path, source: str) -> None:
    path.write_text(source)
    path.chmod(0o755)


class ShellFixture:
    """Run generated POSIX shell against fake iw/ip/uci/tcpdump commands."""

    def __init__(self, root: Path, *, capture_mode: bool = False,
                 tcpdump_start_failure: bool = False,
                 existing_monitor: bool = False,
                 state_mismatch: bool = False,
                 uci_failure: bool = False,
                 index_change_on_down: bool = False,
                 sys_class_available: bool = True):
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir()
        self.state = root / "monitor-present"
        self.log = root / "commands.log"
        self.sys_class = root / "sys-class-net"
        if sys_class_available:
            self.sys_class.mkdir()
        self.tcpdump_start_failure = tcpdump_start_failure
        self.uci_failure = uci_failure
        self.index_change_on_down = index_change_on_down
        if existing_monitor:
            self.state.write_text("777\n")
            (self.sys_class / "awdlmon0").mkdir()
            (self.sys_class / "awdlmon0" / "ifindex").write_text("777\n")
        self._commands(state_mismatch)
        self.remote_tmp = root / "remote-tmp"
        self.remote_tmp.mkdir(mode=0o700)
        remote = capture.build_remote_script(
            ap_interfaces=["wlan0", "wlan1"],
            selected_interface="wlan1", monitor_interface="awdlmon0",
            expected=[capture.parse_expected_ap("wlan0:0:6:2437:20"),
                      capture.parse_expected_ap("wlan1:1:36:5180:160")],
            run_id=uuid.uuid4().hex, capture=capture_mode, duration=12,
            packet_limit=2,
        )
        remote = remote.replace(
            'TMP="/tmp/iw-awdl-capture-$RUN_ID"',
            'TMP="' + str(self.remote_tmp) + '/$RUN_ID"')
        remote = remote.replace(
            'TCPDUMP="/tmp/iw-awdl-tools/bin/tcpdump"',
            'TCPDUMP="' + str(self.bin / "tcpdump") + '"')
        remote = remote.replace('LIBDIR="/tmp/iw-awdl-tools/lib"',
                                'LIBDIR="' + str(self.root / "lib") + '"')
        remote = remote.replace('SYS_CLASS_NET="/sys/class/net"',
                                'SYS_CLASS_NET="' + str(self.sys_class) + '"')
        # macOS has no /proc. Keep the shell fixture real while supplying a
        # deterministic starttime value for the remote-Linux ownership fence.
        remote = re.sub(r"proc_start_time\(\) \{\n.*?\n\}",
                        'proc_start_time() { printf "1"; }', remote,
                        count=1, flags=re.S)
        # The test sleep shim is accelerated, so preserve watchdog's relative
        # margin rather than letting its 40 mock seconds race the fixture.
        remote = remote.replace("left=40", "left=400")
        # Background POSIX shells inherit SIGINT as ignored; use TERM in this
        # mock-only process to exercise the bounded local cleanup path.
        self.script = remote.replace('kill -INT "$CAP_PID"',
                                     'kill -TERM "$CAP_PID"')

    def _commands(self, state_mismatch: bool) -> None:
        state = str(self.state)
        log = str(self.log)
        mismatch = "1" if state_mismatch else "0"
        change_index = "1" if self.index_change_on_down else "0"
        write_executable(self.bin / "iw", r'''#!/bin/sh
printf 'iw %s\n' "$*" >> "''' + log + r'''"
if [ "$1" = dev ] && [ "$2" = awdlmon0 ] && [ "$3" = info ]; then
  if [ -f "''' + state + r'''" ]; then
    idx=$(cat "''' + state + r'''")
    printf 'Interface awdlmon0\n\tifindex %s\n\twiphy 1\n\ttype monitor\n' "$idx"
    exit 0
  fi
  exit 1
fi
if [ "$1" = dev ]; then
  iface=$2
  case "$iface" in
    wlan0) vals='101 0 6 2437 20' ;;
    wlan1)
      if [ "''' + mismatch + r'''" = 1 ]; then vals='102 1 36 5200 160'
      else vals='102 1 36 5180 160'; fi ;;
    awdlmon0)
      if [ -f "''' + state + r'''" ]; then
        if [ "$3" = info ]; then
          idx=$(cat "''' + state + r'''")
          printf 'Interface awdlmon0\n\tifindex %s\n\twiphy 1\n\ttype monitor\n' "$idx"
          exit 0
        fi
        if [ "$3" = del ]; then
          printf 'del-monitor\n' >> "''' + log + r'''"
          rm -f "''' + state + r'''"
          rm -rf "''' + str(self.sys_class / 'awdlmon0') + r'''"
          exit 0
        fi
      fi
      exit 1 ;;
    *) exit 1 ;;
  esac
  set -- $vals
  printf 'Interface %s\n\tifindex %s\n\twiphy %s\n\ttype AP\n\tchannel %s (%s MHz), width: %s MHz\n\taddr aa:bb:cc:dd:ee:ff\n\tssid PRIVATE-SSID\n' \
    "$iface" "$1" "$2" "$3" "$4" "$5"
  exit 0
fi
if [ "$1" = phy ] && [ "$3" = info ]; then
  printf 'Wiphy %s\n\tSupported interface modes:\n\t\t* managed\n\t\t* monitor\n' "$2"
  exit 0
fi
if [ "$1" = phy ] && [ "$3" = interface ] && [ "$4" = add ]; then
  printf 'add-monitor\n' >> "''' + log + r'''"
  printf '777\n' > "''' + state + r'''"
  mkdir -p "''' + str(self.sys_class / 'awdlmon0') + r'''"
  printf '777\n' > "''' + str(self.sys_class / 'awdlmon0' / 'ifindex') + r'''"
  exit 0
fi
if [ "$1" = dev ] && [ "$3" = del ]; then
  printf 'del-monitor\n' >> "''' + log + r'''"
  rm -f "''' + state + r'''"
  exit 0
fi
exit 1
''')
        write_executable(self.bin / "ip", r'''#!/bin/sh
printf 'ip %s\n' "$*" >> "''' + log + r'''"
if [ "$1" = link ] && [ "$2" = show ]; then
  [ -f "''' + state + r'''" ] && exit 0
  exit 1
fi
if [ "$1" = link ] && [ "$2" = set ] && [ "$5" = down ] &&
   [ "''' + change_index + r'''" = 1 ]; then
  printf '888\n' > "''' + state + r'''"
  printf '888\n' > "''' + str(self.sys_class / 'awdlmon0' / 'ifindex') + r'''"
fi
exit 0
''')
        write_executable(self.bin / "uci", "#!/bin/sh\nprintf 'config wireless\n'\n")
        if self.uci_failure:
            write_executable(self.bin / "uci", "#!/bin/sh\nexit 1\n")
        write_executable(self.bin / "sha256sum", "#!/bin/sh\nexec /usr/bin/shasum -a 256 \"$@\"\n")
        write_executable(self.bin / "base64", "#!/bin/sh\nif [ \"$1\" = -d ]; then shift; exec /usr/bin/base64 -D \"$@\"; fi\nexec /usr/bin/base64 \"$@\"\n")
        write_executable(self.bin / "sleep", "#!/bin/sh\n/bin/sleep 0.01\n")
        if self.tcpdump_start_failure:
            tcpdump = "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'tcpdump version 4.99.5\\nlibpcap version 1.10.5\\n'; exit 0; fi\nexit 3\n"
        else:
            tcpdump = '''#!/usr/bin/python3
import signal
import sys
import time

if "--version" in sys.argv:
    print("tcpdump version 4.99.5\\nlibpcap version 1.10.5")
    raise SystemExit(0)
output = sys.argv[sys.argv.index("-w") + 1]
with open(output, "wb") as handle:
    handle.write(bytes.fromhex("''' + PCAP_HEADER.hex() + '''"))
print("tcpdump: listening on awdlmon0, link-type IEEE802_11_RADIO (radiotap header), snapshot length 2048 bytes", file=sys.stderr, flush=True)
def stop(_signum, _frame):
    print("0 packets captured\\n0 packets received by filter\\n0 packets dropped by kernel", file=sys.stderr, flush=True)
    raise SystemExit(0)
signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)
while True:
    time.sleep(0.03)
'''
        write_executable(self.bin / "tcpdump", tcpdump)

    def popen(self) -> subprocess.Popen[bytes]:
        env = os.environ.copy()
        env["PATH"] = str(self.bin) + ":/usr/bin:/bin"
        proc = subprocess.Popen(["/bin/sh", "-c", capture.REMOTE_BOOTSTRAP],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, bufsize=0)
        assert proc.stdin
        proc.stdin.write(base64.b64encode(self.script.encode("utf-8")) + b"\n")
        proc.stdin.flush()
        return proc


def read_line(stream) -> bytes:
    line = stream.readline()
    if not line:
        raise AssertionError("unexpected EOF in shell fixture")
    return line.rstrip(b"\n")


def install_ack_losing_ssh(bin_dir: Path) -> str:
    pcap_sha = hashlib.sha256(PCAP_HEADER).hexdigest()
    pcap_printf = "".join(r"\%03o" % byte for byte in PCAP_HEADER)
    protocol = (
        "#!/bin/sh\n"
        "IFS= read -r remote_script || exit 9\n"
        "printf 'AP\\tbefore\\twlan0\\t101\\t0\\t1\\t6\\t2437\\t20\\n'\n"
        "printf 'UCI\\tbefore\\t%s\\n' '" + "a" * 64 + "'\n"
        "printf 'PREFLIGHT\\t4.99.5\\t1.10.5\\t1\\t1\\n'\n"
        "printf 'READY\\t%s\\t12\\t127\\n' '" + "b" * 32 + "'\n"
        "printf 'WINDOW\\t%s\\t12\\n' '" + "b" * 32 + "'\n"
        "printf 'AP\\tafter\\twlan0\\t101\\t0\\t1\\t6\\t2437\\t20\\n'\n"
        "printf 'UCI\\tafter\\t%s\\n' '" + "a" * 64 + "'\n"
        "printf 'RESULT\\t0\\t0\\t0\\t0\\t24\\t" + pcap_sha + "\\t0\\t1\\n'\n"
        "printf 'PCAP-BEGIN\\n'\n"
        "printf '" + pcap_printf + "'\n"
        "IFS= read -r verify || exit 4\n"
        "case \"$verify\" in VERIFY*) exit 5 ;; *) exit 6 ;; esac\n"
    )
    write_executable(bin_dir / "ssh", protocol)
    return pcap_sha


class OpenWrtCaptureTests(unittest.TestCase):
    def test_cli_bounds_and_expected_ap_validation(self) -> None:
        with self.assertRaises(capture.CaptureError):
            capture.validate_capture_limits(11, 1)
        with self.assertRaises(capture.CaptureError):
            capture.validate_capture_limits(21, 1)
        with self.assertRaises(capture.CaptureError):
            capture.validate_capture_limits(12, 4097)
        with self.assertRaises(capture.CaptureError):
            capture.parse_expected_ap("wlan0:0:6:2437:20:extra")

    def test_default_preflight_shell_is_read_only(self) -> None:
        script = capture.build_remote_script(
            ap_interfaces=["wlan0", "wlan1"], selected_interface="wlan1",
            monitor_interface="awdlmon0", expected=[], run_id="a" * 32,
            capture=False,
        )
        self.assertIn("if [ \"$CAPTURE\" -eq 0 ]; then exit 0; fi", script)
        self.assertNotIn('interface add "$MON"', script.split('if [ "$CAPTURE" -eq 0 ]')[0])
        self.assertNotIn('"$TCPDUMP" -nn', script.split('if [ "$CAPTURE" -eq 0 ]')[0])
        argv = capture.build_ssh_argv("root@router", "/tmp/control")
        self.assertLess(len(argv[-1].encode("utf-8")),
                        capture.MAX_BOOTSTRAP_COMMAND_BYTES)
        self.assertGreater(len(script.encode("utf-8")),
                           capture.MAX_BOOTSTRAP_COMMAND_BYTES)
        self.assertNotIn("PREFLIGHT", argv[-1])

    def test_stale_pid_starttime_ticket_is_not_signaled(self) -> None:
        script = capture.build_remote_script(
            ap_interfaces=["wlan0"], selected_interface="wlan0",
            monitor_interface="awdlmon0", expected=[], run_id="d" * 32,
            capture=False)
        functions = []
        for name in ("signal_owned_pid", "signal_pid_ticket"):
            match = re.search(r"(?m)^" + name + r"\(\) \{\n.*?^\}",
                              script, flags=re.S)
            self.assertIsNotNone(match)
            functions.append(match.group(0))
        shell = ("#!/bin/sh\nproc_start_time() { printf '1'; }\n" +
                 "\n".join(functions) + "\n" +
                 "sleep 30 &\npid=$!\ntrap 'kill -KILL \"$pid\" 2>/dev/null || true' EXIT\n" +
                 "ticket=$(mktemp)\nprintf '%s 2\\n' \"$pid\" > \"$ticket\"\n" +
                 "if signal_pid_ticket \"$ticket\" TERM; then exit 3; fi\n" +
                 "kill -0 \"$pid\" || exit 4\nkill -KILL \"$pid\"\nwait \"$pid\" 2>/dev/null || true\n" +
                 "rm -f \"$ticket\"\ntrap - EXIT\n")
        result = subprocess.run(["/bin/sh", "-c", shell],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))

    def test_local_posix_shell_ready_capture_verify_ack_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = ShellFixture(Path(temp), capture_mode=True)
            proc = fixture.popen()
            assert proc.stdout and proc.stdin
            first = read_line(proc.stdout)
            self.assertTrue(first.startswith(b"AP\tbefore\twlan0\t"))
            lines = [first]
            while not any(line.startswith(b"READY\t") for line in lines):
                lines.append(read_line(proc.stdout))
            ready = next(line for line in lines if line.startswith(b"READY\t"))
            self.assertEqual(ready.split(b"\t")[2:], [b"12", b"127"])
            self.assertIn(b"WINDOW\t", read_line(proc.stdout))
            while True:
                line = read_line(proc.stdout)
                lines.append(line)
                if line.startswith(b"RESULT\t"):
                    result = line.split(b"\t")
                    break
            byte_count = int(result[5])
            remote_sha = result[6].decode("ascii")
            self.assertEqual(result[7], b"0", "fd3 reader must not treat stdin as EOF")
            self.assertEqual(result[8], b"1")
            self.assertEqual(proc.stdout.read(len(b"PCAP-BEGIN\n")), b"PCAP-BEGIN\n")
            pcap = proc.stdout.read(byte_count)
            self.assertEqual(len(pcap), byte_count)
            self.assertEqual(pcap[:24], PCAP_HEADER)
            self.assertEqual(hashlib.sha256(pcap).hexdigest(), remote_sha)
            proc.stdin.write(("VERIFY " + remote_sha + "\n").encode("ascii"))
            proc.stdin.flush()
            self.assertEqual(read_line(proc.stdout), b"ACK\tOK")
            self.assertEqual(proc.wait(timeout=3), 0)
            self.assertFalse(fixture.state.exists())
            command_log = fixture.log.read_text()
            self.assertIn("add-monitor", command_log)
            self.assertIn("del-monitor", command_log)
            all_output = b"\n".join(lines).decode("ascii", "replace")
            self.assertNotIn("PRIVATE-SSID", all_output)
            self.assertNotIn("aa:bb:cc:dd:ee:ff", all_output)
            self.assertFalse(list(fixture.remote_tmp.iterdir()))
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()

    def test_preexisting_monitor_is_refused_without_deleting_it(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = ShellFixture(Path(temp), capture_mode=True, existing_monitor=True)
            proc = fixture.popen()
            assert proc.stdout
            output = proc.stdout.read().decode("ascii", "replace")
            self.assertEqual(proc.wait(timeout=2), 2)
            self.assertIn("ERROR\tMONITOR_EXISTS", output)
            self.assertTrue(fixture.state.exists())
            self.assertNotIn("add-monitor", fixture.log.read_text())
            self.assertNotIn("del-monitor", fixture.log.read_text())
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()

    def test_missing_sys_class_is_unknown_and_refuses_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = ShellFixture(Path(temp), capture_mode=True,
                                   sys_class_available=False)
            proc = fixture.popen()
            assert proc.stdout
            output = proc.stdout.read().decode("ascii", "replace")
            self.assertEqual(proc.wait(timeout=2), 2)
            self.assertIn("ERROR\tMONITOR_STATE_UNKNOWN", output)
            self.assertNotIn("PREFLIGHT", output)
            self.assertNotIn("READY", output)
            self.assertNotIn("add-monitor", fixture.log.read_text())
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()

    def test_ap_state_mismatch_stops_before_monitor_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = ShellFixture(Path(temp), capture_mode=True, state_mismatch=True)
            proc = fixture.popen()
            assert proc.stdout
            output = proc.stdout.read().decode("ascii", "replace")
            self.assertEqual(proc.wait(timeout=2), 2)
            self.assertIn("ERROR\tSTATE_MISMATCH", output)
            self.assertNotIn("add-monitor", fixture.log.read_text())
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()

    def test_tcpdump_start_failure_removes_only_created_monitor(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = ShellFixture(Path(temp), capture_mode=True,
                                   tcpdump_start_failure=True)
            proc = fixture.popen()
            assert proc.stdout
            output = proc.stdout.read().decode("ascii", "replace")
            self.assertEqual(proc.wait(timeout=3), 2)
            self.assertIn("ERROR\tTCPDUMP_START_FAILED", output)
            self.assertFalse(fixture.state.exists())
            self.assertIn("add-monitor", fixture.log.read_text())
            self.assertIn("del-monitor", fixture.log.read_text())
            self.assertFalse(list(fixture.remote_tmp.iterdir()))
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()

    def test_changed_ifindex_is_never_deleted_and_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = ShellFixture(Path(temp), capture_mode=True,
                                   index_change_on_down=True)
            proc = fixture.popen()
            assert proc.stdout
            output = proc.stdout.read().decode("ascii", "replace")
            self.assertEqual(proc.wait(timeout=3), 2)
            self.assertIn("ERROR\tMONITOR_CLEANUP_UNCONFIRMED", output)
            report_line = next(line for line in output.splitlines()
                               if line.startswith("CLEANUP_REPORT\t"))
            parts = report_line.split("\t")
            self.assertEqual(parts[2:], ["777", "888", "0"])
            self.assertTrue(fixture.state.exists())
            self.assertNotIn("del-monitor", fixture.log.read_text())
            report = Path("/tmp/iw-awdl-cleanup-" + parts[1] + ".status")
            try:
                self.assertTrue(report.exists())
                self.assertIn("monitor_removed=0", report.read_text())
            finally:
                report.unlink(missing_ok=True)
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()

    def test_uci_export_failure_is_unknown_and_never_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = ShellFixture(Path(temp), capture_mode=True, uci_failure=True)
            proc = fixture.popen()
            assert proc.stdout
            output = proc.stdout.read().decode("ascii", "replace")
            self.assertEqual(proc.wait(timeout=2), 2)
            self.assertIn("ERROR\tUCI_EXPORT_UNAVAILABLE", output)
            self.assertNotIn("PREFLIGHT", output)
            self.assertNotIn("READY", output)
            self.assertNotIn("add-monitor", fixture.log.read_text())
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()

    def test_ack_loss_preserves_complete_verified_private_pcap(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            pcap_sha = install_ack_losing_ssh(bin_dir)
            sock_path = root / "control.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(sock_path))
            output = root / "capture.pcap"
            args = SimpleNamespace(
                host="root@router", control_path=str(sock_path),
                ap=["wlan0"], interface="wlan0", monitor="awdlmon0",
                expect_ap=["wlan0:0:6:2437:20"], capture=True,
                duration=12, max_packets=2, output=str(output),
            )
            try:
                with mock.patch.dict(os.environ, {"PATH": str(bin_dir) + ":/usr/bin:/bin"}):
                    with contextlib.redirect_stdout(io.StringIO()):
                        with self.assertRaises(capture.CaptureError) as raised:
                            capture.run_session(args)
            finally:
                server.close()
            self.assertEqual(raised.exception.code, "CAPTURE_STREAM_INCOMPLETE")
            self.assertEqual(output.read_bytes(), PCAP_HEADER)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            marker = Path(str(output) + ".capture-failed.json")
            self.assertTrue(marker.exists())
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            status = json.loads(marker.read_text())
            self.assertEqual(status["status"], "failed_after_local_pcap_verification")
            self.assertEqual(status["pcap_sha256"], pcap_sha)

    def test_fsync_failure_keeps_hash_verified_pcap_and_failure_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            pcap_sha = install_ack_losing_ssh(bin_dir)
            sock_path = root / "control.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(sock_path))
            output = root / "capture.pcap"
            args = SimpleNamespace(
                host="root@router", control_path=str(sock_path),
                ap=["wlan0"], interface="wlan0", monitor="awdlmon0",
                expect_ap=["wlan0:0:6:2437:20"], capture=True,
                duration=12, max_packets=2, output=str(output),
            )
            original_fsync = os.fsync
            fsync_calls = []

            def fail_first_fsync(fd: int) -> None:
                if not fsync_calls:
                    fsync_calls.append(fd)
                    raise OSError("injected fsync failure")
                original_fsync(fd)

            try:
                with mock.patch.dict(os.environ, {"PATH": str(bin_dir) + ":/usr/bin:/bin"}):
                    with mock.patch.object(capture.os, "fsync", side_effect=fail_first_fsync):
                        with contextlib.redirect_stdout(io.StringIO()):
                            with self.assertRaises(capture.CaptureError) as raised:
                                capture.run_session(args)
            finally:
                server.close()
            self.assertEqual(raised.exception.code, "PCAP_SYNC_FAILED")
            self.assertEqual(output.read_bytes(), PCAP_HEADER)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            marker = Path(str(output) + ".capture-failed.json")
            self.assertTrue(marker.exists())
            status = json.loads(marker.read_text())
            self.assertEqual(status["error"], "PCAP_SYNC_FAILED")
            self.assertEqual(status["pcap_sha256"], pcap_sha)

    def test_sigterm_sends_remote_cancel_before_process_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            log = root / "cancel.log"
            token = "c" * 32
            ssh = r'''#!/bin/sh
IFS= read -r remote_script || exit 9
printf 'AP\tbefore\twlan0\t101\t0\t1\t6\t2437\t20\n'
printf 'UCI\tbefore\t%s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
printf 'PREFLIGHT\t4.99.5\t1.10.5\t1\t1\n'
printf 'READY\t''' + token + r'''\t12\t127\n'
IFS= read -r command || exit 7
printf '%s\n' "$command" > "''' + str(log) + r'''"
if [ "$command" = CANCEL ]; then printf 'ERROR\tCANCELLED\n'; exit 2; fi
exit 8
'''
            write_executable(bin_dir / "ssh", ssh)
            sock_path = root / "control.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(sock_path))
            output = root / "capture.pcap"
            args = [
                sys.executable, str(MODULE_PATH), "--host", "root@router",
                "--control-path", str(sock_path), "--ap", "wlan0",
                "--expect-ap", "wlan0:0:6:2437:20", "--interface", "wlan0",
                "--capture", "--output", str(output), "--duration", "12",
                "--max-packets", "2",
            ]
            env = os.environ.copy()
            env["PATH"] = str(bin_dir) + ":/usr/bin:/bin"
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, env=env)
            try:
                assert proc.stdout is not None
                ready = proc.stdout.readline()
                self.assertIn("READY " + token, ready)
                proc.terminate()
                rest, stderr = proc.communicate(timeout=5)
                self.assertEqual(proc.returncode, 2, stderr)
                self.assertEqual(json.loads(rest.splitlines()[-1])["error"], "CANCELLED")
                self.assertEqual(log.read_text().strip(), "CANCEL")
                self.assertFalse(output.exists())
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=2)
                server.close()

    def test_truncated_or_bad_hash_pcap_never_sends_verify(self) -> None:
        for payload, expected_error in ((PCAP_HEADER[:10], "CAPTURE_STREAM_INCOMPLETE"),
                                        (PCAP_HEADER, "PCAP_HASH_MISMATCH")):
            writes = []
            tmp = tempfile.TemporaryFile(mode="w+b")
            consumer = capture.ProtocolConsumer(
                True, output_file=tmp,
                on_pcap_complete=lambda value: writes.append(value))
            consumer.state.ready_token = "a" * 32
            consumer.state.ready_window_seconds = 12
            consumer.state.ready_link_type = 127
            consumer.state.result = {
                "pcap_bytes_remote": len(PCAP_HEADER),
                "pcap_sha256_remote": "0" * 64,
            }
            consumer.state.pcap_started = True
            if payload == PCAP_HEADER[:10]:
                consumer.feed(payload)
                with self.assertRaises(capture.CaptureError) as raised:
                    consumer.finish()
            else:
                with self.assertRaises(capture.CaptureError) as raised:
                    consumer.feed(payload)
            self.assertEqual(raised.exception.code, expected_error)
            self.assertFalse(writes)
            tmp.close()

    def test_control_socket_must_be_existing_socket(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            plain = Path(temp) / "not-a-socket"
            plain.write_text("x")
            with self.assertRaises(capture.CaptureError):
                capture.validate_control_socket(str(plain))
            sock_path = Path(temp) / "control.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                server.bind(str(sock_path))
                capture.validate_control_socket(str(sock_path))
            finally:
                server.close()


if __name__ == "__main__":
    unittest.main()
