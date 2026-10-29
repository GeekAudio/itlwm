import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import observe_continuity_window as observer  # noqa: E402


class FakeTimedOutChild:
    def __init__(self, now):
        self.now = now
        self.returncode = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.killed:
            self.returncode = -9
            return self.returncode
        if self.terminated:
            raise subprocess.TimeoutExpired("mock-child", timeout)
        self.now[0] += 1_000_000_000
        raise subprocess.TimeoutExpired("mock-child", timeout)

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class ObserveContinuityWindowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.research = self.root / "research"
        self.research.mkdir(mode=0o700)
        self.research.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def test_default_is_disarmed_and_does_not_spawn_commands(self):
        output = io.StringIO()
        with mock.patch.object(observer.subprocess, "Popen", side_effect=AssertionError("must stay disarmed")) as popen:
            with mock.patch.object(observer, "RESEARCH_DIR", self.research):
                with contextlib.redirect_stdout(output):
                    self.assertEqual(observer.main([]), 0)
        popen.assert_not_called()
        self.assertEqual(list(self.research.iterdir()), [])
        self.assertIn("默认安全模式", output.getvalue())

    def test_capture_rejects_invalid_duration_and_interface_before_spawn(self):
        with mock.patch.object(observer.subprocess, "Popen", side_effect=AssertionError("must not spawn")) as popen:
            with mock.patch.object(observer, "RESEARCH_DIR", self.research):
                for args in (
                    ["--capture", "--interface", "en0", "--duration", "14", "--output-dir", str(self.research / "run1")],
                    ["--capture", "--interface", "en0;touch", "--output-dir", str(self.research / "run2")],
                ):
                    with contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit):
                            observer.main(args)
        popen.assert_not_called()
        self.assertEqual(list(self.research.iterdir()), [])

    def test_output_must_be_new_direct_research_child(self):
        outside = self.root / "outside"
        with self.assertRaises(observer.InputError):
            observer.prepare_output_dir(str(outside), self.research)
        existing = self.research / "existing"
        existing.mkdir(mode=0o700)
        with self.assertRaises(observer.InputError):
            observer.prepare_output_dir(str(existing), self.research)
        created = observer.prepare_output_dir(str(self.research / "new"), self.research)
        self.assertEqual(os.stat(created).st_mode & 0o777, 0o700)
        created.rmdir()

    def test_deadline_timeout_terminates_then_kills_and_waits(self):
        now = [0]
        child = FakeTimedOutChild(now)
        status, code = observer._wait_child(child, observer.StopState(), 1_000_000_000, lambda: now[0])
        self.assertEqual(status, "timed_out")
        self.assertEqual(code, -9)
        self.assertTrue(child.terminated)
        self.assertTrue(child.killed)
        self.assertIsNotNone(child.returncode)

    def test_log_command_requests_info_level(self):
        proc = mock.Mock()
        with mock.patch.object(observer.subprocess, "Popen", return_value=proc) as popen:
            child, output, info = observer._start_log_stream(self.research)
            command = popen.call_args.args[0]
            self.assertIn("info", command)
            self.assertIn("--level", command)
            self.assertEqual(command[command.index("--style") + 1], "ndjson")
            output.close()

    def test_early_log_exit_is_not_reported_as_full_window(self):
        proc = mock.Mock()
        proc.poll.return_value = 1
        info = {"status":"running"}
        observer._finish_log_stream(proc, None, info)
        self.assertEqual(info["status"], "exited_before_cleanup")
        self.assertFalse(info["alive_at_cleanup_boundary"])
        proc.terminate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
