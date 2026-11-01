#!/usr/bin/env python3
"""Offline proof that an outer timeout terminates a wrapper and its child group."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).with_name("bounded_process.py")
SPEC = importlib.util.spec_from_file_location("test100_run_rx_timeout", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProcessGroupTimeoutTests(unittest.TestCase):
    def _run_child_case(self, *, close_child_stdio: bool) -> Path:
        with tempfile.TemporaryDirectory(prefix="test100-timeout-test-") as temp:
            marker = Path(temp) / "late-child-marker"
            child_code = (
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "time.sleep(0.8); pathlib.Path(%r).write_text('survived')"
            ) % str(marker)
            stdio = (
                "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, "
                "stdin=subprocess.DEVNULL"
                if close_child_stdio else ""
            )
            parent_code = (
                "import subprocess,sys,time; "
                "subprocess.Popen([sys.executable, '-c', %r]%s); "
                "print('child-spawned', flush=True); time.sleep(30)"
            ) % (child_code, ", " + stdio if stdio else "")

            result = MODULE.run_wrapper_process_group(
                [sys.executable, "-c", parent_code],
                timeout=0.1,
                term_grace_seconds=0.1,
            )
            self.assertTrue(result["timed_out"])
            cleanup = result["timeout_cleanup"]
            self.assertTrue(cleanup["sigterm_sent"])
            self.assertTrue(cleanup["sigkill_sent"])
            self.assertTrue(cleanup["process_reaped"])
            if not close_child_stdio:
                self.assertIn("child-spawned", result["stdout"])

            time.sleep(0.9)
            self.assertFalse(marker.exists(), "grandchild survived timeout and could act later")

            # Return a detached path so the TemporaryDirectory context can end;
            # the marker assertion above proves the child did not create it.
            return marker

    def test_timeout_terminates_child_process_group(self) -> None:
        self._run_child_case(close_child_stdio=False)

    def test_timeout_kills_grandchild_after_stdio_is_closed(self) -> None:
        self._run_child_case(close_child_stdio=True)


if __name__ == "__main__":
    unittest.main()
