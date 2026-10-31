from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


TOOL_DIR = Path(__file__).resolve().parent
ADAPTER_PATH = TOOL_DIR / "native_controlled_capture_test099.py"
SPEC = importlib.util.spec_from_file_location(
    "test099_native_worker_adapter_under_test", ADAPTER_PATH)
assert SPEC and SPEC.loader
adapter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)


class NativeWorkerAdapterTests(unittest.TestCase):
    def test_hooks_are_installed_in_actual_worker_function_globals(self):
        worker = adapter.load_test087_worker()
        captured_commands = []
        run_token = "0123456789abcdef0123456789abcdef"
        worker._wait_for_helper_gate = lambda: ("ARM", run_token)

        adapter.configure_worker(worker.__dict__)

        self.assertIs(worker.main.__globals__, worker.__dict__)
        self.assertIs(worker._native_preflight.__globals__, worker.__dict__)
        self.assertEqual(worker.HELPER_SOURCE, adapter.TEST099_ARM_HELPER)
        self.assertEqual(worker._wait_for_helper_gate(), ("ARM", run_token))

        with mock.patch.object(adapter._subprocess, "run",
                               side_effect=lambda command, *args, **kwargs:
                               captured_commands.append(command) or object()):
            worker.subprocess.run([
                "/tmp/arm-p2p-rx149", "--expect-build", "Test099"])
        self.assertEqual(captured_commands, [[
            "/tmp/arm-p2p-rx149", "--expect-build", "Test099",
            "--run-token", run_token]])

    def test_nested_test087_helper_loader_uses_test099_source(self):
        worker = adapter.load_test087_worker()
        adapter.configure_worker(worker.__dict__)

        nested = worker._load_module(
            "test087_controlled_protocol",
            worker.TOOL_DIR / "test087_controlled.py")

        self.assertEqual(nested.HELPER_SOURCE, adapter.TEST099_ARM_HELPER)


if __name__ == "__main__":
    unittest.main()
