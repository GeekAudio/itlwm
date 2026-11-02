#!/usr/bin/env python3
"""Offline plan, CLI, and mocked restore-flow tests for Test111."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
import uuid
from typing import Optional


SCRIPT = Path(__file__).with_name("openwrt_monitor_window111.sh")
SOURCE = SCRIPT.read_text()
DEFINITIONS = SOURCE.rsplit('\nmain "$@"', 1)[0]


def run_restore_mock(*, token: str, active: Optional[str], state: str = "prepared",
                     terminate_ok: bool = True, ap_ok: bool = True,
                     owner_written: bool = True) -> subprocess.CompletedProcess[str]:
    temp = tempfile.TemporaryDirectory()
    root = Path(temp.name)
    state_dir = root / "state"
    state_dir.mkdir(mode=0o700)
    if owner_written:
        (state_dir / "owner").write_text(token + "\n")
    (state_dir / "state").write_text(state + "\n")
    log = root / "events.log"
    active_path = root / "active"
    if active is not None:
        active_path.write_text(active + "\n")
    script = DEFINITIONS + f"""
RUN_TOKEN={shlex.quote(token)}
STATE_DIR={shlex.quote(str(state_dir))}
ACTIVE={shlex.quote(str(active_path))}
LOCK={shlex.quote(str(root / 'lock'))}
LOG={shlex.quote(str(log))}
validate_state_path() {{ :; }}
validate_owner() {{ :; }}
event() {{ printf '%s\\n' "$1" >> "$LOG"; }}
terminate_echo() {{ event terminate; return {0 if terminate_ok else 1}; }}
remove_owned_monitor() {{ event remove-monitor; return 0; }}
ubus() {{ event "ubus $*"; return 0; }}
verify_radio0_restored() {{ event verify-radio0; return {0 if ap_ok else 1}; }}
assert_radio1_unchanged() {{ event verify-radio1; return 0; }}
assert_config_unchanged() {{ event verify-config; return 0; }}
sleep() {{ :; }}
cancel_guard_after_verified_restore() {{ event cancel-guard; clear_active_after_success; }}
restore_action
printf 'FINAL_ACTIVE=%s\\n' "$(active_token)"
printf 'FINAL_STATE=%s\\n' "$(cat "$STATE_DIR/state" 2>/dev/null || true)"
"""
    result = subprocess.run(["/bin/sh"], input=script, text=True,
                            capture_output=True, check=False)
    result._test_tempdir = temp  # Keep mock files alive for the caller's assertions.
    result._test_log = log
    result._test_active = active_path
    result._test_state = state_dir / "state"
    return result


def make_mock_watchdog_proc(state_dir: Path, pid: str, token: str,
                            *, command_token: Optional[str] = None) -> Path:
    proc_dir = state_dir / "proc" / pid
    proc_dir.mkdir(parents=True)
    (proc_dir / "exe").symlink_to("/bin/sh")
    command_token = command_token or token
    argv = ["sh", str(state_dir / "monitor_window111.sh"), "--watchdog",
            "--state-dir", str(state_dir), "--run-token", command_token,
            "--lease-seconds", "60"]
    (proc_dir / "cmdline").write_bytes(b"\0".join(arg.encode() for arg in argv) + b"\0")
    return proc_dir


class MonitorWindowTests(unittest.TestCase):
    def test_state_directory_metadata_uses_strict_numeric_ls_fields(self):
        token = uuid.uuid4().hex
        state_dir = Path("/tmp") / f"iw111echo-{token}"
        state_dir.mkdir(mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(state_dir, ignore_errors=True))
        harness_path = state_dir / "monitor_window111.sh"

        def validate(ls_output: str) -> subprocess.CompletedProcess[str]:
            script = DEFINITIONS + f"""
RUN_TOKEN={shlex.quote(token)}
STATE_DIR={shlex.quote(str(state_dir))}
ls() {{ printf '%s\\n' "$MOCK_LS"; }}
validate_state_path
"""
            harness_path.write_text(script)
            env = os.environ.copy()
            env["MOCK_LS"] = ls_output
            return subprocess.run(["/bin/sh", str(harness_path)], text=True,
                                  capture_output=True, env=env, check=False)

        good = f"drwx------ 2 0 0 4096 Nov 2 12:00 {state_dir}"
        self.assertEqual(validate(good).returncode, 0)
        self.assertNotEqual(validate(good.replace("drwx------", "drwxr-xr-x")).returncode, 0)
        self.assertNotEqual(validate(good.replace(" 2 0 0 ", " 2 501 0 ")).returncode, 0)
        self.assertNotEqual(validate(good + "\n" + good).returncode, 0)

    def test_watchdog_waits_for_parent_pid_receipt_before_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = uuid.uuid4().hex
            state_dir = root / "state"
            state_dir.mkdir()
            active = root / "active"
            active.write_text(token + "\n")
            (state_dir / "owner").write_text(token + "\n")
            script = DEFINITIONS + f"""
RUN_TOKEN={shlex.quote(token)}
STATE_DIR={shlex.quote(str(state_dir))}
ACTIVE={shlex.quote(str(active))}
LEASE_SECONDS=30
SCRIPT_PATH={shlex.quote(str(state_dir / 'monitor_window111.sh'))}
validate_state_path() {{ :; }}
validate_owner() {{ :; }}
uptime_cs() {{ printf '100\\n'; }}
sleep() {{
    if [ ! -e "$STATE_DIR/guard.pid" ]; then printf '%s\\n' "$$" > "$STATE_DIR/guard.pid";
    else : > "$STATE_DIR/cancel"; fi
}}
printf 'PID=%s\\n' "$$"
watchdog_action
"""
            result = subprocess.run(["/bin/sh"], input=script, text=True,
                                    capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            shell_pid = result.stdout.strip().split("=", 1)[1]
            ready = (state_dir / "guard.ready").read_text().split()
            self.assertEqual(ready[:2], [token, shell_pid])
            self.assertTrue((state_dir / "cancel").exists())

    def test_guard_cancel_refuses_pid_reuse_and_cancels_only_matching_run(self):
        token = uuid.uuid4().hex
        pid = "43210"

        def run_cancel(*, command_token: str):
            temp = tempfile.TemporaryDirectory()
            root = Path(temp.name)
            state_dir = root / "state"
            state_dir.mkdir()
            active = root / "active"
            active.write_text(token + "\n")
            (state_dir / "guard.pid").write_text(pid + "\n")
            (state_dir / "guard.ready").write_text(f"{token} {pid} 100\n")
            make_mock_watchdog_proc(state_dir, pid, token, command_token=command_token)
            script = DEFINITIONS + f"""
RUN_TOKEN={shlex.quote(token)}
STATE_DIR={shlex.quote(str(state_dir))}
ACTIVE={shlex.quote(str(active))}
PROC_ROOT={shlex.quote(str(state_dir / 'proc'))}
SCRIPT_PATH={shlex.quote(str(state_dir / 'monitor_window111.sh'))}
MOCK_PID={shlex.quote(pid)}
MOCK_LOG={shlex.quote(str(root / 'signals'))}
LOCK_HELD=0
MOCK_DEAD=0
kill() {{
    if [ "$1" = -0 ] && [ "$2" = "$MOCK_PID" ]; then [ "$MOCK_DEAD" = 0 ]; return; fi
    if [ "$1" = -TERM ] && [ "$2" = "$MOCK_PID" ]; then
        printf 'TERM\\n' >> "$MOCK_LOG"
        MOCK_DEAD=1
        return 0
    fi
    return 1
}}
sleep() {{ :; }}
cancel_guard_after_verified_restore || exit $?
printf 'FINAL_ACTIVE=%s\\n' "$(active_token)"
"""
            result = subprocess.run(["/bin/sh"], input=script, text=True,
                                    capture_output=True, check=False)
            result._test_tempdir = temp
            result._test_log = root / "signals"
            result._test_active = active
            result._test_cancel = state_dir / "cancel"
            return result

        mismatch = run_cancel(command_token=uuid.uuid4().hex)
        self.addCleanup(mismatch._test_tempdir.cleanup)
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertFalse(mismatch._test_log.exists())
        self.assertFalse(mismatch._test_cancel.exists())
        self.assertEqual(mismatch._test_active.read_text().strip(), token)

        matching = run_cancel(command_token=token)
        self.addCleanup(matching._test_tempdir.cleanup)
        self.assertEqual(matching.returncode, 0, matching.stderr)
        self.assertEqual(matching._test_log.read_text().splitlines(), ["TERM"])
        self.assertTrue(matching._test_cancel.exists())
        self.assertFalse(matching._test_active.exists())

    def test_prepare_cleanup_refuses_to_term_reused_watchdog_pid(self):
        token, pid = uuid.uuid4().hex, "43211"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_dir = root / "state"
            state_dir.mkdir()
            active = root / "active"
            active.write_text(token + "\n")
            (state_dir / "guard.pid").write_text(pid + "\n")
            make_mock_watchdog_proc(state_dir, pid, token,
                                    command_token=uuid.uuid4().hex)
            script = DEFINITIONS + f"""
RUN_TOKEN={shlex.quote(token)}
STATE_DIR={shlex.quote(str(state_dir))}
ACTIVE={shlex.quote(str(active))}
PROC_ROOT={shlex.quote(str(state_dir / 'proc'))}
SCRIPT_PATH={shlex.quote(str(state_dir / 'monitor_window111.sh'))}
ACTION=prepare
PREPARE_SUCCEEDED=0
PREPARE_IN_PROGRESS=0
LOCK_HELD=0
MOCK_PID={shlex.quote(pid)}
MOCK_LOG={shlex.quote(str(root / 'signals'))}
kill() {{
    if [ "$1" = -0 ] && [ "$2" = "$MOCK_PID" ]; then return 0; fi
    printf '%s\\n' "$1 $2" >> "$MOCK_LOG"
    return 0
}}
radio_field() {{ printf true; }}
assert_radio1_unchanged() {{ return 0; }}
assert_config_unchanged() {{ return 0; }}
on_exit
"""
            result = subprocess.run(["/bin/sh"], input=script, text=True,
                                    capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "signals").exists())
            self.assertEqual(active.read_text().strip(), token)
            self.assertIn("refusing to signal a PID that is not this run watchdog", result.stderr)

    def test_no_argument_mode_is_read_only_plan(self):
        with tempfile.TemporaryDirectory() as mock_bin:
            marker = Path(mock_bin, "unexpected-router-command")
            for command in ("ubus", "iw", "iwinfo"):
                stub = Path(mock_bin, command)
                stub.write_text(f"#!/bin/sh\\nprintf called > '{marker}'\\nexit 99\\n")
                stub.chmod(0o700)
            env = os.environ.copy()
            env["PATH"] = f"{mock_bin}:{env.get('PATH', '/usr/bin:/bin')}"
            result = subprocess.run(["/bin/sh", str(SCRIPT)], text=True,
                                    capture_output=True, env=env, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertFalse(plan["echo_rf_action"])
        self.assertTrue(plan["runtime_wifi_change"])
        self.assertFalse(plan["persistent_config_write"])
        self.assertFalse(plan["wan_lan_change"])
        self.assertFalse(marker.exists())

    def test_prepare_cli_parses_mode_before_path_validation_without_router_calls(self):
        token = uuid.uuid4().hex
        with tempfile.TemporaryDirectory() as mock_bin:
            marker = Path(mock_bin, "unexpected-ubus")
            stub = Path(mock_bin, "ubus")
            stub.write_text(f"#!/bin/sh\\nprintf called > '{marker}'\\nexit 99\\n")
            stub.chmod(0o700)
            env = os.environ.copy()
            env["PATH"] = f"{mock_bin}:{env.get('PATH', '/usr/bin:/bin')}"
            result = subprocess.run(
                ["/bin/sh", str(SCRIPT), "--prepare", "--state-dir",
                 f"/tmp/iw111echo-{token}", "--run-token", token],
                text=True, capture_output=True, env=env, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("state directory must already exist", result.stderr)
        self.assertNotIn("unknown mode", result.stderr)
        self.assertFalse(marker.exists())

    def test_echo_timeout_or_exit_failure_stops_before_monitor_and_ap(self):
        token = uuid.uuid4().hex
        result = run_restore_mock(token=token, active=token, terminate_ok=False)
        self.addCleanup(result._test_tempdir.cleanup)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result._test_log.read_text().splitlines(), ["terminate"])
        self.assertEqual(result._test_active.read_text().strip(), token)
        self.assertNotIn("cancel-guard", result.stderr + result.stdout)

    def test_ap_verification_failure_keeps_guard_and_active_token(self):
        token = uuid.uuid4().hex
        result = run_restore_mock(token=token, active=token, ap_ok=False)
        self.addCleanup(result._test_tempdir.cleanup)
        self.assertNotEqual(result.returncode, 0)
        events = result._test_log.read_text().splitlines()
        self.assertEqual(events[:3], ["terminate", "remove-monitor", 'ubus call network.wireless up {"device":"radio0"}'])
        self.assertIn("verify-radio0", events)
        self.assertNotIn("cancel-guard", events)
        self.assertEqual(result._test_active.read_text().strip(), token)

    def test_success_has_ordered_restore_and_clears_only_its_active_token(self):
        token = uuid.uuid4().hex
        result = run_restore_mock(token=token, active=token)
        self.addCleanup(result._test_tempdir.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = result._test_log.read_text().splitlines()
        self.assertEqual(events, [
            "terminate", "remove-monitor", 'ubus call network.wireless up {"device":"radio0"}',
            "verify-radio0", "verify-radio1", "verify-config", "cancel-guard",
        ])
        self.assertIn("FINAL_ACTIVE=", result.stdout)
        self.assertIn("FINAL_STATE=restored", result.stdout)
        self.assertFalse(result._test_active.exists())

    def test_old_token_cannot_touch_new_run_and_restored_retry_is_read_only(self):
        old_token, new_token = uuid.uuid4().hex, uuid.uuid4().hex
        stale = run_restore_mock(token=old_token, active=new_token)
        self.addCleanup(stale._test_tempdir.cleanup)
        self.assertNotEqual(stale.returncode, 0)
        self.assertEqual(stale._test_log.read_text() if stale._test_log.exists() else "", "")
        self.assertEqual(stale._test_active.read_text().strip(), new_token)

        restored = run_restore_mock(token=old_token, active=None, state="restored")
        self.addCleanup(restored._test_tempdir.cleanup)
        self.assertEqual(restored.returncode, 0, restored.stderr)
        events = restored._test_log.read_text().splitlines()
        self.assertEqual(events, ["verify-radio0", "verify-radio1", "verify-config"])
        self.assertIn('"idempotent":true', restored.stdout)
        self.assertFalse(restored._test_active.exists())

        untouched = run_restore_mock(token=old_token, active=None, owner_written=False)
        self.addCleanup(untouched._test_tempdir.cleanup)
        self.assertEqual(untouched.returncode, 0, untouched.stderr)
        self.assertEqual(untouched._test_log.read_text() if untouched._test_log.exists() else "", "")
        self.assertIn("prepare never claimed this token", untouched.stdout)


if __name__ == "__main__":
    unittest.main()
