#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the actual Test128 monitor gates with no devices or networking."""
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


DIR = Path(__file__).resolve().parent
SCRIPT = DIR / "openwrt_monitor_window128.sh"
OLD = DIR.parent / "test111" / "openwrt_monitor_window111.sh"
DEFINITIONS = SCRIPT.read_text().rsplit('\nmain "$@"', 1)[0]
TOKEN = "1234567890abcdef1234567890abcdef"
PEER = "02:11:22:33:44:55"
OTHER = "02:11:22:33:44:66"
IDENTITY = "28\t0x9\tmonitor\tchannel 6 (2437 MHz)\n"


def mocked(action, *, cap_exit=0, cap_sha_ok=True, add_ok=True, active_ok=True,
           run_mac=PEER, live_mac=PEER, final_mac=PEER, final_identity=IDENTITY):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp)
        log = path / "events"
        echo = path / "openwrt_echo110"
        echo.write_text(
            '#!/bin/sh\nprintf "echo %s\\n" "$*" >> "$LOG"\nprintf \'READY\\n\'\n'
        )
        echo.chmod(0o700)
        cap = path / "openwrt_active_monitor_capability128"
        cap.write_text(f'#!/bin/sh\nprintf "GET_WIPHY %s\\n" "$1" >> "$LOG"\nexit {cap_exit}\n')
        cap.chmod(0o700)
        for name, value in {
            "owner": TOKEN + "\n", "state": "prepared\n", "monitor.peer-mac": PEER + "\n",
            "monitor.identity": IDENTITY, "lease.seconds": "60\n", "guard.pid": "321\n",
            "guard.ready": TOKEN + " 321 1000\n", "active": TOKEN + "\n",
        }.items():
            (path / name).write_text(value)
        if action == "prepare_action":
            for name in ("owner", "state", "active"):
                (path / name).unlink()
        environment = {
            "STATE_DIR": str(path), "LOG": str(log), "RUN_TOKEN": TOKEN,
            "ACTIVE": str(path / "active"), "ECHO_BIN": str(echo), "PEER_MAC": run_mac,
            "LIVE_MAC": live_mac, "FINAL_MAC": final_mac,
            "FIRST_IDENTITY": IDENTITY, "FINAL_IDENTITY": final_identity,
            "LOCAL_MAC": "02:00:00:00:00:01", "LOCAL_IPV6": "fe80::1",
            "PEER_IPV6": "fe80::2", "NONCE": "1122334455667788",
            "ADD_EXIT": str(0 if add_ok else 95), "ACTIVE_EXIT": str(0 if active_ok else 16),
            "CAP_SHA_OK": str(int(cap_sha_ok)),
        }
        assigns = "\n".join(f"{key}={shlex.quote(value)}" for key, value in environment.items())
        mocks = r'''
export LOG
PHY0=0
PHY1=1
validate_state_path() { :; }
load_phy_map() { :; }
discover_phy_map() { :; }
id() { printf '0\n'; }
kill() { :; }
uptime_cs() { printf '1000\n'; }
phy_for_if() { printf '0\n'; }
iface_is_up() { :; }
event() { printf '%s\n' "$*" >> "$LOG"; }
ip() { event "ip $*"; }
ubus() { event "UNEXPECTED ubus $*"; return 1; }
assert_radio_map() { event "UNEXPECTED assert_radio_map $*"; return 1; }
sha256sum() {
    case "$1" in
        */openwrt_echo110) printf '%s  %s\n' "$ECHO_SHA256" "$1" ;;
        */openwrt_active_monitor_capability128)
            [ "$CAP_SHA_OK" = 1 ] && printf '%s  %s\n' "$CAPABILITY_SHA256" "$1" ||
                printf 'different  %s\n' "$1" ;;
        *) return 1 ;;
    esac
}
iwinfo() { printf 'Channel: 6 (2.437 GHz)\n'; }
info_fields() {
    if [ -e "$STATE_DIR/verified-active" ]; then printf '%s' "$FINAL_IDENTITY"
    else printf '%s' "$FIRST_IDENTITY"; fi
}
iw() {
    case "$*" in
        'phy phy0 interface add iw111mon type monitor flags active')
            event "iw $*"; return "$ADD_EXIT" ;;
        'dev iw111mon set channel 6') event "iw $*" ;;
        'dev iw111mon set monitor active')
            event "iw $*"
            [ "$ACTIVE_EXIT" = 0 ] && : > "$STATE_DIR/verified-active"
            return "$ACTIVE_EXIT" ;;
        'dev iw111mon info')
            if [ -e "$STATE_DIR/verified-active" ]; then printf '  addr %s\n' "$FINAL_MAC"
            else printf '  addr %s\n' "$LIVE_MAC"; fi ;;
        *) event "UNEXPECTED iw $*"; return 1 ;;
    esac
}
'''
        result = subprocess.run(
            ["/bin/sh"], input="\n".join((DEFINITIONS, assigns, mocks, action)),
            text=True, capture_output=True, check=False,
        )
        events = log.read_text().splitlines() if log.exists() else []
        return result, events


class MonitorContractTests(unittest.TestCase):
    def test_plan_is_read_only_and_includes_capability_check(self):
        result = subprocess.run(["/bin/sh", SCRIPT, "--plan"], text=True,
                                capture_output=True, check=True)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["schema"], "test128-openwrt-monitor-window/v1")
        self.assertFalse(plan["echo_rf_action"])
        self.assertTrue(plan["runtime_auto_ack_possible"])
        self.assertIn("GET_WIPHY", " ".join(plan["steps"]))

    def test_prepare_fails_before_claim_or_radio_action_on_capability_errors(self):
        for status, sha_ok, error, events in (
            (3, True, "does not support", ["GET_WIPHY 0"]),
            (4, True, "could not verify", ["GET_WIPHY 0"]),
            (0, False, "SHA256 mismatch", []),
        ):
            with self.subTest(status=status, sha_ok=sha_ok):
                result, calls = mocked("prepare_action", cap_exit=status, cap_sha_ok=sha_ok)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)
                self.assertEqual(calls, events)

    def test_active_add_has_no_fallback(self):
        result, calls = mocked("configure_active_monitor", add_ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ["iw phy phy0 interface add iw111mon type monitor flags active"])

    def test_exact_mac_is_set_before_interface_up(self):
        result, calls = mocked("configure_active_monitor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [
            "iw phy phy0 interface add iw111mon type monitor flags active",
            f"ip link set dev iw111mon address {PEER}",
            "ip link set dev iw111mon up",
            "iw dev iw111mon set channel 6",
        ])

    def test_ready_is_passed_through_only_after_active_and_identity(self):
        result, calls = mocked("run_action", run_mac=PEER.upper())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "READY\n")
        self.assertEqual(calls[:2], ["GET_WIPHY 0", "iw dev iw111mon set monitor active"])
        self.assertIn(f"--peer-mac {PEER}", calls[2])

    def test_run_refuses_peer_or_interface_drift_and_active_failure(self):
        for kwargs, reason in (
            ({"run_mac": OTHER}, "prepared peer MAC"),
            ({"live_mac": OTHER}, "prepared peer MAC"),
            ({"active_ok": False}, "active monitor verification failed"),
            ({"cap_exit": 3}, "does not support"),
            ({"final_mac": OTHER}, "MAC changed during active verification"),
            ({"final_identity": IDENTITY.replace("0x9", "0xa")}, "identity changed"),
            ({"run_mac": "ff:ff:ff:ff:ff:ff"}, "invalid unicast peer MAC"),
        ):
            with self.subTest(kwargs=kwargs):
                result, calls = mocked("run_action", **kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn(reason, result.stderr)
                self.assertFalse(any(call.startswith("echo ") for call in calls))

    def test_watchdog_and_restore_flow_are_inherited_byte_for_byte(self):
        for name in ("terminate_echo", "remove_owned_monitor", "verify_radio0_restored",
                     "restore_runtime", "restore_action", "watchdog_action", "on_exit"):
            start = "\n" + name + "() {\n"
            self.assertEqual(DEFINITIONS.split(start, 1)[1].split("\n}\n", 1)[0],
                             OLD.read_text().split(start, 1)[1].split("\n}\n", 1)[0])


if __name__ == "__main__":
    unittest.main()
