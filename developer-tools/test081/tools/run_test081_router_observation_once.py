#!/usr/bin/env python3
"""One-shot coordinator for passive Test081 channel-149 RX observation.

Default mode only prints the planned gates. --run requires a fresh boot, an
already authenticated OpenWrt control socket, and an explicit nearby-phone
confirmation. It never changes router configuration or retunes either AP.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import select
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
BUILD = '25G332-Test081'
DURATION = 20
MAX_CAPTURE_PACKETS = 4096
CLEANUP_SECONDS = 4.0
TOTAL_SECONDS = 60.0
CAPTURE_SECONDS = DURATION + 5.0
OUTPUT_PARENT = ROOT / 'research/test081-router-runtime-private'
MAX_PROTOCOL_BYTES = 65536


def load_capture():
    sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location(
        'capture_test081_receive149_once', ROOT / 'capture_test081_receive149_once.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ready_event(line):
    return load_capture().ready_event(line)


def receiver_capture_args(python_executable, host, control_path, folder):
    return load_capture().receiver_capture_args(
        python_executable, host, control_path, folder)


class StartFence:
    def __init__(self):
        self.consumed = False

    def release(self, line, callback):
        token = ready_event(line)
        if self.consumed:
            raise ValueError('Duplicate READY; never retry')
        self.consumed = True
        return token, callback()


class ReceiverBudget:
    def __init__(self):
        self.token = None
        self.ready_at = None
        self.window_at = None
        self.remaining = None
        self.closed = False

    def ready(self, line, now):
        if self.token is not None:
            raise ValueError('Duplicate receiver READY')
        self.token = ready_event(line)
        self.ready_at = now

    def window(self, line, now):
        match = re.fullmatch(r'WINDOW ([a-f0-9]{32}) remaining_seconds=(\d+)', line)
        if not match or match.group(1) != self.token:
            raise ValueError('Mismatched receiver window token')
        remaining = int(match.group(2))
        if remaining > DURATION or (self.remaining is not None and remaining > self.remaining):
            raise ValueError('Invalid receiver countdown')
        self.remaining = remaining
        self.window_at = now

    def available(self, now):
        if self.closed or self.ready_at is None or self.window_at is None or now - self.window_at > 1.6:
            return 0.0
        return max(0.0, min(DURATION - (now - self.ready_at),
                            self.remaining - (now - self.window_at)) - 2.0)


def receiver_result_healthy(result, token):
    return (isinstance(result, dict) and result.get('schema_version') == 1 and
            result.get('cancelled') is False and result.get('monitor_removed') is True and
            result.get('state_unchanged') is True and result.get('ready_token') == token and
            type(result.get('tcpdump_exit_code')) is int and result['tcpdump_exit_code'] == 0)


def protocol_lines(state, chunk):
    buffer = state[1] + chunk
    if len(buffer) > MAX_PROTOCOL_BYTES:
        raise ValueError('Capture protocol line exceeds bound')
    lines = []
    while b'\n' in buffer:
        raw, buffer = buffer.split(b'\n', 1)
        lines.append(raw.decode('utf-8'))
    state[1] = buffer
    return lines


def _prepare_private_directory(path, account):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refuse symlinked private output')
    created = False
    try:
        path.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('Private output is not a directory')
    if created:
        os.chown(path, account.pw_uid, account.pw_gid)
        os.chmod(path, 0o700)
        info = path.lstat()
    if info.st_uid != account.pw_uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise PermissionError('Private output ownership or permissions are unsafe')
    return created


def _prepare_output_folder(folder, account):
    folder = Path(folder)
    if folder.parent != OUTPUT_PARENT:
        raise ValueError('Observation folder must be a direct child of Test081 output root')
    _prepare_private_directory(OUTPUT_PARENT, account)
    created = _prepare_private_directory(folder, account)
    if not created:
        raise FileExistsError('Observation output already exists; refusing overwrite/retry')
    return folder


def _write_report(path, report, account):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refuse symlinked coordinator report')
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    flags |= os.O_TRUNC if path.exists() else os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        os.fchown(fd, account.pw_uid, account.pw_gid)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8', closefd=False) as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def _preflight_control_socket(path, account):
    info = os.lstat(path)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != account.pw_uid:
        raise ValueError('Require an existing authenticated workspace-user OpenWrt control socket')


def _stop_group(process, timeout=1.0, sig=signal.SIGTERM):
    if process is None or process.poll() is not None:
        return {'leader': 'not_running', 'signal_sent': False}
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return {'leader': 'not_found', 'signal_sent': True}
    except OSError as error:
        return {'leader': 'signal_error', 'error_type': type(error).__name__, 'signal_sent': True}
    try:
        process.wait(timeout=max(0.0, timeout))
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass
    return {'leader': 'exited' if process.poll() is not None else 'unreaped', 'signal_sent': True}


def _claim_preflight(capture, account, boot):
    claim = capture._claim_directory(account) / ('boot-' + str(boot) + '.json')
    if claim.exists() or claim.is_symlink():
        raise FileExistsError('This boot already has a consumed observation claim; no capture/retry')
    if any(path.exists() or path.is_symlink()
           for path in capture._legacy_claims(capture._claim_directory(account), boot)):
        raise FileExistsError('This boot already has a legacy Test065-Test079 claim; no capture/retry')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--phone-ready', action='store_true')
    parser.add_argument('--host')
    parser.add_argument('--control-path')
    parser.add_argument('--observation-id')
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({
            'mode': 'offline_description', 'capture_started': False,
            'native_rx149_arm_started': False, 'no_router_config_changes': True,
            'same_test081_fresh_boot_required': True,
            'receiver_interface': 'wlan1', 'receiver_channel': 149,
            'receiver_frequency_mhz': 5745, 'ap_width_mhz': 80,
            'receiver_window_seconds': DURATION,
            'receiver_packet_limit': MAX_CAPTURE_PACKETS,
            'packet_limit_is_full_window_guarantee': False,
            'native_profile': 'native_awdl_rx149_observation_only',
            'native_trigger_ms': 100, 'host_tx_blocked_required': True,
            'retries_allowed': False, 'efi_modified': False,
        }, sort_keys=True))
        return 0

    capture = load_capture()
    if os.geteuid() != 0 or not args.phone_ready:
        raise SystemExit('Require root and freshly confirmed nearby/unlocked iPhone')
    if not args.host or not args.control_path or not capture.fresh_observation_id(args.observation_id):
        raise SystemExit('Missing OpenWrt socket/host or invalid observation id')

    # An explicitly disarmed next-boot record must stop before sysctl, ioreg,
    # SSH, output creation, helper build, or any RF-related process.
    try:
        metadata = capture._load_metadata()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit('Test081 next-boot metadata unavailable; no capture; reason=' + type(error).__name__)
    if metadata.get('armed') is not True:
        raise SystemExit('Test081 metadata is disarmed; no system command, capture, or claim')
    boot = capture._sysctl_boot_epoch()
    problems = capture.test081_metadata_problems(metadata, boot_epoch=boot, root=ROOT)
    if problems:
        raise SystemExit('Test081 metadata/build gate failed; no capture; fields=' + ','.join(problems))
    if args.observation_id is None:
        raise SystemExit('Missing observation id')
    account = pwd.getpwuid(ROOT.stat().st_uid)
    try:
        _claim_preflight(capture, account, boot)
        _preflight_control_socket(args.control_path, account)
        folder = _prepare_output_folder(OUTPUT_PARENT / (args.observation_id + '-boot' + str(boot)), account)
    except (OSError, ValueError) as error:
        raise SystemExit('Read-only Test081 preflight failed; no capture/claim; reason=' + type(error).__name__)

    report_path = folder / 'coordinator-private.json'
    report = {
        'schema': 1, 'build': BUILD, 'boot_epoch': boot,
        'observation_id': args.observation_id,
        'profile': capture.PROFILE,
        'capture_started': False, 'native_collector_invocations': 0,
        'native_arm_released': False, 'retry_allowed': False,
        'receiver_interface': 'wlan1', 'receiver_channel': 149,
        'receiver_frequency_mhz': 5745, 'ap_configuration_changed': False,
        'router_observation_windows': [], 'receiver_result': None,
        'receiver_ready_received': False, 'receiver_arm_overlap_proven': False,
        'session_complete': False, 'channel149_rx_observed': None,
        'mif_decode_status': 'unknown_not_inferred_from_session_completion',
        'peer_table_acceptance': None,
        'clock_mapping_proven': False, 'peer_receipt_proven': False,
        'native_awdl_reply_proven': False, 'airdrop_proven': False,
        'efi_modified': False, 'status': 'preflight_passed',
    }
    _write_report(report_path, report, account)
    native_args = [sys.executable, str(ROOT / 'capture_test081_receive149_once.py'),
        '--expect-build', BUILD, '--arm', '--phone-ready', '--receiver-gated',
        '--router-observation-id', args.observation_id, '--output', str(folder)]
    receiver_args = receiver_capture_args(sys.executable, args.host, args.control_path, folder)
    native = receiver = None
    streams = {}
    receiver_state = ReceiverBudget()
    fence = StartFence()
    receiver_ready_line = None
    started = time.monotonic()
    deadline = started + TOTAL_SECONDS
    capture_deadline = deadline - CLEANUP_SECONDS
    try:
        native = subprocess.Popen(native_args, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True)
        report['native_collector_invocations'] = 1
        streams[native.stdout] = ['native', b'']
        while streams:
            remaining = capture_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Bounded Test081 deadline; do not retry this boot')
            readable, _, _ = select.select(list(streams), [], [], min(0.2, remaining))
            for stream in readable:
                name, buffer = streams[stream]
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    if buffer:
                        raise ValueError('Incomplete child protocol line')
                    del streams[stream]
                    if name == 'receiver':
                        receiver_state.closed = True
                    continue
                streams[stream][1] = buffer
                for line in protocol_lines(streams[stream], chunk):
                    now = time.monotonic()
                    if name == 'native':
                        if line == 'NATIVE-PREFLIGHT-READY':
                            if receiver is not None:
                                raise ValueError('Native preflight repeated; no retry')
                            receiver = subprocess.Popen(
                                ['/usr/bin/sudo', '-n', '-u', account.pw_name, '--'] + receiver_args,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, start_new_session=True)
                            streams[receiver.stdout] = ['receiver', b'']
                            report['capture_started'] = True
                            report['capture_deadline_monotonic_ns'] = int(
                                min(now + CAPTURE_SECONDS, capture_deadline) * 1_000_000_000)
                        elif line == 'NATIVE-ARM-RETURNED':
                            report['native_arm_return_parent_monotonic_ns'] = time.monotonic_ns()
                        elif line.startswith('{'):
                            value = json.loads(line)
                            if not isinstance(value, dict):
                                raise ValueError('Malformed native summary')
                            report['native_summary'] = value
                        else:
                            raise ValueError('Unexpected native protocol event')
                    elif line.startswith('READY '):
                        if receiver is None or receiver.poll() is not None:
                            raise ValueError('Receiver stopped before READY')
                        receiver_state.ready(line, now)
                        receiver_ready_line = line
                        report['receiver_run_id'] = receiver_state.token
                        report['receiver_ready_received'] = True
                        report['receiver_ready_parent_monotonic_ns'] = time.monotonic_ns()
                    elif line.startswith('WINDOW '):
                        receiver_state.window(line, now)
                        report['router_observation_windows'].append({
                            'parent_monotonic_ns': time.monotonic_ns(),
                            'remaining_seconds': receiver_state.remaining})
                        if not report['native_arm_released']:
                            if receiver_ready_line is None or receiver_state.available(now) < 6.0:
                                continue
                            token, _ = fence.release(receiver_ready_line, lambda: True)
                            if token != receiver_state.token:
                                raise ValueError('Receiver token changed before arm')
                            if native is None or native.poll() is not None:
                                raise ValueError('Native worker exited before receiver-ready arm')
                            native.stdin.write(b'ARM\n')
                            native.stdin.flush()
                            report['native_arm_released'] = True
                            report['native_arm_release_parent_monotonic_ns'] = time.monotonic_ns()
                            report['receiver_arm_overlap_proven'] = receiver_state.available(now) > 0
                    elif line.startswith('{'):
                        result = json.loads(line)
                        if not isinstance(result, dict):
                            raise ValueError('Malformed receiver result')
                        report['receiver_result'] = result
                        receiver_state.closed = True
                    else:
                        raise ValueError('Unexpected receiver protocol event')
                    _write_report(report_path, report, account)

        if native is not None and native.poll() is None:
            native.wait(timeout=max(0.0, capture_deadline - time.monotonic()))
        if receiver is not None and receiver.poll() is None:
            receiver.wait(timeout=max(0.0, capture_deadline - time.monotonic()))
        report['native_exit'] = native.returncode if native else None
        report['receiver_exit'] = receiver.returncode if receiver else None
        report['receiver_healthy'] = receiver_result_healthy(
            report.get('receiver_result'), report.get('receiver_run_id'))
        native_summary = report.get('native_summary', {})
        report['prepare_diagnostic'] = native_summary.get('prepare_diagnostic')
        report['prepare_rejection_captured'] = bool(
            native_summary.get('prepare_rejection_captured') is True and
            report['receiver_healthy'] and report['native_arm_released'] and
            report['receiver_arm_overlap_proven'])
        report['session_complete'] = native_summary.get('session_complete') is True
        report['channel149_rx_observed'] = native_summary.get(
            'channel149_rx_observed')
        report['mif_decode_status'] = native_summary.get(
            'mif_decode_status', 'unknown_not_inferred_from_session_completion')
        report['peer_table_acceptance'] = native_summary.get(
            'peer_table_acceptance')
        report['complete'] = bool(
            report['session_complete'] and report['native_arm_released'] and
            report['receiver_healthy'] and
            report['receiver_arm_overlap_proven'] and native is not None and
            native.returncode == 0 and native_summary.get('complete') is True)
        report['status'] = ('capture_and_rx149_observation_complete' if report['complete'] else
            'prepare_rejected_diagnostic_captured_no_rx_claim' if report['prepare_rejection_captured'] else
            'incomplete_no_retry')
        _write_report(report_path, report, account)
        print(json.dumps({
            'complete': report['complete'], 'session_complete': report['session_complete'],
            'channel149_rx_observed': report['channel149_rx_observed'],
            'mif_decode_status': report['mif_decode_status'],
            'peer_table_acceptance': report['peer_table_acceptance'],
            'status': report['status'],
            'prepare_diagnostic': report.get('prepare_diagnostic'),
            'prepare_rejection_captured': report['prepare_rejection_captured'],
            'native_collector_invocations': report['native_collector_invocations'],
            'retry_allowed': False, 'ap_configuration_changed': False,
            'efi_modified': False, 'host_management_or_data_tx_blocked': True,
            'peer_receipt_proven': False, 'native_awdl_reply_proven': False,
            'airdrop_proven': False,
        }, sort_keys=True))
        return 0 if report['complete'] else 2
    except (ValueError, TimeoutError, OSError, subprocess.SubprocessError) as error:
        report['complete'] = False
        report['status'] = 'incomplete_no_retry'
        report['error_type'] = type(error).__name__
        try:
            _write_report(report_path, report, account)
        except OSError:
            pass
        print(json.dumps({'complete': False, 'status': 'incomplete_no_retry',
                          'native_collector_invocations': report['native_collector_invocations'],
                          'retry_allowed': False}, sort_keys=True))
        return 2
    finally:
        report['cleanup'] = {
            'native': _stop_group(native, timeout=1.5, sig=signal.SIGTERM),
            'receiver': _stop_group(receiver, timeout=1.5, sig=signal.SIGINT),
        }
        report['total_elapsed_seconds'] = round(time.monotonic() - started, 3)
        try:
            _write_report(report_path, report, account)
        except OSError:
            pass


if __name__ == '__main__':
    raise SystemExit(main())
