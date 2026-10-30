#!/usr/bin/env python3
"""Run one router-only TX-status observation; never ARM the Intel driver.

The frozen Test087 transaction provides the temporary monitor and cleanup.
The Test089 C tool sends exactly one unchanged Test088 probe. Default is plan.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import selectors
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
MAX_LINE = 16384
MAX_OUTPUT = 131072


def validate_event_order(events: list) -> list[str]:
    """The successful C transcript is SEND, zero or more OBSERVATION, RESULT."""
    if (not isinstance(events, list) or len(events) < 2 or
            events[0] != 'TEST089_SEND' or events[-1] != 'TEST089_RESULT' or
            any(event != 'TEST089_OBSERVATION' for event in events[1:-1])):
        return ['json_event_order']
    return []


def validate_result(result: dict, observations: list, token: str,
                    send_events: list) -> list[str]:
    """Validate the send receipt and completed observation as one transcript."""
    errors = []
    send_keys = {'event','run_token','send_attempted','send_completed','send_bytes',
                 'send_errno','send_started_ns','send_finished_ns',
                 'firmware_tx_status_proven','airborne_proven',
                 'rf_delivery_proven','acked_proven'}
    observation_keys = {'event','run_token','kind','packet_type','exact_mpdu_match',
                        'wifi_sequence','awdl_sequence','has_tx_flags','tx_flags',
                        'has_data_retries','data_retries','firmware_tx_status_proven',
                        'airborne_proven','rf_delivery_proven','acked_proven'}
    required = {'event','status','run_token','send_attempted','send_completed',
                'setup_error','send_errno','send_bytes','observation_complete',
                'timeout','recv_error','deadline_reached','capture_limit_reached',
                'rx_window_ms','elapsed_ms',
                'tx_flags_requested','firmware_tx_status_proven','airborne_proven',
                'rf_delivery_proven','acked_proven','counts'}
    if not isinstance(result, dict) or set(result) != required:
        return ['result_field_set']
    if not isinstance(send_events, list) or len(send_events) != 1:
        return ['send_event_count']
    send_event = send_events[0]
    if not isinstance(send_event, dict) or set(send_event) != send_keys:
        return ['send_field_set']
    if send_event['event'] != 'TEST089_SEND' or send_event['run_token'] != token:
        errors.append('send_identity')
    for k in ('send_attempted','send_completed'):
        if send_event[k] is not True: errors.append(f'send_{k}')
    for k in ('firmware_tx_status_proven','airborne_proven',
              'rf_delivery_proven','acked_proven'):
        if send_event[k] is not False: errors.append('send_overclaim')
    for k,v in {'send_bytes':106,'send_errno':0}.items():
        if type(send_event[k]) is not int or send_event[k] != v:
            errors.append(f'send_{k}')
    for k in ('send_started_ns','send_finished_ns'):
        if type(send_event[k]) is not int or send_event[k] <= 0:
            errors.append(k)
    if (type(send_event['send_started_ns']) is int and
            type(send_event['send_finished_ns']) is int and
            send_event['send_finished_ns'] < send_event['send_started_ns']):
        errors.append('send_timestamp_order')
    if result['event'] != 'TEST089_RESULT' or result['run_token'] != token:
        errors.append('result_identity')
    for k in ('send_attempted','send_completed','observation_complete','timeout',
              'deadline_reached'):
        if result[k] is not True:errors.append(k)
    for k in ('firmware_tx_status_proven','airborne_proven',
              'rf_delivery_proven','acked_proven'):
        if result[k] is not False:errors.append(k)
    if result['capture_limit_reached'] is not False:errors.append('capture_limit_reached')
    if type(result['timeout']) is not bool:errors.append('timeout_type')
    for k,v in {'setup_error':0,'send_errno':0,'recv_error':0,'send_bytes':106,'rx_window_ms':2000}.items():
        if type(result[k]) is not int or result[k] != v:errors.append(k)
    if type(result['elapsed_ms']) is not int or not 1999 <= result['elapsed_ms'] <= 4000:
        errors.append('elapsed_ms')
    if result['tx_flags_requested'] != 'NOACK|NOSEQNO':errors.append('tx_flags_requested')
    counts = result['counts']
    keys = {'rx_packets','probe_matches','outgoing_echo','host_driver_completion_candidate','other_match'}
    if not isinstance(counts, dict) or set(counts) != keys:
        return errors + ['counts_field_set']
    if any(type(v) is not int or v < 0 for v in counts.values()):
        return errors + ['counts_type']
    if counts['rx_packets'] < counts['probe_matches']:errors.append('count_order')
    classified = {'outgoing_echo':0,'host_driver_completion_candidate':0,'other_match':0}
    if not isinstance(observations, list):
        return errors + ['observations_type']
    for row in observations:
        if not isinstance(row, dict) or set(row) != observation_keys:
            errors.append('observation_field_set')
            continue
        if (row.get('event') != 'TEST089_OBSERVATION' or row.get('run_token') != token or
                row.get('exact_mpdu_match') is not True or row.get('wifi_sequence') != 291 or
                row.get('awdl_sequence') != 34305):
            errors.append('observation_identity');continue
        if (type(row['packet_type']) is not int or
                not 0 <= row['packet_type'] <= 7 or
                type(row['has_tx_flags']) is not bool or
                type(row['has_data_retries']) is not bool or
                type(row['tx_flags']) is not int or not 0 <= row['tx_flags'] <= 0xffff or
                type(row['data_retries']) is not int or not 0 <= row['data_retries'] <= 0xff):
            errors.append('observation_types')
            continue
        if any(row.get(k) is not False for k in (
                'firmware_tx_status_proven','airborne_proven',
                'rf_delivery_proven','acked_proven')):
            errors.append('observation_overclaim')
        if ((not row['has_tx_flags'] and row['tx_flags'] != 0) or
                (not row['has_data_retries'] and row['data_retries'] != 0)):
            errors.append('absent_radiotap_value')
        kind = row.get('kind')
        if kind == 'packet_outgoing_echo':
            classified['outgoing_echo'] += 1
            if (row['packet_type'] != 4 or not row['has_tx_flags'] or
                    row['tx_flags'] != 0x18 or row['has_data_retries']):
                errors.append('outgoing_packet_type_or_radiotap')
        elif kind == 'host_driver_completion_candidate':
            classified[kind] += 1
            if (row['packet_type'] != 3 or not row['has_tx_flags'] or
                    not row['has_data_retries']):
                errors.append('completion_fields')
        elif kind == 'other_matching_packet':
            classified['other_match'] += 1
        else:
            errors.append('observation_kind')
    if any(classified[k] != counts[k] for k in classified):errors.append('observation_counts')
    if counts['probe_matches'] != sum(classified.values()):errors.append('probe_matches')
    for key in ('send_attempted','send_completed','send_bytes','send_errno'):
        if result[key] != send_event[key]: errors.append('send_result_mismatch')
    expected = ('host_driver_completion_candidate_observed' if classified['host_driver_completion_candidate']
                else 'no_status_candidate_observed' if classified['other_match']
                else 'outgoing_echo_only' if classified['outgoing_echo'] else 'no_matching_observation')
    if result['status'] != expected:errors.append('status_counts')
    return errors


def load_router():
    directory = ROOT / 'developer-tools/test087'
    sys.path.insert(0, str(directory))
    path = directory / 'run_controlled_probe_once.py'
    spec = importlib.util.spec_from_file_location('test089_router_transport', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_script(router, binary: bytes, digest: str, token: str, ap: str) -> str:
    script = router.protocol.build_remote_monitor_sender_script(
        binary=binary, binary_sha256=digest, run_token=token,
        ap=ap, monitor='iwtx089')
    old = '"$BIN" --send --interface "$MON" --count 16 --interval-ms 80 --nonce "$RUN_TOKEN" --wait-go <&3 &'
    new = '"$BIN" --send --interface "$MON" --nonce "$RUN_TOKEN" --wait-go <&3 &'
    if script.count(old) != 1:
        raise ValueError('frozen sender command changed')
    return script.replace(old, new).replace('/tmp/iwn-t087-controlled-', '/tmp/iwn-t089-status-')


def write_private(path: Path, report: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def run(args) -> dict:
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('output already exists')
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = args.output.parent.lstat()
    if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid()
            or stat.S_IMODE(parent_info.st_mode) != 0o700):
        raise ValueError('output parent must be owned by this user with mode 0700')
    if args.binary.is_symlink() or not args.binary.is_file():
        raise ValueError('sender is not a regular file')
    binary = args.binary.read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    if digest != args.sha256:
        raise ValueError('sender digest differs')
    router = load_router()
    argv = router.build_bootstrap_argv(args.host, str(args.control_path))
    token = secrets.token_hex(16)
    script = build_script(router, binary, digest, token, args.ap)
    report = {'schema': 'test089-router-tx-status/v1', 'run_token': token,
              'sender_sha256': digest, 'script_sha256': hashlib.sha256(script.encode()).hexdigest(),
              'intel_arm_invoked': False, 'efi_written': False, 'wan_lan_changed': False,
              'go_sent': False, 'go_write_attempted': False, 'lines': [],
              'json_event_order': [], 'send_events': [], 'observations': [], 'status': 'starting',
              'rf_transmission_proven': False, 'peer_receipt_proven': False}
    process = None
    selector = selectors.DefaultSelector()
    pending = bytearray()
    total = 0
    ready = False
    monitor = None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, bufsize=0)
        process.stdin.write(router.remote_script_bytes(script))
        process.stdin.flush()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            events = selector.select(min(0.25, max(0, deadline - time.monotonic())))
            if not events:
                if process.poll() is not None:
                    break
                continue
            chunk = os.read(process.stdout.fileno(), 8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_OUTPUT:
                raise ValueError('output limit')
            pending.extend(chunk)
            if b'\n' not in pending and len(pending) > MAX_LINE:
                raise ValueError('line limit')
            while b'\n' in pending:
                line_bytes, _, pending = pending.partition(b'\n')
                if len(line_bytes) > MAX_LINE:
                    raise ValueError('line limit')
                line = line_bytes.decode('utf-8', errors='strict').rstrip('\r')
                report['lines'].append(line)
                if line.startswith('MONITOR_READY '):
                    if monitor is not None:
                        raise ValueError('duplicate monitor readiness')
                    monitor = router.protocol.parse_monitor_ready(line)
                    report['monitor_ready'] = monitor
                elif line.startswith('READY '):
                    if ready or monitor is None or report.get('remote_error'):
                        raise ValueError('sender readiness order')
                    if line != 'READY frames=1 packet_bytes=106 rx_window_ms=2000':
                        raise ValueError('sender readiness contract')
                    ready = True
                    report['go_write_attempted'] = True
                    process.stdin.write(('GO ' + token + '\n').encode())
                    process.stdin.flush()
                    report['go_sent'] = True
                    deadline = time.monotonic() + 8
                elif line.startswith('CLEANUP '):
                    if 'cleanup' in report:
                        raise ValueError('duplicate cleanup')
                    cleanup = json.loads(line[len('CLEANUP '):])
                    if cleanup.get('run_token') != token:
                        raise ValueError('cleanup identity')
                    report['cleanup'] = cleanup
                elif line.startswith('{'):
                    item = json.loads(line)
                    report['json_event_order'].append(item.get('event'))
                    if item.get('event') == 'TEST089_SEND':
                        if (report['send_events'] or not report['go_sent'] or
                                'result' in report):
                            raise ValueError('send event order or duplicate')
                        report['send_events'].append(item)
                    elif item.get('event') == 'TEST089_OBSERVATION':
                        if not report['send_events'] or 'result' in report:
                            raise ValueError('observation event order')
                        report['observations'].append(item)
                    if item.get('event') == 'TEST089_RESULT':
                        if ('result' in report or item.get('run_token') != token or
                                not report['send_events']):
                            raise ValueError('result identity or duplicate')
                        report['result'] = item
                elif line.startswith('REMOTE_ERROR '):
                    # The remote EXIT trap still reports cleanup after errors.
                    report['remote_error'] = line
        if pending:
            report['trailing_output'] = pending.decode('utf-8', errors='replace')[:MAX_LINE]
        try:
            report['exit_code'] = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            raise ValueError('remote deadline')
        cleanup = report.get('cleanup', {})
        cleaned = all(cleanup.get(k) is True for k in
                      ('monitor_removed','ap_unchanged','temporary_files_removed'))
        result = report.get('result')
        report['result_validation_errors'] = validate_result(
            result, report['observations'], token, report['send_events'])
        report['result_validation_errors'].extend(
            validate_event_order(report['json_event_order']))
        report['complete'] = (report['exit_code'] == 0 and ready and cleaned and
                              not report.get('remote_error') and
                              not report['result_validation_errors'])
        report['status'] = ('captured_router_only' if report['complete'] else 'incomplete')
    except Exception as error:
        report.update(status='stopped', complete=False, error=str(error))
    finally:
        selector.close()
        if process is not None:
            if process.stdin:
                process.stdin.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
        write_private(args.output, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--host')
    parser.add_argument('--control-path', type=Path)
    parser.add_argument('--ap')
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'mode':'plan', 'max_frames':1, 'rx_window_ms':2000,
                          'intel_arm':False, 'efi_write':False, 'wan_lan_write':False}))
        return 0
    if any(getattr(args,k) is None for k in ('host','control_path','ap','binary','sha256','output')):
        parser.error('run requires host, control-path, ap, binary, sha256 and output')
    value = run(args)
    print(json.dumps({k:value.get(k) for k in ('status','complete','go_sent','exit_code')}))
    return 0 if value.get('complete') else 1


if __name__ == '__main__':
    raise SystemExit(main())
