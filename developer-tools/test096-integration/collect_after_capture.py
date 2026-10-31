#!/usr/bin/env python3
"""Read-only ROC correlation collection after the existing bounded diagnostic.

This command never arms a probe, sends a frame, or changes EFI. It retains the
original capture and writes a separate result. Missing evidence stays unknown.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = '25G332-Test096'
MODULES = ROOT / 'developer-tools/test096'
sys.path.insert(0, str(MODULES))
from roc_rx_correlation_runtime import derive_closed_identity
from roc_rx_correlation_collect import collect_after_closed_marker


def bind_capture(report, build, boot, loaded_uuid):
    identity = report.get('identity', {})
    expected = build.get('mach_o_uuid')
    if (report.get('candidate') != CANDIDATE or build.get('candidate') != CANDIDATE
            or report.get('boot_epoch') != boot or not isinstance(boot, int) or boot <= 0
            or not expected or loaded_uuid != expected
            or identity.get('loaded_uuid') != expected
            or identity.get('loaded_uuid_matches_receipt') is not True
            or identity.get('archive_binary_sha256_verified') is not True
            or identity.get('archive_info_plist_sha256_verified') is not True
            or report.get('expected_archive_binary_sha256') != build.get('binary_sha256')
            or report.get('boot_attempt_claim_consumed') is not True
            or report.get('native_helper_invoked') is not True
            or not isinstance(report.get('arm_run_token'), str) or not report['arm_run_token']):
        raise ValueError('candidate, boot, loaded image, or consumed capture binding mismatch')
    return {'verified': True, 'loadedUUID': loaded_uuid, 'bootEpoch': boot,
            'armRunToken': report['arm_run_token']}


def collect(report, binding, reader, publication_timeout=3.0,
            publication_trace_reader=None):
    p = report.get('preowner_observation', {})
    comparison = p.get('comparison', {})
    preowner = {'binding': binding, 'stable': comparison.get('stable'),
                'stableReadCount': len(p.get('raw_reads', [])),
                'commitMarkersValidForAllReads': p.get('commit_markers_valid_for_all_reads'),
                'decoded': comparison.get('decoded')}
    trace = {'binding': binding, 'rawSnapshot': report.get(
        'management_trace_u32_evidence', {}).get('raw_snapshots', {}).get('post')}
    adapted = derive_closed_identity(binding, preowner, trace)
    if adapted['status'] != 'verified_end_marker':
        return {'status': 'unknown', 'reason': adapted.get('reason'),
                'attempts': None, 'copies': None, 'independent_marker': adapted}
    result = collect_after_closed_marker(lambda: adapted['marker'], reader,
        expected_identity=adapted['expected_identity'], close_marker_timeout=0,
        publication_timeout=publication_timeout, stable_reads=3,
        publication_trace_reader=publication_trace_reader)
    result['independent_marker'] = adapted
    result['coverage_scope'] = ('Retained ROC records only. Empty or complete '
        'records do not prove full RF coverage or absence of peer packets.')
    return result


def current_boot():
    raw = subprocess.check_output(['/usr/sbin/sysctl', '-n', 'kern.boottime'], text=True)
    match = re.search(r'sec = (\d+)', raw)
    if not match:
        raise ValueError('boot identity unavailable')
    return int(match.group(1))


def loaded_uuid():
    text = subprocess.check_output(['/usr/bin/kmutil', 'showloaded', '--list-only'],
                                   text=True, stderr=subprocess.DEVNULL)
    values = re.findall(r'org\.geekaudio\.AirportItlwm \([^)]*\) ([0-9A-F-]{36})', text)
    if len(values) != 1:
        raise ValueError('loaded driver UUID is ambiguous')
    return values[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', required=True, type=Path)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = json.loads(args.capture.read_text())
    build = json.loads(args.build.read_text())
    boot, uuid = current_boot(), loaded_uuid()
    binding = bind_capture(report, build, boot, uuid)
    reads = []
    def reader():
        objects = plistlib.loads(subprocess.check_output(
            ['/usr/sbin/ioreg', '-a', '-r', '-c', 'AirportItlwm'], timeout=8))
        if len(objects) != 1 or objects[0].get('NativeTestBuild') != CANDIDATE:
            raise ValueError('registry candidate changed')
        blob = objects[0].get('NativeRXRocCopyCorrelation')
        if isinstance(blob, bytes):
            reads.append({'sha256': hashlib.sha256(blob).hexdigest(),
                          'length': len(blob), 'hex': blob.hex()})
            return blob
        return None
    result = collect(report, binding, reader)
    if current_boot() != boot or loaded_uuid() != uuid:
        raise ValueError('runtime identity changed during read-only collection')
    result.update(candidate=CANDIDATE, boot_epoch=boot, loaded_uuid=uuid,
        original_capture_sha256=hashlib.sha256(args.capture.read_bytes()).hexdigest(),
        build_receipt_sha256=hashlib.sha256(args.build.read_bytes()).hexdigest(),
        raw_property_reads=reads, rf_triggered=False, original_capture_modified=False)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fchown(fd, args.capture.stat().st_uid, args.capture.stat().st_gid)
    with os.fdopen(fd, 'w') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps({'status': result['status'], 'output': str(args.out), 'rf_triggered': False}))

if __name__ == '__main__':
    main()
