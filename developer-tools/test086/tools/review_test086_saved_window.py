#!/usr/bin/env python3
"""Read-only offline review of an already-saved Test086 observation.

This tool never contacts IORegistry, OpenWrt, a peer, or the radio. It reads the
saved native/coordinator JSON, applies the existing explicit RX-event U32
normalizer to the three saved trace snapshots, and re-runs the production trace
guard in memory. It writes a new report without changing the original inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TRACE_BLOCKER = 'rx_trace_snapshot_not_complete_or_owner_guard_failed'
RECEIPT_BLOCKER = 'native_awdl_data_rx149_receipt_missing_unstable_or_invalid'
COUNTER_NAMES = (
    'NativeAwdlDataRxCaptured', 'NativeAwdlDataRxRejected',
    'NativeAwdlDataRxQueueFull', 'NativeAwdlDataRxDecoded',
    'NativeAwdlDataRxDelivered', 'NativeAwdlDataRxInputFailed',
)


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot_load_module:{path.name}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


NORMALIZER = _load_module('test086_saved_window_u32', ROOT / 'tools' / 'awdl_ioreg_u32.py')
COLLECTOR = _load_module('test086_saved_window_collector', ROOT / 'capture_test086_receive149_once.py')


def _read_json(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved = path.expanduser().resolve(strict=True)
    raw = resolved.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f'invalid_json:{resolved.name}') from exc
    if not isinstance(value, dict):
        raise ValueError(f'json_root_must_be_object:{resolved.name}')
    source = {
        'path': str(resolved),
        'size_bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(),
    }
    return value, source


def _summary_original_trace(trace: Any) -> dict[str, Any]:
    if not isinstance(trace, dict):
        return {'present': False, 'valid': None, 'reasons': [], 'invalid_fields': []}
    return {
        'present': True,
        'valid': trace.get('valid') if type(trace.get('valid')) is bool else None,
        'stable_complete_snapshot': trace.get('stable_complete_snapshot'),
        'trace_coverage_complete': trace.get('trace_coverage_complete'),
        'reasons': trace.get('reasons') if isinstance(trace.get('reasons'), list) else [],
        'invalid_fields': trace.get('invalid_fields') if isinstance(trace.get('invalid_fields'), list) else [],
    }


def _counter_observation(snapshot: Any, name: str) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        return {'present': False, 'value': None, 'status': 'snapshot_unavailable'}
    presence = snapshot.get('counter_presence')
    counters = snapshot.get('counters')
    present = isinstance(presence, dict) and presence.get(name) is True
    value = counters.get(name) if isinstance(counters, dict) else None
    if present and type(value) is int and value >= 0:
        return {'present': True, 'value': value, 'status': 'observed_numeric_counter'}
    if present:
        return {'present': True, 'value': None, 'status': 'present_but_invalid_value'}
    return {'present': False, 'value': None, 'status': 'unobserved_unknown'}


def _counter_report(native: dict[str, Any]) -> dict[str, Any]:
    initial = native.get('native_awdl_data_rx_initial')
    after = native.get('native_awdl_data_rx_after')
    delta_report = native.get('native_awdl_data_rx_delta')
    reported_delta = (delta_report.get('observed_counter_delta')
                      if isinstance(delta_report, dict) else None)
    result = {}
    for name in COUNTER_NAMES:
        delta = reported_delta.get(name) if isinstance(reported_delta, dict) else None
        delta_known = type(delta) is int and delta >= 0
        result[name] = {
            'initial': _counter_observation(initial, name),
            'after': _counter_observation(after, name),
            'reported_delta': {
                'value': delta if delta_known else None,
                'status': 'observed_numeric_delta' if delta_known else 'unobserved_unknown',
            },
        }
    initial_candidate = initial.get('descriptor_candidate_count') if isinstance(initial, dict) else None
    after_candidate = after.get('descriptor_candidate_count') if isinstance(after, dict) else None
    result['_awdl_data_candidate_descriptor_count'] = {
        'initial': _optional_nonnegative(initial_candidate),
        'after': _optional_nonnegative(after_candidate),
        'interpretation': 'Driver candidate count only; not RF absence or peer receipt.',
    }
    return result


def _optional_nonnegative(value: Any) -> dict[str, Any]:
    if type(value) is int and value >= 0:
        return {'value': value, 'status': 'observed_numeric_count'}
    return {'value': None, 'status': 'unobserved_unknown'}


def _receipt_summary(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        return {
            'observed': None, 'status': 'unknown_report_missing',
            'missing_field_count': None, 'invalid_field_count': None,
            'local_ifnet_input_kpi_accepted': None,
            'peer_or_socket_receipt_proven': False, 'airdrop_proven': False,
        }
    missing = receipt.get('missing')
    invalid = receipt.get('invalid')
    return {
        'observed': receipt.get('receipt_observed') if type(receipt.get('receipt_observed')) is bool else None,
        'status': receipt.get('status') if isinstance(receipt.get('status'), str) else 'unknown',
        'missing_field_count': len(missing) if isinstance(missing, list) else None,
        'invalid_field_count': len(invalid) if isinstance(invalid, list) else None,
        'local_ifnet_input_kpi_accepted': (
            receipt.get('local_ifnet_input_kpi_accepted')
            if type(receipt.get('local_ifnet_input_kpi_accepted')) is bool else None),
        'peer_or_socket_receipt_proven': receipt.get('peer_or_socket_receipt_proven') is True,
        'airdrop_proven': receipt.get('airdrop_proven') is True,
    }


def _receipt_delta_summary(delta: Any) -> dict[str, Any]:
    if not isinstance(delta, dict):
        return {
            'session_complete': None,
            'new_sequence_since_prearm': None,
            'local_ifnet_input_kpi_accepted': None,
            'peer_or_socket_receipt_proven': False,
            'airdrop_proven': False,
        }
    return {
        'session_complete': delta.get('receipt_session_complete') is True,
        'new_sequence_since_prearm': (
            delta.get('new_sequence_since_prearm')
            if type(delta.get('new_sequence_since_prearm')) is int else None),
        'local_ifnet_input_kpi_accepted': delta.get('local_ifnet_input_kpi_accepted') is True,
        'peer_or_socket_receipt_proven': delta.get('peer_or_socket_receipt_proven') is True,
        'airdrop_proven': delta.get('airdrop_proven') is True,
    }


def review_saved_window(native: dict[str, Any], coordinator: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a corrected, fail-closed derived review without mutating inputs."""
    if not isinstance(native, dict):
        raise ValueError('native_report_must_be_object')
    raw_reads = native.get('rx_trace_properties')
    if not isinstance(raw_reads, list) or len(raw_reads) != 3 or any(not isinstance(x, dict) for x in raw_reads):
        raise ValueError('exactly_three_saved_trace_snapshots_required')
    raw_copies = tuple(dict(sample) for sample in raw_reads)
    derived = NORMALIZER.derive_rx_trace_guard_report(
        *raw_copies, COLLECTOR.guarded_rx_trace_evidence)
    normalized = derived['normalization']
    normalized_reads = normalized['normalized_snapshots']
    guard = derived['guard']
    production_complete = COLLECTOR.rx_trace_snapshot_complete(
        guard, normalized_reads['post'])
    complete = normalized.get('valid') is True and production_complete

    relevant_keys = {
        'event_count', 'event_capacity', 'valid', 'stable_complete_snapshot',
        'schema_supported', 'epoch_match', 'owner_present', 'owner_inactive_post_roc',
        'producer_closed', 'pending_drain_count', 'untracked_pending_drain_count',
        'untracked_pending_identity_overflow_count', 'producer_time_valid',
        'dropped_event_count', 'stale_completion_count', 'source_table_full_count',
        'time_event_notification_dropped_count', 'source_attribution_complete',
        'stage_results_valid', 'trace_coverage_complete', 'missing_fields',
        'invalid_fields', 'reasons',
    }
    corrected_trace = {key: guard.get(key) for key in relevant_keys if key in guard}
    corrected_trace['production_guard_valid'] = guard.get('valid') is True
    corrected_trace['transport_normalization_valid'] = normalized.get('valid') is True
    corrected_trace['valid'] = derived.get('combined_valid') is True
    corrected_trace['trace_coverage_complete'] = (
        normalized.get('valid') is True and guard.get('trace_coverage_complete') is True)
    corrected_trace['snapshot_complete_gate'] = complete
    corrected_trace['derived_by_existing_production_guard'] = True
    corrected_trace['source_raw_snapshots_mutated'] = False
    corrected_trace['peer_receipt_or_airdrop_proven'] = False

    normalization_audit = normalized.get('audit', [])
    converted = [
        item for item in normalization_audit
        if any(type(raw) is int and raw < 0
               for raw in item.get('raw_by_read', {}).values())
    ]
    raw_trace = _summary_original_trace(native.get('rx_trace_evidence'))
    raw_problems = native.get('post_profile_problems')
    if not isinstance(raw_problems, list):
        raw_problems = []
    corrected_problems = [problem for problem in raw_problems
                          if not (problem == TRACE_BLOCKER and complete)]
    receipt_initial = _receipt_summary(native.get('native_awdl_data_rx149_receipt_initial'))
    receipt_after = _receipt_summary(native.get('native_awdl_data_rx149_receipt_after'))
    roc_complete = native.get('roc_session_complete') is True
    roc_problems = native.get('roc_session_problems')
    if not isinstance(roc_problems, list):
        roc_problems = []

    return {
        'schema': 'Test086 saved-window corrected review',
        'schema_version': 1,
        'scope': 'Read-only offline re-evaluation of saved reports; no RF, IORegistry, EFI, retry, peer, or AirDrop action.',
        'trace_review': {
            'original_collector_trace': raw_trace,
            'signed_u32_normalization': {
                'valid': normalized.get('valid') is True,
                'checked_property_count': normalized.get('checked_property_count'),
                'converted_scalar_count': normalized.get('converted_scalar_count'),
                'converted_fields': [
                    {
                        'property': item.get('property'),
                        'raw_by_read': item.get('raw_by_read'),
                        'normalized_by_read': item.get('normalized_by_read'),
                        'bit_width': item.get('bit_width'),
                    }
                    for item in converted
                ],
                'invalid_fields': normalized.get('invalid_fields', []),
                'missing_fields': normalized.get('missing_fields', []),
                'raw_changed': normalized.get('raw_changed', []),
                'method': 'Existing explicit RX-event U32 whitelist only; only signed-I32-range values are mapped modulo 2^32.',
            },
            'corrected_production_trace_guard': corrected_trace,
            'trace_guard_changed_from_fail_to_pass': (
                raw_trace.get('valid') is False and derived.get('combined_valid') is True and complete),
        },
        'roc': {
            'roc_session_complete': roc_complete,
            'roc_session_problems': roc_problems,
            'interpretation': 'ROC success is reported independently from trace validity and data-input acceptance.',
        },
        'native_data_rx': {
            'counts': _counter_report(native),
            'receipt_initial': receipt_initial,
            'receipt_after': receipt_after,
            'receipt_delta': _receipt_delta_summary(native.get('native_awdl_data_rx149_receipt_delta')),
            'unpublished_receipt_remains_unknown': (
                receipt_after.get('observed') is False and
                receipt_after.get('status') == 'not_published_yet'),
            'data_input_acceptance_claimed': False,
            'peer_or_socket_receipt_proven': False,
            'airdrop_proven': False,
        },
        'acceptance': {
            'source_session_complete': native.get('session_complete') is True,
            'coordinator_complete': (
                coordinator.get('complete') is True if isinstance(coordinator, dict) else None),
            'original_post_profile_problems': raw_problems,
            'derived_remaining_problems_after_trace_recheck': corrected_problems,
            'roc_session_failed': not roc_complete,
            'overall_measurement_complete': False,
            'overall_data_acceptance_promoted': False,
            'reason': 'Trace normalization removes only the confirmed host-parser false negative. Missing per-MPDU receipt and zero observed data-RX deltas remain unchanged; no data-input success is inferred.',
        },
        'raw_reports_changed': False,
    }


def write_new_report(path: Path, report: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-report', required=True, type=Path)
    parser.add_argument('--coordinator-report', type=Path)
    parser.add_argument('--output', required=True, type=Path,
                        help='New output path; existing files are never overwritten.')
    args = parser.parse_args(argv)
    native, native_source = _read_json(args.native_report)
    coordinator = None
    coordinator_source = None
    if args.coordinator_report:
        coordinator, coordinator_source = _read_json(args.coordinator_report)
    report = review_saved_window(native, coordinator)
    report['inputs'] = {'native': native_source, 'coordinator': coordinator_source}
    write_new_report(args.output, report)
    print(json.dumps({
        'output': str(args.output.expanduser().resolve()),
        'trace_guard_valid': report['trace_review']['corrected_production_trace_guard'].get('valid'),
        'trace_snapshot_complete': report['trace_review']['corrected_production_trace_guard'].get('snapshot_complete_gate'),
        'roc_session_complete': report['roc']['roc_session_complete'],
        'overall_data_acceptance_promoted': report['acceptance']['overall_data_acceptance_promoted'],
    }, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
