#!/usr/bin/env python3
"""Offline parser tests; producer and constructed records are format fixtures, not runtime evidence."""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location(
    "test136_diagnostics_under_test", HERE / "test136_diagnostics.py")
assert SPEC is not None and SPEC.loader is not None
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)

TOKEN = 101
IDENTITY = {
    "token": TOKEN,
    "context_generation": 4,
    "power_generation": 7,
    "station_generation": 18,
    "roc_generation": 4,
}
WIRE = {
    "station_id": 9,
    "queue_id": 4,
    "ring_size": 256,
    "descriptor_index": 0,
    "sequence_control": 0x20,
    "frame_control": 0x0808,
    "mpdu_length": 96,
    "legacy_host_pre_doorbell_us": 270000,
    "raw_doorbell_us": 270100,
    "raw_finish_us": 270200,
}
TRACE_DOORBELL_US = 270150


def legacy_qm_bytes(overrides: dict | None = None) -> bytes:
    values = {name: 0 for name in D._LEGACY.QM_WIRE_FIELD_NAMES}
    values.update({
        "schema": 1,
        "token": TOKEN,
        "context_generation": 4,
        "power_generation": 7,
        "station_generation": 18,
        "roc_token": 4,
        "station_id": WIRE["station_id"],
        "queue_id": WIRE["queue_id"],
        "ring_size": WIRE["ring_size"],
        "descriptor_index": WIRE["descriptor_index"],
        "frame_control": WIRE["frame_control"],
        "sequence_control": WIRE["sequence_control"],
        "mpdu_length": WIRE["mpdu_length"],
        "header_length": 24,
        "address_role_flags": 1,
        "header_is_valid": 1,
        "host_pre_doorbell_us": WIRE["legacy_host_pre_doorbell_us"],
    })
    if overrides:
        values.update(overrides)
    return struct.pack("<" + "Q" * len(D._LEGACY.QM_WIRE_FIELD_NAMES),
                       *(values[name] for name in D._LEGACY.QM_WIRE_FIELD_NAMES))


def qwr1_bytes(overrides: dict | None = None) -> bytes:
    raw = {
        "magic": D.QWR1_MAGIC,
        "schema": D.QWR1_SCHEMA,
        "header_bytes": D.QWR1_HEADER_BYTES,
        "total_bytes": D.QWR1_TOTAL_BYTES,
        "flags": D.QWR1_CANDIDATE | D.QWR1_COMMAND_COPIED |
                 D.QWR1_MPDU_DONE | D.QWR1_STAGE_ACCEPTED,
        "token": TOKEN,
        "context_generation": 4,
        "power_generation": 7,
        "station_generation": 18,
        "roc_token": 4,
        "station_id": WIRE["station_id"],
        "queue_id": WIRE["queue_id"],
        "ring_size": WIRE["ring_size"],
        "descriptor_index": WIRE["descriptor_index"],
        "sequence_control": WIRE["sequence_control"],
        "frame_control": WIRE["frame_control"],
        "command_actual_length": 56,
        "command_copied_length": 56,
        "mpdu_actual_length": WIRE["mpdu_length"],
        "mpdu_copied_length": WIRE["mpdu_length"],
        "command_copy_result": 0,
        "mpdu_copy_result": 0,
        "stage": D.QWR1_STAGED_AWAITING_PUBLISH,
        "doorbell_us": WIRE["raw_doorbell_us"],
        "finish_us": WIRE["raw_finish_us"],
    }
    if overrides:
        raw.update(overrides)
    header = D.QWR1_HEADER.pack(*[raw[key] for key in (
        "magic", "schema", "header_bytes", "total_bytes", "flags",
        "token", "context_generation", "power_generation", "station_generation",
        "roc_token", "station_id", "queue_id", "ring_size", "descriptor_index",
        "sequence_control", "frame_control", "command_actual_length",
        "command_copied_length", "mpdu_actual_length", "mpdu_copied_length",
        "command_copy_result", "mpdu_copy_result", "stage", "doorbell_us", "finish_us")])
    command = b"C" * raw["command_copied_length"]
    mpdu = b"M" * raw["mpdu_copied_length"]
    return (header + command.ljust(D.QWR1_COMMAND_CAPACITY, b"\0") +
            mpdu.ljust(D.QWR1_MPDU_CAPACITY, b"\0"))


def qws1_bytes(status: int = 10, overrides: dict | None = None) -> bytes:
    values = {
        "magic": D.QWS1_MAGIC, "schema": D.QWS1_SCHEMA,
        "byte_count": D.QWS1_BYTES, "status": status, "reserved": 0,
        "token": TOKEN, "context": 4, "power": 7, "station": 18, "roc": 4,
    }
    if overrides:
        values.update(overrides)
    return D.QWS1_STATUS.pack(*[values[key] for key in (
        "magic", "schema", "byte_count", "status", "reserved",
        "token", "context", "power", "station", "roc")])


def trace_properties(overrides: dict | None = None) -> dict:
    values = {}
    for name in D.DATA_TX_TRACE_HEADER_SUFFIXES:
        values["NativeP2PDataTxTrace" + name] = 0
    values.update({
        "NativeP2PDataTxTraceSnapshotVersionBegin": 26,
        "NativeP2PDataTxTraceSnapshotVersionEnd": 26,
        "NativeP2PDataTxTraceSnapshotComplete": 1,
        "NativeP2PDataTxTraceSchemaVersion": 1,
        "NativeP2PDataTxTraceRevision": 26,
        "NativeP2PDataTxTraceOwnerPresent": 1,
        "NativeP2PDataTxTraceOwnerSerial": 4,
        "NativeP2PDataTxTraceOwnerDiagnosticGeneration": 4,
        "NativeP2PDataTxTraceOwnerContextGeneration": 4,
        "NativeP2PDataTxTraceOwnerPowerGeneration": 7,
        "NativeP2PDataTxTraceOwnerStationGeneration": 18,
        "NativeP2PDataTxTraceOwnerRocGeneration": 4,
        "NativeP2PDataTxTraceCount": 1,
        "NativeP2PDataTxTraceDroppedCount": 0,
        "NativeP2PDataTxTraceCoverageUnknown": 0,
    })
    for slot in range(D.DATA_TX_TRACE_SLOTS):
        for suffix in D.DATA_TX_TRACE_RECORD_SUFFIXES:
            values[f"NativeP2PDataTxTraceRecord{slot}{suffix}"] = 0
    row = {
        "RecordPresent": 1, "Used": 1, "RecordSerial": 1,
        "Token": TOKEN, "DiagnosticGeneration": 4,
        "ContextGeneration": 4, "PowerGeneration": 7,
        "StationGeneration": 18, "RocGeneration": 4,
        "StagePresenceFlags": sum(D.DATA_TX_TRACE_STAGE_BITS[name] for name in (
            "queue_born", "dequeued", "submit_call_start", "final_wire",
            "ring_reserved", "descriptor_ready", "doorbell_marked",
            "doorbell_issued", "completion", "submit_call_end")),
        "QueueMetadataPresent": 1, "QueryClass": 1, "Eligible": 1,
        "QueueBornUs": 269000, "DequeuedUs": 269100,
        "SubmitCallStartUs": 269200, "FinalWireUs": 269300,
        "RingReservedUs": 269400, "DescriptorReadyUs": 269500,
        "DoorbellMarkedUs": 269900, "DoorbellIssuedUs": TRACE_DOORBELL_US,
        "CompletionUs": 270500, "SubmitCallEndUs": 270600,
        "FrameControl": WIRE["frame_control"],
        "SequenceControl": WIRE["sequence_control"],
        "MpduLength": WIRE["mpdu_length"],
        "QueueId": WIRE["queue_id"], "RingSize": WIRE["ring_size"],
        "DescriptorIndex": WIRE["descriptor_index"],
        "SubmitCallResult": 0, "CompletionResult": 10,
        "FirmwareEchoesFullIdentity": 0,
        "AmbiguousLateQueueUnknown": 1,
    }
    values.update({f"NativeP2PDataTxTraceRecord0{name}": value
                   for name, value in row.items()})
    if overrides:
        values.update(overrides)
    return values


def event_payload(rows: list[tuple] | None = None, overrides: dict | None = None) -> bytes:
    if rows is None:
        rows = [(270180, 1, 3, 0x3FF, 149, 96, 0x0008, 1, 2)]
    header = [D.RX_EVENTS_MAGIC, D.RX_EVENTS_SCHEMA, 4 + 9 * len(rows), len(rows)]
    if overrides:
        header = [overrides.get("magic", header[0]), overrides.get("schema", header[1]),
                  overrides.get("total_words", header[2]), overrides.get("event_count", header[3])]
    return struct.pack("<" + "Q" * len(header), *header) + b"".join(
        D.RX_EVENTS_ROW.pack(*row) for row in rows)


def rx_properties(overrides: dict | None = None, overflow: int = 0,
                  mpdu_count: int = 1) -> dict:
    values = {D.RX_WINDOW_PREFIX + suffix: 0 for suffix in D.RX_WINDOW_SUFFIXES}
    values.update({
        "NativeAwdlDiscoveryRxWindowSchemaVersion": 1,
        "NativeAwdlDiscoveryRxWindowPublished": 1,
        "NativeAwdlDiscoveryRxWindowSnapshotBegin": 8,
        "NativeAwdlDiscoveryRxWindowSnapshotEnd": 8,
        "NativeAwdlDiscoveryRxWindowValid": 1,
        "NativeAwdlDiscoveryRxWindowComplete": 0 if overflow else 1,
        "NativeAwdlDiscoveryRxWindowOverflow": overflow,
        "NativeAwdlDiscoveryRxWindowCloseReason": 1,
        "NativeAwdlDiscoveryRxWindowDriverGeneration": 7,
        "NativeAwdlDiscoveryRxWindowRocConfiguration": 3,
        "NativeAwdlDiscoveryRxWindowContextGeneration": 4,
        "NativeAwdlDiscoveryRxWindowPowerGeneration": 7,
        "NativeAwdlDiscoveryRxWindowStationGeneration": 18,
        "NativeAwdlDiscoveryRxWindowRocGeneration": 4,
        "NativeAwdlDiscoveryRxWindowStartMonotonicUs": 269950,
        "NativeAwdlDiscoveryRxWindowEndMonotonicUs": 280000,
        "NativeAwdlDiscoveryRxWindowFirstMpduEntryMonotonicUs": 270180 if mpdu_count else 0,
        "NativeAwdlDiscoveryRxWindowLastMpduEntryMonotonicUs": 270180 + min(mpdu_count, 64) - 1 if mpdu_count else 0,
        "NativeAwdlDiscoveryRxWindowMpduEntryCount": mpdu_count,
        "NativeAwdlDiscoveryRxWindowManagementMpduCount": 0,
        "NativeAwdlDiscoveryRxWindowControlMpduCount": 0,
        "NativeAwdlDiscoveryRxWindowDataMpduCount": mpdu_count if not overflow else 0,
        "NativeAwdlDiscoveryRxWindowExtensionMpduCount": 0,
        "NativeAwdlDiscoveryRxWindowUnknownTypeMpduCount": mpdu_count if overflow else 0,
        "NativeAwdlDiscoveryRxWindowAwdlDataCandidateCount": 1 if not overflow else 0,
        "NativeAwdlDiscoveryRxWindowLeaseQualifiedCount": 1 if not overflow else 0,
        "NativeAwdlDiscoveryRxWindowLeaseUnqualifiedCount": mpdu_count - 1 if not overflow else mpdu_count,
        "NativeAwdlDiscoveryRxWindowDescriptorUnavailableCount": 0 if not overflow else mpdu_count,
        "NativeAwdlDiscoveryRxWindowCrcRejectedCount": 0,
        "NativeAwdlDiscoveryRxWindowOverrunRejectedCount": 0,
        "NativeAwdlDiscoveryRxWindowChannel149Count": 1 if not overflow else 0,
        "NativeAwdlDiscoveryRxWindowRoutePassToStaCount": 0,
        "NativeAwdlDiscoveryRxWindowRouteQueuedForNativeCount": 1 if not overflow else 0,
        "NativeAwdlDiscoveryRxWindowRouteDuplicateRetryCount": 0,
        "NativeAwdlDiscoveryRxWindowBridgeRxPendingBefore": 1,
        "NativeAwdlDiscoveryRxWindowBridgeRxPendingAfter": 0,
        "NativeAwdlDiscoveryRxWindowBridgeRxCapturedBefore": 0,
        "NativeAwdlDiscoveryRxWindowBridgeRxCapturedAfter": 1,
        "NativeAwdlDiscoveryRxWindowBridgeRxDecodedBefore": 0,
        "NativeAwdlDiscoveryRxWindowBridgeRxDecodedAfter": 1,
        "NativeAwdlDiscoveryRxWindowBridgeRxDeliveredBefore": 0,
        "NativeAwdlDiscoveryRxWindowBridgeRxDeliveredAfter": 1,
        "NativeAwdlDiscoveryRxWindowBridgeDiscoveryInputCallsBefore": 0,
        "NativeAwdlDiscoveryRxWindowBridgeDiscoveryInputCallsAfter": 1,
        "NativeAwdlDiscoveryRxWindowBridgeDiscoveryInputSuccessBefore": 0,
        "NativeAwdlDiscoveryRxWindowBridgeDiscoveryInputSuccessAfter": 1,
        "NativeAwdlDiscoveryRxWindowBridgeDiscoveryInputSameWindowCommittedBefore": 0,
        "NativeAwdlDiscoveryRxWindowBridgeDiscoveryInputSameWindowCommittedAfter": 1,
    })
    if overrides:
        values.update(overrides)
    return values


def b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def compile_production_fixture() -> dict[str, int | bytes]:
    compiler = shutil.which("clang++") or shutil.which("c++")
    if compiler is None:
        raise RuntimeError("C++ compiler required for production encoder fixture")
    with tempfile.TemporaryDirectory(prefix="test136-production-fixture-") as temp:
        binary = Path(temp) / "test136-producer-fixture"
        subprocess.run([
            compiler, "-std=c++17", "-I", str(REPO / "native"),
            str(HERE / "test136_producer_fixture.cpp"), "-o", str(binary),
        ], check=True, capture_output=True, text=True)
        result = subprocess.run([str(binary)], check=True, capture_output=True,
                                text=True)
    output: dict[str, int | bytes] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            raise AssertionError(f"invalid C++ fixture output line: {line!r}")
        if key.endswith("_hex"):
            output[key[:-4]] = bytes.fromhex(value)
        else:
            output[key] = int(value)
    return output


def trace_properties_from_production_fixture(values: dict[str, int | bytes]) -> dict:
    properties = {}
    for suffix in D.DATA_TX_TRACE_HEADER_SUFFIXES:
        properties["NativeP2PDataTxTrace" + suffix] = values["header." + suffix]
    for slot in range(D.DATA_TX_TRACE_SLOTS):
        for suffix in D.DATA_TX_TRACE_RECORD_SUFFIXES:
            properties[f"NativeP2PDataTxTraceRecord{slot}{suffix}"] = values[
                f"record.{slot}.{suffix}"]
    return properties


def full_receipt(overrides: dict | None = None) -> dict:
    final = trace_properties()
    final.update(rx_properties())
    final.update({
        "NativeP2PQmWireSnapshotBase64": b64(legacy_qm_bytes()),
        "NativeP2PQmWireRawSnapshotPrivateBase64": b64(qwr1_bytes()),
        "NativeP2PQmWireRawSnapshotPrivateStatusBase64": b64(qws1_bytes()),
        "NativeAwdlDiscoveryRxWindowEventsBase64": b64(event_payload()),
    })
    if overrides:
        final.update(overrides)
    return {
        "schema": 1,
        "run_id": "format-fixture",
        "expected_build": "25G416-Test136",
        "expected_uuid": "39DC43C3-9054-399A-873E-45EE1DCFDC0B",
        "browse": {"callbacks": 0, "service_names_recorded": False},
        "cleanup": {"status": "cleanup_receipt_proven"},
        "publication": {"status": "published_diagnostics_observed"},
        "final": final,
    }


class TestTest136Diagnostics(unittest.TestCase):
    def test_capture_field_lists_match_decoder_contract(self):
        source = (HERE / "query_capture_test136.swift").read_text()
        def helper_array(name: str) -> tuple[str, ...]:
            match = re.search(r"private let " + name + r" = \[(.*?)\n\]", source, re.S)
            self.assertIsNotNone(match)
            return tuple(re.findall(r'"([^"]+)"', match.group(1)))

        self.assertEqual(helper_array("discoveryRxWindowFields"), D.RX_WINDOW_SUFFIXES)
        self.assertEqual(helper_array("dataTxTraceHeaderFields"),
                         D.DATA_TX_TRACE_HEADER_SUFFIXES)
        self.assertEqual(helper_array("dataTxTraceRecordFields"),
                         D.DATA_TX_TRACE_RECORD_SUFFIXES)
        self.assertIn('"NativeAwdlDiscoveryRxWindowEvents"', source)
        self.assertIn('"RocConfiguration"', source)
        self.assertIn('"NativeP2PQmWireStageRejectCount"', source)

    def test_legacy_qm_size_uses_actual_field_list(self):
        payload = legacy_qm_bytes()
        self.assertEqual(len(payload), len(D._LEGACY.QM_WIRE_FIELD_NAMES) * 8)
        report = D.decode_legacy_qm_wire_snapshot(payload)
        self.assertTrue(report["valid"])
        self.assertEqual(report["values"]["roc_token"], IDENTITY["roc_generation"])
        self.assertFalse(D.decode_legacy_qm_wire_snapshot(payload[:-8])["valid"])

    def test_qws1_status_distinguishes_pending_failure_and_success(self):
        for pending in (0, 1, 3, 6):
            decoded = D._decode_qws1(qws1_bytes(status=pending))
            self.assertTrue(decoded["valid"])
            self.assertFalse(decoded["published"])
            self.assertFalse(decoded["explicit_failure"])
        failure = D._decode_qws1(qws1_bytes(status=4))
        self.assertTrue(failure["explicit_failure"])
        success = D._decode_qws1(qws1_bytes(status=10))
        self.assertTrue(success["published"])

    def test_raw_capture_checks_exact_identity_and_legacy_descriptor(self):
        legacy = D.decode_legacy_qm_wire_snapshot(legacy_qm_bytes())
        valid = D.decode_qm_raw_publication(qwr1_bytes(), qws1_bytes(), legacy)
        self.assertTrue(valid["valid"])
        self.assertEqual(valid["wire_fields"]["queue_id"], 4)
        bad_identity = D.decode_qm_raw_publication(
            qwr1_bytes({"token": TOKEN + 1}), qws1_bytes(), legacy)
        self.assertFalse(bad_identity["valid"])
        bad_descriptor = D.decode_qm_raw_publication(
            qwr1_bytes({"descriptor_index": 2}), qws1_bytes(), legacy)
        self.assertFalse(bad_descriptor["valid"])
        unstaged = D.decode_qm_raw_publication(
            qwr1_bytes({"stage": 2}), qws1_bytes(), legacy)
        self.assertFalse(unstaged["valid"])
        self.assertIn("raw_stage_not_staged_for_publish",
                      unstaged["raw_snapshot"]["reasons"])
        self.assertFalse(D._decode_qwr1(qwr1_bytes()[:-1])["valid"])

    def test_exact_trace_row_joins_descriptor_owner_and_nonidentical_times(self):
        trace = D.decode_data_tx_trace(trace_properties(), IDENTITY, WIRE)
        self.assertTrue(trace["valid"])
        self.assertEqual(trace["identity_match_status"], "exact_local_identity_match")
        self.assertEqual(trace["matched_record"]["slot"], 0)
        self.assertTrue(trace["doorbell_timing_match"])
        self.assertEqual(trace["matched_record"]["QueueBornUs"], 269000)
        mismatch = D.decode_data_tx_trace(
            trace_properties({"NativeP2PDataTxTraceRecord0QueueId": 9}),
            IDENTITY, WIRE)
        self.assertFalse(mismatch["valid"])
        self.assertIsNone(mismatch["matched_record"])
        wrong_epochs = dict(IDENTITY, power_generation=99)
        no_row = D.decode_data_tx_trace(trace_properties(), wrong_epochs, WIRE)
        self.assertEqual(no_row["identity_match_status"], "identity_mismatch")
        self.assertIsNone(no_row["matched_record"])

    def test_completion_success_uses_production_result_enum_value(self):
        fixture = compile_production_fixture()
        self.assertEqual(fixture["completion_enum_ready"], 0)
        self.assertEqual(fixture["completion_enum_frame_failed"], 9)
        self.assertEqual(fixture["completion_enum_completion"], 10)
        for result in (0, 9, 11):
            trace = D.decode_data_tx_trace(
                trace_properties({
                    "NativeP2PDataTxTraceRecord0CompletionResult": result,
                }), IDENTITY, WIRE)
            self.assertTrue(trace["valid"])
            self.assertFalse(trace["matched_record_events"][
                "local_completion_succeeded"])
        successful = D.decode_data_tx_trace(
            trace_properties({
                "NativeP2PDataTxTraceRecord0CompletionResult":
                    fixture["completion_enum_completion"],
            }), IDENTITY, WIRE)
        self.assertTrue(successful["matched_record_events"][
            "local_completion_succeeded"])

    def test_production_encoders_facts_status_and_ledger_decode_end_to_end(self):
        fixture = compile_production_fixture()
        raw = fixture["raw"]
        facts = fixture["facts"]
        status = fixture["status"]
        self.assertEqual(len(raw), D.QWR1_TOTAL_BYTES)
        self.assertEqual(len(facts), D._LEGACY.QM_WIRE_SIZE)
        self.assertEqual(len(status), D.QWS1_BYTES)

        legacy = D.decode_legacy_qm_wire_snapshot(facts)
        self.assertTrue(legacy["valid"])
        publication = D.decode_qm_raw_publication(raw, status, legacy)
        self.assertTrue(publication["valid"], publication)
        self.assertEqual(publication["status_code"], 10)
        self.assertEqual(publication["identity"], {
            "token": TOKEN, "context_generation": 4, "power_generation": 7,
            "station_generation": 18, "roc_token": 4,
        })

        expected_wire = dict(publication["wire_fields"])
        expected_wire.update({
            "raw_doorbell_us": publication["doorbell_us"],
            "raw_finish_us": publication["finish_us"],
        })
        trace = D.decode_data_tx_trace(
            trace_properties_from_production_fixture(fixture),
            D._identity_for_trace(legacy), expected_wire)
        self.assertTrue(trace["valid"], trace["reasons"])
        record = trace["matched_record"]
        self.assertIsNotNone(record)
        self.assertEqual(record["CompletionResult"], 10)
        self.assertEqual(record["TxRspStatus"], 1)
        self.assertEqual(record["TxRspHandlerDisposition"], 1)
        self.assertEqual(record["AssociationStrength"], 3)
        self.assertTrue(trace["matched_record_events"][
            "local_completion_succeeded"])
        self.assertFalse(trace["peer_receipt_proven"])

    def test_rx_event_parser_orders_only_exact_same_generation_events(self):
        window_values = rx_properties()
        window = D.decode_discovery_rx_window(window_values, IDENTITY)
        self.assertTrue(window["valid"])
        self.assertTrue(window["correlated_to_tx_generation"])
        events = D.decode_discovery_rx_events(
            event_payload(), window, raw_doorbell_us=WIRE["raw_doorbell_us"],
            tx_generation_matches=window["same_generation_as_tx"])
        self.assertTrue(events["valid"])
        self.assertEqual(events["events"][0]["relative_to_raw_doorbell"],
                         "after_raw_doorbell")
        self.assertEqual(events["events"][0]["data_route"], "queued_for_native")
        self.assertTrue(events["events"][0]["lease_qualified"])
        mismatch_window = D.decode_discovery_rx_window(
            rx_properties({"NativeAwdlDiscoveryRxWindowPowerGeneration": 99}), IDENTITY)
        self.assertEqual(mismatch_window["generation_status"], "generation_mismatch")
        mismatch_events = D.decode_discovery_rx_events(
            event_payload(), mismatch_window, WIRE["raw_doorbell_us"],
            mismatch_window["same_generation_as_tx"])
        self.assertEqual(mismatch_events["events"][0]["relative_to_raw_doorbell"],
                         "unknown_tx_generation_or_doorbell")

    def test_rx_pending_depth_may_fall_and_overflow_blocks_absence_claim(self):
        normal = D.decode_discovery_rx_window(rx_properties(), IDENTITY)
        self.assertTrue(normal["valid"])
        self.assertEqual(normal["bridge_boundary_counters"]["RxPending"]["delta"], -1)
        overflow = D.decode_discovery_rx_window(
            rx_properties(overflow=1, mpdu_count=65), IDENTITY)
        self.assertFalse(overflow["valid"])
        self.assertTrue(overflow["scalar_aggregates_valid"])
        rows = [(270180 + i, i + 1, 0, 0, 0, 0, 0, 2, 0) for i in range(64)]
        events = D.decode_discovery_rx_events(
            event_payload(rows), overflow, WIRE["raw_doorbell_us"], True)
        self.assertTrue(events["valid"])
        self.assertFalse(events["sequence_complete"])
        self.assertEqual(events["event_count"], 64)

    def test_event_header_length_magic_route_and_missing_fields_fail_closed(self):
        window = D.decode_discovery_rx_window(rx_properties(), IDENTITY)
        self.assertFalse(D.decode_discovery_rx_events(event_payload()[:-1], window)["valid"])
        self.assertFalse(D.decode_discovery_rx_events(
            event_payload(overrides={"magic": 0}), window)["valid"])
        invalid_route = event_payload(rows=[(270180, 1, 3, 0x3FF, 149, 96, 8, 1, 0)])
        self.assertFalse(D.decode_discovery_rx_events(invalid_route, window)["valid"])
        missing_window = dict(rx_properties())
        missing_window.pop("NativeAwdlDiscoveryRxWindowComplete")
        self.assertFalse(D.decode_discovery_rx_window(missing_window, IDENTITY)["valid"])
        wrong_configuration = rx_properties({
            "NativeAwdlDiscoveryRxWindowRocConfiguration": 2})
        self.assertFalse(D.decode_discovery_rx_window(
            wrong_configuration, IDENTITY)["valid"])

    def test_full_receipt_summary_joins_local_records_but_never_exposes_bytes(self):
        summary = D.decode_test136_receipt(full_receipt())
        self.assertTrue(summary["valid"])
        self.assertTrue(summary["private_command_mpdu_capture"]["valid"])
        self.assertTrue(summary["raw_legacy_trace_join"][
            "raw_facts_status_identity_joined_to_one_trace_row"])
        self.assertTrue(summary["local_tx_path"]["driver_doorbell_issued_observed"])
        self.assertTrue(summary["local_tx_path"]["local_completion_succeeded"])
        self.assertFalse(summary["local_tx_path"]["peer_ack_proven"])
        self.assertTrue(summary["discovery_rx_events"]["valid"])
        encoded = json.dumps(summary, sort_keys=True)
        self.assertNotIn("NativeP2PQmWireRawSnapshotPrivateBase64", encoded)
        self.assertNotIn(b64(qwr1_bytes()), encoded)

    def test_missing_trace_fields_remain_unknown(self):
        receipt = full_receipt()
        receipt["final"].pop("NativeP2PDataTxTraceRecord7CompletionResult")
        summary = D.decode_test136_receipt(receipt)
        self.assertFalse(summary["data_tx_trace"]["valid"])
        self.assertIsNone(summary["data_tx_trace"]["matched_record"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
