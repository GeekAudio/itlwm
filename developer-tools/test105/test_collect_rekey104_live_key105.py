"""Test104 sample/capture retention of independent Test105 metadata."""
from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
for relative in ("developer-tools/test105", "developer-tools/test104",
                 "developer-tools/test103", "developer-tools/test100"):
    sys.path.insert(0, str(ROOT / relative))

import collect_rekey100 as base
import collect_rekey104 as collector
from firmware_single_queue_completion105 import evaluate
from live_key105 import FIELDS, PREFIX, completion_with_live_authority, parse_live_key
from test_firmware_single_queue_completion105 import fixture as completion_fixture


UUID = "17D05CC1-2351-3A74-BAAD-77F67E362577"
BOOT = 1793525969
BUILD = "25G332-Test104"
EVENT_NS = 123456789


def live_key_properties(*, owner_generation=9, output_epoch=8,
                        context_stable=1, sample_ns=3_000_000_000):
    values = {PREFIX + key: 0 for key in FIELDS}
    values.update({PREFIX + key: value for key, value in {
        "Schema": 1,
        "RevisionBegin": 2,
        "RevisionEnd": 2,
        "SampleMonotonicNs": sample_ns,
        "OwnerGeneration": owner_generation,
        "HctxFrozen": 1,
        "HctxManualLatched": 1,
        "OwnerOutputEpoch": output_epoch,
        "OwnerContextStable": context_stable,
        "SubmitPresent": 1,
        "SubmitStable": 1,
        "SubmitDroppedCount": 0,
        "SubmitDroppedSerial": 0,
        "SubmitSerial": 28,
        "SubmitMonotonicNs": 100_000_000,
        "SubmitDriverGeneration": owner_generation,
        "SubmitFirmwareGeneration": owner_generation,
        "SubmitPhase": 1,
        "SubmitSource": 1,
        "SubmitCommandId": 0x17,
        "SubmitGroupId": 1,
        "SubmitIndex": 20,
        "SubmitHeaderSequence": 20,
        "SubmitFlags": 1 << 4,
        "ResponsePresent": 1,
        "ResponseStable": 1,
        "ResponseDroppedCount": 0,
        "ResponseDroppedSerial": 0,
        "ResponseSerial": 27,
        "ResponseMonotonicNs": 90_000_000,
        "ResponseDriverGeneration": owner_generation,
        "ResponseFirmwareGeneration": owner_generation,
        "ResponsePhase": 7,
        "ResponseSource": 2,
        "ResponseCommandId": 0x17,
        "ResponseGroupId": 1,
        "ResponseIndex": 20,
        "ResponseHeaderSequence": 20,
        "ResponseFlags": 1 << 10,
        "ResponseResult": 1,
    }.items()})
    return values


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class IncrementingNs:
    def __init__(self, start=2_000_000_000):
        self.value = start

    def __call__(self):
        self.value += 1_000
        return self.value


def service_fixture(*, include_live=True, **live_kwargs):
    service = {"NativeTestBuild": BUILD}
    service.update(completion_fixture())
    if include_live:
        service.update(live_key_properties(**live_kwargs))
    service.update({
        "SSID": "TEST105_PRIVATE_SSID_SENTINEL",
        "BSSID": "TEST105_PRIVATE_BSSID_SENTINEL",
        "KeyMaterial": "TEST105_PRIVATE_KEY_SENTINEL",
    })
    return service


def ioreg_fixture(service):
    raw = plistlib.dumps([service], fmt=plistlib.FMT_BINARY)

    def read(argv, **_kwargs):
        if argv != ["/usr/sbin/ioreg", "-a", "-r", "-c", "AirportItlwm"]:
            raise AssertionError("unexpected ioreg query")
        return raw

    return read


class LiveKeyCollectorIntegrationTests(unittest.TestCase):
    def test_sample_once_to_capture_jsonl_retains_separate_unknown_live_key(self):
        service = service_fixture()
        ioreg = ioreg_fixture(service)
        clock = FakeClock()
        ticks = IncrementingNs()

        def sample_reader(build, identity):
            return collector.sample_once(
                build, identity, ioreg_fn=ioreg,
                ifconfig_fn=lambda _argv, **_kwargs: (
                    b"en1: flags=8863<UP,RUNNING> mtu 1500\n"
                    b" status: active\n inet 192.0.2.3\n"),
                monotonic_ns=ticks,
                wall_now=lambda: datetime.datetime.fromisoformat(
                    "2026-11-01T10:00:00+08:00"))

        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            os.chmod(output_dir, 0o700)
            path = output_dir / "sample.jsonl"
            result = collector.capture(
                path, boot_epoch=BOOT, expected_uuid=UUID,
                expected_build=BUILD, duration=0.5, interval=0.25,
                identity_reader=lambda boot, _build: {
                    "boot_epoch": boot,
                    "os_build": base.EXPECTED_OS_BUILD,
                    "loaded_kext_uuid": UUID,
                },
                sample_reader=sample_reader,
                monotonic=clock.monotonic, sleep=clock.sleep,
                wall_now=lambda: datetime.datetime.fromisoformat(
                    "2026-11-01T10:00:00+08:00"))
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            samples = [row for row in rows if row["record_type"] == "sample"]
            self.assertEqual(len(samples), result["sample_count"])
            self.assertGreaterEqual(len(samples), 1)
            for row in samples:
                live = row["live_key"]
                self.assertEqual(live["status"], "stable_publication")
                self.assertEqual(live["command_response_match"], "unknown")
                self.assertEqual(live["key_install_result"], "unknown")
                self.assertEqual(live["observations"]["submit"]["entry"]["Serial"], 28)
                self.assertEqual(live["observations"]["response"]["entry"]["Serial"], 27)
                # The independent queue completion result has its own evidence
                # boundary and cannot promote either sticky key observation.
                self.assertEqual(
                    row["firmware_queue_completion"][
                        "firmware_single_queue_completion_success"], True)
                self.assertFalse(row["firmware_queue_completion"][
                    "peer_receipt_proven"])
                self.assertFalse(row["firmware_queue_completion"]["airdrop_proven"])
            self.assertEqual(rows[-1]["record_type"], "footer")
            self.assertFalse(rows[-1]["peer_ack_proven"])
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            encoded = path.read_text()
            self.assertNotIn("192.0.2.3", encoded)
            for sentinel in ("TEST105_PRIVATE_SSID_SENTINEL",
                             "TEST105_PRIVATE_BSSID_SENTINEL",
                             "TEST105_PRIVATE_KEY_SENTINEL"):
                self.assertNotIn(sentinel, encoded)

    def test_capture_keeps_unqualified_owner_authority_unknown(self):
        scenarios = [
            (service_fixture(include_live=False),
             "authoritative_context_unavailable"),
            (service_fixture(context_stable=0),
             "authoritative_context_unavailable"),
            (service_fixture(owner_generation=8),
             "not_current_ordinary_generation_cut"),
            (service_fixture(output_epoch=7),
             "generation_epoch_or_identity_ambiguous"),
            (service_fixture(sample_ns=EVENT_NS - 1),
             "owner_sample_does_not_cover_event_clock"),
        ]
        clock = FakeClock()
        ticks = IncrementingNs()
        index = 0

        def sample_reader(build, identity):
            nonlocal index
            service = scenarios[index][0]
            index += 1
            return collector.sample_once(
                build, identity, ioreg_fn=ioreg_fixture(service),
                ifconfig_fn=lambda _argv, **_kwargs: b"en1: flags=8863<UP,RUNNING> mtu 1500\n status: active\n",
                monotonic_ns=ticks,
                wall_now=lambda: datetime.datetime.fromisoformat(
                    "2026-11-01T10:00:00+08:00"))

        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            os.chmod(output_dir, 0o700)
            path = output_dir / "authority-cases.jsonl"
            result = collector.capture(
                path, boot_epoch=BOOT, expected_uuid=UUID,
                expected_build=BUILD, duration=1.25, interval=0.25,
                identity_reader=lambda boot, _build: {
                    "boot_epoch": boot,
                    "os_build": base.EXPECTED_OS_BUILD,
                    "loaded_kext_uuid": UUID,
                },
                sample_reader=sample_reader,
                monotonic=clock.monotonic, sleep=clock.sleep,
                wall_now=lambda: datetime.datetime.fromisoformat(
                    "2026-11-01T10:00:00+08:00"))
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            samples = [row for row in rows if row["record_type"] == "sample"]
            self.assertEqual(result["sample_count"], len(scenarios))
            self.assertEqual(len(samples), len(scenarios))
            for row, (_service, reason) in zip(samples, scenarios):
                completion = row["firmware_queue_completion"]
                self.assertEqual(completion["status"], "unknown")
                self.assertIsNone(
                    completion["firmware_single_queue_completion_success"])
                self.assertEqual(completion["reason"], reason)
                self.assertFalse(completion["peer_receipt_proven"])
                self.assertFalse(completion["airdrop_proven"])

    def test_completion_needs_live_current_owner_context_and_covering_time(self):
        completion = completion_fixture()

        unavailable = completion_with_live_authority(
            completion, {"status": "not_published"})
        self.assertIsNone(unavailable["firmware_single_queue_completion_success"])
        self.assertEqual(unavailable["reason"], "authoritative_context_unavailable")

        cases = [
            (live_key_properties(context_stable=0),
             "authoritative_context_unavailable"),
            (live_key_properties(owner_generation=8),
             "not_current_ordinary_generation_cut"),
            (live_key_properties(output_epoch=7),
             "generation_epoch_or_identity_ambiguous"),
            (live_key_properties(sample_ns=EVENT_NS - 1),
             "owner_sample_does_not_cover_event_clock"),
        ]
        for properties, reason in cases:
            with self.subTest(reason=reason):
                live = parse_live_key(properties)
                result = completion_with_live_authority(completion, live)
                self.assertIsNone(
                    result["firmware_single_queue_completion_success"])
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["reason"], reason)
                self.assertFalse(result["peer_receipt_proven"])

    def test_live_response_and_submit_remain_unjoined_even_if_slot_matches(self):
        live = parse_live_key(live_key_properties())
        submit = live["observations"]["submit"]["entry"]
        response = live["observations"]["response"]["entry"]
        self.assertEqual(submit["Index"], response["Index"])
        self.assertEqual(submit["DriverGeneration"], response["DriverGeneration"])
        self.assertLess(response["Serial"], submit["Serial"])
        self.assertEqual(live["command_response_match"], "unknown")
        self.assertEqual(live["key_install_result"], "unknown")
        self.assertNotIn("matched_submit_serial", live)

    def test_kmutil_has_independent_30_second_timeout_without_identity_relaxation(self):
        calls = []

        def run_bytes(argv, timeout=8.0):
            calls.append((argv, timeout))
            if argv[0] == "/usr/sbin/sysctl":
                return f"{{ sec = {BOOT}, usec = 0 }}".encode()
            if argv[0] == "/usr/bin/sw_vers":
                return b"25G332\n"
            if argv[0] == "/usr/bin/kmutil":
                return ("org.geekaudio.AirportItlwm " + UUID + "\n").encode()
            raise AssertionError("unexpected identity command")

        with patch.object(base, "EXPECTED_KEXT_UUID", UUID), \
                patch.object(base, "_run_bytes", side_effect=run_bytes):
            identity = base.read_host_identity(BOOT, BUILD)
        self.assertEqual(identity["loaded_kext_uuid"], UUID)
        self.assertEqual([timeout for _argv, timeout in calls], [8.0, 8.0, 30.0])
        self.assertEqual(calls[-1][0][0], "/usr/bin/kmutil")

        wrong_uuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"

        def mismatched_run(argv, timeout=8.0):
            if argv[0] == "/usr/sbin/sysctl":
                return f"{{ sec = {BOOT}, usec = 0 }}".encode()
            if argv[0] == "/usr/bin/sw_vers":
                return b"25G332\n"
            if argv[0] == "/usr/bin/kmutil":
                return ("org.geekaudio.AirportItlwm " + wrong_uuid + "\n").encode()
            raise AssertionError("unexpected identity command")

        with patch.object(base, "EXPECTED_KEXT_UUID", UUID), \
                patch.object(base, "_run_bytes", side_effect=mismatched_run):
            with self.assertRaises(base.IdentityMismatch) as raised:
                base.read_host_identity(BOOT, BUILD)
        self.assertEqual(raised.exception.field, "loaded_kext_uuid")

        with patch.object(base, "EXPECTED_KEXT_UUID", UUID), \
                patch.object(base, "_run_bytes", side_effect=mismatched_run):
            with self.assertRaises(base.IdentityMismatch) as raised:
                base.read_host_identity(BOOT + 1, BUILD)
        self.assertEqual(raised.exception.field, "boot_epoch")


if __name__ == "__main__":
    unittest.main()
