from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


TOOL_DIR = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "test086_host_clock_domain", TOOL_DIR / "host_clock_domain.py")
clock_domain = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = clock_domain
SPEC.loader.exec_module(clock_domain)

SPEC = importlib.util.spec_from_file_location(
    "test086_clocked_full_coordinator", TOOL_DIR / "controlled_run_coordinator.py")
coordinator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = coordinator
SPEC.loader.exec_module(coordinator)


class HostClockDomainTests(unittest.TestCase):
    def test_non_one_to_one_timebase_uses_integer_conversion(self):
        # 1001 * 125 / 3 = 41708.333...; conversion rounds down exactly.
        self.assertEqual(clock_domain.ticks_to_nanoseconds(1001, 125, 3), 41708)

    def test_uint64_tick_product_exceeds_uint64_without_precision_loss(self):
        ticks = (1 << 64) - 1
        numerator = (1 << 32) - 1
        denominator = 3
        actual = clock_domain.ticks_to_nanoseconds(ticks, numerator, denominator)
        self.assertEqual(actual, ticks * numerator // denominator)
        self.assertGreater(actual, (1 << 64) - 1)

    def test_invalid_or_unsupported_timebase_fails_closed(self):
        for values in ((1, 0, 1), (1, 1, 0), (True, 1, 1), (-1, 1, 1),
                       (1 << 64, 1, 1)):
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    clock_domain.ticks_to_nanoseconds(*values)

        clock = clock_domain.MachBootClock(
            absolute_reader=lambda: (_ for _ in ()).throw(
                clock_domain.ClockUnavailable("injected unsupported host")),
            process_reader=lambda: 123456)
        descriptor = clock.descriptor()
        sample = clock.sample_pair()
        self.assertEqual(descriptor["status"], "unsupported")
        self.assertEqual(descriptor["clock_domain"], "unknown")
        self.assertEqual(sample["status"], "unsupported")
        self.assertEqual(sample["clock_domain"], "unknown")
        self.assertIsNone(sample["boot_monotonic_ns"])
        self.assertEqual(sample["process_monotonic_ns"], 123456)
        self.assertFalse(sample["process_epoch_shared"])

    def test_pair_records_bounds_and_does_not_claim_process_epoch_is_shared(self):
        readings = iter((
            {"ticks": 100, "numerator": 125, "denominator": 3},
            {"ticks": 101, "numerator": 125, "denominator": 3},
            {"ticks": 105, "numerator": 125, "denominator": 3},
        ))
        clock = clock_domain.MachBootClock(
            absolute_reader=lambda: next(readings), process_reader=lambda: 888)
        sample = clock.sample_pair()
        self.assertEqual(sample["status"], "available")
        self.assertEqual(sample["clock_domain"],
                         clock_domain.BOOT_CLOCK_DOMAIN)
        self.assertEqual(sample["boot_sample_lower_ns"], 4208)
        self.assertEqual(sample["boot_sample_upper_ns"], 4375)
        self.assertEqual(sample["boot_monotonic_ns"], 4291)
        self.assertEqual(sample["sample_bracket_width_ns"], 167)
        self.assertEqual(sample["sample_error_bound_ns"], 85)
        self.assertEqual(sample["process_monotonic_ns"], 888)
        self.assertFalse(sample["process_epoch_shared"])

    def test_coordinator_keeps_legacy_field_and_adds_new_domain_field(self):
        class FakeClock:
            @staticmethod
            def sample_pair():
                return {
                    "status": "available",
                    "clock_domain": "mach_absolute_time_ns_since_boot_excludes_sleep",
                    "process_clock_domain": "python_time_monotonic_ns_epoch_not_shared",
                    "process_epoch_shared": False,
                    "process_monotonic_ns": 700,
                    "boot_monotonic_ns": 987654,
                    "boot_sample_lower_ns": 987650,
                    "boot_sample_upper_ns": 987658,
                    "sample_bracket_width_ns": 8,
                    "sample_error_bound_ns": 5,
                }

        report = {"events_parent_monotonic_ns": [],
                  "events_parent_boot_monotonic_ns": []}
        coordinator._append_parent_clock_event(report, "TEST_EVENT", FakeClock())
        self.assertEqual(report["events_parent_monotonic_ns"],
                         [{"event": "TEST_EVENT", "monotonic_ns": 700}])
        boot_event = report["events_parent_boot_monotonic_ns"][0]
        self.assertEqual(boot_event["event"], "TEST_EVENT")
        self.assertEqual(boot_event["boot_monotonic_ns"], 987654)
        self.assertEqual(boot_event["sample_error_bound_ns"], 5)
        self.assertFalse(boot_event["process_epoch_shared"])


if __name__ == "__main__":
    unittest.main()
