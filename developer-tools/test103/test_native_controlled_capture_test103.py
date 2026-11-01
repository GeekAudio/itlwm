import threading
import unittest

from native_controlled_capture_test103 import (
    _collect_hcmd_while_worker_runs,
    _run_worker_with_collector,
)


class FakeClock:
    def __init__(self):
        self.value = 0.0
        self.lock = threading.Lock()

    def __call__(self):
        with self.lock:
            return self.value

    def advance(self, seconds):
        with self.lock:
            self.value += seconds
            return self.value


class FakeStop:
    def __init__(self):
        self.stopped = False

    def is_set(self):
        return self.stopped

    def set(self):
        self.stopped = True


class NativeControlledCaptureTests(unittest.TestCase):
    def test_collector_continues_past_twelve_samples_until_worker_stop(self):
        clock = FakeClock()
        stop = FakeStop()
        samples = []
        state = {}

        def waiter(timeout):
            now = clock.advance(timeout)
            if now >= 15.0:
                stop.set()

        _collect_hcmd_while_worker_runs(
            stop, samples, samples_lock=threading.Lock(), state=state,
            interval_seconds=1.0, maximum_seconds=120.0,
            sampler=lambda: {"sample_status": "ok"},
            clock=clock, waiter=waiter,
        )

        self.assertEqual(len(samples), 15)
        self.assertEqual(state["collector_stop_reason"], "worker_stop_requested")
        self.assertFalse(state["sample_limit_reached"])
        self.assertEqual(state["sample_error_count"], 0)

    def test_maximum_duration_is_explicitly_incomplete(self):
        clock = FakeClock()
        deadline_reached = threading.Event()

        def waiter(timeout):
            now = clock.advance(timeout)
            if now >= 1.0:
                deadline_reached.set()

        def worker():
            self.assertTrue(deadline_reached.wait(1.0))
            # Keep the worker active long enough for the collector to observe
            # that its bounded horizon expired first.
            threading.Event().wait(0.02)
            return 0

        result, samples, state = _run_worker_with_collector(
            worker,
            sampler=lambda: {"sample_status": "ok"},
            interval_seconds=0.25,
            maximum_seconds=1.0,
            clock=clock,
            waiter=waiter,
        )

        self.assertEqual(result, 0)
        self.assertTrue(samples)
        self.assertTrue(state["sample_limit_reached"])
        self.assertFalse(state["worker_lifetime_reached"])
        self.assertFalse(state["coverage_complete"])
        self.assertEqual(state["coverage_status"], "incomplete")
        self.assertTrue(state["collector_thread_joined"])

    def test_worker_waits_for_inflight_reader_before_freezing_samples(self):
        reader_entered = threading.Event()
        reader_release = threading.Event()
        worker_returned = threading.Event()

        def sampler():
            reader_entered.set()
            self.assertTrue(reader_release.wait(1.0))
            self.assertTrue(worker_returned.is_set())
            return {"sample_status": "ok", "value": 7}

        def worker():
            self.assertTrue(reader_entered.wait(1.0))
            worker_returned.set()
            timer = threading.Timer(0.03, reader_release.set)
            timer.start()
            return 0

        result, samples, state = _run_worker_with_collector(
            worker, sampler=sampler, interval_seconds=1.0, maximum_seconds=2.0,
        )

        self.assertEqual(result, 0)
        self.assertEqual(len(samples), 2)
        self.assertEqual(samples[0]["value"], 7)
        self.assertEqual(state["worker_lifetime_sample_count"], 1)
        self.assertEqual(samples[-1]["sampling_phase"], "post_worker")
        self.assertTrue(state["collector_thread_joined"])
        self.assertTrue(state["coverage_complete"])
        self.assertEqual(state["sample_count"], len(samples))
        self.assertIsInstance(samples, tuple)

    def test_post_worker_sample_captures_record_missing_from_last_periodic_read(self):
        first_sample_done = threading.Event()
        count_lock = threading.Lock()
        calls = 0

        def sampler():
            nonlocal calls
            with count_lock:
                calls += 1
                call = calls
            if call == 1:
                first_sample_done.set()
                return {
                    "sample_status": "trace_present",
                    "rx149_capture_attempts": {
                        "status": "stable_complete_cut", "records": [],
                    },
                }
            return {
                "sample_status": "trace_present",
                "rx149_capture_attempts": {
                    "status": "stable_complete_cut",
                    "records": [{"slot": 0, "outcome_name": "rejected"}],
                },
            }

        def worker():
            self.assertTrue(first_sample_done.wait(1.0))
            return 0

        _, samples, state = _run_worker_with_collector(
            worker, sampler=sampler, interval_seconds=1.0, maximum_seconds=2.0,
        )

        self.assertEqual(state["worker_lifetime_sample_count"], 1)
        self.assertEqual(samples[0]["sampling_phase"], "worker_lifetime")
        self.assertEqual(samples[0]["rx149_capture_attempts"]["records"], [])
        self.assertEqual(samples[-1]["sampling_phase"], "post_worker")
        self.assertEqual(
            samples[-1]["rx149_capture_attempts"]["records"][0]["outcome_name"],
            "rejected",
        )
        self.assertTrue(state["post_worker_sample_succeeded"])
        self.assertTrue(state["coverage_complete"])

    def test_sampler_error_is_recorded_and_prevents_complete_coverage(self):
        reader_entered = threading.Event()

        def sampler():
            reader_entered.set()
            raise OSError("synthetic reader failure")

        def worker():
            self.assertTrue(reader_entered.wait(1.0))
            return 0

        _, samples, state = _run_worker_with_collector(
            worker, sampler=sampler, interval_seconds=1.0, maximum_seconds=2.0,
        )

        self.assertEqual(len(samples), 2)
        self.assertEqual(samples[0]["sample_status"], "collector_error")
        self.assertEqual(samples[-1]["sampling_phase"], "post_worker")
        self.assertEqual(state["sample_error_count"], 2)
        self.assertFalse(state["coverage_complete"])
        self.assertIsNotNone(state["tail_sample_error"])


if __name__ == "__main__":
    unittest.main()
