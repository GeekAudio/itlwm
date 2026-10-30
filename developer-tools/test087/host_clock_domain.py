"""Explicit host clock samples for correlating Test087 events with driver trace.

Deadline and selector logic must continue to use ``time.monotonic``.  This
module only adds a second, explicitly tagged clock for evidence correlation.
It never falls back to a process-local Python clock as a boot-time timestamp.
"""
from __future__ import annotations

import ctypes
import sys
import time
from typing import Any, Callable, Dict, Optional


BOOT_CLOCK_DOMAIN = "mach_absolute_time_ns_since_boot_excludes_sleep"
PROCESS_CLOCK_DOMAIN = "python_time_monotonic_ns_epoch_not_shared"
UNKNOWN_CLOCK_DOMAIN = "unknown"
UINT64_MAX = (1 << 64) - 1
UINT32_MAX = (1 << 32) - 1


class ClockUnavailable(RuntimeError):
    pass


def ticks_to_nanoseconds(ticks: int, numerator: int, denominator: int) -> int:
    """Convert Mach ticks with exact integer arithmetic and checked inputs."""
    for value, upper, name in (
        (ticks, UINT64_MAX, "ticks"),
        (numerator, UINT32_MAX, "numerator"),
        (denominator, UINT32_MAX, "denominator"),
    ):
        if type(value) is not int or value < 0 or value > upper:
            raise ValueError("invalid " + name)
    if numerator == 0 or denominator == 0:
        raise ValueError("invalid Mach timebase")
    # Python integers do not overflow at 64 bits. Do not use float or ctypes
    # multiplication here: mach ticks * numer can exceed UINT64_MAX.
    return (ticks * numerator) // denominator


class MachBootClock:
    """Read mach_absolute_time and bracket the existing process clock sample."""

    def __init__(self, *, absolute_reader: Optional[Callable[[], Dict[str, int]]] = None,
                 process_reader: Callable[[], int] = time.monotonic_ns):
        self._absolute_reader = absolute_reader or self._make_mach_absolute_reader()
        self._process_reader = process_reader
        self._unavailable_reason: Optional[str] = None
        self._timebase: Optional[Dict[str, int]] = None
        try:
            first = self._absolute_reader()
            self._validate_reading(first)
            self._timebase = {
                "numerator": first["numerator"],
                "denominator": first["denominator"],
            }
            self._first_reading = first
        except Exception as error:
            self._first_reading = None
            self._unavailable_reason = type(error).__name__

    @staticmethod
    def _validate_reading(reading: Dict[str, int]) -> None:
        if not isinstance(reading, dict):
            raise ClockUnavailable("Mach clock returned no reading")
        if any(type(reading.get(name)) is not int for name in
               ("ticks", "numerator", "denominator")):
            raise ClockUnavailable("Mach clock reading has invalid fields")
        ticks_to_nanoseconds(reading["ticks"], reading["numerator"],
                             reading["denominator"])

    @staticmethod
    def _make_mach_absolute_reader() -> Callable[[], Dict[str, int]]:
        if sys.platform != "darwin":
            raise ClockUnavailable("mach_absolute_time is unavailable")

        class TimebaseInfo(ctypes.Structure):
            _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]

        try:
            system = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
            absolute = system.mach_absolute_time
            absolute.argtypes = []
            absolute.restype = ctypes.c_uint64
            timebase_info = system.mach_timebase_info
            timebase_info.argtypes = [ctypes.POINTER(TimebaseInfo)]
            timebase_info.restype = ctypes.c_int
            info = TimebaseInfo()
            if timebase_info(ctypes.byref(info)) != 0:
                raise ClockUnavailable("mach_timebase_info failed")
            numerator = int(info.numer)
            denominator = int(info.denom)
            ticks_to_nanoseconds(0, numerator, denominator)

            def read() -> Dict[str, int]:
                ticks = int(absolute())
                ticks_to_nanoseconds(ticks, numerator, denominator)
                return {"ticks": ticks, "numerator": numerator,
                        "denominator": denominator}

            return read
        except ClockUnavailable:
            raise
        except Exception as error:
            raise ClockUnavailable(type(error).__name__) from error

    def descriptor(self) -> Dict[str, Any]:
        if self._timebase is None:
            return {
                "status": "unsupported",
                "clock_domain": UNKNOWN_CLOCK_DOMAIN,
                "process_clock_domain": PROCESS_CLOCK_DOMAIN,
                "process_epoch_shared": False,
                "reason": self._unavailable_reason or "unknown",
            }
        return {
            "status": "available",
            "clock_domain": BOOT_CLOCK_DOMAIN,
            "process_clock_domain": PROCESS_CLOCK_DOMAIN,
            "process_epoch_shared": False,
            "timebase_numerator": self._timebase["numerator"],
            "timebase_denominator": self._timebase["denominator"],
            "ticks_to_ns_conversion_error_bound_ns": 1,
        }

    def sample_pair(self) -> Dict[str, Any]:
        """Bracket process monotonic with Mach absolute samples.

        The absolute midpoint's error is bounded by half the observed bracket
        plus one nanosecond for rational-to-integer conversion.  The process
        monotonic value is retained as local context only; its epoch is never
        assumed to match a child process or the driver's uptime clock.
        """
        try:
            if self._timebase is None:
                raise ClockUnavailable(self._unavailable_reason or "unknown")
            before = self._absolute_reader()
            process_ns = self._process_reader()
            after = self._absolute_reader()
            self._validate_reading(before)
            self._validate_reading(after)
            timebase = self._timebase
            for reading in (before, after):
                if (reading["numerator"] != timebase["numerator"] or
                        reading["denominator"] != timebase["denominator"]):
                    raise ClockUnavailable("Mach timebase changed")
            if type(process_ns) is not int or process_ns < 0:
                raise ClockUnavailable("process monotonic sample invalid")
            lower = ticks_to_nanoseconds(
                before["ticks"], timebase["numerator"], timebase["denominator"])
            upper = ticks_to_nanoseconds(
                after["ticks"], timebase["numerator"], timebase["denominator"])
            if upper < lower:
                raise ClockUnavailable("Mach absolute clock moved backwards")
            width = upper - lower
            return {
                "status": "available",
                "clock_domain": BOOT_CLOCK_DOMAIN,
                "process_clock_domain": PROCESS_CLOCK_DOMAIN,
                "process_epoch_shared": False,
                "process_monotonic_ns": process_ns,
                "boot_monotonic_ns": lower + width // 2,
                "boot_sample_lower_ns": lower,
                "boot_sample_upper_ns": upper,
                "sample_bracket_width_ns": width,
                "sample_error_bound_ns": (width + 1) // 2 + 1,
                "timebase_numerator": timebase["numerator"],
                "timebase_denominator": timebase["denominator"],
                "ticks_to_ns_conversion_error_bound_ns": 1,
            }
        except Exception as error:
            process_ns = None
            try:
                process_ns = self._process_reader()
            except Exception:
                pass
            return {
                "status": "unsupported",
                "clock_domain": UNKNOWN_CLOCK_DOMAIN,
                "process_clock_domain": PROCESS_CLOCK_DOMAIN,
                "process_epoch_shared": False,
                "process_monotonic_ns": process_ns,
                "boot_monotonic_ns": None,
                "boot_sample_lower_ns": None,
                "boot_sample_upper_ns": None,
                "sample_bracket_width_ns": None,
                "sample_error_bound_ns": None,
                "reason": type(error).__name__,
            }


def sample_clock_pair(*, absolute_reader: Optional[Callable[[], Dict[str, int]]] = None,
                      process_reader: Callable[[], int] = time.monotonic_ns
                      ) -> Dict[str, Any]:
    """Convenience helper for a single pair (use MachBootClock for runs)."""
    return MachBootClock(absolute_reader=absolute_reader,
                         process_reader=process_reader).sample_pair()
