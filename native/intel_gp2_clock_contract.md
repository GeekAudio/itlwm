<!-- SPDX-License-Identifier: GPL-2.0-only -->
# GP2 to host monotonic interval contract

`IntelGp2Clock::Mapper` is offline clock math and state only. It performs no
device access and is not wired into the driver, OpenCore, or the PSF worker.

## Sample witness

A usable sample must contain a 32-bit GP2 microsecond value and host monotonic
timestamps taken immediately before and after the actual GP2 read, while the
caller holds the NIC lock. The caller marks this as
`kDirectGp2ReadBracket`. An RX descriptor paired with a host timestamp captured
after RX processing is `kLateRxHostTimestamp` and is rejected. The class cannot
prove that a caller told the truth; future integration must only create the
direct-read witness at the guarded register-read site.

## Limits and mapping

The caller must provide an explicit verified drift bound (ppm), maximum host
bracket width, maximum sample/mapping age, and maximum interval width. There are
no proven hardware defaults. Limits fail closed unless the drift bound is
marked verified, the age is below half of the 32-bit GP2 range, and the bracket
and uncertainty limits are internally consistent.

For a forward counter delta `D`, less than `2^31` microseconds, the mapper uses
the caller's relative-rate bound `r` to conservatively map elapsed host time to
`[floor(D * 1e6 / (1e6 + r)), ceil(D * 1e6 / (1e6 - r))]`. It adds that range to
the host bracket endpoints and rejects overflow, stale samples, generation
mismatch, half-range ambiguity, non-monotonic samples, rate-bound violations,
and intervals wider than the configured uncertainty cap.

Every sleep, firmware reset, driver reset, or power epoch change invalidates
the map. A new map requires a strictly increasing, nonzero generation and a
fresh direct-read bracket. GP2 is not converted to TSF, AWDL peer time, or an
Apple clock domain by this helper.

## Test command

```sh
clang++ -std=c++14 -O1 -g -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  native/intel_gp2_clock.cpp native/tests/intel_gp2_clock_test.cpp \
  -o /tmp/intel_gp2_clock_test && /tmp/intel_gp2_clock_test
```
