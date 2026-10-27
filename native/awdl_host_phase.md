# Experimental host-monotonic AWDL phase helper

`awdl_host_phase.{hpp,cpp}` computes the synchronization fields for the
existing one-channel, first-cycle observation plan. The initial host sample is
the fixed phase origin; a later frame passes that same origin, a fresh sample,
the same 16-slot table, and the same conservative ROC deadline. The helper
never rebuilds the table from the later sample, which would restart the
schedule and incorrectly advertise more dwell.

## Source-backed equations

The pinned OWL `sync.c` initializes `last_update=now`, `aw_counter=0`,
`aw_period=16 TU`, and `presence_mode=4`. It converts elapsed microseconds to
TU by integer division. With `elapsedTU=floor((sample-origin)/1024)`, the same
functions compute:

```text
eawTU = 4 * 16 = 64
txDownTU = eawTU - (elapsedTU % eawTU)
nextAwSequence = (elapsedTU % eawTU) / 16
                + 4 * (elapsedTU / eawTU)
```

The TX builder writes `nextAwSequence` to both `next_aw_seq` and `ap_alignment`.
It computes `remaining_aw_length` as `max(0, commonAwLength -
(awPeriod * presenceMode - txDownTU))`; with the fixed common AW length of 16 TU,
this is 16 TU at the exact origin and zero after the first 16 TU of each 64-TU
EAW period. This explains why the old planner's `txDownCounterTu=0` at an exact
origin did not match OWL's formula: the boundary value is 64 TU.

The pinned AWDL spec says the TX down-counter is TU to the next slot boundary,
presence mode 4 is AWs per slot, and the next channel is the channel of the
next AW. The helper maps the sequence to the four-AW slot index, takes that
channel from the unchanged original table, and accepts only the current
confirmed ROC channel. It accepts only a contiguous prefix of one social
channel followed by zero/unused slots. Every advertised complete slot must fit
inside the same hard ROC deadline. It rejects partial or later-cycle coverage.

## Evidence and limits

- [Pinned OWL `sync.c`](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/sync.c)
- [Pinned OWL `tx.c`](https://github.com/seemoo-lab/owl/blob/0ee3263f944ea721c355f826aa90d636d012a512/src/tx.c)
- [Pinned AWDL wire spec](https://github.com/t4t5/owly/blob/9a676e11d011c34ea32798a2541f2b1eeb66e731/docs/SPEC.md)

This is math for the explicit OWL-style host-monotonic experiment only. It
does not map host monotonic time to Intel GP2, TSF, or peer AWDL time; it does
not prove actual TX time, on-air slot coverage, channel switching, cyclic
expiry, peer synchronization, native `awdl0`, or AirDrop. Those remain false in
the experiment's runtime profile.

## Test

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -O1 -g \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  native/awdl_host_phase.cpp native/tests/awdl_host_phase_test.cpp \
  -o /tmp/awdl_host_phase_test
/tmp/awdl_host_phase_test
```
