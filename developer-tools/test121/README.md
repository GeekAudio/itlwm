# Test121 AWDL RX tools

The coordinator is a thin Test121 receipt and parser binding over Test120's
existing Test119/Test104 runner. It does not copy or reset the one-use claim
flow.

Test121 repeats the bounded AWDL receive observation with a larger raw monitor
sample bank. The sender remains four frames, 10 ms apart, within 40 ms. The
driver lease stays 100 ms. The 4-second pre-owner observation is unchanged.

## What changed

- The monitor keeps up to 64 raw samples of 512 bytes each. Test120 kept 8 and
  dropped the remaining raw samples from its report when 37 packets arrived.
- The JSON line cap is 128 KiB so a complete 64-sample report fits. All readers
  use the same bound; oversize or malformed records still fail closed.
- Samples beyond the bank, truncated raw samples, receive errors, read-limit
  hits, missing packet statistics, and kernel drops still prevent a loss-free
  result. No counts are inferred from the sample bank alone.
- The sender and parser use new Test121 schemas and an independently compiled
  binary receipt. They do not claim RF transmission, ACK, peer receipt, native
  AWDL reply, or AirDrop.

## Channel comparison

The first planned condition is station channel 36 with the receiver's ROC on
channel 149. It rechecks the earlier Test119 condition. Test120's station 149 /
ROC 149 observation is the same-channel reference, but its raw monitor bank
overflowed, so the counts are not directly comparable until Test121 repeats
the relevant condition with complete capture.

Only compare runs when the measured station and ROC channels, router monitor
channel, sender packet set, timing, and phone conditions match the plan. If a
required channel cannot be established, mark that run `condition_mismatch` and
do not attribute its RX count to a same-channel or cross-channel effect.

The current driver still has its one-use claim behavior. These tools do not
clear claims, loosen owner/PHY/DMA gates, or force a reboot between A/B windows.
Any second-window plan remains subject to the driver's actual permit and claim
state; until the firmware work proves otherwise, an unavailable window stays
unavailable.

## Offline checks

`python3 developer-tools/test121/coordinate_test121_rx149.py --plan` prints an
inert plan. `python3 -B -m unittest discover -s developer-tools/test121 -p test_test121_awdl_tooling.py -v` checks 37-sample retention, the 64-read fail-closed limit, 64-sample line sizing, truncation handling, schema binding, and fixed sender timing limits. Neither command contacts the router, changes EFI, or transmits frames.

The Test121 sender is cross-compiled for aarch64 Linux musl and kept with its
private build receipt under RuntimeTest121. It is not executable on the Mac
host; the offline host tests validate the wire protocol and capture contract.

Runtime capture requires a matching Test121 driver build/deployment receipt,
fresh disarmed metadata, and current target/router identity. Router identity
collection is read-only; never include its host address, MACs, SSIDs, run
nonces, or private runtime logs in Git. The existing START/GO claim path remains
the gate for an actual capture.
