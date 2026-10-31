# ROC RX host-path summary, schema 2

This addition measures how far a bounded, successful ROC window progresses
through the host receive service path. It changes no firmware command, RX
admission rule, owner filter, descriptor interpretation, TX behavior, or power
management behavior.

## Wire compatibility

The magic remains `IRXROC01`; records remain 192 bytes, with 64 fixed slots.

| Schema | Header | Records | Snapshot |
| --- | ---: | ---: | ---: |
| 1 | 128 bytes | 64 × 192 bytes | 12,416 bytes |
| 2 | 192 bytes | 64 × 192 bytes | 12,480 bytes |

The decoder accepts both versions. A v1 snapshot reports its RX summary as
unavailable; it is never filled with synthetic zeroes. The first 128 bytes of
the v2 header and all record offsets keep the v1 layout. New v2 header fields
are little-endian 32-bit integers:

| Offset | Field |
| ---: | --- |
| 128 | boundary/counter flags |
| 132 | derived stage |
| 136 | host RX interrupt-handler callbacks |
| 140 | legacy RX cause callbacks |
| 144 | MSI-X Q0/Q1 cause callbacks |
| 148 | notification-drain calls |
| 152 | host RX-ring slots consumed |
| 156 | parsed notification headers seen |
| 160 | notification headers passing generic header/length checks |
| 164 | rejected notification headers/lengths |
| 168 | validated notifications other than `RX_MPDU` |
| 172 | validated `RX_MPDU` notification headers |
| 176/180 | first/last host ring slot |
| 184/188 | hardware head observed at first/last slot |

Boundary flags are `Started`, `Ended`, `CounterOverflow`, and
`TimelineInvalid`. `Unknown` is intentional when a successful START/END pair
was not established. The flags and close reason distinguish “not started” or
“window incomplete” from a successful window that observed no host RX
interrupt.

## Stage interpretation

Stages are derived only after a canonical, successful START and END for the
same context, power, station, ROC generation, and session token. The order is a
first-blocker summary; numeric fields retain the counts behind it.

| Stage | Meaning |
| --- | --- |
| `Unknown` | No successful matching START/END pair; inspect boundary flags and close reason. |
| `NoHostRxInterrupt` | No instrumented host RX interrupt callback during the bounded window. This says nothing about RF reception. |
| `RxInterruptWithoutDrain` | RX cause reached the host event callback, but no notification drain was observed. |
| `DrainWithoutRingSlot` | Drain ran, but the host RX-ring loop consumed no slot. |
| `RingSlotsWithoutNotification` | Host slots were consumed, but no notification header reached the parser. |
| `RejectedNotificationsOnly` | Every seen notification was rejected by the generic header/length checks. |
| `ValidatedNonMpduOnly` | Every classified notification passed generic checks and was not `RX_MPDU`. A Session Protection END notification such as `0x3FB` may be the only item. |
| `RxMpduNotificationValidated` | At least one `RX_MPDU` notification header passed generic checks. The MPDU descriptor, channel, owner gate, BSD input, AWDL identity, and peer delivery are not established here. |
| `InvalidCountersOrTimeline` | A numeric counter saturated or an observation time went backwards. Do not infer a blocker from the incomplete counts. |
| `NotificationSeenWithoutValidation` | At least one header was seen but not all seen notifications reached a classified parser outcome. |
| `MixedNotificationResults` | The window contained both rejected and validated notifications, with no validated `RX_MPDU` notification. |

Stage 7 takes precedence when an `RX_MPDU` notification was validated; inspect
the numeric validated/rejected counts for additional mixed traffic.

IRQ, drain, ring-slot, and notification counters describe host callbacks and
software processing only. They are not PHY/RF packet counts. In particular,
the 24-byte `0x3FB` Session Protection END control notification has no PHY
descriptor; seeing it does not prove continuous RX activity across the ROC
window. Nor does a validated `RX_MPDU` notification prove an AWDL data frame or
AirDrop receive.

## Serialization and release safety

`ItlIwx::attach` assigns `pci.workloop = getMainWorkLoop()`. `iwx_attach`
registers the `IOFilterInterruptEventSource` on `pa->workloop`, which is saved
as `rxInterruptWorkloop_`; `tahoeP2pOnMainGate()` checks that the current code
is in that main workloop gate. The START/END reducer callback, interrupt
action, drain, slot, notification parser, stop synchronization, and snapshot
publication use this serialized gate. The summary hooks copy only bounded
scalar values, acquire no lock, allocate nothing, and perform no register,
DMA, or firmware operations.

The fixed recorder is a driver member. Stop increments the existing stop
serial/depth; the next gate turn closes capture before publication. Snapshot
encoding is allowed only for a closed recorder after all retained slot tokens
are finalized. Samples at or after the exclusive ROC deadline, after END, or
from a different epoch are not included.

## Offline checks

Run the C++ recorder test, v1/v2 decoder test, wire test, and integration
source/boundary tests before building:

```sh
python3 developer-tools/test096/test_roc_rx_correlation.py
python3 developer-tools/test096/test_roc_rx_correlation_decode.py
python3 developer-tools/test096/test_roc_rx_correlation_wire.py
python3 developer-tools/test096/test_roc_rx_correlation_source.py
python3 developer-tools/test096/test_roc_rx_correlation_sync.py
python3 developer-tools/test096/test_roc_rx_correlation_boundary.py
```
