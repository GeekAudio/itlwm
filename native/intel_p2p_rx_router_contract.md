# P2P RX and TIME_EVENT tap contract

`intel_p2p_rx_router.{hpp,cpp}` is a bounded side-channel from the existing
firmware receive path to the separate AWDL worker. It never owns or consumes an
mbuf, sends firmware commands, performs I/O Registry work, allocates, or sleeps.
The fixed four-record SPSC queue is produced by the serialized `iwx_rx_pkt`
dispatcher and drained by one worker. A full queue is counted and dropped; the
existing STA input and global TIME_EVENT handling must still run.

## HAL insertion points

1. In `ItlIwx::iwx_rx_pkt()`, case `IWX_TIME_EVENT_NOTIFICATION`, call
   `captureTimeEvent(pkt->data, iwx_rx_packet_payload_len(pkt), snapshot)`
   before the current STA-global UID/END checks. The 24-byte payload fields are
   decoded little-endian as timestamp, session ID, UID, MAC ID/color, action,
   and status. Correlation uses all three software generations plus exact
   MAC-ID/color and, when known, exact UID. UID zero is valid. If the command
   may have been submitted but no UID response was decoded, a matching
   MAC-context event is copied with `kLearnCandidate`; it is not treated as a
   successful start. `rawStatus` is preserved without mapping zero to success.
   Do not `break`, consume, or replace the existing global notification path.

2. In `ItlIwx::iwx_rx_frame()`, tap immediately before
   `ieee80211_inputm(IC2IFP(ic), m, ni, rxi, ml)`. Capture the Protected bit
   before any decryption/decapsulation and pass it as
   `protectedBeforeDecap`. The local RX descriptor has `mac_phy_idx`, but this
   checkout does not map it to a MAC ID/color; pass `rxMacContextKnown=false`
   and `rxMacIdAndColor=0` until such a mapping is proven. The result is an
   AWDL capture tagged `kContextUnknown`, never an assertion that it belongs to
   the P2P Device. `iwx_rx_frame` must then continue into `ieee80211_inputm`
   unconditionally.

## Suggested owner and snapshots

Keep one `IntelP2PRx::Router` member in the constructed `ItlIwx` C++ object (not
the C-style `iwx_softc`, whose constructor is not run). Build a local
`LeaseSnapshot` for each tap from the `IntelAwdl::ContextLease` and the current
power/station epochs. `active` means a P2P context still owns resources,
including `kCleanupRequired`; `timeEventSubmitted` stays true while firmware
may own the TE; `timeEventUidKnown` is a separate boolean so UID 0 is not a
sentinel. Add read-only accessors for those two bits if needed. Drain records
off the RX path and feed only the independent AWDL receive context there.

```cpp
// Notification tap: side effect only, then execute existing global STA logic.
const IntelP2PRx::LeaseSnapshot lease = makeP2pLeaseSnapshot(sc);
that->p2pRxRouter.captureTimeEvent(
    pkt->data, iwx_rx_packet_payload_len(pkt), lease);

// In iwx_rx_frame, immediately before ieee80211_inputm().
that->p2pRxRouter.tapActionFrame(
    mtod(m, const uint8_t *), mbuf_len(m), wasProtected, chanidx,
    false, 0, makeP2pLeaseSnapshot(sc));
ieee80211_inputm(IC2IFP(ic), m, ni, rxi, ml);
```

The local RX frame parser accepts only complete public AWDL PSF/MIF Action
frames. Protected frames are rejected before parsing even if hardware already
decrypted the body. A raw event with unknown action bits is recorded as
`kOther`; a foreign UID/MAC context or stale generation is not routed. These
return values describe the side tap only and never control the primary RX
path.

## Primary-source resource fact check

The upstream Linux iwlwifi MVM ROC path adds a P2P Device MAC context at
interface creation. For legacy P2P-device ROC, `iwl_mvm_roc_link()` adds the
binding first and then the P2P broadcast/internal station; its source comment
explicitly requires station/queue setup after binding. ROC cleanup flushes and
removes that station and then the binding. This supports a binding plus a
dedicated station/queue for an active ROC, not a blanket rule that every P2P
MAC must permanently have a station or binding.

Primary references:

- https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/mvm/mac80211.c
- https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/mvm/time-event.c
- https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/mvm/sta.c

Queue numbering differs by TX API. This checkout's local `if_iwxreg.h` names
static DQA queue 2 as `IWX_DQA_P2P_DEVICE_QUEUE`, and also aliases monitor
injection to queue 2, so the implementation must arbitrate that collision.
Current Linux MVM on 22000+ uses TVQM to allocate `p2p_dev_queue` dynamically
after adding the broadcast station; its queue number is not evidence that this
checkout should use Linux's dynamic queue ID.

## Offline test

```sh
clang++ -std=c++11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/awdl_action_frame.cpp \
  native/intel_p2p_rx_router.cpp \
  native/tests/intel_p2p_rx_router_test.cpp \
  -o /private/tmp/intel-p2p-rx-router-test
/private/tmp/intel-p2p-rx-router-test
```
