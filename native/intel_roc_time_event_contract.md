# Intel time-event ROC adapter

This offline helper encodes the existing `iwx_time_event_cmd` API-v2 payload
and structurally decodes the fixed-size ADD response. It does not submit
commands or claim that a P2P/AWDL interface exists. A decoded response is not
classified as accepted or rejected.

The wire layout and event IDs come from this repository's
`itlwm/hal_iwx/if_iwxreg.h` (`iwx_time_event_cmd`, `iwx_time_event_resp`,
`IWX_TE_P2P_DEVICE_DISCOVERABLE`, `IWX_TE_P2P_CLIENT_ASSOC`) and the existing
STA command path in `ItlIwx.cpp`. ROC field choices follow the legacy
time-event fallback in upstream Linux
[`iwlwifi/mvm/time-event.c`](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/mvm/time-event.c);
modern Linux may use the separate ROC command instead. Its P2P frame TX path
also selects a P2P-specific station and off-channel queue in
[`iwlwifi/mvm/tx.c`](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/mvm/tx.c),
which the current itlwm STA transmit path does not expose.

## Response-field evidence and limit

The local API comment says `status` bit 0 indicates success, while the local
`iwx_send_time_event_cmd()` tests `status == 0` as success. Current upstream
Linux API documentation says bit 0 indicates success in
[`fw/api/time-event.h`](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/fw/api/time-event.h#L214-L227),
but its response callback checks payload length and event type, then stores
`unique_id` without examining `status` or rejecting UID 0
([`mvm/time-event.c`](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/mvm/time-event.c#L490-L541)).
Current [FreeBSD](https://cgit.freebsd.org/src/tree/sys/dev/iwx/if_iwx.c#n14302)
and [OpenBSD](https://github.com/openbsd/src/blob/master/sys/dev/pci/if_iwx.c#L2917)
`iwx` paths use session-protection commands for association protection and do
not provide a validating TIME_EVENT ADD response path. The available primary
sources therefore do not resolve the conflict for the firmware response used
here or prove UID 0 invalid.

`DecodeRawTimeEventResponse()` preserves all four little-endian fields. It
checks only the response length and pointer; callers must not treat
`ResponseResult::kDecoded` as firmware success. UID 0 is retained as raw data.

The helper currently covers only a single TE ADD payload and structurally
decodes its response. A real ROC still needs an independently allocated P2P MAC
context, PHY/channel setup, binding and station/TX-queue setup, serialized
per-event UID/state with notification handling, and a management-frame TX/RX
route. The current itlwm path has STA-global TE/binding state and STA-bound TX,
so this helper must not be wired into it without that lifecycle work and HAL
review.

Offline test:

```sh
clang++ -std=c++11 -Wall -Wextra -Werror \
  native/intel_roc_time_event.cpp \
  native/tests/intel_roc_time_event_test.cpp \
  -o /tmp/intel_roc_time_event_test
/tmp/intel_roc_time_event_test
```
