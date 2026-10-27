# Intel AWDL context ownership

`intel_awdl_context.{hpp,cpp}` is an unlinked HAL ownership controller. It
serializes acquisition and reverse cleanup of a firmware PHY lease, P2P Device
MAC, MAC-to-PHY binding, firmware station, DQA P2P Device queue, and a TIME_EVENT
v2 session. It does not send firmware commands itself. A future adapter must
provide the real iwx command calls and run every method and notification on the
HAL command gate.

The resource names come from this checkout's `if_iwxreg.h` and `ItlIwx.cpp`:

- `IWX_NUM_PHY_CTX` is 3; startup adds PHY IDs 0, 1, and 2. Infrastructure STA
  authentication binds its node to PHY 0. P2P must lease a separately-owned
  pre-created slot and must not overwrite the STA PHY.
- `IWX_NUM_MAC_INDEX_DRIVER` is 4; the auxiliary scanning MAC uses ID 4. The
  normal MAC setup currently only creates BSS STA or listener contexts and
  stores one `IWX_FLAG_MAC_ACTIVE` bit. P2P Device MAC type 6 is defined by the
  firmware ABI but has no production creation path here.
- Binding carries up to three MAC IDs, while current `iwx_binding_cmd` adds a
  single MAC. The controller rejects an unavailable PHY/channel lease instead
  of assuming that the existing STA binding can be reused.
- DQA assigns static queue 2 to P2P Device traffic; this checkout also uses
  queue 2 for monitor injection. Admission must prove the latter is unused.
  Current `iwx_add_sta_cmd` manages only the single infrastructure station.
- TIME_EVENT UID and `IWX_FLAG_TE_ACTIVE` are currently global singletons. The
  v2 notification contains UID, MAC ID/color, action, and scheduling status;
  the current consumer matches only the global UID and END bit. An adapter must
  route the whole tuple to this controller. The controller preserves raw ADD
  response status and UID (including zero) and waits for a matching successful
  START notification before reporting its Active state.

Acquisition failures unwind only resources known to have been created. A
callback that cannot tell whether firmware applied a command returns
`kNeedsCleanup`; the controller retains the dependency and retries reverse
cleanup. Once a TIME_EVENT command may have been applied, it retains all
resources until a matching END or a completed `iwx_stop_device` reset. A mere
RESET_BEGIN, scan completion, or command response is not treated as that drain.

Admission requires the controller and station radio to be ready, the P2P
firmware and DQA capabilities, an idle scan, no RF kill or shutdown, queue 2
ownership, and a channel lease. If the station and AWDL channels differ, an
explicit compatible-channel lease is required. That lease still needs a real
firmware time/channel scheduler before any production adapter can issue ROC or
management-frame traffic.

## Test

```sh
clang++ -std=c++11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/intel_awdl_context.cpp \
  native/tests/intel_awdl_context_test.cpp -o /private/tmp/intel-awdl-context-test
/private/tmp/intel-awdl-context-test
```

The test drives the actual controller methods with fault-injected command
callbacks. It does not load a kext, transmit a frame, or prove hardware AWDL.
