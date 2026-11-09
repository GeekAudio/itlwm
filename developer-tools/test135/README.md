# Test135 system QM browse helper

Test135 is the deployed Discovery RX candidate; its first system browse/ARM run awaits the next boot. This helper has not been run. It is fixed to build `25G416-Test135`, UUID `7ED85846-F29A-33EB-BED1-EBA2D9009D36`, and the reviewed A baseline. It refuses to browse or arm unless the loaded UUID, build tag, runtime switches, and idle state match.

The profile requires manual TX probe, PSF observation, MIF followup, GP2 observation, resident data, TX evidence, Discovery experiment, MIF current-slot, and Discovery RX input. It requires current-AW fallback, QM normal-priority B, RX149, directed-data, multicast admission, and reply shadow to be off. Baseline QM flags remain `7` (`CMD_RATE | ENCRYPT_DIS | HIGH_PRI`); the B comparison flag stays disabled.

## Run

The default command is read-only and prints a JSON preflight receipt:

```sh
swift developer-tools/test135/browse_system_qm_test135.swift
```

Before the one-shot run, confirm Wi-Fi is enabled and associated and native `awdl0` is bound using read-only interface state; this is not a connectivity smoke test. After the exact candidate is loaded and preflight matches, the command starts one system Bonjour browse for `_airdrop._tcp.` in `local.` with `kDNSServiceFlagsIncludeP2P` and `kDNSServiceInterfaceIndexAny`, then sets `NativeP2PArmOnce` exactly once. It observes the driver for at most 20 seconds. It does not pick a network interface, send test UDP, retry, reset the device, or force cleanup.

```sh
sudo swift developer-tools/test135/browse_system_qm_test135.swift --run \
  > /path/to/private/RuntimeTest135-system-browse-private.json
```

Keep the receipt in the private RuntimeTest135 evidence directory. The JSON contains before/after numeric snapshots, address-free `NativeP2PQmWireSnapshot` and `NativeP2PCurrentAwAttemptOnly` payloads as base64, browse callback counts without service names, and the current PSF/MIF scalar properties. To decode the two payloads with the existing decoder, load `developer-tools/test079/tools/awdl_osdata_diagnostics.py` and call `decode_qm_wire_osdata(base64.b64decode(snapshot))` and `decode_current_aw_attempt_osdata(base64.b64decode(snapshot))` for the corresponding final fields.

## Evidence scope

The JSON distinguishes the Browse API being accepted, a terminal probe snapshot, cleanup receipts, Discovery ifnet input counters, and the local QM wire snapshot. Its `cleanup_receipt_proven` status is limited to probe states 7 (complete) or 10 (exercise failed but recovery accepted), plus exact build/loaded UUID, unchanged power-reset count, a changed and internally consistent context generation, stable terminal generations, no possible remaining resource, successful outer remove, accepted Discovery MAC remove, a real ROC END with accepted status and `CleanupAllowed`, no unknown ROC outcome, and an empty RX pending count. A missing ROC END leaves cleanup unknown. State 10 keeps the operation error visible. Any missing field, profile mismatch, timeout, reset, generation mismatch, or cleanup mismatch remains blocked or unknown.

`NativeAwdlDataDiscoverySameWindowCommitted` only records that the input remained within the published lease window; it does not prove a post-input peer recheck. An accepted Bonjour browse or local driver TX snapshot is not independent radio ACK evidence, peer receipt, mDNS reachability, or successful AirDrop.
