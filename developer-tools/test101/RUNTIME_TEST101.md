# Test101 runtime tools

Test101 reuses the frozen Test087 coordinator and Test088 sender transport. Its adapter pins the current 4-frame, 10 ms interval, 40 ms budget and the 100 ms channel-149 receive profile. The sender is the separate OpenWrt AF_PACKET tool; the Mac remains host-TX blocked during the receive window.

The coordinator accepts only an explicit local IWN root. It validates the Test101 build/deployment receipts, the disarmed metadata bundle, the private sender build receipt, and the sender source and binary hashes before it creates a run directory or consumes the one-use claim. The sender hashes currently pinned by the tool are:

| Artifact | SHA-256 |
| --- | --- |
| `developer-tools/openwrt-tx-observation/afpacket-sender/awdl_probe_sender.c` | `5ff9f26def49743e803cae4e700b899b826fcc27ecfe996071bc89c8fc4592ad` |
| `developer-tools/openwrt-tx-observation/afpacket-sender/build/awdl_probe_sender-aarch64-linux-musl` | `b304381f776ecf4c91a531341a541d311d754523c2b96dc9441684e0bc7e2f22` |

Test088 retains its strict old result parser. The adapter keeps the complete new `SENDER_RESULT` event for the Test101 provenance classifier and constructs a separate legacy projection containing only the fields Test088 accepts. That projection is for transport compatibility; it is not RF evidence. AF_PACKET `send()` success, monitor echoes, radiotap completion copies, and native RX readiness do not prove over-air transmission, peer receipt, ACK, or AirDrop.

The native worker samples the read-only `NativeHcmdRxTrace` property during its lifetime. A sample is accepted only when the publication revision is stable and even, the wire header and mirrored scalar fields agree, and the row bounds are valid. A matching `ADD_STA_KEY` no-buffer response reports only the captured raw 32-bit firmware status (when its presence flag is set). Missing events mean “not observed”; a raw zero does not mean key installation succeeded. Firmware status is not a peer ACK or Wi-Fi stability result.

## Offline checks

Run the focused Test101 tools tests and syntax checks:

```sh
python3 -m py_compile developer-tools/test101/*.py
python3 -m unittest -v developer-tools/test101/test_runtime_tools_test101.py
swiftc -typecheck developer-tools/test101/arm_p2p_rx149_test101.swift
swiftc -typecheck developer-tools/test101/read_rx149_start_test101.swift
```

Print the no-action plan:

```sh
python3 developer-tools/test101/controlled_run_test101.py \
  --iwn-root /absolute/path/to/IntelWirelessNative
```

The plan is disarmed and does not read hardware, contact the router, create a run directory, consume a claim, arm the driver, or send RF.

After the Test101 and baseline build receipts plus sender receipt have been written under the explicit private root, the Test101 metadata finalizer can validate and write the disarmed bundle:

```sh
python3 developer-tools/test101/runtime_binding_test101.py write \
  --iwn-root "/Users/geek/Library/Application Support/IntelWirelessNative/RuntimeTest101" \
  --candidate 25G332-Test101 \
  --minimum-boot-epoch-exclusive <current-boot-epoch>

python3 developer-tools/test101/runtime_binding_test101.py prearm \
  --iwn-root "/Users/geek/Library/Application Support/IntelWirelessNative/RuntimeTest101" \
  --metadata "/Users/geek/Library/Application Support/IntelWirelessNative/RuntimeTest101/research/test101-runtime-private/native-controlled-probe-private.json"
```

The writer runs only the source/build/baseline/sender receipt validators and creates a mode-`0600` metadata file under the mode-`0700` candidate runtime directory. It does not read IORegistry, contact the router, consume a boot claim, arm the driver, or send RF.

## Runtime receipt inputs

The explicit IWN root must contain these current candidate-bound private files:

```text
research/test101-build-private.json
research/test101-deployment-private.json
research/test101-preparation-private/sender-build-private.json
research/test101-runtime-private/native-controlled-probe-private.json
```

The sender receipt is mode `0600`; its source/binary paths and hashes must match the fixed pins above. The deployment receipt must identify the same candidate UUID and binary hash as the offline build receipt, with `automatic_reboot=false`. Runtime creates only a new private `test101-tools-boot<boot-epoch>` directory. A second attempt in the same boot is rejected.

An authorized runtime invocation has this shape:

```sh
python3 developer-tools/test101/controlled_run_test101.py --run \
  --iwn-root /absolute/path/to/IntelWirelessNative \
  --metadata /absolute/path/to/IntelWirelessNative/research/test101-runtime-private/native-controlled-probe-private.json \
  --host root@192.168.5.1 \
  --control-path /private/tmp/test101-control.sock \
  --ap wlan7
```

No WAN/LAN settings are changed. The router adapter uses the prepared AP/monitor transport and verifies cleanup and AP preservation; no radio test is implicit in the offline plan.
