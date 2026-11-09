# Test129 directed data acceptance

Test129 carries its own one-shot helper and coordinator for the new `25G416-Test129` kext. The coordinator reuses the bounded Test111 execution path, the Test124 echo protocol, and the Test128 active-monitor peer script. Runtime success requires the helper and post-run IORegistry snapshot to agree on the same run token, build, boot, loaded UUID, and accepted RX lease generations.

The terminal gate reports TX completion, firmware send success, and matched UDP return separately. It accepts only directed `Stage=8` / `Result=0`, cleanup acknowledgement and absent inner resources, plus outer probe `State=7`, `RemoveResult=0`, and `ResourceMayExist=0`. Outer context, power, and station generations must match the generations frozen from the valid RX lease check that admitted the send. Radio ACK, peer receipt, and AirDrop remain false.

Build the helper offline with:

```sh
python3 developer-tools/test129/build_helper_test129.py
```

The builder writes its binary and private source-hash receipt under `RuntimeTest129/research/preparation-private/tools`. The coordinator's default mode validates Test129 build, deployment, helper, Test128 monitor, and Test124 peer receipts and prints a no-action plan. Only `--run` dispatches the existing one-shot flow; this checkout work did not run it.

The source lineage was checked before edits. At base commit `b708398c69baed74a824c5c728c26c420f051998`, SHA-256 values were:

| Derived contract | Source | SHA-256 |
| --- | --- | --- |
| One-shot helper baseline | `developer-tools/test107/arm_directed_data107.swift` | `54cfd4a49395dbeb284e1c59a4d6a82ddf56a0e94f42b8ecaaa8c8dff50cca36` |
| Coordinator baseline | `developer-tools/test127/coordinate_directed_test127.py` | `56d9c01f9ec0738c1b266830c3176b632417c30f70de064e417e062583223556` |
| Shared receipt/runner adapter | `developer-tools/test124/coordinate_directed_test124.py` | `6b8accfdf90203ef581942ac87311509d59ffca5000acc8f0f45bc1e746369aa` |
| Offline helper builder baseline | `developer-tools/test124/build_helper_test124.py` | `ff3d54ef45d9f03865e94d973bc0c6a8f57d8d0348f421392520926b28fdd10a` |
| Active-monitor peer baseline | `developer-tools/test128/openwrt_monitor_window128.sh` | `c83c993afa58c917e1b884d95043879fb97307b30b314f9eb52cf580cd311d46` |
| Active-monitor capability baseline | `developer-tools/test128/openwrt_active_monitor_capability128.cpp` | `50f54ff4666da58da8f2ca9309e2791d576b5f442637d66153ca1d423b9b5cb9` |

GitNexus was run before editing. Its index was at `2c09e69` and nine commits stale versus the source checkout; the impact query could not resolve `execute_run`, and `NativeP2PProbe` had no indexed callers. Those graph results were treated as incomplete. Manual source tracing verified the outer property publisher in `itlwm/hal_iwx/ItlIwxP2PProbe.cpp` and the terminal state values in `native/p2p_hal_probe.hpp`.
