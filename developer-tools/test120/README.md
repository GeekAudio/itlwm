# Test120 受控接收采集

Test120 的候选绑定、接收 worker 和最终 HAL 样本报告都在本目录。默认入口只输出计划；运行时复用 Test119 的双 socket sender 与 Test104 的一次性 START/GO 调度，但 build、源码冻结、部署、metadata 和当前启动身份全部以 Test120 收据校验。

    python3 developer-tools/test120/coordinate_test120_rx149.py

离线收据核对：

    python3 developer-tools/test120/test120_capture_contract.py --verify-preparation-receipts
    python3 developer-tools/test120/test120_capture_contract.py --verify-reuse-receipt

构建和部署收据齐备后，`--verify-preparation-receipts` 只读本地文件、校验归档并用 `git show` 核对冻结源文件。`--verify-current-runtime` 还会只读 `kern.boottime` 和已加载 UUID，并核对当前 runtime handoff。它们不会扫描、连接、SSH 或发送无线数据。

## 复用的发送端

Test120 明确复用 Test119 的 C sender、双 socket 协议和既有 `aarch64-linux-musl` 二进制。`sender-reuse-receipt-test120.json` 记录真实源码、协议及二进制 SHA256，并标明 `newly_compiled_for_test120=false`、`rf_tested=false`。校验会对照 Test119 私有构建收据和文件哈希，不执行 sender。

## Test120 收据位置

- 构建准备收据：RuntimeTest120/research/preparation-private/
- 运行私有目录：RuntimeTest120/research/runtime-current-private/awdl-preparation/
- 候选标识：25G332-Test120

建立 disarmed metadata 前，工具核对 Test120 build receipt 的 `source_commit` 与 `source-commit-private.json` 的 `commit`，要求 `pushed=true`；逐项以 `git show <commit>:<path>` 核实 production freeze 哈希；核对 build-input before/after 及 build receipt 绑定的 manifest 哈希；再验证归档、二进制、Info.plist、Mach-O UUID 和部署收据。Test120 不固定引用旧提交号。

重启后的运行身份必须满足：实际 boot epoch 大于本次部署绑定的门槛，kmutil 当前加载 UUID 与 Test120 build/archive/deployment 收据一致，候选和 production-freeze 哈希也一致。任一收据缺失、哈希不符或值未知都拒绝运行。

## 最终 HAL 样本

Test120 worker 已接入 Test087 的最终同快照 `_report_sample`。每个 `post_samples` 条目都附带 `native_p2p_probe_lifecycle`，只保留九项数值字段：Selected、Attempted、State、ResourceMayExist、EndSeen、RecoveryAttempted、ProofAccepted、ExerciseResult、RemoveResult。缺字段、布尔代替数字或未知状态都保持 unknown，不能用 0 补齐。接口地址、网络名和 MAC 不会复制进这个字段。

- State 7：只有选择、尝试、END、正常 exercise、资源清除及 remove 结果均符合时，标为 probe_completed_and_released。它只表示这次 HAL 诊断完成并释放资源，不代表收到 AirDrop 数据或对端确认。
- State 10：标为 exercise_failed_but_safely_cleaned，这是失败但清理获准，不是成功实验。
- State 8：标为 quarantine；若资源仍可能存在，明确记录 quarantined_resource_may_exist。
- 其他状态、缺少证明或字段不一致，都不升级为通过。

## 验证

运行离线 mock/协议测试，包含子进程 plan/import、错误 metadata 路径拒绝和实际报告 hook 的状态映射：

    python3 -m unittest developer-tools/test120/test_test120_capture_contract.py

协调器支持显式 `--prepare`、`--capture-target`、`--capture-router` 和 `--run`。准备阶段只做本地 mock/静态校验；本次没有执行 SSH、扫描、发送器、kext 或 RF。`--run` 受 Test120 收据、fresh boot/UUID、disarmed metadata、handoff、身份收据、零 host-TX 计数、one-use claim 和 START/GO 票据门控。没有新证据不得重复消耗本次启动 claim。
