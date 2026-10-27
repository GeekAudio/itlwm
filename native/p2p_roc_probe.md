# Intel P2P 驻留测试

Test018 已在 AX201 / 25G241 上收到 P2P MAC 创建和删除的固件 ACK，普通 Wi-Fi 保持连接。
Test019 已于 2026-10-27 实机通过独立 PHY、绑定和固件驻留通知测试：开始、结束通知均为成功，资源清理完成，随后 en1 HTTPS 请求正常。它还不提供 AWDL 接口、管理帧发送或 AirDrop 文件传输。

Test019 的运行时属性曾漏改，显示为 Test018；加载的 Mach-O UUID `AD54D3E5-6DEC-3F95-BE26-D8065C695522` 与 Test019 发布包一致。后续打包从 `AirportTahoeBuild` 自动生成运行时标签，读取脚本同时核对已归档二进制的 UUID。

## 本机命令路径

本机实际固件为 `iwlwifi-so-a0-hr-b0-68.ucode`，宣告 capability 54（Session Protection）和 44（Dynamic Quota）。早期使用 QuZ 测试样本不能代表本机传输路径。
命令版本表中 Session Protection 为 group 3 / command 5 / API 1，通知为 group 3 / command 0xfb / API 2。
因此使用 24 字节 `SESSION_PROTECTION_CMD`，常规驻留持续 100 ms；接收 16 字节通知。
发现/监听使用配置 2；管理帧发送使用配置 3，
与官方 Linux 的 `IEEE80211_ROC_TYPE_MGMT_TX` 路径一致。
唯一的 300 ms 例外是配置 3 且 P2P PHY 1 已绑定到当前合法的第 6 信道；300 ms 按 API 换算为 292 TU。其他配置、频道和时长仍限于原 100 ms 路径。
准备、命令提交、通知匹配和清理必须使用同一配置，未知配置拒绝执行。
本轮不发送旧 `TIME_EVENT_CMD`，也不调用只收集 STA 的旧配额表函数。

顺序：

1. 延用 Test018 的独立 MAC 1；STA 使用 MAC 0、PHY 0。
2. 预留启动时已创建的空闲 PHY 1，保存原信道，移除后以 20 MHz 在目标信道创建。仍支持同频道；离频道只允许当前信道表 `ic_channels[6]` 中合法的 2.4 GHz / 2437 MHz 第 6 信道。
3. 创建独立 binding 1，将 P2P MAC 与 PHY 1 绑定。
4. 在主 gate 内先启用通知记录器，然后在 gate 外提交驻留命令。
5. 在 gate 外限时等待通知；只接受本次运行代次、MAC 1、本轮配置和合法状态字段。
6. 收到匹配的结束通知后，删除绑定，恢复 PHY 1，再由原测试流程删除 MAC 1。

成功要求命令 ACK 为 0、实际收到顺序正确且状态为 1 的开始和结束通知、资源清理完成。
Test031 已在同频道配置 3 下得到管理帧 ticket 完成、开始和结束通知均为状态 1、资源清理完成，且 Wi-Fi 可用。这只证明本机管理帧发送和固件驻留生命周期；没有证明收到对端帧或完成 AirDrop。
Test032 候选将配置 3 链路限于当前信道表里的合法第 6 信道，以 300 ms 单次手动驻留和一帧诊断 TX 观察对端响应；本轮尚未实机验证。
配置 3 在[上游固件 API](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/fw/api/time-event.h#L425-L432)中是不分片的，因此 300 ms 是连续离频道窗口，可能让 STA 流量短暂停顿；独立 PHY/binding 不等于实机并发无损保证。worker 总等待 800 ms，固件开始延迟仍是配置相关；若超时或缺少匹配 END，测试隔离资源，不做推测性清理。
命令 ACK、持续时间过去、开始通知失败，都不能代替结束通知。
超时、未知命令结果、矛盾通知或清理失败会隔离本次测试，保留可能存在的资源，不重试。
旧 STA 通知路径只接收 MAC 0、配置 0；P2P 结束通知不会清除 STA 的关联状态。

## Test032 频道边界

Test032 的 off-channel 请求必须由 worker 传入当前接口的 `&ic_channels[6]`。HAL 再核对指针身份、2.4 GHz 标记、信道号 6、2437 MHz、有效 flags，并拒绝 `PASSIVE` 或 `DFS`。同频道第 6 信道也走同一检查，避免 STA 与目标指针相同而绕开 TX 规则。其他 off-channel 信道 fail closed；既有同频道非第 6 信道流程保留。

Test032 仅给独立 P2P MAC 1 增加接收过滤：保留探测请求，同时请求管理/控制帧和组播帧送到主机；不启用 promiscuous mode。此项改动不触碰现有 STA MAC 的过滤器、MAC 地址或私有地址。过滤位语义与 Linux 主线定义一致（[mac.h](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/fw/api/mac.h)）；上游 P2P Device 路径仍只请求探测请求过滤（[mac-ctxt.c](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/mvm/mac-ctxt.c#L3553-L3568)）。本轮是为 AWDL 公共 Action 帧接收做的窄偏离，是否被本机固件接受仍需实机观测。固件 ACK、ROC 通知和 TX ticket 完成仍不等于收到 AirDrop 对端帧。

Linux 上游的参考路径是：[ROC / off-channel 管理帧处理](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/mvm/mac80211.c#L4632-L4822)、[Session Protection 配置映射](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/mvm/time-event.c#L1071-L1155) 和 [P2P Device MAC 过滤器](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/mvm/mac-ctxt.c#L829-L845)。这里参考控制流和隔离策略，不复制 Linux 或第三方 macOS 实现。

## 构建和读取

默认构建不启用测试。仅测试包使用：

```sh
python3 scripts/build_tahoe.py --configuration Debug --p2p-roc-probe --output /private/tmp/new-test.zip
```

`NativeP2PRocStage=5` 表示资源流程已经安全结束；同时要求
`NativeP2PRocResult=0`、`NativeP2PRocObserved=1` 和原 MAC 测试成功，才算本轮通过。
Stage 6 表示隔离，不应在本次启动中重试。
这些结果只能证明固件驻留生命周期，不能证明已收到对端无线帧或完成 AirDrop。

协议依据：[Intel 上游 Session Protection 实现](https://github.com/torvalds/linux/blob/v6.1/drivers/net/wireless/intel/iwlwifi/mvm/time-event.c#L762)。
没有复制第三方 macOS fork 的实现。
