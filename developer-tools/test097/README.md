# Test097

本轮针对 Test096 的密钥更新掉线、睡醒后无法恢复和 149 频道没有目标数据回包继续开发。离线测试和构建通过不代表实机问题已修复。

## 改动范围

- 系统唤醒后，在用户仍要求 Wi-Fi 开启、驱动未停止且接口完全关闭时，尝试恢复网卡。用户主动关闭仍然有效。
- 对单帧 TX_RSP，在它即将回收的活动描述符区间内只读扫描主机 TX_CMD。仅当区间完整可读且 FC/SC 恰好唯一匹配时，记录主机侧候选；不把它说成固件接受或对端收到，也不按固定序号差值猜测归属。
- 分开记录同一次 149 接收窗口里的中断、通知队列推进和 MPDU 入口。固件控制通知不等于无线数据帧。

当前实验配置仍关闭主机 AWDL 管理和数据发送。原生 awdl0 已注册、本机有 IPv6 地址，都不能算作对端回包或 AirDrop 传输通过。

## 重启后的验证

| 窗口 | 内容 | 必须保留的结果 |
| --- | --- | --- |
| 启动与联网 | 加载版本、接口、地址、网关、DNS、HTTPS；五分钟被动观察 | 错误和复位计数、链路是否自行消失 |
| 开关与扫描 | 一次关闭再开启、扫描列表、已知及新网络 | 用户动作时间、实际开关次数、扫描延迟；缺少新网络条件时注明 |
| 密钥更新 | 至少 65 分钟被动观察，或完整覆盖已锚定的小时更新事件前后 | 实际命令和响应、密钥事件、断开及恢复时间；后续恢复不清除本轮失败 |
| 原生接收 | 同一有界接收窗并行采集 Mac、手机和路由器证据 | 中断、队列、MPDU、原生输入分别判断；本地发送完成不当作手机收包 |
| 睡眠恢复 | 独立睡眠与唤醒窗口，随后验证联网和 awdl0 | 用户开关意图、恢复动作、固件代次；旧错误表不能归因新故障 |
| 即时热点 | 独立记录发现、加入、超时及返回原网络 | 结果不计作 AirDrop 成功 |

40 项验收逐项给出通过、部分、失败或未覆盖原因。只读采集与分析并行；开关、睡眠、热点加入和射频诊断串行。完整 AirDrop 文件验收需要当前配置支持双向数据，并以实际收件和文件哈希为准。

原始日志、设备标识、凭据、EFI 和回滚包保留在本地，不进入此目录。

## 采集 TX completion

系统启动后，确认加载版本与 `--build` 一致，再运行有界采集器：

```sh
python3 developer-tools/test097/capture_native_sta_completion.py \
  --build 25G332-Test097 --duration 3900 --interval 1 \
  --output /path/to/private/Test097-completion.jsonl
```

采集器每秒读取一次 AirportItlwm 的数字型 `NativeStaCompletion*` 属性，文件以独占方式新建并设为仅当前用户可读写。它保留每次采样的完整性字段；撕裂快照、记录丢失或版本不匹配都不会解码成有效结果。`txcmd_identity.status` 可能是 `unique_host_command_candidate`、`complete_no_match`、`complete_ambiguous`、`incomplete_scan` 或 `not_observed`；它们只描述主机侧证据。旧 schema 1 记录继续可读，身份扫描显示 `unavailable_in_schema_1`。

TX_CMD 的 API 版本仍按 `IWX_LONG_GROUP` 查询；写入设备命令头时，普通 STA 和 P2P 发送路径使用窄命令组 0，8 位 `idx` 按描述符位置低 8 位写入。可以用下面的离线测试把实际 producer 代码与 TX_RSP 扫描器串起来，覆盖 Gen2、Gen3 布局和 1024 项队列中的 257、1023 号位置：

```sh
python3 native/tests/test097_txcmd_producer_scanner.py
```

如需单独解码一次 `ioreg -a -r -c AirportItlwm` 的 plist：

```sh
python3 developer-tools/test097/txcmd_identity_completion.py \
  /path/to/private/AirportItlwm.ioreg.plist \
  --output /path/to/private/Test097-completion.json
```

## 备份规则

部署前仅保存将被替换的 `AirportItlwm.kext` 和当前 `config.plist`。确认新驱动写入并回读一致后，只保留这一份最近回滚包；不再累计整份 EFI 历史备份。其他驱动和配置未变更时不重复备份。
