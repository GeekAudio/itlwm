# Test089：OpenWrt 单帧 TX status 观察

## 当前状态

离线 host 检查和 ARM64 静态构建已通过。Test089 路由器工具本轮**尚未运行**，没有本轮 RF 发送、固件 TX status、空口到达或手机收件证据。工具也没有部署或触碰 Intel EFI/驱动。

Test089 将原 Test088 的 106 字节探针原样发送一次，并在同一个 OpenWrt monitor socket 上观察最多 2 秒。Test088 sender 与驱动均保持冻结。C 工具默认只打印 dry-run 计划；实际单帧运行由 Test089 wrapper 的显式 GO 控制。

## 结果能说明什么

- `PACKET_OUTGOING` 是本机 packet socket 的发射回显。
- `PACKET_OTHERHOST`、完整匹配同一 96 字节 MPDU，且同时带 Radiotap `TX_FLAGS` 与 `DATA_RETRIES` 时，记作 `host_driver_completion_candidate`。其形式符合 mac80211 的 host completion 副本，但仍只记为候选；`run_token` 不在帧内，不能证明该副本唯一属于本次发送。
- 探针设置了 `NOACK|NOSEQNO`。mt76 对 `NO_ACK` 帧可以在 host completion 路径生成这个副本，而不等待 firmware TXS；所以候选回执不能证明 firmware TX status、RF 空口发送、ACK 或对端收到。`TX_FLAGS=0` 也不表示 ACK 成功。
- 没有 status 候选只表示本次有界窗口没有观察到符合条件的副本，不能据此认定帧被丢弃。

`run_token`/nonce 只用于本机协调器关联，不写进 Wi-Fi 帧，也不是空口身份。

## 复用组件和运行依赖

Test089 复用 Test087 的 OpenWrt monitor 创建、协议解析与清理流程，并复用 Test087 引用的 Test086 SSH bootstrap。Test089 wrapper 只会临时创建并清理 monitor 接口；要求 AP 已在 channel 149、5745 MHz、80 MHz，且该 PHY 支持 monitor。它不调整 AP 信道，不改 WAN/LAN 配置。

本机需要 Python 3 标准库、`ssh` 和已认证的 SSH ControlMaster。OpenWrt 侧需要 root/CAP_NET_RAW、`iw`、`ip`、`awk`、`base64`、`sha256sum` 及常见 BusyBox shell 工具。C 观察器是静态 ARM64 Linux musl 程序。

## 离线验证

```sh
make -C developer-tools/test089/txstatus-observer host-test
PYTHONDONTWRITEBYTECODE=1 python3 developer-tools/test089/test_router_tx_status_once.py
make -C developer-tools/test089/txstatus-observer aarch64 ZIG=/path/to/zig
```

Host 检查覆盖 Test088 源码和 manifest 的探针字节一致性、radiotap 解析与对齐、严格 MPDU 长度、明确 FCS 标记处理、packet type 分类、字段缺失和错误输入。wrapper 的 13 项单元测试只验证本地协议结果，不连接路由器。

源码和复用依赖的 SHA256、ARM64 构建产物 SHA256 记录在 [SOURCE-MANIFEST.json](SOURCE-MANIFEST.json)。构建二进制留在本地 `build/` 目录，不纳入 Git 提交。
