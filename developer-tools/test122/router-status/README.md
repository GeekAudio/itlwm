# Test122 路由器发送状态尾窗

这个工具只在 OpenWrt 路由器上运行，不启动 Intel 接收实验。默认命令只显示计划，不连接路由器。

```sh
python3 developer-tools/test122/router-status/router_status_tail_test122.py
```

显式运行时需要提供已经认证的 SSH ControlMaster、发送器二进制及 SHA-256、当前身份绑定的 528 字节 Test104 packet set 及 SHA-256，以及一个尚不存在的私有报告路径。发送前会先在路由器运行 `--verify-only`；只有 packet set 验证通过、149 频道 monitor 就绪且 C sender 输出完整 READY 后，工具才发送一次 GO。

```sh
python3 developer-tools/test122/router-status/router_status_tail_test122.py \
  --run \
  --host <已认证的OpenWrt主机> \
  --control-path <SSH-ControlMaster-socket> \
  --binary <router-status-sender> \
  --binary-sha256 <64位SHA256> \
  --packet-set <当前运行绑定的packet-set.bin> \
  --packet-set-sha256 <64位SHA256> \
  --output <私有目录>/router-status-tail.json
```

## 本轮范围

- 固定使用 OpenWrt 上的 `wlan7` 作为 149 频道 AP；临时创建 `iwtail122` monitor，检查其与 AP 同处 149 频道，并在退出时清理。
- 发送器以 10 ms 间隔最多发送 4 帧，发送预算 40 ms；之后独立观察至发送开始后的 2040 ms，总共约 40 ms 发送段和 2 秒状态尾窗。
- 不改 AP 设置或信道，不改 WAN/LAN，不启动 Intel 驱动、claim 或 EFI 操作。
- 完整原始 transcript 会写到新建且权限为 `0600` 的私有 JSON；里面的候选帧前缀可能含 MAC 或 IPv6 地址。父目录必须为当前用户所有、权限 `0700`。

## 证据边界

本地 `send()` 返回、monitor 的 outgoing tap、以及状态尾窗中的 candidate 都不能单独证明实际 RF 发射或原始固件 TXS、MAC ACK、对端收件或 AirDrop。`run_token` 不在发送帧内，包序号和 payload 在不同运行间可能复用；因此即使尾窗看到与 probe 相符的 candidate，也只能报告“在有界观察窗中观察到 status-candidate frame”，不能认定它属于本次发送，也不能据此推断它在 40 ms 之后才到达。样本没有逐包内核接收时间戳。

本工具不会将 unknown 改写为失败或成功；`raw_txs`、MAC ACK、RF、对端收件、原生 awdl0 输入和 AirDrop 仍分别记录为 unknown/未证明。

## 离线检查

```sh
python3 -m unittest discover -s developer-tools/test122/router-status -p 'test_*.py'
```

真实运行由协调者在核对二进制和 packet set 哈希后单独触发；离线检查本身不访问路由器。
