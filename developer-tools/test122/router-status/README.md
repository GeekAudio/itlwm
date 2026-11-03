# Test122 逐帧发送状态观察

这个工具在 OpenWrt 上发送少量测试帧，核对主机发送状态副本。默认只显示计划；不会连接路由器。

```sh
python3 developer-tools/test122/router-status/router_status_tail_test122.py
```

## v2 增加什么

- 每轮生成一个非零、随机的 8 字节 `wire_nonce`，写入四个测试帧的 UDP 内容；Wi-Fi 完整 Sequence Control 和 AWDL 序号分别按帧递增。IPv6 UDP 校验和重新计算。
- 保持原来的 96 字节 MPDU、4 帧、10 ms 间隔和 40 ms 发送预算；总观察窗口为 2040 ms，包含独立的 2 秒状态尾窗。
- 每次 `recvmsg` 返回后记录 `CLOCK_MONOTONIC` 时间。这是**用户态读到样本的时刻**，不是内核到达时间或空口时间，不能直接与 Mac 的时钟相减。
- 当前实现先完成四帧发送，再读取观察队列。因此逐包的发送前后时间可以定位调用顺序，观察时间不能用于计算硬件完成延迟。
- 用帧内标记、完整 SC、AWDL 序号及地址核对回执；同一持久目录里的 nonce 领取记录禁止重复使用标记。失败后也使用新标记。
- 无法解析、不支持或不匹配的样本保留最多 8 条，每条最多 256 字节原始前缀，并记录截断、溢出和缺失字段。未知不会被改写成成功。

新 packet set 为 `test122-correlated-packet-set/v2`：112 字节头、4 个 106 字节 packet，共 536 字节。旧 528 字节 Test104 数据不被 v2 接受。纯离线编码器是 `packetset_correlated_test122.py`；它不访问设备。

## 运行

使用已认证的 SSH ControlMaster、已核对 SHA-256 的 ARM64 Linux sender、新生成且绑定当前地址的 packet set，以及私有输出目录。`--nonce-ledger-dir` 必须持续复用同一个目录，不能每轮换目录。

```sh
python3 developer-tools/test122/router-status/router_status_tail_test122.py \
  --run \
  --host <已认证的OpenWrt主机> \
  --control-path <SSH-ControlMaster-socket> \
  --binary <router-status-sender> \
  --binary-sha256 <64位SHA256> \
  --packet-set <本轮packet-set.bin> \
  --packet-set-sha256 <64位SHA256> \
  --nonce-ledger-dir <固定的私有nonce目录> \
  --output <私有目录>/router-status-tail.json
```

发送前先验证 packet set，确认临时 monitor 与 `wlan7` AP 同处 149 频道，再发送一次 GO。结束时清理临时接口及文件。工具不改 AP 信道、WAN/LAN、Intel 驱动、EFI 或 Intel 采集门禁。

原始记录可能含地址，只写入权限 `0600` 的私有报告；父目录和 nonce 目录须为当前用户所有且权限 `0700`。

## 结果怎么看

`frame_correlation` 将本轮标记对应的主机状态副本与发送调用关联，保留原始 TX flags、重试数和观察时间。`host_tx_fail_bit` 只是驱动栈报告的失败位；未置位也不等于独立验证了硬件 ACK、实际空口发送、Intel 收件或 AirDrop。

本工具不重新启动 Intel 接收窗口。新路由器记录不能与旧 Intel 快照拼成同帧证据；严格接收验证仍需要同一窗口的帧身份或实际载荷。

`capture_loss_free` 只表示当前队列、截断和内核丢包检查通过；是否完整分类另看 `classification_complete`。不支持的 radiotap 字段和原始样本缓冲溢出必须保留为未知。

## 与 Intel 接收验证的接线边界

`coordinate_test122_rx149.py` 仍使用旧 528 字节 packet set 和固定载荷 `T086RX01`，尚未接入这里的 v2。下一步需一起适配 packet-set binder、sender/protocol 和 `awdl0` UDP listener，使发送和接收校验共用本轮 nonce；保留原有 GO、100 ms 接收 lease 和清理路径。ACK 状态不作为接收测试的放行条件。

当前内核可通过 listener 实际收到 nonce 验证原生输入成功。若未收到，现有 RX 记录只有部分帧身份，不能据此判断该 nonce 在哪一层丢失。特别是 `Rx149InputReceipt.sequence` 是本地收据序号，不是 Wi-Fi Sequence Control；严格的入口归因仍需补充有界内核记录。

四个测试帧的 UDP 载荷共用同一个 nonce。listener 收到它，只能证明本轮至少一次载荷输入；收到四份相同 nonce 也可能包含重复包，不能据此认定四个不同 ordinal 全部到达。逐帧接收计数必须在同一 MPDU/收据中关联完整 Wi-Fi SC、AWDL 序号和 nonce，再按 ordinal 去重；只有 payload 的 socket 记录不满足这一条件。

## 离线验证

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s developer-tools/test122/router-status -p 'test_*.py' -v
```

测试覆盖 Python/C 编解码互通、错误标记和校验和、序号回绕、时间边界、异常样本保留及 nonce 重复领取。离线测试不发送无线帧。
