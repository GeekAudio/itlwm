# Test107：原生单帧发送诊断

Test108 / Test109 / Test110 沿用此工具，`--expect-build` 填当前测试版本。加入 Test110 只扩展允许的版本身份，不放宽任何运行门禁。

只验证 `awdl0 → BSD 输出 → 独立 LINK/TID0 队列 → 固件完成 → 回收`。不把 socket 返回成功或固件完成当成手机收件、无线 ACK 或 AirDrop 成功。

默认只检查参数，不访问 IOKit、socket 或无线硬件。加 `--run` 且以管理员运行才会申请一次诊断；任何错误都不会自动重试。驱动默认关闭此路径，测试构建也须由管理员显式触发。

```sh
xcrun swiftc arm_directed_data107.swift -o /tmp/arm_directed_data107
/tmp/arm_directed_data107 --expect-build 25G332-Test107 --expect-uuid UUID --peer-mac MAC --local-ipv6 LINK_LOCAL --nonce 16hex --run-token 32hex
```

用实际加载的 Mach-O UUID、对端单播 MAC、`awdl0` 的标准形式链路本地 IPv6 地址，以及本次新生成的 nonce 和 token 替换参数。地址参数不含 `%awdl0`。测试程序会提前绑定 `awdl0` 和 UDP 源端口 49153；匹配 ROC START 后只发一条 8 字节 nonce 到 `ff02::1:49152`，跳数为 1。

本诊断把 IPv6 组播报文封装为发给指定对端的单播 AWDL 数据帧，用于检查独立发送队列；不注入邻居记录，不伪造手机回复。只使用当前监管配置允许主动发送的频道 6，最长 100 ms，不解除频道 149 的 PASSIVE 限制。

结果按行输出 JSON，区分 ARM 是否可能生效、实际 UDP 提交、数据描述符、固件完成及资源回收。若完成身份不明，驱动保留可能仍被 DMA 使用的缓冲区并隔离队列；不要自动重跑。输出不包含输入的 MAC、IPv6、nonce 或 token。

## Test110：同 socket 限时回包验证

Test110 在上述单帧发送后，继续使用原来已绑定 `awdl0:49153` 的同一个 socket 接收；不会创建第二个监听器，也不会在收到错误包后重发。C 辅助层按 `recvmsg` 的完整 payload、`IPV6_PKTINFO`、`IPV6_HOPLIMIT` 和来源地址严格匹配。有效回包必须来自本轮对端 IPv6/49152，目的为本机 IPv6/49153，scope 与 `awdl0` ifindex 一致、hop limit 为 1，完整 8 字节 payload 与本轮 nonce 完全相同。最多处理 16 个数据报，接收时间不超过 100 ms，也不超过本轮内核 RX lease deadline 和对端 READY 剩余窗口。

运行前必须由真实 OpenWrt echo 进程产生 READY，再由协调器从该子进程的实时 stdout 生成权限为私有的 JSON 收据；禁止从旧日志或手写内容生成 READY。`developer-tools/test110/openwrt_echo_peer.cpp` 只监听已经准备好的 2.4 GHz 频道 6 monitor 接口，不改接口、信道或 WAN/LAN；它仅在收到匹配本轮身份、完整 UDP/IP 校验和及 nonce 的帧后尝试回送一次。`openwrt_echo_ready.py` 校验仍在运行的子进程、完整 READY 行、身份和 16 秒窗口，并记录原始 READY 行 SHA256。收据绑定本轮 run token、nonce、本地与对端 IPv6/MAC、频道和端口契约；工具校验 UTC 创建时间不超过 120 秒、对端窗口至少剩 6 秒，并独立重算契约摘要。计划模式只校验命令行，不读取 READY 文件、不访问 IOKit、不创建 socket。

匹配的 nonce 回包证明该报文已到绑定 `awdl0` 的 UDP socket，经过本机 IP/ifnet 接收路径。没有回包时只报告 `no_peer_return_observed` 或 `no_matching_peer_return`，不据此判定驱动 RX 故障。即使回包匹配，也不代表 802.11 ACK 或 AirDrop 成功。

Test110 构建时把接收 helper 链接到 Swift 工具：

```sh
xcrun clang -std=c11 -Wall -Wextra -Werror -c ../test110/matched_return_test110.c -o /tmp/matched_return_test110.o
xcrun swiftc arm_directed_data107.swift /tmp/matched_return_test110.o -o /tmp/arm_directed_data110
```

离线验证严格地址/端口/scope/ifindex/hop/完整 nonce 与 ancillary 拒绝条件：

```sh
xcrun clang -std=c11 -Wall -Wextra -Werror ../test110/test_matched_return_test110.c -o /tmp/test_matched_return110
/tmp/test_matched_return110
python3 -m unittest discover -s ../test110 -p 'test_openwrt_echo_ready.py'
```

OpenWrt echo parser 和构帧检查也可离线验证；这些用例不打开无线接口：

```sh
xcrun clang++ -std=c++17 -Wall -Wextra -Werror ../test110/test_openwrt_echo110.cpp ../../native/awdl_data_frame.cpp -o /tmp/test_openwrt_echo110
/tmp/test_openwrt_echo110
```
