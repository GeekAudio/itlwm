# Test107：原生单帧发送诊断

Test108 / Test109 沿用此工具，`--expect-build` 填当前测试版本。

只验证 `awdl0 → BSD 输出 → 独立 LINK/TID0 队列 → 固件完成 → 回收`。不把 socket 返回成功或固件完成当成手机收件、无线 ACK 或 AirDrop 成功。

默认只检查参数，不访问 IOKit、socket 或无线硬件。加 `--run` 且以管理员运行才会申请一次诊断；任何错误都不会自动重试。驱动默认关闭此路径，测试构建也须由管理员显式触发。

```sh
xcrun swiftc arm_directed_data107.swift -o /tmp/arm_directed_data107
/tmp/arm_directed_data107 --expect-build 25G332-Test107 --expect-uuid UUID --peer-mac MAC --local-ipv6 LINK_LOCAL --nonce 16hex --run-token 32hex
```

用实际加载的 Mach-O UUID、对端单播 MAC、`awdl0` 的标准形式链路本地 IPv6 地址，以及本次新生成的 nonce 和 token 替换参数。地址参数不含 `%awdl0`。测试程序会提前绑定 `awdl0` 和 UDP 源端口 49153；匹配 ROC START 后只发一条 8 字节 nonce 到 `ff02::1:49152`，跳数为 1。

本诊断把 IPv6 组播报文封装为发给指定对端的单播 AWDL 数据帧，用于检查独立发送队列；不注入邻居记录，不伪造手机回复。只使用当前监管配置允许主动发送的频道 6，最长 100 ms，不解除频道 149 的 PASSIVE 限制。

结果按行输出 JSON，区分 ARM 是否可能生效、实际 UDP 提交、数据描述符、固件完成及资源回收。若完成身份不明，驱动保留可能仍被 DMA 使用的缓冲区并隔离队列；不要自动重跑。输出不包含输入的 MAC、IPv6、nonce 或 token。
