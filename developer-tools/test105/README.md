# Test105 开发工具

## 当前可验证的范围

`arm_directed_prepare105.swift` 请求创建一个定向 LINK 站点和 TID0 队列，再核对释放结果。它不发送数据帧，也不接通系统的 UDP 回复。默认只检查参数；只有显式 `--run` 才会访问驱动，且要求管理员权限、Test105 的实际加载 UUID 和本轮独立 token。

该准备模式与 RX149 接收模式保留在同一个构建中，但目前共用单次控制器：同一启动中运行一个模式后，另一个模式会拒绝。工具不会清除这个状态，也不会自动重试。IOKit 返回失败时请求也可能已进入驱动，必须先查看结果再决定后续操作。

准备是否成功以 `NativeP2PDirectedPrepareStage=5`、`Result=0` 和本轮站点、队列、清理回执为准。`Stage=6` 是拒绝或失败，即使通用 worker 为了继续移除 MAC 而返回 0，也不算准备成功。`ResourcesAbsent` 表示资源已知不存在，不能单独替代清理回执。

`live_key105.py` 分别读取实时密钥提交和响应，保留时间、代次及丢失计数。它不会把两个独立记录拼成一次成功安装。`firmware_single_queue_completion105.py` 用当前归属、队列和完成区间检查单帧回执；固件成功状态、帧头精确匹配和对端实际收到是不同的证据，不能互相替代。

## 单次 IPv6 受控回复器

该工具只验证主机侧的一次 UDP 回复路径。默认是 `--run` 关闭的计划模式，不创建 socket。明确传入 `--run` 才会在 macOS 上绑定 `awdl0` 的指定链路本地地址和接口索引。

协议固定为：对端 `49152 → 本机 49153` 发送本轮显式配置的 8 字节 nonce；工具只接受地址、端口、scope、`awdl0` ifindex、hop limit 1、ancillary 和完整长度全部匹配的首个数据报，然后从同一个 IPv6 UDP socket 将原 nonce 反向回复 `49153 → 49152` 一次。系统网络栈负责 UDP checksum。零 nonce 和旧静态标记 `T086RX01` 会被拒绝。可用 `openssl rand -hex 8` 生成新 nonce；不要复用不同测试轮的值。

示例（只计划，不打开 socket）：

```sh
./awdl_directed_responder_test105 \
  --peer fe80::2 --local fe80::1 --ifindex 17 \
  --nonce 0102030405060708
```

真正监听/回复必须显式增加 `--run`，并提供当前 `awdl0` 的本机地址、对端地址、接口索引及匹配的 per-run nonce。监听在指定端口等待一个有界窗口，最多检查 16 个数据报；不匹配包不回复。接收和校验后会再次读取单调时钟；如果处理已越过窗口或时钟倒退，就不发送。一次会话只能调用一次，成功或失败都不重试。该候选不改路由、邻居表、驱动或射频状态。操作系统可能在发送时自行进行普通邻居解析；本程序不判断其完成情况。

输出仅为 JSON `READY`/`RESULT` 事件，不打印 IPv6 地址或 nonce。`local_send_accepted` 仅表示 `sendmsg` 被本机网络栈接受；邻居状态保持 `unknown`。它不证明帧已上空口、对端收到或处理、AirDrop 成功。

离线测试使用 mock I/O 回调覆盖正确请求单次发送、错 nonce/身份/端口/scope/ifindex/hop/长度/ancillary 拒绝、截断拒绝、请求预算、超时、发送错误和禁止重试。脚本会编译生产 socket 前端，但只运行无 socket 的计划模式：

```sh
./run_offline_tests_test105.sh
```

测试二进制放在系统临时目录并在结束后清理。此验证不运行 `--run`，不操作 `awdl0` 或路由器，不写 EFI。
