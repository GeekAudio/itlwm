# Test103: AWDL 单播接收观察

Test103 用一个有界的 IPv6 单播数据帧组，观察 AX201 的 149 频道接收入口。发送器最多写 4 帧，间隔 10 ms，预算 40 ms；Mac 侧只监听，不启用主机发包。

## 证据边界

- OpenWrt 的 `send()` 返回和同一 monitor 接口的本机副本，只能说明本地调用与观察结果。
- 本工具没有可绑定到本次帧的 raw TX status 来源，因此 RF 发射、硬件 ACK、对端收件和 AirDrop 均保持未知或未证明。
- Mac 接收端只接受同一份本轮新鲜 packet manifest 绑定的 OpenWrt 源 IPv6 和 Mac `awdl0` 目的 IPv6 单播包，并核对接口索引、UDP 49152→49153、hop limit 1、固定载荷及完整未截断的接收控制信息。
- 接收端不再把旧 `ff02::1` 多播探针当成这轮单播包。它只报告地址匹配布尔值和短身份标签，不记录原始 IP；即使匹配成功，也只证明数据到达 Mac 的该 UDP socket，不能单独证明 RF/TX status、AirDrop 或 iPhone 收件。
- 探针载荷固定，不能仅凭载荷内容判定它属于哪一轮；因此结果还必须同时匹配本轮新鲜源/目的身份和接口索引。
- 报告、路由器身份收据和原始帧观察保存在本地私有目录。帧头可能包含附近设备地址，不应公开原始数据。

## Test103 诊断字段

Test103 在原有 Hcmd 只读采样旁读取 `NativeAwdlDataRx149CaptureAttempts`。该字段是固定 3400 字节的 LE64 数值快照，最多保留 8 次 capture 决策；解码器严格核对 magic、schema、字数、提交位图和完整切面，并保留部分发布与 sticky overflow 状态。记录的是 capture gate 的输入和检查结果，不含帧载荷，也不代表队列消费、ifnet 交付、ROC 正常收尾或 AirDrop 成功。旧轮没有该字段时保持“未观测”。

Test103 还会只读采集 TX completion trace。schema 4 没有本轮新增的三项重试计数时会标记不可用；只有 schema 5 的单帧完整布局才解读为具名计数。它们是驱动观察字段，不代表固件 API 布局、硬件 ACK 或对端收件。

Test103 仅在收到 `NATIVE_ARM_RESULT` 后，把 native worker 下一次读取 `NATIVE_RESULT` 的等待上限设为 45 秒；ARM、READY、GO、listener、sender 和射频窗口均沿用原有时序与超时。worker 的其他状态仍即时发送。父进程收到终态前，采集线程已退出，post-worker 只读快照及汇总已原子写入并同步到目录；写入未确认时只回报失败终态，不把不完整报告标成成功。45 秒仍是硬上限，超时照常失败关闭。

## 离线准备

所有命令默认只读或写入尚未启用的私有配置；不会启动无线采集。

下面的 `--iwn-root` 指本轮运行目录，例如 `RuntimeTest103`，其中包含 `research` 和本轮收据。

```sh
python3 developer-tools/test103/controlled_run_test103.py \
  --iwn-root "/absolute/path/to/IntelWirelessNative"

python3 developer-tools/test103/runtime_binding_test103.py write \
  --iwn-root "/absolute/path/to/IntelWirelessNative" \
  --minimum-boot-epoch-exclusive <部署前的 kern.boottime 秒值>
```

部署并重启到候选系统后，读取当前已加载 UUID、启动时间和 `awdl0` 地址，生成目标收据：

```sh
python3 developer-tools/test103/runtime_binding_test103.py capture-target \
  --iwn-root "/absolute/path/to/IntelWirelessNative" \
  --minimum-boot-epoch-exclusive <部署前的 kern.boottime 秒值>
```

同一轮还需要刷新 `research/test103-preparation-private/router-identity-private.json`：只读记录 OpenWrt `wlan7` 当前 MAC、链路本地 IPv6、149 频道和 80 MHz 状态。不要从旧轮复制地址。配置器会拒绝启动时间、驱动 UUID、收据哈希或 180 秒时效不匹配的身份。

先用下面的命令做无动作校验：

```sh
python3 developer-tools/test103/runtime_binding_test103.py prearm \
  --iwn-root "/absolute/path/to/IntelWirelessNative" \
  --metadata "/absolute/path/to/IntelWirelessNative/research/test103-runtime-private/native-controlled-probe-private.json"
```

## 单次运行

只有显式加 `--run` 才会启动一次 RX149 采集、创建临时 monitor 并发送最多 4 帧。已有 SSH ControlMaster、AP 必须是 `wlan7`：

```sh
python3 developer-tools/test103/controlled_run_test103.py --run \
  --iwn-root "/absolute/path/to/IntelWirelessNative" \
  --metadata "/absolute/path/to/IntelWirelessNative/research/test103-runtime-private/native-controlled-probe-private.json" \
  --host root@192.0.2.1 \
  --control-path /private/tmp/test103-control.sock \
  --ap wlan7
```

运行前会重新读取本机启动时间和已加载 UUID，检查新鲜的 Mac 与 OpenWrt 身份，再从同一身份组生成 packet set 与 unicast listener 绑定。接收器将 socket 绑定到当前 `awdl0` 接口索引，并验证目标 IPv6 确实配置在该接口上；源/目的、端口、hop limit、payload 或截断标记任一不符，都不会记为成功。路由器脚本会检查 AP 保持原频道/配置并清理临时文件和 monitor；不会改 WAN/LAN 或保存的 Wi-Fi 配置。同一启动目录已存在时拒绝再次运行。

离线测试：

```sh
python3 -m unittest discover -s developer-tools/test103 -p 'test_*.py' -v
python3 -m py_compile developer-tools/test103/*.py
```
