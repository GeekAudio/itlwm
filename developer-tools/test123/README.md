# Test123 接收验证工具

本版升级采集工具，运行的驱动仍是 **25G332-Test122**。不重新打包 kext，也不把工具测试当作 Wi-Fi 或 AirDrop 验收。

## 本轮要验证什么

同一份 v2 测试包贯穿路由器发送器、接收编排和原生 awdl0 UDP 监听器。包内带本轮随机 8 字节标记；四帧各自有完整 Wi-Fi Sequence Control 和 AWDL 序号。

1. 用实际运行的驱动、启动实例和接口身份核对接收环境。
2. 发送器与监听器校验同一份 packet set，监听器 READY 后进入已有的接收流程。
3. 在有效 START 和发送期限内发送四帧，记录发送调用和主机状态样本；发送失败状态不作为禁止检查接收结果的条件。
4. 分别保存发送、观察、驱动接收记录和 socket 结果，再清理本轮资源。

发送预算为 40 ms，帧间隔 10 ms；原有 Intel 接收窗口为 100 ms。发送后的状态观察不延长接收窗口，也不新增无线发送。已用的内核接收实例不会通过更换标记、目录或工具编号重新启用。

## 结果口径

- 主机发送状态与本轮帧匹配，不等于确认了空口发送或硬件 ACK。
- awdl0 监听器实际收到匹配标记，并通过接口、地址、端口、hop limit 和截断检查，才算本轮载荷输入的正证据。
- 四帧共用本轮标记。收到四份相同标记可能包含重复包，不能直接算四个不同帧全部到达。
- 报告中的 `wire_nonce_hex_ascii_sha256` 哈希的是 16 个小写十六进制字符的 ASCII 字节，不是原始 8 字节 nonce。
- 当前内核输入收据缺少完整 SC、AWDL 序号和标记。它与 socket 结果分开保存，不直接声称是同一个 MPDU。
- START 是同 owner 的一次性快照。重复读取它不等于获得当前 HAL、BSD lease 和 ifnet 的原子快照。
- 路由器与 Mac 的时钟分开记录；用户态读取时间不等于内核到达或空口时间。没有转换依据的时间差保持未知。

本版不做联网冒烟或睡眠测试，不修改路由器 WAN/LAN。

## 离线检查

默认入口只输出计划，不启动诊断：

    python3 developer-tools/test123/coordinate_test123_rx149.py --plan

监听器的离线测试会编译实际 C 代码，并通过无 socket 的测试入口检查字节匹配与输出协议：

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
      -s developer-tools/test123 -p 'test_listener_test123.py' -v

协调器的导入、计划、T087/T088 协议接缝也有不接触设备的集成测试：

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
      developer-tools/test123/test_coordinate_test123_integration.py -v

## 运行前刷新身份

Test123 继续使用 Test122 的 disarmed metadata、内核构建/部署收据和运行目录。每次新启动后，先用 Test122 工具刷新本机 awdl0 与 OpenWrt wlan7 的只读身份，再运行 Test123；过期或不匹配会在 ARM/claim 前失败。

    python3 developer-tools/test122/coordinate_test122_rx149.py \
      --capture-target --minimum-boot-epoch-exclusive <metadata中的值>
    python3 developer-tools/test122/coordinate_test122_rx149.py \
      --capture-router --host <OpenWrt主机> --control-path <已认证SSH控制套接字>

然后显式运行一次：

    python3 developer-tools/test123/coordinate_test123_rx149.py \
      --run --host <OpenWrt主机> --control-path <已认证SSH控制套接字> \
      --metadata <Test122 disarmed metadata> --ap wlan7

每个启动实例仍只有原 Test122 的一次性接收 claim。身份刷新只读设备和 OpenWrt 接口配置，不改 Wi-Fi、WAN 或 LAN。不要重复使用同一启动实例或 wire nonce。

### 唯一一次的预 ARM 中断续测

只有上一条记录明确为 `MONITOR_READY_MALFORMED`，并且同一启动实例的原始报告、native capture、清理观察和主机进程观察全部通过私有证据核对时，才可以显式加 `--resume-prearm`。该选项只允许与 `--run` 一起使用：

    python3 developer-tools/test123/coordinate_test123_rx149.py \
      --run --resume-prearm --host <OpenWrt主机> \
      --control-path <已认证SSH控制套接字> \
      --metadata <Test122 disarmed metadata> --ap wlan7

续测会使用本启动内一个全新输出目录并留下持久的一次性标记；它不会清除或重置 Test122 内核 claim。原有 Test104/T087 身份、加载版本、START、100 ms 接收窗口和 claim 检查仍照常执行。证据过期、启动实例不同、已有续测标记或新输出目录已存在时会停止。其他失败不能用此选项重跑。

工具构建收据与 packet set 保存在私有 RuntimeTest123 目录；主采集报告仍写在 Test122 metadata 所在的私有运行目录，以兼容原生 worker 的输出目录校验。含接口地址、包样本和运行日志的私有数据不进入公开里程碑。
