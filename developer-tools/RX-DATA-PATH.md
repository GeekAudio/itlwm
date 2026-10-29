# RX 数据通路审查

审查对象为 Test078 源码和 Test077 已保存的有界实测。Test078 尚待首次启动验证。

## 已定位的边界

- Test077 的有效 RX-entry 记录有 24 条完整 v3 descriptor（64 字节），长度、状态、CRC 和容量拒绝均为 0；其中 20 条管理帧、1 条普通 Data，AWDL BSSID 候选为 0。
- AWDL 数据候选在 early、解密后、重复检测后和 tap 阶段均为 0。现有证据没有显示某个已识别候选被 input ring 丢弃；数据帧来源及未观察到的频道仍未知。
- resident 构建为 P2P MAC 1 配置 `IWX_MAC_FILTER_IN_PROMISC`、管理/控制和组播接收。它是提交给固件的配置，不能代替固件实际过滤行为证明。
- 原生接口常驻与无线接收 owner 是两件事。当前 sidecar 只在有效、匹配 generation 的手动 ROC lease 与频道 6 内复制数据；解除 lease 条件不能建立真正的常驻无线调度。

## 软件路径检查

`native/tests/test060_native_bridge_asan.py` 编译生产 `awdl_native_bsd_data_25G332.cpp`，ASan/UBSan 下 23 项通过，覆盖有效明文单次交付、generation 不匹配、protected 拒绝、关闭边界及缺少 `M_PKTHDR`。这是 host fixture，不能替代 Darwin 内核或对端收件。

`native/tests/test_iwx_p2p_hal.py` 现在分别编译 default 和 resident profile，确认 data 接收标志只应用于预期 P2P MAC 1；不把默认测试配置误当成部署配置。

`inspect()` 只有在完整 descriptor 与声明的 MPDU 都落在实际通知/DMA 边界内时才发布 frame-control，因此没有发现所怀疑的前置候选判定越界。

当前 sidecar 不支持受保护 AWDL 数据：它拒绝 Protected 标志，tap 也早于正常 STA 路径移除 CCMP IV。不能只清保护位或跳过验证来支持它；Test077 未捕获到这种候选，所以这也不是该轮候选为 0 的已证根因。

## 下一个判定

先在有效 owner 内建立可关联的对端 AWDL 数据刺激，沿 descriptor → 候选判定 → capture → decode → ifnet 查首次消失点。候选为 0 时，保留“对端未发、无线未达、过滤或判定不匹配”等解释；不能仅由这个零值认定 descriptor 或 input ring 有缺陷。

对端地址尚未确认，且当前实验发送只接受严格 mDNS QM；独立 ICMPv6 试验需要独立、有限类型与预算的准入。`ifnet_input()==0` 只证明 KPI 接受，不等于 socket 收到 Echo Reply 或 AirDrop 成功。
