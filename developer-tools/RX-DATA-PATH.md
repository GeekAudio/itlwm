# RX 数据通路审查

审查对象为 Test078 源码、首次启动实测，以及 Test077 保存的有界实测。

## Test079 实现边界

Test079 新增引导后配对阶段，保留引导历史，要求新的同条目 PSF/MIF 及运行代际匹配。候选准备、最终提交和 QM 前分别复核锁定的对端、版本、接收时间和时效；只有匹配的普通 MIF 真实完成才能推进。引导帧仍计入原有总预算，旧帧、忙队列、代际变化或已结束驻留不能借升级重试。

接收消费不再依赖数据发送门打开；它仍受同一 owner、代际、频道和有效驻留约束。收尾在同一门内关闭观察生产者后，消费一次固定容量队列，再读取真实 pending 计数。它不伪造清零、不延迟持有 worker 指针，也不增加 RF session。

这些是待实测的开发改动，不是 AirDrop 支持声明。

## Test078 本轮结果

Test078 已加载，Wi-Fi 在诊断前、后各约 124 秒的观察内保持关联，复位计数不变，未新增 watchdog 或固件错误。默认路由走有线接口，这不代表 Wi-Fi 公网、长期或睡眠恢复验收。

后续一次 300 秒目标观察在约 39 秒因关联丢失停止，稍后驱动 watchdog 和复位计数增加，后续只读复查已重新关联。保存的原因码 16 只是组密钥超时线索，不能确定它就是此次离网原因；也不能把 Apple 的 `handleWATCHDOG` 日志直接当成本驱动的 timer 到期记录。该问题仍未定位，不能用前面的短测注销。

- 原生 awdl0 保持运行；两条真实内核输出进入软件队列。
- PSF 和 MIF 控制发送各记录一次固件成功；接收端解析并接纳了一条 MIF 和四条 PSF。完整对端身份和阶段授权仍需独立核对。
- 本轮选中了仅发一次 presence MIF 的 bootstrap 分支。该分支明确禁止进入数据提交路径，因此 planner 检查、数据编码、QM 提交均为 0。它们不是已发出查询后的收包失败。
- RX-entry 有 23 条完整 v3 descriptor：21 条管理帧、2 条 MPDU 过短，Data 和 AWDL 数据候选均为 0。路由器频道 6 的 20 秒窗口也未捕获 AWDL Data 候选；不能由此判断其他频道、对端是否发射或 input ring 是否丢包。
- CurrentAW 收尾快照保留了“RX 未排空”标记，但后续 RX trace 显示 producer 已关闭、pending 为 0。这是独立的最终快照发布问题，不能解释数据入口为何未执行。

下一步需要在新鲜、同一 entry 的 PSF/MIF 身份与运行 epoch 都符合条件时，从 bootstrap 转入正常配对阶段。不能直接删除 bootstrap 门禁，也不能把 bootstrap 的固件完成当作数据发送的时序授权。

独立源码复核还发现：按现有 phase helper 的 16 TU 新鲜度限制，本轮旧 MIF 的有效时间上界比本机 bootstrap MIF 完成早约 9.6 毫秒；后续首条 PSF 到达更晚。因此单独取消 bootstrap 限制也不能使用这个旧 MIF 放行。这是结合接收时间和代码约束推导的上界，并非本轮 planner 实际发布的窗口或空口同步证明。后续须取得新的配对证据，不放宽时效来制造成功。

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
