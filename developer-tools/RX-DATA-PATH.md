# RX 数据通路审查

审查对象为 Test079 本次启动、Test078 首次启动实测，以及 Test077 保存的有界实测。

## Test079 实现边界

Test079 新增引导后配对阶段，保留引导历史，要求新的同条目 PSF/MIF 及运行代际匹配。候选准备、最终提交和 QM 前分别复核锁定的对端、版本、接收时间和时效；只有匹配的普通 MIF 真实完成才能推进。引导帧仍计入原有总预算，旧帧、忙队列、代际变化或已结束驻留不能借升级重试。

接收消费不再依赖数据发送门打开；它仍受同一 owner、代际、频道和有效驻留约束。收尾在同一门内关闭观察生产者后，消费一次固定容量队列，再读取真实 pending 计数。它不伪造清零、不延迟持有 worker 指针，也不增加 RF session。

完整 Tahoe 构建、针对性离线测试和独立复核已完成；Test079 已部署并核对新启动的实际加载。它仍不是 AirDrop 支持声明。

本次博通对照后，Test079 增加三种精确 DNS-SD 服务的 PTR/IN 查询兼容：`_airdrop._tcp.local`、`_companion-link._tcp.local`、`_asquic._udp.local`。实验发送仍只接受通过校验和、地址和端口检查的 QM；未知服务、混合 QU/QM 和无效报文不放行。查询分类数值及快照布局保持。

发现选择器会在固定 32 项队列内找最早的有效 QM，按 token、入队时间、代际和分类复验后只取该项；前面的其他包保留相对顺序，普通发送仍按 FIFO。2 秒新鲜度、单个 in-flight、关闭与代际保护不变。完整构建和合并验证由本轮收据记录；对端回包与文件传输仍需重启后实测。

博通 Test023r2 已有双向成功窗口，可直接作为参照，对照工具已重新编译。路由器保留 2.4 GHz 的 6 频道，将 5 GHz 改为 149/80 MHz 后，已被动捕获到标记为 5745 MHz 的帧；WAN/LAN 未改。监听范围仍有限，不能由此宣称完整频道覆盖或同一个数据包的跨层关联。

博通对照配置在完整备份后部署过，并完成加载核对、即时热点和双向 AirDrop 分窗记录；间歇异常仍单独处理。随后备份整份博通 ESP，恢复四个无线启用开关并部署 Test079。博通文件保留，其结果不计入 Intel 验收。

## Test079 本轮实测

新启动的 UUID 与构建归档匹配。诊断前后两段被动观察的实际样本跨度约 124 秒和 298 秒，保持关联和 IPv4，没有新增 reset、watchdog 或固件错误；两段之间不是连续覆盖，也未验证睡眠。三次绑定无线接口的 1 MB 请求返回 HTTP 200，外网路径平均 2.38 Mbps，不作为网卡最高速率。

唯一一次有界诊断完成：1 条本机 PSF、3 条 MIF 本地固件成功，四个控制 ticket 在 channel 6 PCAP 都有唯一字段候选匹配。驱动解析并接纳 7 条 peer PSF，但本 owner 窗口没有 MIF 样本。状态 19、blocker 1 表示同一条目的 MIF 尚未选中。按生产执行顺序，严格 QM peek 已成功，但候选未锁定或消费；真实数据编码、提交、RX 捕获、解码和原生输入均为 0。不能把它解释成查询发出后没有应答。

路由器两路 20 秒捕获记录了 6 和 149 频道。同一匿名来源在两路都出现，尚未绑定为 iPhone；5 条 driver PSF 可按 SC、长度、PHY 和 target 字段匹配，另 2 条在旁路未匹配。五点经验 offset 散布 45 微秒；仅在这个条件性对齐下，owner ROC 内同源 MIF 在 149 有 7 条、在 6 为 0，最近的 6 频道 MIF 分别在窗口前约 1.059 秒和后约 2.246 秒。这支持频道或相位错开的候选解释，不是正式时钟校准、无丢包或源身份证明。

149 频道的两个尾随零字节由当前 Intel parser 的短零尾分支容忍；这不证明 Apple/Broadcom 原生解析会接受，也不证明尾部来源。手机同期日志只显示 AirDrop advertise 和频道规划，没有逐帧 TX/RX 或自身 AWDL 地址绑定。

当前 MIF-current 路径没有获得入站配对前置，不能用本机 MIF 成功代替 peer MIF。下一步先复核组播发现需要的 PSF 同步条件及该实验的 MIF 前置，再决定候选；不据此放宽解析、资源归属、代际或时效保护。本轮矩阵为 16/40 复验通过，新增历史验收项为 0。

后续离线频道核算发现：5 条可唯一完整匹配的 PSF，按生产 `nextSlot=(floor(awCounter/4)+1)%16` 计算，下一时隙分别为 149、0、0、0、0；0 表示未服务时隙，因此均不满足本实验的下一时隙必须为 6 频道的条件。仅切换 PSF 模式不能让这 5 条样本发送。其余 2 条及调用时 peer/current 快照绑定未知，没有真实 planner 调用时刻，也没有完整 `estimateTarget` 重放；不能据此排除所有合法窗口。此项只收窄后续调度研究方向，没有新增实机验收项。

原生路径的静态复核已核对当前 25G332 磁盘 KC 身份；9 个目标函数保留指令、立即数和对象偏移，排除 PC-relative 引用后形状一致，其中 3 个原始字节一致。这不是完整 ABI、外部 callee、数据或运行实例等价，旧版绝对地址不能直接用于当前内核。

能力链显示：若实际采用原生 PCIe bus 的 FlowID capability，manager 会选择跳过写入 legacy 组播允许位的替代分支；该分支的最终出队效果尚未闭合，不能把 legacy peer gate 代表为全部原生发送路径。AW-start 事件已静态追到 PostOffice 和条件性 WCL 投递；`SkywalkInterface::postMessage` 与相邻的 `reportDataPathEvents` 是不同回调，到 manager 的订阅和资格分支仍未知。下一步只追这两处缺口，不凭局部没有 MIF 比较就删除 Intel 条件。以上没有增加 RF、稳定性或 AirDrop 验收。

后续有界复核已把替代分支条件性静态追到 Proximity 注册输出、PCIe 队列 factory、`p2pMulticastTx` 与 `dequeuePackets` 入口；没有据此认定运行时选中了这些类、队列注册成功或实际出队。AW 事件的 outgoing Glue 指向 WCLGlue，已区分发送、反向接收和同步 fallback 的方向；订阅门及通用 fanout 不代表已找到具体 manager 消费者，正常返回也不代表 pipe 写入或消费者收件。

Intel 当前实际实验链是另一条路径：`awdl_native_bsd_data_25G332.cpp` 的 `IntelNativeAWDLData` ifnet 过滤器把查询放入自有 `Ring<Tx,32>`，`ItlIwxP2PProbe` 用自有 peer table 和 MIF-current 条件绑定、验证并消费，再经 `iwx_tahoe_p2p_action_tx_submit` 向 Intel IWX 队列提交。在本次限定检查中，原生 Proximity 队列注册、Intel 的 FlowID override 和 WCL AW0x29 接收入口未定位；ABI 声明或 Intel Session Protection ROC 状态不能代替这些证据。这不排除未检查路径，但不能用博通静态队列直接解释或替换当前 Intel 实验发送链。

原生静态步骤到此收口。后续回到 Intel 自有授权与频道时序问题，保留同条目 MIF、时效、代际和资源保护，直到有依据的替代设计通过验证。静态入口定位没有增加实机验收项。

149 接收观察的源码可行性也已核对：ROC API 与 PHY context 命令能够表达 5 GHz 的 149，但现有异频道策略、900 ms GO-neg 配置及若干接收消费门固定为 6 频道，不能直接替换常量。RX router 与 peer 表已传递实际频道并保留身份、epoch 和新鲜度语义。可评估独立的接收观察模式，沿用已有受限窗口，不进入 station/TX queue/builder/submit 分支，并在实际 ROC START、选定目标和 owner/epoch 一致时消费；必须等待 END 确认，再按原契约恢复 PHY。监管表可用性与固件接受仍未实测，本阶段未实现或部署新候选。

## 本次博通实测对照

新启动已核对博通驱动绑定及 USB 蓝牙归属。手机确认正向收件；Mac 新收到的反向文件为 32768 字节，SHA 与源文件一致。独立的成功控制/BPF窗口完整：观测 622 包、33 条 mDNS 应答；控制样本 PSF 76、MIF 85，733 条观察中有 572 条主动抽稀。窗口级匿名别名交集不等于逐包关联，也不证明 `ifnet_input` 返回值。

这些是窗口级证据：BPF采用256字节头部采样，有277条合法截断；mDNS计数没有按AirDrop服务过滤。旁路PCAP只覆盖点击后约13至14秒，没有覆盖后来的完整成功阶段，不能称为成功传输的完整空口抓包。

即时热点 H01 可连接、取得地址，并经指定无线接口请求 Apple 端点返回 HTTP 200；DNS 解析采用另外的路径，不算无线 DNS 验收。另一端点超时单独保留；一次成功不解决间歇不稳定问题。本次尚未复现热点加入失败。

初次 AirDrop 异常已分成不同发送状态机：失败发生在按需发现阶段，随后另一次请求成功，不能合成同一次“迟到传输”。失败附近的旁路帧可解出有效的 `_companion-link._tcp.local` PTR/QM；不能把它们当作只在软件里发起的查询。异常定位交由博通会话处理，本轮只做采集和对比。

新的成功样本也包含重试：从点击到结束约27.8秒，首次按需发现约16秒超时，下一轮约9.2秒后才发现对端；之后TCP连接约43毫秒、服务解析约6毫秒。等待集中在对端服务出现前，不能把这段合成一次25秒解析，也不能把最终成功写成异常已修复。

手机端日志已通过可信 USB 连接补齐，覆盖本次失败、成功和即时热点窗口。H01 两端四条 PairVerify 日志内容逐条匹配；手机内部从收到热点请求到发送响应约 0.72 秒。同一 `companion-link` 服务实例也在手机发布、Mac 发现的记录中精确匹配。

早期 `NeedsCLink` 广播与后续处理的进程内设备标识不同。随后逐字段复核发现，早期广播末尾三字节与后续目标 AuthTag、手机自身 AuthTag 一致，支持共同目标关联；它仍不足以证明完整发送者身份或同一无线包，不能直接把约 24 秒先后间隔认定为同次完整链路延迟。手机活动级别解密错误也不是已证根因。两端时钟未校准，未计算跨设备单向延迟；原始手机、蓝牙和网络日志保持私有。

对照时 Intel 原有代码只把 `_airdrop._tcp.local` 识别为目标，实验选择器还只看 FIFO 队首；`companion-link` 和 `asquic` 可以入队，却不能成为该实验的发送候选。Test079 本次已针对这两处差异修改，仍需重启后核对所选查询、固件提交和真实回包。它们不是已经确定的 Intel 失败根因，也没有据此放宽资源、代际和时效保护。

所见普通明文 AWDL Data 在 24 字节 MAC 头后还有 16 字节 Apple SNAP/AWDL 封装，IPv6 从完整 MPDU 的偏移 40 开始。当前 Intel codec 的 OUI、供应商字段、字节序和 IPv6 偏移与它吻合；最初外部分析器把 `0x0800` 当 IPv4 而漏包，不能沿用这个零样本结论。格式吻合仍不证明 Intel 已收到或交付这些帧。

## Test078 本轮结果

Test078 已加载，Wi-Fi 在诊断前、后各约 124 秒的观察内保持关联，复位计数不变，未新增 watchdog 或固件错误。默认路由走有线接口，这不代表 Wi-Fi 公网、长期或睡眠恢复验收。

后续一次 300 秒目标观察在约 39 秒因关联丢失停止，稍后驱动 watchdog 和复位计数增加，后续只读复查已重新关联。保存的原因码 16 只是组密钥超时线索，不能确定它就是此次离网原因；也不能把 Apple 的 `handleWATCHDOG` 日志直接当成本驱动的 timer 到期记录。该问题仍未定位，不能用前面的短测注销。

- 原生 awdl0 保持运行；两条真实内核输出进入软件队列。
- PSF 和 MIF 控制发送各记录一次固件成功；接收端解析并接纳了一条 MIF 和四条 PSF。完整对端身份和阶段授权仍需独立核对。
- 本轮选中了仅发一次 presence MIF 的 bootstrap 分支。该分支明确禁止进入数据提交路径，因此 planner 检查、数据编码、QM 提交均为 0。它们不是已发出查询后的收包失败。
- RX-entry 有 23 条完整 v3 descriptor：21 条管理帧、2 条 MPDU 过短，Data 和 AWDL 数据候选均为 0。路由器频道 6 的 20 秒窗口也未捕获 AWDL Data 候选；不能由此判断其他频道、对端是否发射或 input ring 是否丢包。
- CurrentAW 收尾快照保留了“RX 未排空”标记，但后续 RX trace 显示 producer 已关闭、pending 为 0。这是独立的最终快照发布问题，不能解释数据入口为何未执行。

Test078 后的设计是在新鲜、同一 entry 的 PSF/MIF 身份与运行 epoch 都符合条件时，从 bootstrap 转入正常配对阶段。Test079 已包含此逻辑；本轮没有选择 bootstrap，因此这段升级没有被实机覆盖。不能把 bootstrap 的固件完成当作数据发送的时序授权。

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
