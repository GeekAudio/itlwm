window.TEST_RECORDS = [
  {
    "id": "record-test032",
    "version": "25G241-Test032",
    "label": "历史验证",
    "state": "开关回归未通过",
    "tone": "warning",
    "date": "2026-10-27",
    "summary": "已加载并核对 UUID。频道 6 的 P2P 会话闭环；Wi-Fi 关闭回归未通过，连接恢复但 Wi-Fi 关闭状态仍未通过验收。",
    "evidence": [
      "候选 UUID 已核对；6 次 1 MB HTTP 请求成功。",
      "开关失败后继续观察 120 秒；9 个采样均连通，reset_count=10 且未再变化。",
      "频道 6、conf3、300 ms 会话观察到 START=1、END=1；诊断 TX 完成，队列、站点与 DMA 资源释放。",
      "收到 3 个真实 AWDL envelope；3 次因 InvalidTlv 被拒绝，有效 peer 数为 0。",
      "关闭尝试 40 次、重试 40 次；OffResult=-536870187（kIOReturnBusy）。",
      "关闭时 PowerReady=1、HALFlags=65 仍为开启状态；约 9.7 秒后连接与 IPv4 恢复。"
    ],
    "blockers": [
      "定位 power-off 返回 Busy 及异步关闭状态未切换的原因。",
      "定位 InvalidTlv 的具体拒绝分支；目前尚未解析出有效 AWDL 对端。"
    ],
    "next": [
      "修复关闭路径后，证明 PowerReady/HAL 状态完成关闭和重新开启，再验证回连与 HTTP。",
      "增加可审查的 TLV 拒绝原因与字段轨迹，解析真实对端和同步字段。"
    ]
  },
  {
    "id": "record-test033",
    "version": "25G241-Test033",
    "label": "历史验证",
    "state": "单次冒烟测试通过",
    "tone": "success",
    "date": "2026-10-27",
    "summary": "Test033 已加载并完成一次诊断、一次 Wi-Fi 开关及回连。短时联网通过；本次未收到 AWDL 帧，AirDrop 仍未完成。",
    "evidence": [
      "实际加载 UUID 与部署包一致；开关前后三次、共六次 1 MB HTTP 请求成功。",
      "Wi-Fi 关闭 2 次尝试、1 次等待后成功：真实 Ready/flags 均为 0；重新开启后自动回连并取得 IPv4。",
      "回连后连续 120 秒、9 次采样保持在线，重置计数保持 11；私有地址切换返回成功且未隔离。",
      "频道 6 的 300 ms 单次会话 START/END 成功，诊断 TX 完成；队列、站点与 DMA 资源全部释放。",
      "本次 AWDL 标识帧接收为 0，有效对端为 0；因此没有新的解析拒绝字段可分析。"
    ],
    "blockers": [
      "还未完成新网络、长时间运行与睡眠唤醒的全面验收。",
      "尚未解析有效 AWDL 对端，也没有真实 AWDL 双向发送、原生 awdl0 或 AirDrop 文件传输证明。"
    ],
    "next": [
      "下一候选延长单次接收窗口并调整等待期限，继续采集真实对端帧。",
      "保留严格资源回收与隔离规则，回归普通 Wi-Fi 开关和联网。",
      "同步推进真实 AWDL 报文编码与原生接口生命周期。"
    ]
  },
  {
    "id": "record-test034",
    "version": "25G241-Test034",
    "label": "历史验证",
    "state": "队列准备失败，诊断已隔离",
    "tone": "warning",
    "date": "2026-10-27",
    "summary": "Test034 已启动。联网与私有地址正常；固件分配队列 3 后，主机发送环冲突导致诊断被隔离，尚未进入 900 ms 接收窗口。",
    "evidence": [
      "实际加载 UUID 与部署包一致；诊断前后六次 1 MB HTTP 请求成功，私有地址返回成功。",
      "120 秒、9 次被动采样均在线，重置计数保持 10；这不代表长时间稳定性已验收。",
      "固件队列回复有效，分配队列 3；主机槽位仍有 256 项发送环和 DMA 缓冲，因此返回 Busy 并保留资源。",
      "未进入 ROC、未发送诊断帧、未收到有效 AWDL 对端。本次未做开关，也未重复触发诊断。"
    ],
    "blockers": [
      "该主机槽位仍保留发送环；当前快照不足以区分停止后残留与活动队列，不能直接释放。",
      "AWDL 对端收发、原生 awdl0 数据通路和双向 AirDrop 仍未完成。"
    ],
    "next": [
      "只在硬件确认停止 DMA 后回收旧动态发送环；确认失败时继续保留，队列安装检查保持严格。",
      "下一版启动后核查实际回收计数，再做单次 AWDL 诊断与 Wi-Fi 回归。"
    ]
  },
  {
    "id": "record-test035",
    "version": "25G241-Test035",
    "label": "历史验证",
    "state": "单次冒烟通过，AWDL 解析待修",
    "tone": "warning",
    "date": "2026-10-27",
    "summary": "已启动并完成一次 900 ms 诊断、一次 Wi-Fi 开关与回连。收到了 6 个 AWDL 标识帧，均因解析检查被拒；尚无有效对端或 AirDrop 传输。",
    "evidence": [
      "实际加载 UUID 与部署包一致；私有地址正常，前后六次 1 MB HTTP 请求成功。",
      "Wi-Fi 关闭两次尝试、一次等待后 Ready/flags 均为 0；重新开启并自动回连，取得 IPv4。",
      "回连后 120 秒、九次采样在线，重置计数保持 16。",
      "频道 6 的 900 ms 会话 START/END 完整；诊断 TX 完成且队列、站点、DMA 全释放。固件分配队列 4。",
      "关闭时硬件停止检查通过，实际回收 1 个动态发送环并清除对应临时别名。",
      "收到 6 个 AWDL 标识帧，最后拒绝为 RequiredOrder：类型轨迹 4、5、18、19、6，服务参数声明 15 字节。"
    ],
    "blockers": [
      "固定 TLV 顺序和固定服务参数长度需要按接收协议修正。",
      "本次队列 4 通过，不能推断队列 3 的活动归属冲突已解决。",
      "原生 awdl0 尚未创建；系统日志中的 AWDL 接口查找失败与此一致，不能归因于帧解析错误。"
    ],
    "next": [
      "合并字段顺序、服务参数布局和更完整的数字类型轨迹到 Test036。",
      "重启后一次验证真实帧解析，继续回归 Wi-Fi；不在本次启动重复触发诊断。",
      "保持 macOS 原生 mDNS 与 sharingd 路线，推进原生接口和实际数据通路。"
    ]
  },
  {
    "id": "record-test036",
    "version": "25G241-Test036",
    "label": "历史验证",
    "state": "升级后拒绝初始化",
    "tone": "warning",
    "date": "2026-10-27",
    "summary": "系统升级到 26.7.2 / 25G332 后，Test036 的精确版本检查拒绝初始化，Wi-Fi 接口未创建；不是没有加载 kext。",
    "evidence": [
      "接收不再强制 TLV 固定顺序；必需字段与重复检查保留。",
      "服务参数长度按 9 + 位图置位数量校验；不把 15 字节硬编码为例外。",
      "选举参数 v2 为可选，有则检查长度及重复；v1 仍必需，尚不支持仅 v2。",
      "头部诊断最多扫描 128 个 TLV，记录前 16 个类型，长度越界即停，不记录报文内容。",
      "完整构建、签名和符号检查通过；解析器、RX 路由、对端观察器、编码器的 ASan/UBSan 回归通过，独立审查无阻断项。",
      "当前加载 UUID 与 Test036 一致，注册状态停在 runtime，结果为 0；未出现 en1。"
    ],
    "blockers": [
      "精确准入列表只有旧系统 25G241，无法在 25G332 继续初始化。",
      "解析修复尚无真实报文验收；原生 awdl0 和实际 AirDrop 传输未完成。"
    ],
    "next": [
      "使用已部署的 Test037 恢复候选，重启后先验收普通 Wi-Fi。"
    ]
  },
  {
    "id": "record-test037",
    "version": "25G332-Test037",
    "label": "历史验证",
    "state": "新版系统 Wi-Fi 冒烟通过",
    "tone": "success",
    "date": "2026-10-27",
    "summary": "Test037 已恢复 26.7.2 / 25G332 的 Wi-Fi 识别、连接和私有地址。一次开关与回连通过，前后 6 次无线 HTTP 请求成功，回连后 120 秒保持在线。",
    "evidence": [
      "已核对 Test037、controller ready 和系统 Wi-Fi 接口 en1；四项 P2P 配置关闭，探测次数为 0。",
      "私有地址 stage 5 / result 0，未进入隔离。关闭时真实 Ready/HAL flags 归零，重新开启后自动回连并取得 IPv4。",
      "前后各 3 次 1 MB HTTPS 请求绑定 en1，均收到完整响应；代理绕过。该结果只代表连通性，不代表最高吞吐。",
      "CoreWLAN 连接快照：5 GHz、频道 36、TX 链路值 1733 Mbps；链路值与外网下载速度分开记录。",
      "回连后 120 秒、9 次被动采样均在线，重置计数始终 17。10→17 的变化全部落在本次主动开关及回连窗口。",
      "新版 AWDL 专用类的槽位、对象大小和父类链完成静态复核；没有创建 awdl0 或执行 AWDL 探测。"
    ],
    "blockers": [
      "关闭期间内部重试 92 次后成功，开关延迟仍需优化。",
      "本轮没有重新验收满速、新网络、即时热点、长时间运行或睡眠唤醒。",
      "新系统 P2P 诊断、真实 AWDL 对端和双向 AirDrop 仍未完成。"
    ],
    "next": [
      "保留 Test037 作为当前系统的恢复版本。",
      "Test038 仅恢复一次手动诊断，先确认联网和资源状态，再采集真实帧解析结果。"
    ]
  },
  {
    "id": "record-test038",
    "version": "25G332-Test038",
    "label": "历史验证",
    "state": "诊断与 Wi-Fi 通过，实帧解析待修",
    "tone": "warning",
    "date": "2026-10-27",
    "summary": "Test038 完成一次手动 900 ms 诊断，发送和资源清理通过。收到 8 个 AWDL 标识帧，全部解析拒绝；最后卡在类型 12、长度 47 的数据路径参数。",
    "evidence": [
      "启动时尚未触发，iPhone 准备后只执行一次。频道 6、900 ms 驻留 START/END 成功。",
      "队列 4 的诊断 TX 完成，站点、队列、发送环和潜在资源全部归零。",
      "8 帧均未通过解析，有效对端为 0；最后为 MIF/type12/47B/InvalidValue，类型轨迹共 21 项，记录前 16 项。",
      "私有地址正常，一次开关及自动回连通过；三阶段共 9 次完整 1 MB 无线 HTTP 请求成功。",
      "回连后 120 秒、9 次采样在线，重置计数保持 12；5 到 12 的变化发生在主动开关窗口。",
      "日志未发现可归因于驱动的 panic 或固件断言；系统频道回调曾返回 unsupported，具体归因仍待核对。"
    ],
    "blockers": [
      "实际 flags 未记录，长度 47 不能确定现场格式。",
      "关闭重试 92 次后成功，延迟待优化；满速、即时热点、新网络和睡眠唤醒待验收。",
      "原生 awdl0、真实 AWDL 双向发送及 AirDrop 传输未完成。"
    ],
    "next": [
      "Test039 合并可选字段布局修复和纯数字拒绝诊断。",
      "下一轮保持单次手动诊断，资源不明确时停止。"
    ]
  },
  {
    "id": "record-test039",
    "version": "25G332-Test039",
    "label": "历史验证",
    "state": "诊断与 Wi-Fi 通过，扩展位待修",
    "date": "2026-10-27",
    "summary": "Test039 完成单次诊断和 Wi-Fi 回归；5 个 AWDL 帧仍未通过解析，新增数字详情已把拒绝原因定位到扩展标志 0x20。",
    "evidence": [
      "唯一手动 900 ms 频道 6 会话 START/END 成功，队列 4 的诊断 TX 完成，站点、队列、发送环及潜在资源全部释放。",
      "接收 5 个 AWDL 标识帧，解析通过 0、有效对端 0；最后为 PSF/type12/47B，拒绝子阶段 UnsupportedExtFlags。",
      "flags=0x9f23、extFlags=0x197d、Options 长度 4；偏移 29 后剩 18 字节，与既有扩展字段长度一致。未保存报文内容。",
      "私有地址正常，一次开关及自动回连通过；共 9 次完整 1 MB 无线 HTTP 请求成功。",
      "回连后 120 秒、9 次采样在线，重置计数保持 11；5 到 11 的变化落在主动开关窗口。",
      "本轮关闭约 0.09 秒、重试 1 次，前两轮曾重试 92 次；不能据单次较快认定延迟问题解决。"
    ],
    "blockers": [
      "已命名的 0x20 Misc 标志此前被保守拒绝，真实帧接受仍待 Test040。",
      "尚未重新验收满速、即时热点、新网络及睡眠唤醒。",
      "真实 AWDL 公告、原生 awdl0 与双向 AirDrop 传输仍未完成。"
    ],
    "next": [
      "Test040 最小支持 0x20，保留所有长度检查和其他未知位拒绝。",
      "下一轮仅触发一次，再判断有效对端及拒绝详情。"
    ],
    "tone": "warning"
  },
  {
    "id": "record-test040",
    "version": "25G332-Test040",
    "label": "历史验证",
    "state": "实帧解析通过，准入未确认",
    "date": "2026-10-27",
    "summary": "Test040 已有 4 帧通过解析并进入对端观察器，解析拒绝为 0；收到的 5 帧中另有 1 帧因队列满丢弃。有效对端准入仍待确认。",
    "evidence": [
      "唯一手动频道 6、900 ms 驻留 START/END 成功，队列 4 的诊断 TX 与资源释放通过。",
      "5 个 AWDL 标识帧中，4 帧完成解析并进入观察器，解析拒绝为 0；四格队列满计数为 1。",
      "观察器接受记录为 4、拒绝为 0，最后结果为 CandidateOnly；当前有效 peer 数为 0。尚无历史准入统计，不能反推会话中所有时刻的准入状态。",
      "私有地址正常，一次开关及自动回连通过；共 9 次完整 1 MB 无线 HTTP 请求成功。",
      "回连后 120 秒、9 次采样在线，重置计数保持 12；主动关闭约 2.4 秒、内部重试 92 次。"
    ],
    "blockers": [
      "丢弃帧的类型未知，不能直接认定它就是 MIF。",
      "当前有效 peer 是同一 epoch 内的近期观测，不能证明当前无线可达。",
      "满速、即时热点、新网络及睡眠唤醒待验收；真实 AWDL TX、awdl0、IPv6 与 AirDrop 尚未完成。"
    ],
    "next": [
      "Test041 扩大固定队列并保存分类与历史准入证据。",
      "下一轮先确认完整突发、MIF 与严格准入，再推进真实发送和原生数据通路。"
    ],
    "tone": "pending"
  },
  {
    "id": "record-test041",
    "version": "25G332-Test041",
    "label": "历史验证",
    "state": "对端准入与 Wi-Fi 冒烟通过",
    "tone": "success",
    "date": "2026-10-27",
    "summary": "Test041 首次记录到有效 AWDL 对端及同步字段：3 帧 PSF、1 帧 MIF 全部解析，准入 1 次。Wi-Fi 单次冒烟通过；实际 AirDrop 传输尚未实现。",
    "evidence": [
      "实际加载版本、UUID 与部署包一致；iPhone 准备后仅执行一次手动诊断。",
      "频道 6、900 ms START/END 成功；固件队列 4 的诊断 TX 和全部资源清理通过。",
      "4 个 AWDL 标识帧全部入队并解析；PSF 3、MIF 1、候选 3、准入 1、更新 0，队列满及解析拒绝均为 0。",
      "读回近期有效对端 1、同步字段有效；准入与峰值属于上下文 4。此结果不能证明当前可达或数据通路。",
      "私有地址正常，一次开关及自动回连通过；三个阶段共 9 次完整 1 MB 无线 HTTP 成功，只验证连通性。",
      "回连后 120 秒、9 次采样在线，重置计数保持 11；5 到 11 的变化落在主动开关窗口。",
      "本轮关闭约 0.09 秒、内部重试 1 次；限定日志窗口未匹配到 panic、驱动错误或固件断言模式。"
    ],
    "blockers": [
      "真实 PSF 通告尚未发送；需解决循环时隙的到期行为和时钟证据。",
      "原生 awdl0、IPv6 和 AirDrop 数据传输尚未实现。",
      "满速、即时热点、新网络、长期运行与睡眠唤醒尚未重新验收。"
    ],
    "next": [
      "保留当前 Test041 与现有完整 EFI 备份；本轮没有重复诊断或开关。",
      "下一版先离线实现真实 PSF 的时间与驻留约束；达到可上机条件后再部署。",
      "同步补齐原生接口创建布局、对象持有与释放。"
    ]
  },
  {
    "id": "record-test042",
    "version": "25G332-Test042",
    "label": "历史验证",
    "state": "单帧 PSF 固件发送与 Wi-Fi 冒烟通过",
    "tone": "success",
    "date": "2026-10-27",
    "summary": "Test042 已启动。231 字节真实 PSF 的固件发送和资源清理通过；收到 6 帧 AWDL，形成 1 个有效对端。普通 Wi-Fi 单次冒烟通过，AirDrop 尚未实现。",
    "evidence": [
      "实际加载版本、UUID 及五项手动配置均核对；预检未触发，手机准备后只执行一次。",
      "频道 6、878 TU 驻留 START/END 完整；帧类型为 PSF、长度 231、固件发送完成，站点、队列、发送环和潜在资源归零。",
      "构造到主机提交门约 53 微秒，提交门保守剩余窗口 872336 微秒；空中覆盖、时钟及循环到期证明保持为 0。",
      "接收 PSF 5、MIF 1，全部解析成功；严格准入 1 次、历史峰值 1，所属上下文 4。丢帧与解析拒绝均为 0。",
      "私有地址正常，三个阶段共 9 次完整 1 MB 无线 HTTP 成功；一次开关、自动回连及 IPv4 恢复通过。",
      "回连后 120 秒、9 次采样在线，重置计数保持 11；5 到 11 的变化位于主动开关窗口。关闭约 0.09 秒、内部重试 1 次。",
      "四个限定日志窗口未匹配到 panic、驱动错误或固件断言模式，也未再匹配到两个频道回调不支持提示。",
      "系统频道 36、TX 链路值 1560 Mbps；小流量 HTTP 只验证连通性，不代表无线最高吞吐。"
    ],
    "blockers": [
      "固件完成不等于手机收到，6 帧接收也不能当作手机对本次发送的响应。",
      "本地时序起点需修正：OWL 边界倒计时为 64 TU；后续两帧应共享同一起点和频道表。",
      "原生 awdl0、持续时隙、IPv6 和双向 AirDrop 尚未打通。"
    ],
    "next": [
      "Test043 合并同一次手动会话内的 PSF＋MIF，严格保留首帧结果及第二帧的队列、驻留和代次检查。",
      "继续完成原生具体类、对象持有与停止清理；离线时钟映射基础保留到硬件见证可用后再接入。",
      "下一次部署前更新全部纵向里程碑；备份与回滚保留在 EFI 外。"
    ]
  },
  {
    "id": "record-test043",
    "version": "25G332-Test043",
    "label": "历史验证",
    "state": "PSF＋MIF 固件发送与 Wi-Fi 冒烟通过",
    "tone": "success",
    "date": "2026-10-27",
    "summary": "Test043 已启动验收。PSF 与 MIF 在同一手动驻留中完成，提交、完成、成功均为 2；收到 6 帧 AWDL，形成一个有效对端并更新一次。Wi-Fi 单次冒烟通过，AirDrop 尚未完成。",
    "evidence": [
      "实际加载版本、二进制身份和六项配置核对通过；手机准备后仅触发一次。",
      "PSF 231 字节、MIF 254 字节，各自提交、完成、成功均为 1；总计 2／2／2，两帧完成和成功标志均为 1。",
      "频道 6 驻留 START/END 完整；站点、队列、发送环、在途和潜在资源全部释放，Wi-Fi 在诊断后保持联网。",
      "收到 PSF 5、MIF 1，解析拒绝与队列丢帧为 0；严格准入 1 次、更新 1 次、有效对端峰值 1。",
      "三个阶段合计 9 次完整 1 MB 无线 HTTP 成功；一次开关、自动回连和地址恢复通过。",
      "主动开关内重置计数 5→12，随后 120 秒、9 次采样均在线且计数保持 12。",
      "四个限定日志窗口未匹配到 panic、命名驱动错误、固件断言重置或两个频道回调不支持模式。",
      "频道 36、系统报告 TX 链路值 1733 Mbps。小流量 HTTP 只用于联网检查，不能代表最高吞吐。"
    ],
    "blockers": [
      "固件完成和接收记录均不能证明手机收到本次公告，也不能证明已经同步或可传文件。",
      "设备时钟映射、持续频道驻留和对端主节点状态尚未接入，数据通路保持关闭。",
      "原生 awdl0、IPv6 和双向 AirDrop 尚未打通；睡眠、即时热点与长期连接仍待验收。"
    ],
    "next": [
      "Test044 合并硬件时钟原始采样与 RX 原始设备时间戳保留；仍只进行一次手动 PSF＋MIF 会话。",
      "在真实采样基础上验证时钟关系，再接主节点选举和持续时隙调度。",
      "继续原生具体类生命周期与数据路径；离线构造器证据不能代替内核加载。"
    ]
  },
  {
    "id": "record-test044",
    "version": "25G332-Test044",
    "label": "历史验证",
    "state": "硬件时钟、双帧与 Wi-Fi 冒烟通过",
    "tone": "success",
    "date": "2026-10-27",
    "summary": "Test044 已完成单次诊断：两次硬件时钟采样通过，PSF 与 MIF 的提交、完成、成功均为 2；8 帧 AWDL 全带设备时间戳，Wi-Fi 冒烟通过。AirDrop 尚未打通。",
    "evidence": [
      "实际加载版本、二进制身份和七项配置核对通过；手机准备后只触发一次。",
      "PSF 231 字节、MIF 254 字节，固件提交／完成／成功为 2／2／2；驻留 START/END 完整，所有发送资源释放。",
      "两次 GP2 读取前后主机时间区间各宽 2 微秒；设备推进 924623 微秒，主机经过区间为 924621–924625 微秒。",
      "时钟映射、长期漂移界和发送时序证明仍为 0；没有将局部读数吻合当作对端同步。",
      "收到 7 PSF、1 MIF，8 帧都保留 RX GP2；无解析拒绝或队列丢帧。严格准入 1 次、更新 6 次、有效对端峰值 1。",
      "三个阶段合计 9 次 1 MB 无线 HTTP 成功；一次开关与自动回连通过。回连后 120 秒、9 次采样在线，重置计数保持 11。",
      "四个限定日志窗口未检出 panic、命名驱动错误、固件断言重置或频道回调不支持模式。",
      "频道 36、系统报告 TX 链路值 1733 Mbps；小流量 HTTP 仅验证联网，尚未验收最高速度、睡眠或即时热点。"
    ],
    "blockers": [
      "当前运行版没有保留可发布的同帧对端 PHY 与 RX GP2 配对，不能由最后值推断对端时钟关系。",
      "固件完成不证明手机收到；时钟映射、持续驻留、原生 awdl0、IPv6 和双向 AirDrop 仍未完成。"
    ],
    "next": [
      "Test045 接入每设备有界状态表，保存最近三组原始时间配对和同一 MIF 的同步、频道及选举字段。",
      "MIF 的 5 秒有效期独立于 PSF；过期数据明确标记历史，不能参与调度。",
      "原生对象生命周期与数据帧格式继续离线验证，未验证部分保持关闭。"
    ]
  },
  {
    "id": "record-test045",
    "version": "25G332-Test045",
    "label": "历史验证",
    "state": "同一对端 PSF 时间配对通过；MIF 被新表拒绝",
    "tone": "warning",
    "date": "2026-10-27",
    "summary": "Test045 保留三组 PSF 时间配对；当轮收到 1 帧 MIF，新表报告 InvalidSync 并拒绝。Test046 后续增加了精确 MIF 诊断，但本次重启没有再收到 MIF。",
    "evidence": [
      "Test045 收到 6 PSF、1 MIF；新表拒绝 MIF 1 次，状态为 InvalidSync。",
      "同一对端三组 PHY TX／RX GP2 配对保存成功；这些差值只是观测，不构成时钟映射。",
      "Test045 双帧 TX 2／2／2、资源清理和 Wi-Fi 冒烟通过；详细历史证据保留在本地研究记录中。"
    ],
    "blockers": [
      "Test045 未能定位 InvalidSync 的具体字段分支；不要将该状态套用到后续启动。",
      "原生 awdl0、真实对端数据通路及 AirDrop 仍未完成。"
    ],
    "next": [
      "Test046 增加兼容解析及数字诊断；后续验证以实际收到 MIF 为前提。"
    ]
  },
  {
    "id": "record-test046",
    "version": "25G332-Test046",
    "label": "历史验证",
    "state": "Wi-Fi 冒烟通过；本轮未收到 MIF",
    "tone": "warning",
    "date": "2026-10-27",
    "summary": "Test046 实机通过 Wi-Fi 开关回连和短时连通性检查；当轮只收到 PSF，没有 MIF，因此新 MIF 解码器没有实帧结果。",
    "evidence": [
      "PSF 5、MIF 0；LastMifDecodeStatus=255 表示本启动未调用 MIF 解码器。",
      "双帧固件 TX、资源清理、GP2 原始读数与短时 HTTP／开关回连通过；没有证明时钟映射或对端收包。",
      "后续 reset count 上升原因未定位；本条保留 Test046 历史，不作为 Test047 结果。"
    ],
    "blockers": [
      "原生 awdl0、有效 peer 同步、IPv6 数据通路和双向 AirDrop 尚未完成。",
      "Test047 的 Wi-Fi 复位行为需用各自启动记录独立分析。"
    ],
    "next": [
      "Test047 增加独立 PSF 状态表与完整字段观察。"
    ]
  },
  {
    "id": "record-test047",
    "version": "25G332-Test047",
    "label": "历史验证",
    "state": "Wi-Fi 冒烟与双帧本机 TX 通过；PSF 副本不一致全拒",
    "tone": "warning",
    "date": "2026-10-27",
    "summary": "Test047 加载后完成 Wi-Fi 单次开关与回连；900 ms 窗口收到 7 个 PSF、0 个 MIF。外层解析通过，但 7 个 PSF 都因 type-4 内嵌序列与 type-18 不一致而被新解码器拒绝。PSF 表未准入；本机双帧固件发送与回收 2／2／2 通过。",
    "evidence": [
      "三阶段合计 9 次 1 MB HTTPS 完整成功；一次 Wi-Fi 关闭／开启、自动回连与 IPv4 恢复通过；回连后 120 秒、9 次采样在线且 reset count 为 11。",
      "第一段 600 秒被动观察结束且未标记非计划变化。Test047 第二段开关回连后的被动观察已结束（600.0 秒、1 个样本）；记录未标记非计划变化，复位计数观测值为 11。该观察按变化保存记录，限定窗口内未记录计划外复位；仍不替代长期连接和睡眠测试。",
      "PSF/MIF 固件提交／完成／成功均为 2／2／2，ROC START／END 和队列、站点、发送环、在途资源清理通过；未获对端 ACK。",
      "GP2 设备推进 934515 微秒，主机时间区间 934512–934516 微秒；原始读数接近不等于时钟映射。",
      "7 个 PSF 外层解析通过、MIF 为 0；7 个 PSF 均 InvalidSync / stage 8。type4 length=73、tail=40；type18 length=41；counter=62、AW=16、presence=4。",
      "没有 accepted/fresh PSF、5 秒过期实机证明、MIF 表更新、对端 ACK、awdl0 或 AirDrop 传输。"
    ],
    "blockers": [
      "PSF 重复副本一致性检查使本轮 7 个结构外层有效帧全部拒绝；尚无实机通过或有效期证据。",
      "第二段 post-cycle 600 秒观察状态：已结束，见上方原始观察摘要。",
      "reset cause 诊断、有效 MIF 同步、时钟映射、持续调度、原生 awdl0、IPv6 和双向 AirDrop 均未完成。"
    ],
    "next": [
      "Test048 只将完整 recognized embedded-copy 与必需 type18 的逐槽差异改为非致命诊断；type18保持canonical，结构与 malformed rejection保持严格。",
      "Test048 加入 Wi-Fi 复位原因和恢复请求来源记录，不改变恢复行为；并发测试、完整构建、签名及最终产物检查已通过。",
      "native VIF init/free 安全仍 blocked；不链接候选、不创建 awdl0、不启用选主或时隙调度。"
    ]
  },
  {
    "id": "record-test048",
    "version": "25G332-Test048",
    "label": "历史验证",
    "state": "PSF/MIF 接纳与到期、Wi-Fi 冒烟通过",
    "tone": "success",
    "date": "2026-10-27",
    "summary": "Test048 已启动验收：6 个 PSF、1 个 MIF 全部接纳，独立有效状态和到期转换有记录；Wi-Fi 单次开关回连与短时联网通过。AirDrop 仍未实现。",
    "evidence": [
      "Test048 版本与 UUID 已核对；三个阶段共 9 次完整 1 MB 无线 HTTPS 成功，一次关闭、开启、历史网络自动回连与 IPv4 恢复通过。回连后 120 秒九次采样在线，reset count 保持 11；600 秒被动观察未记录计划外重置或未就绪。私有地址 stage 5、result 0，未隔离。",
      "本轮只触发一次 900 ms 手动会话，PSF 与 MIF 提交／完成／成功为 2／2／2；ROC START/END 匹配，队列、站点、发送环和在途资源归零。",
      "两次 GP2 直接读取各有 2 微秒主机括区，设备推进 931060 微秒，主机推进区间 931058–931062 微秒。同一对端保留三组 PSF PHY/RX GP2：相邻推进差为 3 和 2 微秒；MIF 自有时间对单独保存。",
      "7 个 AWDL 帧全部入队、外层解析通过；PSF 接纳 6、拒绝 0，MIF 接纳 1、拒绝 0，队列丢帧 0。PSF/MIF 有效峰值均为 1。重复副本差异为 index 0、38 对 36，保留诊断并使用必需 type 18 频道表；解码 status 0、reject stage 0。PSF 最后有效 age 4112846 微秒、首次过期 5113476；MIF 为 4663763 与 5664393。",
      "新增重置来源快照已在实机发布，完整快照的 sequence 与 reset count 匹配。启动 baseline 为停用 2、未运行初始化恢复 3；计划开关后累计 5 与 6。恢复请求来源计数独立，不能与某次重置一一配对。",
      "本次启动限定日志审计未匹配到 panic/fatal、驱动命名错误或固件断言模式；另一个 panic token 已确认是 watchdog 配置说明，非崩溃。"
    ],
    "blockers": [
      "没有真实 AWDL 数据 RX/TX、有效持续调度或 AirDrop 文件传输记录。",
      "prepareRelease 尚无真实原生绑定。exact 25G332 的 failed-super-init/free 空指针风险、BPF 锁/list 清理及未 start 对象的 terminate 前置状态仍未全部解决。",
      "原生 awdl0、真实 IPv6 邻居与 mDNS 交换均未验收。",
      "仍需对端时序与频道调度、原生 awdl0、数据 RX/TX、IPv6 与服务发现。"
    ],
    "next": [
      "原生接口 owner 的 14 个离线场景通过；清理回调和内核对象创建仍待真实绑定与验收。",
      "继续时序、时隙与原生数据通路；不把状态表准入当成同步或 AirDrop。",
      "本轮没有新 kext/EFI 部署，不需要再次重启。"
    ]
  },
  {
    "id": "record-test049",
    "version": "25G332-Test049",
    "label": "历史验证",
    "state": "原生 init/cleanup 通过；后续 Wi-Fi 断开已恢复",
    "tone": "warning",
    "date": "2026-10-27",
    "summary": "本轮首次实机完成未发布原生 AWDL 对象的初始化、PM 注销及释放，Wi-Fi 保持联网。未执行 attach/start、awdl0 注册或 AirDrop。",
    "evidence": [
      "本轮管理员单次触发成功，最终 flags 14335（0x37ff），PM 注销结果 0，释放前引用计数 1，类大小 320 字节。无隔离、分配失败或初始化失败标志。实验固件尝试与潜在资源均为 0，Wi-Fi 保持在线。模块存活期结果记录正常，没有保留工作线程栈指针。",
      "Test049 实际加载 UUID 与部署包一致。原生对象诊断前后三次、合计六次完整 1 MB HTTPS 请求成功；120 秒观察没有计划外变化，重置计数保持 5。私有地址 stage 5、result 0，未隔离。",
      "本次启动限定日志审计覆盖 72268 条记录，未匹配到 panic/fatal、驱动命名错误或固件断言模式。原始消息未保存或上传。",
      "Test050 尚未加载时，Test049 出现 Ready 0、HAL flags 0，固件软件错误触发计数为 1，重置计数从先前 5 增至 9。保留了故障快照；一次关闭、开启恢复联网，恢复后三次完整 1 MB HTTPS 请求通过。"
    ],
    "blockers": [
      "原生 start 的部分提前退出分支仍返回 true；role 6 的原生 stop 又会读取 peer-manager，因此必须验证部分启动状态并绑定安全清理。当前没有原生接口注册或数据通路。",
      "原生 awdl0、真实 IPv6 邻居与 mDNS 交换均未验收。",
      "仍缺有效频道调度、原生 awdl0 数据 RX/TX、IPv6 邻居与 mDNS，以及真实双向文件传输。",
      "固件错误及恢复未就绪的根因尚未修复；一次开关可恢复不代表稳定性问题已解决。日志中的最近一次 reset trace 与总计数不匹配，不能据此强行归因。"
    ],
    "next": [
      "保留当前 Test049 和 EFI 外的 Test048 回滚备份；本轮没有新部署，无需再重启。",
      "原生 start 的返回值不作为唯一成功依据；补齐状态见证和真实失败清理，再合并下一版运行测试。"
    ]
  },
  {
    "id": "record-test050",
    "version": "25G332-Test050",
    "label": "历史验证",
    "state": "临时原生 awdl0 注册与启停通过",
    "tone": "success",
    "date": "2026-10-28",
    "summary": "首次实机完成原生队列注册、接口启动、临时 awdl0 出现及停止释放。Wi-Fi 保持连接；持续数据通路和 AirDrop 尚未完成。",
    "evidence": [
      "本轮只手动触发一次，最终 flags 0x1cfffff，启动状态见证 0x3ff。原生 BSD awdl0 索引 13，扩展标志 0x43e0080 含 AWDL 位；停止后接口消失。控制器别名已清除，注册、队列及对象均释放，释放前引用计数 1；失败阶段与错误码均为 0，无隔离。Wi-Fi 重置计数保持 5。",
      "Test050：实际 UUID 与部署包一致，原生生命周期前后六次完整 1 MB HTTPS 请求成功；120 秒观察重置计数保持 5，私有地址 stage 5、result 0、未隔离。",
      "本次启动日志审计没有匹配到 panic/fatal、驱动命名错误或固件断言模式；1 个 panic 词条经核对为 watchdog 配置说明，非本次崩溃。日志启发式检查不代表不存在任何错误。",
      "本轮未再写 EFI；整份 Test049 回滚备份与当前 Test050 部署包均已保留。",
      "Test050 原生启停前后六次完整 1 MB 请求、私有地址与 120 秒观察通过。Test051 开发期间额外观察 600 秒，未记录计划外复位，重置计数保持 5。"
    ],
    "blockers": [
      "当前为临时生命周期测试：数据回调接受 0 个包，没有保持常驻的 awdl0，也没有真实 AWDL 数据 RX/TX、持续频道调度或 AirDrop 传输。",
      "上一版 Test049 开发期间发生过固件软件错误触发及未就绪，一次开关后恢复；根因仍未修复。用户记不清是否睡眠或手动切换，诱因保留为未知。长期连接、睡眠恢复、满速及即时热点仍待独立验收。",
      "仍缺有效频道调度、原生 awdl0 数据 RX/TX、IPv6 邻居与 mDNS，以及真实双向文件传输。"
    ],
    "next": [
      "下一步接入持续运行的原生数据队列与 Intel AWDL 收发，建立真实完成及清理回报。",
      "随后验证 awdl0 的 IPv6 邻居、mDNS 和双向文件传输；不以接口出现替代这些验收。",
      "当前没有新版本部署，无需再次重启。"
    ]
  },
  {
    "id": "record-test051",
    "version": "25G332-Test051",
    "label": "历史验证",
    "state": "原生常驻与系统输出通过；发送校验阻塞",
    "tone": "warning",
    "date": "2026-10-28",
    "summary": "常驻原生 awdl0 已实测，真实 IPv6 输出进入驱动；本轮没有数据帧提交固件。已定位错误的绑定前校验，修正合并进 Test052。",
    "evidence": [
      "Test051 自动创建原生 awdl0，BSD 索引 8、phase 13、flags 0x4003ff、start 见证 0x3ff。接口在诊断后仍存在。初始缺少 RUNNING 和 IPv6；通过标准接口配置补齐后，真实用户态 IPv6 包进入驱动队列。Test050 临时启停证据保留。",
      "Test051 实机收到 8 个 PSF 与 1 个 MIF，共 9 个控制帧解析通过，拒绝 0，接纳 1 次并更新 7 次。原生接口常驻没有破坏已有对端控制帧接收。",
      "Test051 仍只执行一次 900 ms 会话，PSF 与 MIF 各一次；控制帧提交／完成／成功为 2／2／2，START/END 匹配，诊断后无线资源归零。",
      "Test051 内核累计接纳 18 个真实 IPv6 输出包，其中受控诊断新增 4 个查询；最终 18 个全部到期，编码、固件提交／完成／成功均为 0。检查发现数据路径误用要求“绑定不存在”的绑定前校验，而此时实际绑定已活动。",
      "本轮加载身份核对、联网和私有地址通过；诊断前 180 秒被动观察没有记录到计划外复位，诊断后联网正常。启动日志未匹配到明确 panic/fatal、驱动命名错误或固件断言模式；另有一个未分类 panic 词条，未据此宣称日志完全无错。"
    ],
    "blockers": [
      "自动 IPv6 初始化、数据帧固件接受、无线数据回送仍待下一次启动实测；持续调度和稳定数据吞吐尚未完成。",
      "仍需真实无线数据收发、邻居发现、mDNS 响应和持续传输；本地 sendto 成功不代表已发到手机。",
      "上一版 Test049 开发期间发生过固件软件错误触发及未就绪，一次开关后恢复；根因仍未修复。用户记不清是否睡眠或手动切换，诱因保留为未知。长期连接、睡眠恢复、满速及即时热点仍待独立验收。"
    ],
    "next": [
      "本轮单次无线诊断已用完，不再重新触发。",
      "Test052 合并自动 IPv6、软件校验和与活动 ROC 校验；重启后分层验收。"
    ]
  },
  {
    "id": "record-test052",
    "version": "25G332-Test052",
    "label": "当前运行候选",
    "state": "自动 IPv6 通过；无线诊断发生内核崩溃",
    "tone": "warning",
    "date": "2026-10-28",
    "summary": "原生 awdl0 自动 RUNNING、IPv6 和系统输出通过；单次无线诊断被 M_PKTHDR 内核断言中断。已定位 mbuf 分配缺陷，待 Test053 运行验证。",
    "evidence": [
      "Test052 自动建立原生 awdl0，phase 13、flags 0x4003ff、start 见证 0x3ff、BSD 索引 9；IPv6 配置结果 0、已配置 1，RUNNING 与 link-local 地址可用，无 tentative 或 duplicated。无需手动配置。无线诊断随后因 M_PKTHDR 断言崩溃。",
      "Test052 最后保存的采样显示，活动 ROC 的 owner、代次、站点、命令、MAC、绑定、PHY、会话和发送队列条件均通过；阻塞值 0xA00 表示当时没有有效且新鲜的对端。采样截止时 Data 编码／提交／完成为 0，随后发生内核崩溃，最终计数未保存。",
      "崩溃前 Test052 正确加载，Wi-Fi 和私有地址正常，三次完整 1 MB HTTPS 请求通过。单次无线诊断随后被 M_PKTHDR 内核断言中断；此轮不能算整体稳定性通过。",
      "Test052 崩溃前的加载身份、普通 Wi-Fi 和私有地址已核对；被动观察未完成。恢复启动并临时关闭 awdl0 后，三次完整 1 MB 请求和 120 秒观察通过，重置计数保持 5。这不是 Test053 的运行验收。"
    ],
    "blockers": [
      "确认代码错误：mbuf_getcluster 在空指针输入时不创建系统输入队列要求的包头。已改用 mbuf_getpacket，并检查 PKTHDR；内核修复效果待验证。",
      "观察记录停在约 0.385 秒，崩溃约发生在 arm 后 3.18 秒；最终 Data RX/TX、资源清理及 AirDrop 均未验收。"
    ],
    "next": [
      "本轮不再触发 RF，awdl0 已临时关闭，普通 Wi-Fi 保持可用。",
      "Test053 修正分配、补齐真实包头语义回归，并由子代理独立复核后再部署。"
    ]
  },
  {
    "id": "record-test053",
    "version": "25G332-Test053",
    "label": "历史运行记录",
    "state": "本轮运行已记录；无线诊断因队列冲突阻塞",
    "tone": "warning",
    "date": "2026-10-28",
    "summary": "Test053 正确加载；原生 awdl0 常驻、自动 IPv6、内核输出与私有地址状态已核对。单次 RF 在 ROC 前因 qid 3 队列冲突以 EBUSY 中止，未产生数据 TX/RX，因此尚未验证 PKTHDR 修复或 AirDrop。",
    "evidence": [
      "加载身份正确。原生 awdl0 常驻、自动 IPv6 与本地内核输出路径通过；私有地址 Stage 5 / Result 0 / 未隔离。",
      "RF 前被动观察实际 120.004 秒：Ready=1、ResetCount=5、en1 active 且有 IPv4，观察报告未见变化。",
      "本地网关 2/2 响应、丢包 0%、平均 3.497 ms；en1 的 Ierrs/Oerrs/Coll 均为 0。Cloudflare 与 Apple 外网探测 5 秒超时且 0 字节，不算互联网连通通过。",
      "唯一 RF 尝试收到有效 firmware qid 3 回复；既有 host ring 冲突使 stage 29 / step 6 返回 EBUSY=16。没有 ROC START/END、数据 TX 或 RX。",
      "潜在固件资源仍未确认释放，retry_permitted=false；没有重试或强制回收。closeout 记录 Wi-Fi Ready=true、ResetCount=5、未观察到 panic。",
      "诊断后资源隔离保留状态下，再被动观察 120.005 秒，Ready=1、ResetCount=5、en1 active/IPv4 均稳定；私有地址 Stage5 / Result0 / 未隔离。不能由此声称队列资源已清理、互联网通过或 PKTHDR 路径实测通过。",
      "Test054 开发期另观察 180.002 秒：Ready=1、ResetCount=5，en1 与私有地址稳定；前后网关各 2/2，接口错误为 0。"
    ],
    "blockers": [
      "firmware qid 3 与已有 host ring 的所有权/生命周期不明；先安全解决，资源不明时不得重试或强制释放。",
      "本轮没有触及真实 RX/TX mbuf 包头路径，Test053 的 PKTHDR 修复效果仍未运行验证；没有数据收发、对端应答或 AirDrop 证据。",
      "完整互联网、吞吐、长时间运行、睡眠恢复、即时热点及新网络仍待单独验收。"
    ],
    "next": [
      "本次启动唯一诊断已用完，不再触发 RF 或强行释放未知资源。",
      "Test054 已合并、离线验证并部署；重启后核对新版本，再安排一次诊断。"
    ]
  },
  {
    "id": "record-test054",
    "version": "25G332-Test054",
    "label": "历史运行记录",
    "state": "ROC与控制接收通过；首次发送前隔离，链路有回归",
    "tone": "warning",
    "date": "2026-10-28",
    "summary": "空闲qid4安装、900ms驻留和7PSF/1MIF接收通过；首次发送前EBUSY，未arm或doorbell，潜在资源保留。后测短暂掉线且一笔下载超时，AirDrop未通过。",
    "evidence": [
      "固件分配 qid4、flags1、reserved0、write pointer0；host slot 为空，setup step6/result0。频道6的900ms会话得到 START/END。RebindFlushAttempted=0、RetainedRingCount=0，因此没有运行到 qid3 旧 DMA 暂存或回收路径。",
      "本轮唯一一次频道6、conf3、900ms请求，命令结果0、START/END各1且状态1，Unknown=0。首次PSF候选231字节，门槛阻塞0、剩余驻留约872067微秒，但提交前被拒绝。",
      "单次窗口收8个真实AWDL控制帧：PSF7、MIF1、PSF接纳7、有效peer准入1，解码拒绝0。真实数据帧捕获与ifnet输入仍为0。",
      "PSF门槛为0但helper返回16；ActionState=Quarantined，ticket/outstanding/diagnostics armed均为0，PSF/MIF提交与固件完成均0。最终stage29/result60，保留潜在资源。",
      "Test054 exact UUID已加载；phase13、flags0x4003ff、启动见证0x3ff、BSD索引8，自动RUNNING和IPv6配置结果0，诊断后接口仍常驻。",
      "版本 UUID、5 GHz 连接、私有地址 Stage5/Result0 已核对；RF 前 3/3 个 1 MB HTTPS 请求完整成功。RF 后仅 2/3 完成，第三笔 20 秒收到 613751/1000000 字节后超时。120.002 秒后测内 Ready=1、ResetCount=5 不变，但链路/IPv4 在 23.249 秒与 38.130 秒采样缺失，39.185 秒恢复。",
      "启动日志限定审计覆盖本boot82678条记录，没有匹配明确panic/fatal、驱动命名错误或固件断言模式；另有1个未分类panic词条，不等于日志完全无错。"
    ],
    "blockers": [
      "当前资源仍被隔离，本启动不重试或强行清理；冲突分支仍待实测。",
      "真实数据TX/RX、PKTHDR实机效果和对端收包仍未验证。",
      "短暂掉线与下载超时的原因尚未确定；长期、睡眠、开关、吞吐和即时热点没有本轮通过证据。"
    ],
    "next": [
      "本启动不再触发RF、切换Wi-Fi或强制清理未知资源。",
      "Test055合并无在途通知、安全未提交清理及可定位诊断；部署后更新完整里程碑再通知重启。"
    ]
  },
  {
    "id": "record-test055",
    "version": "25G332-Test055",
    "label": "历史运行记录",
    "state": "安全清理和短时联网通过；首次发送仍阻断",
    "tone": "warning",
    "date": "2026-10-28",
    "summary": "启动身份、awdl0常驻和自动IPv6正常。唯一RF收7PSF/1MIF，首次发送在stage6被既有隔离状态拒绝；未发送清理通过，前后6/6完整下载与两段120秒链路观察通过。AirDrop未实现。",
    "evidence": [
      "正确版本与私有地址已核对。前测120.003秒、后测120.021秒，Ready保持1、reset保持5、链路和IPv4未变化；前后各3笔1MB HTTPS均完整成功。",
      "空闲qid4安装成功；首次helper返回16且没有ticket或门铃。确认ROC END后走严格未发送清理，stage28/result16保留原拒绝原因；队列、站点、环和潜在资源均归零，Action恢复Idle。",
      "单次频道6、900ms手动窗口：命令结果0、START/END各1且状态1，Unknown0，CleanupAllowed1；未产生实际门铃发送。",
      "收到7个PSF、1个MIF；累计接纳8、peer准入1，解析拒绝和队列溢出均0。真实数据捕获、解码、原生输入均0。",
      "PSF候选231字节，发送门槛0、剩余驻留约872084微秒；SubmitAttempt1、Stage6、Result16。PreArmEventCount0，无ticket和门铃，PSF/MIF/Data提交完成均0。",
      "phase13、flags0x4003ff、start witness0x3ff；真实BSD awdl0 UP/RUNNING、有有效链路本地IPv6，配置结果0。4次受控查询被内核接纳，诊断后接口仍存活。",
      "额外300.040秒开发期观察稳定，三段共540.064秒；没有把该窗口当作睡眠或长期稳定验收。"
    ],
    "blockers": [
      "冲突队列所有权与旧DMA硬停回收仍缺实机分支覆盖。",
      "启动期无ticket硬停迁代的源码缺陷与现场强一致，缺少该次状态写入直接trace；真实数据与对端收包仍未验证。",
      "IPv6邻居应答、mDNS服务应答和原生分享握手仍未验证。",
      "真实AWDL收发、持续调度、IPv6/mDNS和两方向文件收件仍待完成。"
    ],
    "next": [
      "本启动唯一RF已用完，不重试。",
      "Test056已完成整包构建、签名、独立复核和备份部署；等待用户重启验收。"
    ]
  },
  {
    "id": "record-test056",
    "version": "25G332-Test056",
    "label": "历史运行记录",
    "state": "控制发送恢复；后续TX watchdog，稳定性未通过",
    "tone": "warning",
    "date": "2026-10-28",
    "summary": "启动迁代修复已实测通过，PSF/MIF固件完成2/2、正常回收；前后6次完整下载及两段120秒观察通过。收7PSF而无MIF peer，真实数据检查0xA00，AirDrop尚未实现。 开发期reset5→10并新增一次TX watchdog触发，根因待查，不能称全程稳定。",
    "evidence": [
      "加载UUID及私有地址Stage5/Result0/未隔离正常；前测120.003秒和后测120.000秒，link/IPv4/Ready稳定、reset保持5；6笔1MB HTTPS均完整成功。",
      "实际门铃标记1，PSF/MIF均完成；ROC END确认，stage27/result0，Add/Remove均0，outstanding和潜在资源均0、ticket complete，接口与Wi-Fi保持。",
      "频道6/conf3/900ms，START/END各1且status1，Unknown0、CleanupAllowed1；两个控制帧在此窗口完成。",
      "7个真实PSF进入候选表，parseReject和queueFull均0；MIF总数0、有效peer准入0。PSF解码master/next为6，不能由缺peer的默认频道0推断手机错频道。",
      "PSF231字节、MIF254字节，各完成且status1；SubmitAttempt2/Stage18/Result0，PreArm事件0。真实数据检查156次，阻塞0xA00，无有效MIF peer及其默认频道字段。DataEncoded/Submitted/Completed为0。",
      "phase13/flags0x4003ff/start witness0x3ff，真实BSD awdl0 UP/RUNNING、自动IPv6结果0；4个受控查询被接纳，真实数据编码及输入均0。",
      "加载UUID及私有地址Stage5/Result0/未隔离正常；前测120.003秒和后测120.000秒，link/IPv4/Ready稳定、reset保持5；6笔1MB HTTPS均完整成功。 后续300秒窗口开始时reset已为10，较短测后增加5，并新增1次TX watchdog触发；该300秒内状态稳定。计数增加发生在观察间隙，不能当成5次独立固件崩溃。"
    ],
    "blockers": [
      "冲突队列归属与旧DMA硬停回收仍待实机分支覆盖。",
      "缺少同一有效epoch内的新鲜MIF，尚不清楚是未相遇还是tap前过滤。",
      "原生邻居配置、mDNS应答及分享握手仍未完成。",
      "还需有效peer、真实数据双向通路、服务发现及文件传输。",
      "发送看门狗超时诱因待查；长期、睡眠、开关与即时热点仍未完成。"
    ],
    "next": [
      "本启动唯一RF已用完，不重试。",
      "Test057已部署；重启后核对新版本，先激活原生Finder AirDrop发现，再做一次受控诊断，并保持连续Wi-Fi观察。"
    ]
  },
  {
    "id": "record-test057",
    "version": "25G332-Test057",
    "label": "历史运行记录",
    "state": "有界MIF重播通过；仍缺对端MIF",
    "tone": "working",
    "date": "2026-10-28",
    "summary": "Test057完成1PSF+3MIF固件发送与安全回收；连续约27分27秒与6次联网请求通过。收4PSF/0MIF，未有有效peer，真实无线数据和AirDrop仍未完成。Test058调整MIF发送时序。",
    "evidence": [
      "正确UUID、私有地址Stage5/Result0；启动和RF后各120秒观察通过。另有两段各900秒、相互重叠的被动观察，合并覆盖约27分27秒的基线、RF、后测和开发期，Ready、链路、IPv4保持，reset5、TX watchdog0不变；6/6笔1MB HTTPS完整成功。",
      "实际门铃1，固件完成4/4；ROC END确认，stage27/result0，outstanding与潜在资源0，awdl0存活、Wi-Fi保持。",
      "仅一次频道6、900ms会话，START/END成功、Unknown0；MIF完成间隔约80.0和75.7毫秒，达到3帧上限后停止，没有延长原驻留。",
      "Early、AfterDecrypt、AfterDuplicate及AtTap均为PSF4/MIF0，解密/重复丢弃0；PSF候选接纳4，有效MIF peer0。接收计数在正确owner窗口内出现，不能推断更早硬件或空口从未有MIF。",
      "MIF Prepared/Attempted/Submitted/Completed/Succeeded均3，StopReason1为次数上限。DataGate检查155次、Allowed0、阻塞0xA00；缺有效MIF peer，默认频道字段不代表手机错频道；真实数据TX0。",
      "phase13/flags0x4003ff/start witness0x3ff；自动IPv6结果0、UP/RUNNING。受控查询4次，采集区间总TX接纳增加6，包含Finder等原生系统流量；无线编码/接收/ifnet输入0。"
    ],
    "blockers": [
      "Test056的发送超时诱因仍未定位；长期、睡眠、开关及即时热点待验。",
      "仍缺当前会话有效MIF；TLV4和TLV18复制频道差异未解释，不用于调频或放宽准入。",
      "有效对端IPv6邻居可达、mDNS应答和分享握手尚未完成。",
      "需依次验证有效peer、真实数据、服务发现和两方向收件。"
    ],
    "next": [
      "本启动唯一RF已用完，不重试。",
      "Test058已完成备份部署；重启后核对新版，并验证接收触发的MIF时机及Wi-Fi连续性。"
    ]
  },
  {
    "id": "record-test058",
    "version": "25G332-Test058",
    "label": "历史运行记录",
    "state": "有效MIF准入，真实数据发送4包",
    "tone": "working",
    "date": "2026-10-28",
    "summary": "Test058收到4PSF和1MIF，有效对端通过准入；4个原生awdl0数据包完成固件发送。数据回包仍为0，AirDrop尚未完成。连续15分钟和6次联网请求通过。Test059定位数据回包链路。",
    "evidence": [
      "加载UUID一致，私有地址Stage5/Result0；启动与诊断后各120秒通过，连续900秒覆盖基线、RF、后测和开发期。Ready、链路、IPv4保持，reset5、TX watchdog0；6次1MB HTTPS全部成功。",
      "控制提交/完成/成功2/2/2，真实数据4/4/4；ROC END确认，stage27/result0，outstanding及潜在资源0，awdl0存活。",
      "Early、AfterDecrypt、AfterDuplicate和AtTap均PSF4/MIF1，解密和去重丢弃0；有效MIF准入1。后续数据捕获、解码、原生输入均0。",
      "PSF1/MIF1完成；MIF新PSF锚1。数据Encoded/Submitted/Completed/Succeeded均4、Failed0。DataGate5次中放行4次，唯一阻塞0x100为队列暂忙，末态0。",
      "phase13、flags0x4003ff、witness0x3ff；自动IPv6有效。受控查询4次，采集区间TX接纳增加4，真实数据编码与完成4。无真实无线RX，ifnet输入仍未覆盖。"
    ],
    "blockers": [
      "MIF重新有本轮输入，不能把上轮未覆盖写成解析器回归。仍需区分数据未到接收点、前置过滤和对端未发回应。",
      "本地地址检查不证明实际线上UDP校验或对端收包；Test059加入发送前字节诊断和数据RX分段观察。",
      "继续验证真实无线回包、原生输入、邻居和服务发现，再验两个方向文件收件；60%是验收项占比，不是剩余工时或AirDrop成功率。"
    ],
    "next": [
      "本启动唯一RF已使用，不再重试。",
      "Test059已备份部署，重启后验证数据回包链路。"
    ]
  },
  {
    "id": "record-test059",
    "version": "25G332-Test059",
    "label": "历史运行记录",
    "state": "发送完整性通过；有一次超时恢复，数据回包0",
    "tone": "warning",
    "date": "2026-10-28",
    "summary": "Test059收到6PSF和1MIF，4个真实数据包完成固件发送，UDP校验、源身份和组播映射通过；数据Early及原生输入仍为0。曾发生一次无人工操作的发送超时并恢复；随后900秒观察和联网通过。Test060修复计时并发、代次读取与查询分类，准备原生Bonjour回包对照。",
    "evidence": [
      "UUID匹配，私有地址Stage5/Result0。早期reset5到10、watchdog0到1，用户确认无操作；随后两段900.062秒与900.064秒观察均保持reset10/watchdog1、链路和IPv4正常，两个窗口有间隔；RF后3次1MB HTTPS成功。",
      "PSF1、MIF3完成，数据提交/完成/成功4/4/4，stage27/result0、resource0；awdl0和Wi-Fi仍可用。",
      "PSF/MIF的Early、AfterDecrypt、AfterDuplicate和AtTap均6/1；Data Early/AfterDecrypt/AtTap、Captured/Delivered均0。",
      "Encoded/Submitted/Completed/Succeeded均4、Failed0；checksum mask2，源EUI64、组播映射及malformed异常计数均0。",
      "phase13/flags0x4003ff/start witness0x3ff，UP/RUNNING及自动IPv6正常；诊断后常驻，真实RX输入仍0。"
    ],
    "blockers": [
      "超时现场尚未获得完整队列证据；本轮不能判为长期稳定。睡眠、开关、即时热点继续待验。",
      "无法由Early0区分对端未发回应、无线时隙或固件前置交付；不能直接认定是解码器故障。",
      "系统Bonjour可缓存、合并或先发QU；下一版只有实际QM固件成功才算覆盖QM对照，没有QM不能判RX失败。",
      "先获得原生无线回包与服务发现，再分别验两个方向文件收件及完整性。"
    ],
    "next": [
      "Test060运行结果已记录；本启动不再触发RF。"
    ]
  },
  {
    "id": "record-test060",
    "version": "25G332-Test060",
    "label": "当前运行候选",
    "state": "有限实测完成",
    "tone": "working",
    "date": "2026-10-28",
    "summary": "Wi-Fi连续15分钟观察及诊断前后6次联网检查通过，未见新超时或重置。2条QM查询完成固件发送；无线回包和原生输入仍为0，AirDrop未完成。",
    "evidence": [
      "Test060 UUID匹配，私有地址Stage5/Result0，en1联网可用。RF前后en1绑定的1MB HTTPS请求均3/3成功；平均速率5.75/5.12Mbps（公网端到端样本）。900秒完整被动观察未见新watchdog超时或复位，链路和IPv4保持在线；有限观察不能证明旧超时根因已消除。本次启动限定日志审计覆盖84529条记录：panic/fatal匹配0，未分类panic词条1，驱动错误词条0，固件断言/复位0；原始消息未保存。这是限定规则扫描，不代表日志完全无错。",
      "RF前后en1绑定的1MB HTTPS请求均3/3成功；平均速率5.75/5.12Mbps（公网端到端样本）。",
      "900秒完整被动观察未见新watchdog超时或复位，链路和IPv4保持在线；有限观察不能证明旧超时根因已消除。",
      "mDNS实际分类（尝试/成功）：Legacy 0/0、Qu 0/0、Qm 2/2、Other 0/0、Unknown 0/0。",
      "有成功QM发送样本，可评估该类别回包。",
      "RX尚未完整进入原生输入；按实测阶段定位，不推断对端行为。",
      "本机固件完成不等于对端收件；未获得文件传输成功记录。"
    ],
    "blockers": [
      "有限观察不能证明发送超时根因已经消除。",
      "对端收包、服务响应和双向AirDrop仍未通过。"
    ],
    "next": [
      "本启动唯一RF诊断已结束，不再重复。",
      "依据本轮真实RX分段和mDNS类别确定下一步开发。"
    ]
  },
  {
    "id": "record-test061",
    "version": "25G332-Test061",
    "label": "当前运行候选",
    "state": "队列安装被安全拒绝；内核TX已入队后过期",
    "tone": "warning",
    "date": "2026-10-28",
    "summary": "Test061实机：Wi-Fi稳定与64KiB联网请求通过，私有地址预检未隔离；P2P上下文和广播站点创建成功。qid3发送队列被安全拒绝，awdl0内核TX已入驱动队列但随后过期，未到固件或空口。AirDrop双向可见但发送失败；即时热点已连接。",
    "evidence": [
      "Test061加载身份匹配；私有地址预检Stage5/Result0、未隔离。en1可用，awdl0常驻phase13并配置自动IPv6。",
      "Wi-Fi被动观察900.113秒、809个采样稳定，网关检查2/2。DHCP后完成DNS解析，再绑定en1发送64KiB HTTP请求，返回HTTP 200，耗时0.903384秒。较早HTTP超时发生在DNS隔离阶段，保留原始阶段边界，不合并为连接失败。",
      "本启动唯一一次900ms诊断中，P2P MAC上下文添加/移除结果均为0。广播站点AddStaAttempted=1、SendResult=0、StatusValid=1、FirmwareStatus=1；源码将状态1定义为IWX_ADD_STA_SUCCESS。随后发送队列安装已实际尝试，固件有效回复qid3，但主机槽位拒绝掩码0x700、SetupStep6返回EBUSY(16)，队列没有安装。旧快照仅有聚合DMA存在位，无逐字段状态；ring_count=0、desc/cmd为空、map/owner为0不能单独证明活动DMA，也不授权强制释放。",
      "没有进入ROC（无START/END），无PSF/MIF提交、固件数据发送、无线RX或原生ifnet输入。NativeAwdlDataTxAccepted由76增至78，结束计数为87；Expired亦为87，Encoded和Submitted为0，表示内核包入队后过期，不代表空口发送。NativeAddressFailure=9表示AwaitingP2PAddress，地址验证尚未进行，不是地址不匹配。诊断后P2P资源归零。",
      "用户报告AirDrop双方设备可见但文件发送失败；即时热点已连接。可见性和热点结果不等于文件收件。",
      "Test061开发时已有离线候选检查记录：地址一致性与可选广告方案通过编码器/ASan/UBSan/桥接TSan及完整构建检查；这些只描述候选离线状态，不替代本次无线实测。",
      "Test061离线候选：默认PSF/MIF形态不变；只有地址见证成功的原生手动模式携带flags4和当前源地址，PSF/MIF最大237/307字节。",
      "真实PSF/MIF编码器输出直接进入生产地址校验，覆盖非零时间戳、地址不一致、截断、填充和HT Control；关闭与最终提交两个顺序均测试。",
      "已修正TLV校验起点和旧诊断覆盖问题；门铃前隔离不再误计为已提交，候选与当前身份结果分别记录。",
      "Test061离线ASan/UBSan、桥接TSan、独立源码审查、完整Debug构建与严格签名检查通过。",
      "Test061开发期间运行的仍是Test060；该段900秒观察和前后6次联网成功只证明Test060窗口连通。"
    ],
    "blockers": [
      "旧Test061运行快照缺少逐字段DMA位图；不能把0x700直接解释成正在使用的DMA，也不能在无硬停/所有权证据时强制回收。",
      "本轮没有无线控制帧或数据帧空口收发、原生输入及AirDrop文件落盘证据；内核队列接纳不等于无线发送。",
      "私有地址切换/轮换、Wi-Fi开关回连和睡眠恢复未覆盖；本轮只确认当前私有地址预检通过。",
      "外部手动修改ifnet地址的全局串行不在本轮证明范围；候选读取地址发现不一致时会拒绝，但本轮没有触发该路径。"
    ],
    "next": [
      "Test062已成功部署到EFI：完整备份已验证，332个文件写入并完成卸载重挂hash复核，严格签名与ocvalidate均通过，config和其他bundle未变；自动P2P探测保持关闭。",
      "Test062尚未启动或实机验证。重启后先核对加载身份、Wi-Fi稳定和awdl0状态，再读取DMA字段位图；仅在队列与资源状态安全时做一次有界诊断。"
    ]
  },
  {
    "id": "record-test062",
    "version": "25G332-Test062",
    "label": "当前运行候选",
    "state": "实测已记录；共享时隙与对端回包待突破",
    "tone": "working",
    "date": "2026-10-28",
    "summary": "Test062 已加载并完成单次诊断。Wi-Fi专属900.058秒观察稳定，en1前后联网HTTP 200；awdl0常驻和IPv6正常。本机PSF/MIF控制帧完成，收到4个PSF、0个MIF；DataGate无有效对端而阻断，数据固件TX/RX、ifnet输入和AirDrop收件仍未证明。",
    "evidence": [
      "Test062实际加载身份与候选匹配；en1就绪，私有地址Stage5/Result0且未隔离。",
      "观察前后各一次绑定en1的64KiB HTTPS均HTTP 200，分别耗时0.946908秒和1.127293秒；不是吞吐测试。",
      "Wi-Fi专属观察900.058秒、840样本：Ready/en1 UP/RUNNING/link/IPv4持续正常；reset 5→5、trace sequence 5→5、generation 4、schema2记录完整；watchdog及legacy/MSIX固件软件/硬件错误增量0。watcher总passed=false仅因phase marker和P2P_attempted变化，Wi-Fi专项criteria通过。",
      "awdl0保持phase13、flags 0x4003ff、start witness 0x3ff并配置IPv6；本机地址见证通过，PSF与MIF本机广告和固件完成成功。",
      "qid4空软件槽SetupStep6/result0，三类字段位图及host reject mask均0；这不证明Test061的qid3残留paddr/size修复已经实机覆盖。",
      "900ms频道6 ROC START/END成功；本机PSF 1/1/1、MIF 2/2/2完成/成功。第三条MIF因lease余量不足（pacing reason18）停止，不以跨候选last值提前发送。",
      "接收4个PSF、0个MIF；PSF解析无拒绝，valid/admitted peer=0。DataGate 73次检查、0次放行，mask 0xA00表示无已验证peer及可用peer频道，不证明手机错频道。",
      "kernelTxAccepted增加2且pending增加2；数据TX encoded/submitted/completed、radio RX capture/decode/deliver、native ifnet input均为0。无对端ACK、文件收件或AirDrop成功证据。"
    ],
    "blockers": [
      "qid4空槽成功没有复现qid3冲突；不得据此宣称残留DMA清理修复通过，unknown/live-DMA保护保持。",
      "对端仅发来PSF，没有MIF进入观察器；DataGate在dequeue前阻断。0xA00中的频道位来自没有admitted peer，不证明对端频道错误。",
      "没有真实AWDL数据无线RX、固件数据TX完成、ifnet输入、peer ACK或文件落盘；AirDrop未通过验收。",
      "Wi-Fi900秒观察稳定，但私有地址轮换、开关回连、即时热点保持和睡眠恢复仍未覆盖。"
    ],
    "next": [
      "本轮单次无线诊断已结束；不重复RF，不据此请求重启。",
      "继续解决同一会话中的共享时隙与对端MIF/回包；只有取得真实对端证据后再推进数据TX/RX与双向文件收件。"
    ]
  },
  {
    "id": "record-test063",
    "version": "25G332-Test063",
    "label": "本轮实测",
    "state": "数据发送通过，回包未通",
    "tone": "working",
    "date": "2026-10-28",
    "summary": "Test063已正确加载。单次900ms诊断收到6个PSF和1个MIF，准入1个对端；原生awdl0两条QM mDNS查询获得固件成功，数据回包与AirDrop仍未打通。",
    "evidence": [
      "加载身份与归档相符，私有地址、awdl0常驻及自动IPv6预检通过；普通Wi-Fi诊断前后64KiB HTTPS均200。",
      "本次7个AWDL管理帧均被处理，1个对端进入准入；本机PSF1、MIF1及真实QM数据2分别获得固件成功。",
      "8次完整快照版本26、诊断代次6一致，两个控制票据无丢失、失效或顺序异常；端点GP2间隔935807微秒，落在主机区间内。",
      "恢复后连续900.109秒、822个采样，Wi-Fi与awdl0持续可用，reset 10→10，watchdog及固件软硬件错误增量均0；诊断前后联网HTTP 200。启动早期累计1次固件软件错误，即时热点本轮加入失败仍待定位。"
    ],
    "blockers": [
      "数据RX候选、解码及原生ifnet交付均0；短窗口不足以判定手机未发送或固件过滤，不能证明AirDrop可用。",
      "当前票据未绑定对端时隙；GP2映射及漂移界仍未验证，固件成功不是精确空口时间或手机收包证明。",
      "DNS-SD辅助进程强制结束，回调统计未知；即时热点错误根因尚未定位。"
    ],
    "next": [
      "本启动唯一诊断已使用，不重复触发；继续Wi-Fi被动观察并复核共享窗口与最早RX路径。",
      "没有新驱动部署，不需要为本轮记录再次重启；备份回滚保留。"
    ]
  },
  {
    "id": "record-test064",
    "version": "25G332-Test064",
    "date": "2026-10-28",
    "label": "Test064本轮实测已记录",
    "state": "Wi-Fi稳定 · 单条QM本地发送成功 · 等待对端回包",
    "tone": "working",
    "summary": "Wi-Fi与awdl0连续15分钟稳定，诊断前后HTTPS正常。单条原生QM查询在估算提交区间内进入固件并报告成功；收到5个PSF、0个MIF，没有数据RX或Bonjour回应。Finder本轮可见手机，但未测试双向文件收件；手机端是否能看到Mac未知。历史24/40保持。本轮没有改EFI或要求重启。",
    "evidence": [
      "加载Test064身份正确；私有地址与awdl0 IPv6预检通过。Wi-Fi连续900.094秒、826次采样无变化，reset 10→10、观察期错误增量0；64KiB HTTPS前后HTTP 200。",
      "900ms诊断中的本机PSF和2次MIF burst共3项均获本地固件成功，随后资源清理完成；收到5个PSF、0个MIF、无对端准入。",
      "完整Discovery快照稳定且代次一致；同一队首token被锁定并消费，只有1条QM进入编码、提交并完成。软件入队2次不等于发包2次；末次诊断快照另有1包尚未发送，之后可能过期，不能据此说当前仍排队。",
      "QM调用位于估算提交范围，原始GP2端点区间相容；时钟映射和空口覆盖均未证明。没有AWDL数据RX候选、捕获、解码及ifnet交付。",
      "DNS-SD awdl0 browse请求ready，但helper强制退出，callback数量未知。没有对端服务回应或AirDrop实际文件收件。",
      "独立复核修正采集器将软件队列入队数误作单包无线发送数的问题；原始报告保持不变，18项纯主机保护测试通过。",
      "本轮原生Finder隔空投送界面可见手机；没有实际文件收件测试，也未确认iPhone端能否看到Mac。"
    ],
    "blockers": [
      "本轮收到PSF但没有MIF准入；数据包没有到达最早的主机接收观测点，无法区分对端没有发包和更早阶段过滤。",
      "提交范围基于估算，不能证明时钟映射、真实空口时刻、对端收包或mDNS回应。",
      "Finder本轮可见手机；双向实际文件收件未测试，手机端能否看到Mac未知。即时热点本启动未触发。"
    ],
    "next": [
      "补齐CRC/长度检查之前的有界接收观测，找出数据帧最早的可观测入口。",
      "复核TX使用的station/TID与P2P管理队列、组播数据发送的角色契约。",
      "下一候选尚未构建或部署；继续保持Wi-Fi稳定并验证真实对端回包。"
    ]
  },
  {
    "id": "record-test065",
    "version": "25G332-Test065",
    "date": "2026-10-28",
    "label": "Test065已部署候选",
    "state": "已部署，待重启运行验收",
    "tone": "pending",
    "summary": "Test065已部署并保留完整EFI备份，当前仍运行Test064，等待用户重启后验收。新版本只增加活动manual ROC期间的有界RX入口计数，并在闭窗后发布；不会放宽原有过滤。",
    "evidence": [
      "新增有界RX入口计数：CRC前过滤、RX overrun、实际通知长度和DMA容量分开记录。",
      "最多2个数值descriptor见证，不记录地址；只在活动manual ROC采集，闭窗后完整发布快照。",
      "保留单QM实验与原有peer/包类/地址过滤；记录真实station/TID证据，不凭假设更改P2P管理队列与STA数据角色。",
      "闭窗后校验快照代次和版本；unknown DNS callback不当作零回调，软件队列accepted不当作无线发送。",
      "完整EFI备份、目标kext替换、config与其它bundle保留、卸载重挂核对和部署脚本报告均以Test065部署元数据为准。",
      "Test064本轮已证明的Wi-Fi稳定性和本地单QM发送仍作为历史本轮记录；不推断Test065实机行为。"
    ],
    "blockers": [
      "新增RX计数尚未实机运行；预期DMA通知长度和缓冲区容量仍需现场数据确认。",
      "管理帧P2P_DEVICE与共享STA组播DATA角色契约仍待完整行为验证；目前没有可据以更改队列角色的硬错误证据。",
      "GP/TID 15不自动判非法，也不猜mcastport 1；时钟映射、对端回包、Bonjour应答及AirDrop仍待各自实测。",
      "Test065尚未启动；Wi-Fi稳定性、RX计数、对端回包与AirDrop都没有Test065实机结果。"
    ],
    "next": [
      "重启后先核对Test065加载身份、Wi-Fi、私有地址和awdl0基线。",
      "观察15分钟Wi-Fi，再执行本启动唯一有界诊断；检查RX快照闭窗发布。",
      "按RX入口计数定位首个缺口后，再分步验证Bonjour回应与双向实际文件收件。"
    ]
  }
];
