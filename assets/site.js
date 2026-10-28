(() => {
  "use strict";

  const data = window.PROGRESS_DATA;
  const sourceRecords = window.TEST_RECORDS || [];
  const $ = (selector, root = document) => root.querySelector(selector);
  let activeFilter = "all";

  function node(tag, className, value) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (value !== undefined && value !== null) element.textContent = String(value);
    return element;
  }

  function statusTone(label) {
    const value = String(label || "");
    if (/(未通过|未完成|待修|拒绝|尚未|未打通|失败|回归|超时)/.test(value)) return "warning";
    if (/开发中/.test(value)) return "working";
    if (/(已验证|通过)/.test(value) && !/(待|未|失败|拒绝|待修)/.test(value)) return "success";
    return "pending";
  }

  function hasRuntimeEvidence(milestone) {
    return milestone.has_runtime_evidence === true;
  }

  function chip(label, tone = "pending") {
    return node("span", `status-chip tone-${tone}`, label || "待更新");
  }

  function nextCandidatePresentation() {
    switch (data?.deploymentState) {
      case "test064_offline_verified_not_deployed":
        return { badge: "Test064 离线候选已完成", subtitle: "单次原生QM发现实验、固定候选窗口、队首所有权和最终提交复核已合并，完整构建与宿主检查通过。当前运行Test063；Test064尚未部署或实机验证。", recordLabel: "离线验证候选", recordState: "尚未部署", tone: "working", versionFallback: "25G332-Test064" };
      case "test064_deployed_waiting_reboot":
        return { badge: "Test064已部署 · 待重启验收", subtitle: "已备份整份EFI，仅替换Intel无线kext；当前仍运行Test063。下一启动先验Wi-Fi与awdl0，再尝试一条受限原生QM查询并观察回包。相位仍为估计，Test064尚无实机通过结论，不会自动重启。", recordLabel: "已部署候选", recordState: "待重启运行验收", tone: "pending", versionFallback: "25G332-Test064" };
      case "test064_booted_analysis_pending":
        return { badge: "Test064已启动 · 单次诊断完成", subtitle: "已核对加载身份并完成本启动唯一一次900ms诊断；Wi-Fi与awdl0基线正常，15分钟被动观察仍在进行。当前页面各阶段细项保留上一轮Test063已确认结果；Test064的冻结数据正在复核，随后补齐本轮结论。历史24/40保持。", recordLabel: "本轮运行记录", recordState: "Wi-Fi观察与日志复核中", tone: "working", versionFallback: "25G332-Test064" };
      case "test065_offline_verified_not_deployed":
        return { badge: "Test065离线验证通过 · 尚未部署", subtitle: "全量构建与签名已由候选元数据确认；新增活动manual ROC期间的有界RX入口计数、两个数值descriptor见证和闭窗完整快照发布。当前仍运行Test064，历史24/40保持；Test065无实机结果。", recordLabel: "离线验证候选", recordState: "尚未部署", tone: "working", versionFallback: "25G332-Test065" };
      case "test066_panic_quarantined":
        return { badge: "Test066 诊断崩溃，已停测", subtitle: "已确认MIF嵌套发布耗尽内核栈，正在验证Test067修复；当前不再触发诊断。", recordLabel: "Test067候选", recordState: "离线修复中", tone: "working", versionFallback: "25G332-Test067" };
      case "test067_runtime_no_peer_mif":
        return { badge: "Test067 本轮实测已记录", subtitle: "本轮Wi-Fi三个分开观察窗口稳定；本机PSF/MIF仅有固件完成状态，外部抓包未能归因本机发送或peer收件。收到7个PSF、0个MIF，DataGate未放行，QM未编码/提交，数据RX为0。没有新候选部署，无需重启。", recordLabel: "本轮运行记录", recordState: "等待对端MIF与数据回包", tone: "working", versionFallback: "继续推进MIF接收、QM门槛与数据RX" };
      case "test067_deployed_waiting_reboot":
        return { badge: "Test067 已部署，等待重启", subtitle: "已合并栈占用修复并保留备份；当前仍运行Test066。实机稳定、数据回包和AirDrop等待验证。", recordLabel: "Test067候选", recordState: "等待重启", tone: "working", versionFallback: "25G332-Test067" };
      case "test066_deployed_waiting_reboot":
        return { badge: "Test066 已部署，等待重启", subtitle: "已合并对端绑定、当前MIF时隙与pacing修复。当前仍运行Test065；下一启动再验证QM发送和原生RX，AirDrop尚未完成。", recordLabel: "已部署候选", recordState: "等待重启", tone: "working", versionFallback: "25G332-Test066" };
      case "test065_deployed_waiting_reboot":
        return { badge: "Test065已部署 · 待重启验收", subtitle: "整份EFI备份及卸载重挂核对已由Test065部署报告确认；只更新AirportItlwm.kext，config和其它bundle保持。当前仍运行Test064。重启后先验Wi-Fi和awdl0，再检查manual ROC内RX入口计数及闭窗快照；Test065尚无实机结果。", recordLabel: "已部署候选", recordState: "待重启运行验收", tone: "pending", versionFallback: "25G332-Test065" };
      case "test065_booted_preflight_running":
        return { badge: "Test065已启动 · 基线与RX诊断预检中", subtitle: "本次启动已确认Test065加载且UUID匹配；Wi-Fi基线观察和本启动唯一RX诊断预检正在进行，尚未开展无线空口测试。启动累计reset 15、watchdog 2、FW error 0，目前状态已恢复；监测仍在运行，不能据此判定稳定通过。阶段证据和40项当前结果仍引用Test064上一轮，等待本轮最终汇总；历史24/40保持。", recordLabel: "本轮运行验证", recordState: "基线观察与诊断预检中", tone: "working", versionFallback: "25G332-Test065" };
      case "test065_boot1793181722_runtime_diagnostic_complete":
        return { badge: "Test065本次启动实测已记录", subtitle: "Wi-Fi前后两段观察稳定，中间间隔包含一次RF诊断。控制帧和peer准入通过；QM在取包前被gate关闭，AirDrop未完成。Test066仍是私有提案，未构建或部署，不需要重启。", recordLabel: "本轮运行记录", recordState: "Wi-Fi稳定 · QM发送未触发", tone: "working", versionFallback: "25G332-Test066" };
      case "test065_runtime_diagnostic_complete":
        return { badge: "Test065实测已记录 · 路由器接收预检完成", subtitle: "AX3000T在频道6/2437MHz捕获379条记录：368个管理帧、9个带payload的数据/QoS帧和2个Null帧；11个数据类记录均为foreign BSS。379条均有TSFT但没有FCS。预检未再次arm本机QM，未见own QM不能说明未发射。临时monitor已清理，AP/UCI保持。当前启动的唯一900ms诊断已经用完，不能在本启动重复；同步采集工具已合并并独立复核；当前启动的唯一诊断已用完，下一步需重启沿用Test065，在新启动仅执行一次900ms同步诊断。本次重启只为取得未使用窗口，不代表部署新驱动，EFI不变。", recordLabel: "本轮运行记录", recordState: "工具已复核 · 需新启动", tone: "working", versionFallback: "新启动同步捕获：own QM、peer回包、Mac RX" };
      case "test064_runtime_diagnostic_complete":
        return { badge: "Test064 本轮实测已记录", subtitle: "Wi-Fi与awdl0连续15分钟稳定，诊断前后HTTPS正常。单条原生QM查询到达固件并报告成功，但收到5个PSF、没有MIF准入或数据回包；AirDrop仍未通。估算时钟与空口覆盖未获证明。以上为Test064实测；Test065已部署，待重启验收。", recordLabel: "本轮运行记录", recordState: "对端回包待定位", tone: "working", versionFallback: "原生数据回包入口与队列角色复核" };
      case "test063_runtime_diagnostic_complete":
        return { badge: "Test063 本轮实测已记录", subtitle: "已收到并接纳MIF，原生awdl0两条QM查询完成固件发送；数据回包与AirDrop尚未通过。Wi-Fi恢复后15分钟观察稳定，诊断前后联网正常；启动早期固件错误和即时热点失败仍待定位。本启动唯一诊断已使用，没有新部署。", recordLabel: "本轮运行记录", recordState: "回包与即时热点待突破", tone: "working", versionFallback: "后续开发：数据回包与即时热点" };
      case "test063_deployed_waiting_reboot":
        return { badge: "Test063已部署 · 待重启验收", subtitle: "Test063已写入内置EFI，仅替换Intel无线驱动；config保持原样，整份EFI外部备份和卸载重挂核验已完成。当前启动仍是Test062。重启后先核对加载身份、Wi-Fi基线和awdl0，再检查同次启动的票据时间、GP2区间与快照一致性。Test063尚无实机结果，不会自动重启。", recordLabel: "已部署候选", recordState: "待重启运行验收", tone: "pending", versionFallback: "25G332-Test063" };
      case "test063_offline_verified_not_deployed":
        return { badge: "Test063离线验证通过 · 尚未部署", subtitle: "四槽本地PSF/MIF因果记录、同启动GP2原始采样、完整快照读取和回调归属回归已验证；全量构建、签名及独立复核通过。当前运行仍是Test062，Test063未部署，本轮无需重启。下一步只补同启动本地时间与GP2区间证据；缺少时钟映射、MIF或一致快照时结果保持未知。", recordLabel: "离线验证候选", recordState: "尚未部署", tone: "working", versionFallback: "25G332-Test063" };
      case "test062_runtime_diagnostic_complete":
        return { badge: "Test062 本轮实测已记录", subtitle: "Wi-Fi 专属 900.058 秒观察稳定，en1 诊断前后联网 HTTP 200；awdl0 常驻与 IPv6 正常。本机 PSF/MIF 控制帧完成，但只收到 4 个 PSF、没有 MIF，DataGate 未放行真实数据。qid4 空槽通过不证明 qid3 残留回收已实机通过；下一步聚焦共享时隙和对端回包。当前候选没有新部署，本轮无需重启。", recordLabel: "本轮运行记录", recordState: "共享时隙/对端回包待突破", tone: "working", versionFallback: "后续开发：共享时隙与对端回包" };
      case "test062_booted_preflight_checked":
        return { badge: "Test062已启动 · 单次诊断准备中", subtitle: "加载身份、Wi-Fi、私有地址和awdl0常驻/IPv6预检正常。先观察Wi-Fi基线，再执行本启动唯一900ms诊断；历史记录与本轮证据分开，队列回复和内核入队均不等于对端收件。", recordLabel: "本轮验证", recordState: "等待单次诊断", tone: "working", versionFallback: "原生awdl0数据通路" };
      case "test062_offline_validated_not_deployed":
        return { badge: "Test062离线验证通过 · 尚未部署", subtitle: "全量编译、签名与源冻结完成；完整释放后清理DMA地址/长度元数据，未知状态仍严格拒绝，并增加逐字段位图。共享生产free helper与P2P HAL安全回归通过。当前运行仍是Test061；Test062尚未部署，也没有实机验证。", recordLabel: "离线验证候选", recordState: "尚未部署", tone: "working", versionFallback: "25G332-Test062" };
      case "test062_deployed_waiting_reboot":
        return { badge: "Test062已部署 · 等待重启验收", subtitle: "全量编译、签名与源冻结通过；完整释放后清理DMA地址/长度元数据，未知状态仍严格拒绝，并新增逐字段位图。Test062已写入EFI，332个文件完成卸载重挂hash复核，ocvalidate通过，完整备份已保留。当前启动仍为Test061；重启后先核对加载身份、Wi-Fi与awdl0，再按DMA位图决定是否进行一次有界诊断。无线回包和AirDrop仍待实机验证。", recordLabel: "已部署候选", recordState: "待重启运行验收", tone: "pending", versionFallback: "25G332-Test062" };
      case "test061_booted_preflight_checked":
        return { badge: "Test061已启动 · 单次数据诊断准备中", subtitle: "实际加载身份、Wi-Fi与awdl0常驻/IPv6预检通过。手机已准备，先完成Wi-Fi被动基线，再执行本启动唯一900ms诊断；设备可见不等于文件收件。即时热点现已由用户确认可连接。", recordLabel: "本轮运行验收", recordState: "等待单次诊断", tone: "working", versionFallback: "原生awdl0数据通路" };
      case "intel_test061_deployed_waiting_reboot":
        return { badge: "Test061已部署 · 可以重启验证", subtitle: "博通双向成功窗口与即时热点历史日志已收齐。Test061已完成Wi-Fi回切部署，整份EFI备份、签名/配置检查和卸载重挂核对通过；18份旧启动测试日志已归档。蓝牙和USB保持当前配置。重启后验证Intel Wi-Fi、地址一致性与原生awdl0回包，当前尚无Test061运行通过结论。", recordLabel: "已部署候选", recordState: "待重启运行验收", tone: "pending" };
      case "intel_test061_preparing_return":
        return { badge: "双向对照日志已收齐 · 准备Test061回切", subtitle: "博通两个方向的实际收件及分窗日志已验收，EFI与无线诊断权已交回。本轮只切Intel Wi-Fi，保留当前蓝牙和USB隔离变量；Test061尚未部署。接下来核对新鲜EFI备份、合并配置并部署后通知重启，不等待WPA3完整适配。", recordLabel: "已构建候选", recordState: "正在准备Wi-Fi回切", tone: "working" };
      case "broadcom_control_window_booted_capture_pending":
        return { badge: "博通诊断版已启动 · 待双向分窗采集", subtitle: "已核对Test023r2本次加载身份，分窗已配置，初始窗口尚未开启。先分别抓取两个方向AirDrop实际收件及对应控制帧与awdl0数据，不等待WPA3完整适配。合格日志交接后继续Test061；当前Intel候选尚未部署。", recordLabel: "已构建候选", recordState: "等待博通实传窗口交接", tone: "working" };
      case "broadcom_control_window_deployed_waiting_reboot":
        return { badge: "博通分窗诊断已部署 · 待重启采集", subtitle: "Test023r2已部署并保留完整备份。下一次重启先分别采集双向AirDrop实际收件窗口，对照控制帧与原生awdl0数据；不等待WPA3完整适配。Test061已构建并准备Wi-Fi回切方案，尚未部署，待日志交接后继续。", recordLabel: "已构建候选", recordState: "等待博通新窗口交接", tone: "working" };
      case "collecting_broadcom_airdrop_baseline":
        return { badge: "优先采集双向AirDrop成功窗口", subtitle: "先补齐Mac到iPhone、iPhone到Mac成功传输期间的原生awdl0与控制帧对照，核对窗口质量和收件结果，再回到Test061。WPA3适配不阻塞采集。Test061已构建，尚未部署；当前成功配置与回滚保持。", recordLabel: "已构建候选", recordState: "等待双向成功窗口交接", tone: "working" };
      case "broadcom_test021r2_hotspot_online_sae_pending":
        return { badge: "博通热点联网已实测 · WPA3分支待适配", subtitle: "Test021r2已通过手机热点连接及小流量上下行验证；捕获到一次WPA3认证被转换器拒绝，后续系统选择WPA2路径连接成功。正在只读核对旧驱动的WPA3语义与载体，尚未放宽准入；新AirDrop对照采集与Intel Test061启动仍待完成。", recordLabel: "已构建候选", recordState: "等待博通认证审查与对照", tone: "working" };
      case "broadcom_test021r2_booted_hotspot_pending":
        return { badge: "博通Test021r2已启动 · 热点仍待修复", subtitle: "已核对Test021r2实际加载身份，SET86请求通过兼容转换并被原处理器接受。热点仍无法加入，博通会话正查后续发现、关联和认证。原Wi-Fi/AirDrop回归与新对照采集尚未完成；Intel Test061仍未部署。", recordLabel: "已构建候选", recordState: "等待博通热点定位与回归", tone: "working" };
      case "broadcom_test021r2_deployed_waiting_boot":
        return { badge: "博通Test021r2已部署 · 待启动验证", subtitle: "Test021r2已写入EFI，完整备份及卸载重挂复验完成。博通会话按授权安排正常重启，不清NVRAM，随后验证加载身份、热点、Wi-Fi和双向AirDrop；新运行证据尚未取得，Intel Test061仍未部署。", recordLabel: "已构建候选", recordState: "等待博通启动与回归", tone: "working" };
      case "broadcom_test021r2_deploying":
        return { badge: "博通Test021r2部署校验中", subtitle: "Test021r2已完成离线构建、独立复核及候选与回滚目录准备。博通会话正备份当前EFI并部署，随后负责重启及热点、Wi-Fi和双向AirDrop回归。新的对照日志尚未采集；Intel Test061仍未部署。", recordLabel: "已构建候选", recordState: "等待博通部署与回归", tone: "working" };
      case "broadcom_booted_airdrop_passed_hotspot_scan_blocked":
        return { badge: "博通双向AirDrop已实测 · 热点扫描待兼容", subtitle: "博通基线已恢复Wi-Fi和双向AirDrop；即时热点已完成蓝牙激活，随后专用扫描请求被拒绝，正在核对扫描结构兼容。Test061已构建但未部署；Intel蓝牙仍需独立对照，当前无需为Intel重启。", recordLabel: "已构建候选", recordState: "等待博通扫描兼容与交接", tone: "working" };
      case "broadcom_lilu_debug_deployed_waiting_reboot":
        return { badge: "DEBUG日志诊断已部署 · 待普通重启", subtitle: "下一次普通重启，无需清NVRAM。只切换同版本DEBUG Lilu并开启早期日志，Baseline019 Wi-Fi、HS11/HS14和蓝牙项保持不变。重启后由博通会话核对加载身份与日志；Test061未部署，正式Release暂停。", recordLabel: "已构建候选", recordState: "等待博通日志诊断", tone: "working" };
      case "broadcom_booted_init_missing":
        return { badge: "博通蓝牙已识别 · Wi-Fi初始化待修复", subtitle: "重启后已确认博通蓝牙；当前启动缺少Wi-Fi兼容通道初始化，正在核对Lilu驱动加载与补扫路径。AirDrop可见性变化尚不能算实传通过。Test061未部署，双版本兼容未验收，正式Release暂停。", recordLabel: "已构建候选", recordState: "等待博通初始化修复", tone: "working" };
      case "broadcom_usb_deployed_waiting_reboot":
        return { badge: "蓝牙USB已部署 · 待重启验证", subtitle: "HS11已恢复、HS14已屏蔽，Intel蓝牙项已关闭，Baseline019 Wi-Fi二进制保持不变。下一次重启先核对实际蓝牙控制器并复测双向AirDrop。Test061未部署，双版本兼容未验收，正式Release暂停；由博通会话继续测试。", recordLabel: "已构建候选", recordState: "等待蓝牙对照重启", tone: "working" };
      case "broadcom_booted_airdrop_failed":
        return { badge: "博通Wi-Fi联网通过 · 蓝牙USB待切换", subtitle: "博通Baseline019已完成Wi-Fi双向联网请求，AirDrop仍待修复。下一步由博通会话恢复HS11、屏蔽HS14，保持Wi-Fi二进制不变后重启验证。26.7.1与26.7.2双版本兼容未验收；Test061仍未部署，正式Release暂停。", recordLabel: "已构建候选", recordState: "等待博通蓝牙对照", tone: "working" };
      case "broadcom_deployed_waiting_reboot":
        return { badge: "博通已部署 · 待重启验证", subtitle: "Test061已构建，尚未写入EFI。下一次启动先验证博通Baseline019；Wi-Fi与双向AirDrop通过并完成基线采集后，再协调切回Intel。重启和实机测试由「【稳定期】博通」会话负责。", recordLabel: "已构建候选", recordState: "等待博通实测", tone: "working" };
      case "built_waiting_broadcom_baseline":
        return { badge: "Test061已构建 · 先测博通", subtitle: "按本轮安排，先由「【稳定期】博通」会话部署和验证博通基线，再切回这个Intel候选。Test061尚未写入EFI；重启通知以博通会话为准。", recordLabel: "已构建候选", recordState: "等待博通基线", tone: "working" };
      case "booted_runtime_checked":
        return { badge: "本轮测试已记录", subtitle: "本轮运行结果已归档，下一版尚未部署；当前无需重启。", recordLabel: "开发中的候选", recordState: "尚未部署", tone: "working", versionFallback: "下一版开发中" };
      case "booted_native_lifecycle_checked":
        return { badge: "原生接口启停已实测", subtitle: "Test050 已完成临时 awdl0 的原生注册、启动和停止。下一步接入持续运行与数据通路；当前无需重启。", recordLabel: "开发中的候选", recordState: "尚未部署", tone: "working", versionFallback: "下一版开发中" };
      case "awaiting_admin_authorization":
        return { badge: "已构建 · 等待系统验证", subtitle: "测试包已完成，EFI 写入正在等待管理员验证", recordLabel: "待部署候选", recordState: "等待系统验证后部署", tone: "pending" };
      case "deployed_not_booted":
        return { badge: "已部署 · 待重启", subtitle: "下一候选已部署，等待重启后完成运行验收", recordLabel: "已部署候选", recordState: "待重启运行验收", tone: "pending" };
      case "next_candidate_in_development":
        return { badge: "开发中 · 待部署", subtitle: "下一候选开发中，运行证据待补充", recordLabel: "开发中的候选", recordState: "待部署与运行验收", tone: "working" };
      case "booted_pending_runtime":
        return { badge: "已启动 · 待验收", subtitle: "下一候选已启动，运行结果待核验", recordLabel: "已启动候选", recordState: "运行验收中", tone: "pending" };
      default:
        return { badge: "候选状态待更新", subtitle: "下一候选版本的部署与运行状态待补充", recordLabel: "下一候选", recordState: "状态待更新", tone: "pending" };
    }
  }

  function renderHeader() {
    const updated = $("#updated-at");
    const deployment = $("#deployment-label");
    if (data?.updatedAt) {
      const date = new Date(data.updatedAt);
      updated.dateTime = data.updatedAt;
      updated.textContent = Number.isNaN(date.getTime())
        ? "时间待补充"
        : new Intl.DateTimeFormat("zh-CN", {
            year: "numeric", month: "2-digit", day: "2-digit",
            hour: "2-digit", minute: "2-digit", hourCycle: "h23"
          }).format(date);
    } else {
      updated.textContent = "时间待补充";
    }

    const presentation = nextCandidatePresentation();
    deployment.textContent = presentation.badge;
    const cards = $("#version-cards");
    const currentRecord = sourceRecords.find(record => record.version === data?.runningCandidate);
    const current = node("article", "version-card current");
    const currentTop = node("div", "version-card-top");
    currentTop.append(node("span", "", data?.comparisonBaseline ? "Intel当前运行候选" : "当前运行候选"), node("span", `version-chip status-chip tone-${statusTone(currentRecord?.state)}`, currentRecord?.state || "待核验运行状态"));
    current.append(currentTop);
    current.append(node("h2", "version-id", data?.runningCandidate || "版本待补充"));
    current.append(node("p", "version-subtitle", currentRecord?.summary || "运行状态、实测证据与待验收问题见版本记录。"));

    const next = node("article", "version-card next");
    const nextTop = node("div", "version-card-top");
    nextTop.append(node("span", "", ["test062_runtime_diagnostic_complete", "test063_runtime_diagnostic_complete", "test064_runtime_diagnostic_complete", "test065_runtime_diagnostic_complete", "test065_boot1793181722_runtime_diagnostic_complete", "test067_runtime_no_peer_mif"].includes(data?.deploymentState) ? "下一开发重点" : (["test062_deployed_waiting_reboot", "test063_deployed_waiting_reboot", "test064_deployed_waiting_reboot", "test065_deployed_waiting_reboot", "test066_deployed_waiting_reboot"].includes(data?.deploymentState)) ? "Intel已部署候选" : ["test062_offline_validated_not_deployed", "test063_offline_verified_not_deployed", "test064_offline_verified_not_deployed", "test065_offline_verified_not_deployed"].includes(data?.deploymentState) ? "Intel离线验证候选" : ["test061_booted_preflight_checked", "test065_booted_preflight_running"].includes(data?.deploymentState) ? "本轮验证" : data?.comparisonBaseline || data?.deploymentState === "built_waiting_broadcom_baseline" ? "Intel待切回候选" : "下一候选版本"), node("span", "version-chip", presentation.recordState));
    next.append(nextTop);
    next.append(node("h2", "version-id", data?.nextCandidate || presentation.versionFallback || "版本待补充"));
    next.append(node("p", "version-subtitle", presentation.subtitle));
    const baseline = data?.comparisonBaseline;
    if (baseline) {
      const card = node("article", "version-card next");
      const top = node("div", "version-card-top");
      top.append(node("span", "", ["test061_booted_preflight_checked", "intel_test061_deployed_waiting_reboot", "test062_offline_validated_not_deployed", "test062_deployed_waiting_reboot", "test062_runtime_diagnostic_complete", "test063_offline_verified_not_deployed", "test063_deployed_waiting_reboot", "test063_runtime_diagnostic_complete", "test064_offline_verified_not_deployed", "test064_deployed_waiting_reboot", "test065_deployed_waiting_reboot", "test065_booted_preflight_running"].includes(data?.deploymentState) ? "历史成功窗口 · 博通参考" : ["intel_test061_preparing_return", "broadcom_control_window_booted_capture_pending", "collecting_broadcom_airdrop_baseline", "broadcom_test021r2_booted_hotspot_pending", "broadcom_test021r2_hotspot_online_sae_pending"].includes(data?.deploymentState) ? "当前启动 · 博通候选" : ["broadcom_test021r2_deploying", "broadcom_test021r2_deployed_waiting_boot"].includes(data?.deploymentState) ? "最近确认运行 · 博通基线" : data?.deploymentState === "broadcom_lilu_debug_deployed_waiting_reboot" ? "下一次启动 · 早期日志诊断" : data?.deploymentState === "broadcom_usb_deployed_waiting_reboot" ? "当前博通 · 待验证USB更新" : ["broadcom_booted_airdrop_failed", "broadcom_booted_init_missing", "broadcom_booted_airdrop_passed_hotspot_scan_blocked"].includes(data?.deploymentState) ? "当前启动 · 博通基线" : "博通成功对照"), node("span", "version-chip", baseline.state));
      card.append(top, node("h2", "version-id", baseline.version), node("p", "version-subtitle", baseline.summary));
      cards.replaceChildren(current, card, next);
    } else {
      cards.replaceChildren(current, next);
    }
  }

  const verdictLabels = {
    passed: "本轮通过", regressed: "本轮回归", partial: "部分通过",
    not_covered: "本轮未覆盖", not_implemented: "尚未完成"
  };
  const verdictTones = {
    passed: "success", regressed: "warning", partial: "working",
    not_covered: "pending", not_implemented: "pending"
  };
  function acceptanceCounts(checks) {
    const total = checks.length;
    const passed = checks.filter(check => check.history_verified === true).length;
    const percent = total ? Math.round(passed / total * 1000) / 10 : 0;
    return { total, passed, percent };
  }
  function acceptanceBar(checks, label) {
    const count = acceptanceCounts(checks);
    const block = node("div", "acceptance-progress");
    const heading = node("div", "progress-heading");
    heading.append(node("span", "progress-caption", label),
      node("strong", "progress-value", `${count.percent}%`));
    const track = node("div", "progress-track");
    track.setAttribute("role", "progressbar");
    track.setAttribute("aria-label", label);
    track.setAttribute("aria-valuemin", "0");
    track.setAttribute("aria-valuemax", "100");
    track.setAttribute("aria-valuenow", String(count.percent));
    track.setAttribute("aria-valuetext", `${count.passed} / ${count.total} 项已验证`);
    const fill = node("span", "progress-fill");
    fill.style.width = `${count.percent}%`;
    track.append(fill);
    block.append(heading, track, node("div", "progress-count", `${count.passed} / ${count.total} 项已验证`));
    return block;
  }
  function renderProgress() {
    const target = $("#progress-overview");
    if (!target) return;
    const checks = (data?.milestones || []).flatMap(m => m.checkpoints || []);
    if (!checks.length) return;
    target.append(node("div", "section-kicker", "ACCEPTANCE PROGRESS"),
      acceptanceBar(checks, "历史累计验收完成度"));
    target.append(node("p", "progress-explanation", "固定 40 项验收清单，按已验证项计数；不是工时或剩余测试轮数。历史通过保留，本轮回归单列。"));
    const current = node("div", "current-result-counts");
    current.append(node("span", "current-result-label", data?.validationLabel || `${data.runningCandidate} 本轮`));
    for (const key of ["passed", "partial", "regressed", "not_covered", "not_implemented"]) {
      const count = checks.filter(c => c.current_result === key).length;
      current.append(chip(`${verdictLabels[key]} ${count} 项`, verdictTones[key]));
    }
    target.append(current);
  }

  function renderMilestones() {
    const list = $("#milestone-list");
    const items = Array.isArray(data?.milestones) ? data.milestones : [];
    if (!items.length) {
      list.append(node("li", "empty-state", "当前没有可显示的里程碑记录。"));
      return;
    }

    for (const milestone of items) {
      const tone = verdictTones[milestone.current_result] || milestone.status_tone || "pending";
      const item = node("li", `milestone-item tone-${tone}`);
      item.id = `stage-${milestone.stage}`;
      item.dataset.verified = String(hasRuntimeEvidence(milestone));
      item.dataset.pending = String(milestone.has_pending_work !== false);
      item.dataset.currentResult = milestone.current_result || "";
      item.append(node("span", "stage-node"));

      const details = node("details", "milestone-card");
      details.open = true;
      const summary = node("summary", "milestone-summary");
      summary.append(node("span", "stage-number", String(milestone.stage).padStart(2, "0")));
      const copy = node("span", "summary-copy");
      copy.append(node("strong", "", milestone.name || "未命名阶段"));
      const summaryBadges = node("span", "stage-statuses");
      const checks = milestone.checkpoints || [];
      if (checks.length) {
        const historical = acceptanceCounts(checks);
        summaryBadges.append(chip(`历史已验证 ${historical.passed}/${historical.total}`, historical.passed ? "success" : "pending"));
        summaryBadges.append(chip(milestone.current_result_label || verdictLabels[milestone.current_result], tone));
      } else summaryBadges.append(chip(milestone.status, tone));
      copy.append(summaryBadges);
      summary.append(copy, node("span", "disclosure-chevron"));
      details.append(summary);
      if (checks.length) {
        const proof = node("div", "stage-proof");
        proof.append(acceptanceBar(checks, "历史累计验收"));
        for (const [label, text, kind] of [
          ["历史已验证", milestone.historical_summary, "history"],
          [data?.validationLabel || `${data.runningCandidate} 本轮`, milestone.current_summary, "current"],
          ["仍未完成", milestone.unfinished_summary, "unfinished"]
        ]) {
          const row = node("div", `proof-row proof-${kind}`);
          row.append(node("strong", "proof-label", label), node("p", "", text));
          proof.append(row);
        }
        const checklist = node("details", "checkpoint-details");
        checklist.append(node("summary", "", "查看固定验收清单 · 5 项"));
        const entries = node("ul", "checkpoint-list");
        for (const check of checks) {
          const entry = node("li", "checkpoint-item");
          const name = node("div", "checkpoint-title");
          name.append(node("span", check.history_verified ? "checkpoint-verified" : "checkpoint-open", check.history_verified ? "✓" : "○"), node("strong", "", check.name));
          const evidence = node("p", "checkpoint-evidence", check.history_verified ? `历史通过：${check.verified_in}` : `历史：${check.verified_in}`);
          const current = node("div", "checkpoint-current");
          current.append(chip(verdictLabels[check.current_result], verdictTones[check.current_result]), node("span", "", check.current_detail));
          entry.append(name, evidence, current); entries.append(entry);
        }
        checklist.append(entries); proof.append(checklist); details.append(proof);
      }

      const body = node("dl", "milestone-details");
      const fields = [
        ["阶段说明", milestone.status || "待补充", "status"],
        ["实测范围说明", milestone.validated_scope, "validated_scope"],
        ["本版待验收", milestone.candidate_check, "candidate_check"],
        ["与前版变化", milestone.change_note, "change_note"],
        ["已完成与证据", milestone.evidence || "暂无记录", "evidence"],
        ["当前阻碍", milestone.pending || "当前没有记录的阻碍", "pending"],
        ["下一步验收", milestone.acceptance || "待补充验收条件", "acceptance"]
      ];
      for (const [label, value, field] of fields) {
        if (!value) continue;
        const row = node("div", "detail-row");
        row.append(node("dt", "", label));
        const description = node("dd", "", value);
        description.dataset.field = field;
        row.append(description);
        body.append(row);
      }
      details.append(body);
      item.append(details);
      list.append(item);
    }

    const empty = node("li", "empty-state");
    empty.id = "milestone-empty";
    empty.hidden = true;
    list.append(empty);
  }

  function applyFilter(filter) {
    activeFilter = filter;
    const items = [...document.querySelectorAll(".milestone-item")];
    let visibleCount = 0;
    for (const item of items) {
      const verified = item.dataset.verified === "true";
      const visible = filter === "all" ||
        (filter === "verified" ? verified : filter === "regressed" ? item.dataset.currentResult === "regressed" : item.dataset.pending === "true");
      item.hidden = !visible;
      if (visible) visibleCount++;
    }
    document.querySelectorAll("[data-stage-filter]").forEach(button => {
      const selected = button.dataset.stageFilter === filter;
      button.setAttribute("aria-pressed", String(selected));
      button.classList.toggle("is-selected", selected);
    });
    const empty = $("#milestone-empty");
    if (empty) {
      empty.hidden = visibleCount !== 0;
      empty.textContent = filter === "verified" ? "目前没有记录实机证据。" : "目前没有待解决阶段。";
    }
    const summary = $("#filter-summary");
    if (summary) summary.textContent = `显示 ${visibleCount} / ${items.length} 个阶段`;
  }

  function installMilestoneControls() {
    document.querySelectorAll("[data-stage-filter]").forEach(button => {
      button.addEventListener("click", () => applyFilter(button.dataset.stageFilter));
    });
    $("#expand-all")?.addEventListener("click", () => {
      document.querySelectorAll(".milestone-card").forEach(details => { details.open = true; });
    });
    $("#collapse-all")?.addEventListener("click", () => {
      document.querySelectorAll(".milestone-card").forEach(details => { details.open = false; });
    });
  }

  function nextRecordState() {
    const presentation = nextCandidatePresentation();
    return {
      label: presentation.recordLabel,
      state: presentation.recordState,
      tone: presentation.tone,
      subtitle: presentation.subtitle
    };
  }

  function candidatePlaceholder(version, role) {
    if (role === "next") {
      const state = nextRecordState();
      return {
        id: "record-next-candidate",
        version,
        label: state.label,
        state: state.state,
        tone: state.tone,
        date: "候选状态快照",
        summary: `${state.subtitle}。尚无该版本运行验收结果。`,
        evidence: ["本地进度数据记录了候选版本与部署状态；该候选尚无版本级运行记录。"],
        blockers: ["待完成该候选对应的运行验收。"],
        next: ["补入实际部署、启动及功能验证证据。"]
      };
    }
    return {
      id: "record-current-candidate",
      version,
      label: "当前运行候选",
      state: "运行记录待补充",
      tone: "pending",
      date: "候选状态快照",
      summary: "本地进度数据标记此版本为当前运行候选；尚无匹配的版本级测试记录。",
      evidence: ["当前运行版本来自本地项目进度数据。"],
      blockers: ["版本级运行证据待补充。"],
      next: ["记录该版本的加载状态、功能结果与待解决问题。"]
    };
  }

  function recordForCandidate(version, role) {
    const found = sourceRecords.find(record => record.version === version);
    if (!found) return candidatePlaceholder(version, role);
    const record = { ...found };
    if (role === "current") {
      record.label = data?.deploymentState === "test067_runtime_no_peer_mif"
        ? "本轮运行记录"
        : "当前运行候选";
      record.tone = record.tone || statusTone(record.state);
    } else {
      const state = nextRecordState();
      record.label = state.label;
      record.state = state.state;
      record.tone = state.tone;
    }
    return record;
  }

  function getRecordEntries() {
    const entries = [];
    const used = new Set();
    const currentVersion = data?.runningCandidate;
    const nextVersion = data?.nextCandidate;

    if (currentVersion) {
      const current = recordForCandidate(currentVersion, "current");
      entries.push(current);
      const match = sourceRecords.find(record => record.version === currentVersion);
      if (match) used.add(match);
    }
    if (nextVersion && nextVersion !== currentVersion) {
      const next = recordForCandidate(nextVersion, "next");
      entries.push(next);
      const match = sourceRecords.find(record => record.version === nextVersion);
      if (match) used.add(match);
    }
    for (const record of sourceRecords) {
      if (!used.has(record)) entries.push({ ...record, label: "历史运行记录" });
    }
    return entries;
  }

  function appendBulletBlock(parent, title, values, className) {
    const block = node("section", `record-block ${className}`);
    block.append(node("h4", "", title));
    const list = node("ul");
    for (const value of values || []) list.append(node("li", "", value));
    if (!values?.length) list.append(node("li", "", "暂无记录"));
    block.append(list);
    parent.append(block);
  }

  function renderRecordJump(entries) {
    const nav = $("#record-jump");
    nav.replaceChildren();
    for (const entry of entries) {
      const link = node("a");
      link.href = `#${entry.id}`;
      link.append(node("span", "record-jump-version", entry.version || "版本待补充"));
      link.append(node("span", "", entry.label || "测试记录"));
      nav.append(link);
    }
  }

  function renderRecords(entries) {
    const list = $("#record-list");
    if (!entries.length) {
      list.append(node("p", "empty-state", "测试记录将在证据确认后补充。"));
      return;
    }
    for (const record of entries) {
      const card = node("article", "record-card");
      card.id = record.id;
      const header = node("header", "record-header");
      const heading = node("div");
      const eyebrow = node("div", "record-eyebrow");
      eyebrow.append(node("span", "", record.label || "测试记录"), chip(record.state, record.tone || statusTone(record.state)));
      heading.append(eyebrow, node("h3", "", record.version || "版本待补充"));
      header.append(heading, node("span", "record-date", record.date || "日期待补充"));
      card.append(header, node("p", "record-summary", record.summary || "暂无摘要。"));

      const columns = node("div", "record-columns");
      appendBulletBlock(columns, "已完成与证据", record.evidence, "evidence");
      appendBulletBlock(columns, "当前阻碍", record.blockers, "blockers");
      card.append(columns);

      const next = node("section", "record-next");
      next.append(node("h4", "", "下一步验收"));
      const tasks = node("ul", "record-block next");
      for (const task of record.next || []) tasks.append(node("li", "", task));
      if (!record.next?.length) tasks.append(node("li", "", "待补充验收事项。"));
      next.append(tasks);
      card.append(next, node("div", "record-footer", "阶段结论只依据已记录的实测证据。"));
      list.append(card);
    }
  }

  function renderAcceptance() {
    const list = $("#acceptance-list");
    for (const milestone of data?.milestones || []) {
      const link = node("a", "acceptance-link");
      link.href = `#stage-${milestone.stage}`;
      link.append(node("span", "acceptance-index", String(milestone.stage).padStart(2, "0")));
      const copy = node("span", "acceptance-copy");
      copy.append(node("strong", "", milestone.name || "未命名阶段"));
      copy.append(node("span", "", milestone.acceptance || "验收条件待补充"));
      link.append(copy, node("span", "acceptance-arrow", "↗"));
      list.append(link);
    }
  }

  function updateActiveNavigation() {
    let hash = window.location.hash || "#overview";
    if (/^#stage-/.test(hash)) {
      const target = document.getElementById(hash.slice(1));
      if (target?.hidden) {
        applyFilter("all");
        target.scrollIntoView({ block: "start" });
      }
    }
    const primaryHash = hash.startsWith("#stage-") ? "#milestones"
      : hash.startsWith("#record-") ? "#test-records" : hash;
    document.querySelectorAll(".primary-nav a").forEach(link => {
      const active = link.getAttribute("href") === primaryHash;
      link.classList.toggle("is-active", active);
      if (active) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    });
    document.querySelectorAll(".stage-nav a").forEach(link => {
      const active = link.getAttribute("href") === hash;
      link.classList.toggle("is-active", active);
      if (active) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    });
  }

  function installHashNavigation() {
    document.addEventListener("click", event => {
      const stageLink = event.target.closest('a[href^="#stage-"]');
      if (stageLink && activeFilter !== "all") applyFilter("all");
    });
    window.addEventListener("hashchange", updateActiveNavigation);
    updateActiveNavigation();
  }

  renderHeader();
  renderProgress();
  renderMilestones();
  installMilestoneControls();
  const recordEntries = getRecordEntries();
  renderRecordJump(recordEntries);
  renderRecords(recordEntries);
  renderAcceptance();
  applyFilter("all");
  installHashNavigation();
})();
