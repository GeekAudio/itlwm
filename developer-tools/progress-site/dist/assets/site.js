/* Current development brief. Evidence is rendered from the public snapshot. */
(function () {
  "use strict";
  const data = window.PROGRESS_DATA;
  const $ = selector => document.querySelector(selector);
  const node = (tag, cls, text) => {
    const element = document.createElement(tag);
    if (cls) element.className = cls;
    if (text !== undefined) element.textContent = text;
    return element;
  };
  const shortVersion = value => String(value || "待确认").match(/Test\d+/)?.[0] || String(value || "待确认");
  const labels = { passed: "通过", partial: "部分通过", regressed: "未通过", not_covered: "未覆盖" };
  const symbols = { passed: "✓", partial: "−", regressed: "!", not_covered: "·" };
  const stages = data?.milestones || [];
  const checkpoints = stages.flatMap(stage => stage.checkpoints || []);
  const records = window.TEST_RECORDS || [];
  const candidateVersion = shortVersion(data?.runningCandidate);
  const lineageScope = Object.freeze({
    driverCandidate: "25G416-Test129",
    driverCommit: "3341851cb74a63dec6389ca2cbbc2e43f27bd3ef",
    driverUuid: "061332A5-6890-3A74-B36D-2469895CA8FD",
    toolRound: "Test129",
    toolCommit: "5b055872b056b219e190425c3b315e0f851787c1",
    recordId: "record-test129-runtime",
    validationLabel: "Test129 实机验证"
  });
  const evidenceMatches = records.length === 1 && records[0].version === data?.runningCandidate &&
    data?.runningCandidate === lineageScope.driverCandidate &&
    data?.validationLabel === lineageScope.validationLabel &&
    records[0].id === lineageScope.recordId &&
    records[0].provenance?.driverCandidate === lineageScope.driverCandidate &&
    records[0].provenance?.driverSourceCommit === lineageScope.driverCommit &&
    records[0].provenance?.driverUuid === lineageScope.driverUuid &&
    records[0].provenance?.toolRound === lineageScope.toolRound &&
    records[0].provenance?.toolSourceCommit === lineageScope.toolCommit &&
    /Test129/.test(records[0].state || "");
  if (stages.length !== 8 || checkpoints.length !== 40 ||
      stages.some((stage, index) => stage.stage !== index + 1 || stage.checkpoints?.length !== 5 ||
        stage.checkpoints.some((point, offset) => point.id !== `${index + 1}-${offset + 1}`)) ||
      !evidenceMatches ||
      checkpoints.some(point => !Object.hasOwn(labels, point.current_result))) {
    const message = "本轮验收数据尚未与运行版本对齐，详细结果暂不可用。请稍后重新检查页面。";
    $("#current-summary").textContent = message;
    const title = node("h2", "", "验收数据待同步");
    title.id = "acceptance-title";
    $("#progress-overview").replaceChildren(title, node("p", "scope-note", message));
    return;
  }
  const running = shortVersion(data.runningCandidate);
  const validationRoundLabel = data.validationLabel || `${running} 实测`;
  const next = shortVersion(data.nextCandidate);
  const workflow = data.workflow?.candidate === data.runningCandidate ? data.workflow : null;
  const counts = Object.fromEntries(Object.keys(labels).map(result =>
    [result, checkpoints.filter(point => point.current_result === result).length]));
  const stageById = id => stages.find(stage => stage.stage === id);
  const workflowStep = id => workflow?.steps?.find(step => step.stage === id);

  const evidenceModel = {
    version: "source-scoped-dependencies/v2",
    scope: lineageScope,
    relations: [
      {
        from: "2-1", to: "5-3", mode: "necessary-prerequisite",
        title: "P2P MAC 上下文 ACK 是本次数据发送的必要前置",
        proof: "Probe::add() 仅在 iwx_p2p_mac_context_add() 返回 0 时置 addAcknowledged；MAC_CONTEXT_CMD 的同步命令完成是固件提供的命令回执。Test129 的 directed-data gate 还要求 addAcknowledged、MAC ACTIVE、binding ACTIVE、PHY lease 及同代未结束 ROC。此次同一 descriptor 的成功 TX completion 间接确认这条必要前置路径已通过。",
        scope: "本轮仅限 Test129 queue 4 / station 3 / descriptor 0 的这次 directed-data 发送；该命令回执不代表独立广播站点、无线 ACK 或 AirDrop。2-1 保留间接验证，不改直接通过数。",
        sources: [
          { label: "MAC_CONTEXT_CMD 的同步命令回执", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwx.cpp#L11267-L11323" },
          { label: "Probe 将 ADD 返回值记录为 addAcknowledged", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PProbe.cpp#L6170-L6177" },
          { label: "数据门检查 ADD、MAC、binding、PHY 与 ROC", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PProbe.cpp#L7220-L7259" },
          { label: "Test129 验收范围与运行边界", url: "https://github.com/GeekAudio/itlwm/blob/5b055872b056b219e190425c3b315e0f851787c1/developer-tools/test129/README.md#L1-L13" },
          { label: "Test129 最终验收门与证据限制", url: "https://github.com/GeekAudio/itlwm/blob/5b055872b056b219e190425c3b315e0f851787c1/developer-tools/test129/coordinate_directed_test129.py#L349-L368" }
        ]
      },
      {
        from: "2-3", to: "5-3", mode: "necessary-prerequisite",
        title: "本次 P2P 发送队列的安装与活动租约是完成回执的必要前置",
        proof: "Probe 为 LINK/TID0 directed peer 安装 queue，并要求资源为 ACTIVE、allocation serial 有效；permit 比对 station/queue allocation identity、代次、ROC 与票据，doorbell witness 绑定 run、queue、station、descriptor 和时间。TX_RSP 仅在 allocation、队列槽和 descriptor 同时匹配后才完成 ring 回收。Test129 观察到同一 queue4/station3/descriptor0 的成功 TX_RSP，门铃至完成 27.934 ms，因而间接验证该 queue 前置在本次发送中成立。",
        scope: "只确认 Test129 本轮 queue 4 / station 3 / descriptor 0 的 directed peer 队列被安装、授权并完成一次 TX；不外推到独立广播站点、冲突队列、旧 DMA 硬停或重复发送。2-3 保留间接验证，不改直接通过数。",
        sources: [
          { label: "本轮安装 directed peer 与 TID0 queue", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PProbe.cpp#L9420-L9464" },
          { label: "queue allocator 校验 station 角色与 TID", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PTx.cpp#L1541-L1567" },
          { label: "数据门检查 ADD、MAC、binding、PHY 与 ROC", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PProbe.cpp#L7220-L7259" },
          { label: "TX permit 比对完整 station / queue allocation identity", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PAction.cpp#L2672-L2703" },
          { label: "当前票据与 ROC 通过后生成一次性 permit", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PAction.cpp#L3061-L3127" },
          { label: "doorbell witness 绑定 run、allocation、descriptor 与时间", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PAction.cpp#L3384-L3426" },
          { label: "TX_RSP 只完成匹配的队列、station 和 descriptor", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PAction.cpp#L3492-L3631" },
          { label: "RX handler 将匹配 TX_RSP 交给 directed completion", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwx.cpp#L22279-L22335" },
          { label: "Test129 本轮使用的工具与候选版本", url: "https://github.com/GeekAudio/itlwm/blob/5b055872b056b219e190425c3b315e0f851787c1/developer-tools/test129/README.md#L1-L13" }
        ]
      },
      {
        from: "6-4", to: "5-3", mode: "necessary-prerequisite",
        title: "本次内核输出进入 driver queue 是成功 TX completion 的必要前置",
        proof: "Test129记录将 awdl0 上的 8-byte UDP、96-byte MPDU、queue 4 doorbell 与同一 descriptor completion 绑定；门铃在 ROC START 后16.673 ms，TX_RSP 在44.607 ms到达，间隔27.934 ms。6-4已有本轮直接记录；这里仅展示它在源码路径上是5-3的前置，不重复计作间接状态。",
        scope: "本轮只限这次单帧，不证明 radio ACK、AirDrop 或重复发送。",
        sources: [
          { label: "同一 descriptor 发出 doorbell 并记录单帧 witness", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PAction.cpp#L3384-L3426" },
          { label: "匹配 TX_RSP 并清除同一 ring descriptor", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PAction.cpp#L3492-L3631" }
        ]
      },
      {
        from: "3-1", to: "5-3", mode: "necessary-subcondition",
        title: "成功数据发送要求同一 ROC session 已收到 START",
        proof: "directed-data gate 要求本轮 ROC command 已成功返回、START 已观察到且状态为成功、session 尚未 END。3-1 的频道 6 START/驻留已有独立直接记录；此源码关系不把 5-3 当成频道验收的唯一证据。",
        scope: "本轮不由此推导精确频道、驻留时长、END 或多频道调度；3-1 保持直接实测分类。",
        sources: [
          { label: "数据门要求本轮 ROC 成功 START、未 END 且代次匹配", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PProbe.cpp#L7242-L7259" }
        ]
      }
    ],
    exclusions: {
      "2-2": {
        text: "本次队列角色是 directed peer link；它不能证明独立广播站点已创建。",
        source: { label: "queue release 只接受绑定的 directed peer link", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PAction.cpp#L3641-L3644" }
      },
      "2-4": {
        text: "发送完成本身不等于资源已释放；Test129另取得同代 MAC_CONTEXT REMOVE 空回执、外层移除结果0及最终 ResourcesAbsent=1，2-4据此通过。只覆盖本轮无冲突的单次回收，不证明冲突队列或旧 DMA 硬停（2-5）。",
        source: { label: "最终状态要求匹配 REMOVE 回执与内外资源全空", url: "https://github.com/GeekAudio/itlwm/blob/3341851cb74a63dec6389ca2cbbc2e43f27bd3ef/itlwm/hal_iwx/ItlIwxP2PProbe.cpp#L12717-L12778" }
      },
      "5-4": {
        text: "TX_RSP 成功、匹配 UDP 回包和 MAC REMOVE 命令回执都不等于独立 802.11 radio ACK。Test129 未证明独立 ACK 帧、正式 peer receipt 或 AirDrop，本项仍为部分通过。",
        source: { label: "Test129 验收明确保留 radio ACK、peer receipt 与 AirDrop 为未证明", url: "https://github.com/GeekAudio/itlwm/blob/5b055872b056b219e190425c3b315e0f851787c1/developer-tools/test129/coordinate_directed_test129.py#L362-L368" }
      }
    },
    aligned(sourceData, sourceRecords) {
      if (!sourceData || !Array.isArray(sourceRecords) || sourceRecords.length !== 1)
        return false;
      const record = sourceRecords[0];
      const provenance = record.provenance || {};
      return sourceData.runningCandidate === this.scope.driverCandidate &&
        sourceData.validationLabel === this.scope.validationLabel &&
        record.version === this.scope.driverCandidate &&
        record.id === this.scope.recordId &&
        provenance.driverCandidate === this.scope.driverCandidate &&
        provenance.driverSourceCommit === this.scope.driverCommit &&
        provenance.driverUuid === this.scope.driverUuid &&
        provenance.toolRound === this.scope.toolRound &&
        provenance.toolSourceCommit === this.scope.toolCommit &&
        /Test129/.test(record.state || "");
    },
    exactTxCompletion(sourceData, sourceRecords) {
      if (!this.aligned(sourceData, sourceRecords))
        return false;
      const record = sourceRecords[0];
      const tx = (sourceData.milestones || []).flatMap(stage => stage.checkpoints || [])
        .find(point => point.id === "5-3");
      if (!tx || tx.current_result !== "passed")
        return false;
      const identity = "queue4/station3/descriptor0";
      const detail = tx.current_detail || "";
      const receipt = [record.label, record.state, record.summary,
        ...(Array.isArray(record.evidence) ? record.evidence : [])].join(" ");
      return detail.includes(identity) &&
        /TX completion\s*=\s*1/i.test(detail) &&
        /(?:帧|固件)状态报告成功/.test(detail) &&
        receipt.includes(identity) &&
        /TX completion被观察到/.test(receipt) &&
        /固件状态报告成功/.test(receipt) &&
        /27\.934\s*ms/.test(receipt);
    },
    classify(sourceData, point, sourceRecords) {
      if (point.current_result !== "not_covered") {
        return {
          kind: "direct",
          status: labels[point.current_result] || "已有直接状态",
          rawStatus: point.current_result,
          source: point.current_detail || "当前逐项状态记录",
          relations: this.relations.filter(rule => rule.from === point.id || rule.to === point.id)
        };
      }
      if (!this.aligned(sourceData, sourceRecords) ||
          !this.exactTxCompletion(sourceData, sourceRecords))
        return { kind: "scope", status: "本轮无直接或间接证据", relations: [] };
      const rule = this.relations.find(item =>
        item.from === point.id && item.to === "5-3" &&
        item.mode === "necessary-prerequisite");
      if (!rule)
        return { kind: "scope", status: "本轮无直接或间接证据", relations: [] };
      return {
        kind: "derived",
        status: "间接验证通过",
        source: "Test129 同一轮 5-3 TX completion · Test129 驱动",
        rule,
        relations: [rule]
      };
    }
  };
  window.PROGRESS_EVIDENCE_MODEL = evidenceModel;
  const evidenceLineage = new Map(checkpoints.map(point =>
    [point.id, evidenceModel.classify(data, point, records)]));
  const lineageCounts = Object.fromEntries(["direct", "derived", "scope"].map(kind =>
    [kind, [...evidenceLineage.values()].filter(item => item.kind === kind).length]));
  const visibleCounts = {
    passed: counts.passed,
    derived: lineageCounts.derived,
    partial: counts.partial,
    regressed: counts.regressed,
    not_covered: counts.not_covered - lineageCounts.derived
  };
  const pill = (text, tone = "neutral") => node("span", `pill ${tone}`, text);
  const link = (text, target, cls = "text-link") => {
    const element = node("a", cls, text);
    element.href = target;
    return element;
  };

  function renderBrief() {
    $("#current-summary").textContent = workflow?.headline || data.currentRuntimeLabel || "等待新的实机结果。";
    const phase = node("p", "current-phase-label", workflow?.phaseLabel || `${running} · 当前实测阶段`);
    $("#current-summary").before(phase);

    const panel = $("#version-panel");
    panel.replaceChildren();
    const current = node("div", "version-item");
    current.append(node("span", "label", "最近有据的实测"), node("strong", "version-code", running),
      pill("已有实测记录", "neutral"));
    panel.append(current);
    if (data.nextCandidate && data.nextCandidate !== data.runningCandidate) {
      const candidate = node("div", "version-item");
      candidate.append(node("span", "label", "下一候选版本"), node("strong", "version-code", next));
      candidate.append(pill("下一候选", "neutral"));
      candidate.append(node("p", "muted", data.nextCandidateState || data.nextCandidateSummary || "状态待确认。"));
      panel.append(candidate);
    }

    const date = new Date(data.updatedAt);
    const time = $("#updated-at");
    time.dateTime = data.updatedAt;
    time.textContent = Number.isNaN(date.getTime()) ? "待确认" : new Intl.DateTimeFormat("zh-CN", {
      timeZone: "Asia/Shanghai", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false
    }).format(date) + " UTC+8";

    const focus = $("#focus-area");
    focus.replaceChildren();
    const focusHeading = node("div", "focus-section-heading");
    const focusTitle = node("h2", "", "验证路线");
    focusTitle.id = "focus-heading";
    focus.setAttribute("aria-labelledby", focusTitle.id);
    focusHeading.append(focusTitle, node("p", "", "从当前主要卡点，逐步走向系统原生 AirDrop 端到端验收。"));
    focus.append(focusHeading);
    const routeGrid = node("div", "focus-cards-grid");
    focus.append(routeGrid);

    const primary = workflow?.primaryStage || 5;
    const routeStages = [primary, primary === 5 ? 4 : 5, 8].filter((stage, index, all) => all.indexOf(stage) === index);
    const routeLabels = ["当前主要卡点", "数据通路依据", "最终验收"];
    routeStages.forEach((stageId, index) => {
      const stage = stageById(stageId);
      if (!stage) return;
      const title = workflowStep(stageId)?.title || stageNames[stageId] || stage.name;
      const card = node("article", "focus-card" + (index === 0 ? " is-blocked" : ""));
      card.append(node("span", "card-index", `0${index + 1}`), pill(routeLabels[index] || "验证阶段", index === 0 ? "warning" : "neutral"));
      card.append(node("h3", "", title), node("p", "", workflowStep(stageId)?.detail || stage.current_summary || stage.name));
      card.append(link("查看逐项证据 ↗", `#stage-${stage.stage}`, "card-next"));
      routeGrid.append(card);
    });
  }

  // Short display labels belong to the fixed acceptance IDs, never to evidence prose.
  const shortNames = {
    "1-1": "识别与接口", "1-2": "认证与联网", "1-3": "私有地址", "1-4": "开关回连", "1-5": "稳定与恢复",
    "2-1": "MAC 上下文", "2-2": "广播站点", "2-3": "发送队列", "2-4": "资源回收", "2-5": "冲突与 DMA",
    "3-1": "驻留 START", "3-2": "驻留 END", "3-3": "原始时钟", "3-4": "时钟与相位", "3-5": "多频道调度",
    "4-1": "控制帧捕获", "4-2": "PSF 接纳", "4-3": "MIF 接纳", "4-4": "对端有效期", "4-5": "数据帧解码",
    "5-1": "PSF 完成", "5-2": "MIF 完成", "5-3": "数据帧完成", "5-4": "对端实收", "5-5": "持续双向",
    "6-1": "初始化释放", "6-2": "注册与启停", "6-3": "接口常驻", "6-4": "内核输出", "6-5": "无线包输入",
    "7-1": "IPv6 地址", "7-2": "UDP 输出", "7-3": "邻居可达", "7-4": "Bonjour", "7-5": "分享握手",
    "8-1": "Mac → 手机", "8-2": "手机 → Mac", "8-3": "重复传输", "8-4": "文件完整性", "8-5": "睡眠与共存"
  };
  const stageNames = { 1: "原生 Wi-Fi", 2: "P2P 资源", 3: "频道与时序", 4: "AWDL 接收", 5: "AWDL 发送", 6: "原生 awdl0", 7: "IPv6 与发现", 8: "双向 AirDrop" };
  let activeButton = null;
  let matrixDetails = null;
  const detail = node("section", "evidence-panel");
  detail.id = "matrix-detail";
  detail.hidden = true;
  detail.tabIndex = -1;
  detail.setAttribute("aria-label", "所选项目实测依据");


  function appendLineageDetails(body, checkpoint, lineage) {
    const relevant = lineage?.relations || evidenceModel.relations.filter(rule =>
      rule.from === checkpoint.id || rule.to === checkpoint.id);
    if (relevant.length) {
      body.append(node("span", "detail-label", "源码调用与同轮依赖"));
      relevant.forEach(rule => {
        const card = node("div", "lineage-edge");
        const other = rule.from === checkpoint.id ? rule.to : rule.from;
        const direction = rule.from === checkpoint.id ? "前置条件" :
          rule.to === checkpoint.id ? "后续结果用于验证本前置" : "同一必要路径";
        card.append(node("strong", "", rule.from + " → " + rule.to + " · " + direction));
        card.append(node("p", "", rule.proof));
        card.append(node("p", "lineage-scope", "适用范围：" + rule.scope));
        const links = node("div", "lineage-links");
        links.append(link("查看检查项 " + other + " ↗",
          "#check-" + other, "lineage-record-link"));
        rule.sources.forEach(source => {
          const anchor = link(source.label + " ↗", source.url, "lineage-source-link");
          anchor.target = "_blank";
          anchor.rel = "noopener noreferrer";
          links.append(anchor);
        });
        card.append(links);
        body.append(card);
      });
    }
    const exclusion = evidenceModel.exclusions[checkpoint.id];
    if (exclusion) {
      body.append(node("span", "detail-label", "未推导的边界"));
      body.append(node("p", "lineage-scope", exclusion.text));
      const anchor = link(exclusion.source.label + " ↗", exclusion.source.url, "lineage-source-link");
      anchor.target = "_blank";
      anchor.rel = "noopener noreferrer";
      body.append(anchor);
    }
  }

  function installLineageStyles() {
    if (document.getElementById("evidence-lineage-style")) return;
    const style = node("style", "");
    style.id = "evidence-lineage-style";
    style.textContent = ".progress-summary.with-lineage{grid-template-columns:repeat(5,minmax(0,1fr))}" +
      ".progress-summary .derived .count,.progress-summary .derived .label{color:#08785f}" +
      ".matrix-cell[data-lineage=derived]{border-color:#8dc8b7;background:#edf8f4;color:#135b49}" +
      ".matrix-cell[data-lineage=derived] .cell-status{color:#08785f;font-weight:700}" +
      ".lineage-proof,.lineage-scope{color:var(--muted);font-size:12px;line-height:1.65}" +
      ".lineage-edge{display:grid;gap:6px;margin:8px 0;padding:11px;border:1px solid var(--line);border-radius:9px;background:var(--surface-soft)}" +
      ".lineage-edge strong{font-size:12px;color:var(--ink)}" +
      ".lineage-edge p{margin:0}" +
      ".lineage-links{display:flex;flex-wrap:wrap;gap:7px 13px}" +
      ".lineage-source-link,.lineage-record-link{font-size:11px;color:var(--blue);font-weight:650}" +
      ".lineage-source-link:hover,.lineage-record-link:hover{text-decoration:underline}" +
      "@media(max-width:900px){.progress-summary.with-lineage{grid-template-columns:repeat(3,minmax(0,1fr))}}" +
      "@media(max-width:600px){.progress-summary.with-lineage{grid-template-columns:repeat(2,minmax(0,1fr))}}";
    document.head.append(style);
  }

  function showDetail(stage, checkpoint, trigger, scroll = true) {
    if (activeButton) activeButton.setAttribute("aria-pressed", "false");
    activeButton = trigger;
    if (matrixDetails) matrixDetails.open = true;
    trigger?.setAttribute("aria-pressed", "true");
    detail.replaceChildren();
    const heading = node("div", "detail-heading");
    const title = node("h3", "", checkpoint ? `${checkpoint.id} · ${checkpoint.name}` : `${stage.stage} · ${stage.name}`);
    const close = node("button", "close-detail", "收起 ×");
    close.type = "button";
    close.addEventListener("click", () => {
      detail.hidden = true;
      activeButton?.setAttribute("aria-pressed", "false");
      activeButton?.focus({ preventScroll: true });
      activeButton = null;
      if (/^#(?:stage-|check-)/.test(location.hash)) history.replaceState(null, "", "#acceptance-matrix");
    });
    heading.append(title, close);
    const body = node("div", "detail-body");
    body.append(node("span", "detail-label", `${validationRoundLabel}${checkpoint ? " · " + labels[checkpoint.current_result] : ""}`));
    body.append(node("p", "", checkpoint ? checkpoint.current_detail : stage.current_summary || stage.evidence));

    if (checkpoint) {
      const lineage = evidenceLineage.get(checkpoint.id);
      const classification = lineage?.kind === "derived" ? "同轮间接验证通过（原始状态仍未独立测试）" :
        lineage?.kind === "direct" ? "本轮直接记录 · " + labels[checkpoint.current_result] :
        "本轮没有可应用的直接或间接证据";
      body.append(node("span", "detail-label", "验证分类 · " + classification));
      if (lineage?.kind === "derived" && lineage.rule) {
        body.append(node("p", "lineage-proof", lineage.rule.proof));
        body.append(node("p", "lineage-scope", "适用范围：" + lineage.rule.scope));
      }
      appendLineageDetails(body, checkpoint, lineage);
    }
    if (!checkpoint) {
      body.append(node("span", "detail-label", "还需验证"), node("p", "", stage.pending));
    }
    detail.append(heading, body);
    detail.hidden = false;
    if (scroll) {
      detail.scrollIntoView({ block: "nearest" });
      detail.focus({ preventScroll: true });
    }
  }

  function renderAcceptance() {
    const overview = $("#progress-overview");
    const heading = node("div", "section-heading");
    const title = node("h2", "", `${validationRoundLabel} · 40 项验收`);
    title.id = "acceptance-title";
    heading.append(title);
    overview.replaceChildren(node("div", "section-eyebrow", "CURRENT TEST ROUND"), heading);

    const summary = node("div", "progress-summary");
    summary.classList.add("with-lineage");
    const summaryItems = [
      ["passed", "直接通过", visibleCounts.passed],
      ["derived", "间接验证通过", visibleCounts.derived],
      ["partial", "部分通过", visibleCounts.partial],
      ["regressed", "未通过", visibleCounts.regressed],
      ["not_covered", "无直接/间接证据", visibleCounts.not_covered]
    ];
    summaryItems.forEach(([key, label, value]) => {
      const stat = node("span", key);
      stat.append(node("strong", "count", String(value)), node("span", "label", label));
      summary.append(stat);
    });
    overview.append(summary, node("p", "scope-note",
      `这是 ${validationRoundLabel} 这一轮的 40 项固定检查，不是项目完成度：${counts.passed} 项直接通过、${counts.partial} 项部分通过、${counts.regressed} 项未通过；另有 ${lineageCounts.derived} 项由同轮源码必经路径间接验证通过，${visibleCounts.not_covered} 项本轮没有直接或间接证据。间接项保留原始点位状态，并展示对应源码、运行记录与适用边界。`));

    const evidenceStages = stages.filter(stage =>
      stage.checkpoints.some(point => evidenceLineage.get(point.id)?.kind !== "scope"));
    const highlights = node("section", "stage-highlights");
    highlights.setAttribute("aria-labelledby", "stage-evidence-heading");
    const highlightsHeader = node("div", "stage-highlights-heading");
    const headingCopy = node("div", "stage-highlights-copy");
    const evidenceHeading = node("h3", "", "本轮有直接或间接证据的阶段");
    evidenceHeading.id = "stage-evidence-heading";
    headingCopy.append(evidenceHeading, node("p", "", "通过结果会标明直接实测或由源码必经前置间接验证；其他检查仍保留在完整验收表中。"));
    highlightsHeader.append(headingCopy, node("span", "stage-highlights-count", `${evidenceStages.length} / ${stages.length} 个阶段`));
    highlights.append(highlightsHeader);
    const grid = node("div", "stage-evidence-grid");
    evidenceStages.forEach(stage => {
      const stageCounts = Object.fromEntries(Object.keys(labels).map(result =>
        [result, stage.checkpoints.filter(point => point.current_result === result).length]));
      const indirectCount = stage.checkpoints.filter(point => evidenceLineage.get(point.id)?.kind === "derived").length;
      const resultCount = stageCounts.passed + stageCounts.partial + stageCounts.regressed + indirectCount;
      const tone = stageCounts.regressed ? "warning" : stageCounts.partial ? "warning" : "success";
      const card = node("article", "stage-evidence-card");
      card.append(node("span", "stage-evidence-kicker", `阶段 ${String(stage.stage).padStart(2, "0")}`));
      card.append(node("h4", "", stageNames[stage.stage] || stage.name));
      const badges = node("div", "stage-evidence-status");
      [["passed", "success"], ["partial", "warning"], ["regressed", "warning"]].forEach(([key, badgeTone]) => {
        if (stageCounts[key]) badges.append(pill(`${stageCounts[key]} ${labels[key]}`, badgeTone));
      });
      if (indirectCount) badges.append(pill(`${indirectCount} 间接验证通过`, "success"));
      card.append(badges, node("p", "", stage.current_summary || stage.evidence || stage.name));
      card.append(node("span", "stage-evidence-count", `${resultCount} / 5 项有本轮证据`));
      card.append(link("查看本阶段依据 ↗", `#stage-${stage.stage}`, "stage-evidence-link"));
      card.dataset.tone = tone;
      grid.append(card);
    });
    if (!evidenceStages.length) {
      grid.append(node("p", "empty-evidence", "本轮尚未取得可计入的直接结果。完整检查项和既往证据仍保留在下方。"));
    }
    highlights.append(grid);
    const quietStages = stages.length - evidenceStages.length;
    if (quietStages > 0) {
      highlights.append(node("p", "not-tested-note", `另有 ${quietStages} 个阶段本轮没有新结果；它们不代表失败，可在完整表中逐项查看。`));
    }
    overview.append(highlights);

    matrixDetails = node("details", "acceptance-details");
    matrixDetails.id = "acceptance-details";
    const toggle = node("summary", "acceptance-toggle");
    const toggleCopy = node("span", "acceptance-toggle-copy");
    toggleCopy.append(node("strong", "", `展开全部 ${checkpoints.length} 项验收细节`),
      node("span", "", "查看逐项状态、技术证据与仍待验证内容"));
    toggle.append(toggleCopy, node("span", "acceptance-toggle-count", `${visibleCounts.not_covered} 项无直接/间接证据`));
    matrixDetails.append(toggle, node("p", "matrix-note",
      "原始 40 项状态不被重写。只有同一驱动、同一测试轮次中，源码明确要求的状态前置且后续结果实际通过时才标为间接验证；相关性、先后顺序、TX_RSP 或 active-monitor 能力不会自动等同 ACK。稳定性、大文件、睡眠与共存不从单包结果外推。"));

    const table = node("table", "acceptance-matrix");
    table.append(node("caption", "sr-only", `${validationRoundLabel} · 8 阶段、40 项固定验收`));
    const head = node("thead");
    const header = node("tr");
    ["验收阶段", "检查项 01", "检查项 02", "检查项 03", "检查项 04", "检查项 05"].forEach(text => {
      const th = node("th", "", text);
      th.scope = "col";
      header.append(th);
    });
    head.append(header);
    table.append(head);
    const body = node("tbody");
    stages.forEach(stage => {
      const row = node("tr");
      row.id = `stage-${stage.stage}`;
      const th = node("th", "matrix-row-head");
      th.scope = "row";
      const button = node("button", "stage-button");
      button.type = "button";
      button.setAttribute("aria-pressed", "false");
      button.setAttribute("aria-controls", "matrix-detail");
      button.append(node("span", "", `${String(stage.stage).padStart(2, "0")}  ${stageNames[stage.stage] || stage.name}`));
      const evidenceCount = stage.checkpoints.filter(point =>
        evidenceLineage.get(point.id)?.kind !== "scope").length;
      button.append(node("small", "", `${evidenceCount} / 5 有本轮结果 · 查看阶段`));
      button.addEventListener("click", () => showDetail(stage, null, button));
      th.append(button);
      row.append(th);
      stage.checkpoints.forEach(point => {
        const cell = node("td");
        const button = node("button", "matrix-cell");
        button.type = "button";
        button.id = `check-${point.id}`;
        const lineage = evidenceLineage.get(point.id);
        const visibleStatus = lineage?.kind === "derived" ? "间接验证通过" : labels[point.current_result];
        button.dataset.result = point.current_result;
        button.dataset.lineage = lineage?.kind || "scope";
        button.setAttribute("aria-pressed", "false");
        button.setAttribute("aria-controls", "matrix-detail");
        button.setAttribute("aria-label", `${point.id} ${point.name}：${visibleStatus}；原始点位状态：${labels[point.current_result]}`);
        button.append(node("span", "cell-index", lineage?.kind === "derived" ? "↳" : symbols[point.current_result]), node("span", "cell-name", shortNames[point.id] || point.name), node("span", "cell-status", visibleStatus));
        button.addEventListener("click", () => showDetail(stage, point, button));
        cell.append(button);
        row.append(cell);
      });
      body.append(row);
    });
    table.append(body);
    const scroll = node("div", "matrix-scroll");
    scroll.setAttribute("role", "region");
    scroll.setAttribute("aria-label", "验收表，小屏可左右滚动");
    scroll.tabIndex = 0;
    scroll.append(table);
    const detailsBody = node("div", "acceptance-details-body");
    detailsBody.append(node("p", "matrix-scroll-hint", "左右滑动查看全部检查项 →"), scroll, detail);
    matrixDetails.append(detailsBody);
    $("#matrix-content").replaceChildren(matrixDetails);
  }

  function renderRecent() {
    const section = node("section", "section-card recent-progress");
    section.id = "recent-progress";
    section.setAttribute("aria-labelledby", "recent-progress-title");
    const record = records[0] || null;
    const header = node("div", "recent-progress-heading");
    const copy = node("div");
    copy.append(node("p", "section-eyebrow", "LATEST TEST RECORD"));
    const title = node("h2", "", "最近实测进展");
    title.id = "recent-progress-title";
    copy.append(title, node("p", "section-description", record ? `${record.version} · ${record.date || "日期待确认"}` : `${running} · 本轮结果`));
    header.append(copy, pill(record?.tone === "success" ? "验证完成" : "仍有未闭环", record?.tone === "success" ? "success" : "neutral"));
    section.append(header);

    const lead = node("p", "recent-progress-lead", record?.short_summary || workflow?.headline || data.currentRuntimeLabel || "等待新的实测记录。");
    section.append(lead);

    const factSource = workflow?.facts || [];
    const preferredLabels = ["请求与返回", "接收交付", "首个未闭环步骤", "新完成记录", "下一版部署"];
    let featured = factSource.filter(fact => preferredLabels.includes(fact.label)).slice(0, 4);
    if (!featured.length && record?.evidence?.length) {
      const evidence = record.evidence;
      featured = evidence.slice(0, Math.min(3, evidence.length)).map((value, index) => ({ label: `本轮证据 ${index + 1}`, value }));
      if (evidence.length > 3) featured.push({ label: "尚未闭环", value: evidence[evidence.length - 1] });
    }
    const grid = node("div", "recent-facts-grid");
    featured.forEach(fact => {
      const card = node("article", "recent-fact-card");
      card.append(node("h3", "", fact.label), node("p", "", fact.value));
      grid.append(card);
    });
    if (featured.length) section.append(grid);

    const blockerTitle = workflow?.alert?.title || record?.blockers?.[0] || "";
    const blockerText = workflow?.alert?.detail || record?.blockers?.[0] || "";
    if (blockerTitle || blockerText) {
      const blocker = node("aside", "recent-blocker");
      blocker.append(pill("当前主要卡点", "warning"));
      if (blockerTitle) blocker.append(node("h3", "", blockerTitle));
      if (blockerText && blockerText !== blockerTitle) blocker.append(node("p", "", blockerText));
      section.append(blocker);
    }

    const details = node("details", "recent-record-details");
    const detailSummary = node("summary", "", "展开完整技术记录与边界");
    details.append(detailSummary);
    const body = node("div", "recent-record-body");
    if (record?.summary) body.append(node("p", "recent-record-summary", record.summary));
    const provenance = record?.provenance;
    if (provenance) {
      body.append(node("h3", "", "驱动与对端工具来源"));
      body.append(node("p", "recent-record-summary",
        `驱动：${provenance.driverCandidate} · source_commit ${provenance.driverSourceCommit} · Mach-O UUID ${provenance.driverUuid}`));
      body.append(node("p", "recent-record-summary",
        `对端工具：${provenance.toolRound} · source_commit ${provenance.toolSourceCommit}（本轮实机驱动与工具分别绑定上方记录的 Test129 来源）`));
      const links = node("div", "lineage-links");
      (provenance.sources || []).forEach(source => {
        const anchor = link(source.label + " ↗", source.url, "lineage-source-link");
        anchor.target = "_blank";
        anchor.rel = "noopener noreferrer";
        links.append(anchor);
      });
      if (links.childNodes.length) body.append(links);
    }
    const evidence = record?.evidence || factSource.map(fact => `${fact.label}：${fact.value}`);
    if (evidence.length) {
      body.append(node("h3", "", "本轮观测"));
      const list = node("ul", "recent-evidence-list");
      evidence.forEach(item => list.append(node("li", "", item)));
      body.append(list);
    }
    if (record?.blockers?.length) {
      body.append(node("h3", "", "仍待验证"));
      const list = node("ul", "recent-evidence-list");
      record.blockers.forEach(item => list.append(node("li", "", item)));
      body.append(list);
    }
    if (record?.next?.length) {
      body.append(node("h3", "", "记录中的下一步"));
      const list = node("ul", "recent-evidence-list");
      record.next.forEach(item => list.append(node("li", "", item)));
      body.append(list);
    }
    details.append(body);
    section.append(details);
    return section;
  }

  function renderNext() {
    const host = $("#next-content");
    const candidate = node("div", "next-candidate-card");
    const candidateVersion = data.nextCandidate ? next : running;
    candidate.append(pill(candidateVersion, "neutral"), node("strong", "", data.nextCandidateState || "当前状态待核实"));
    if (data.nextCandidateSummary) candidate.append(node("p", "", data.nextCandidateSummary));

    const alert = workflow?.alert;
    const blocker = node("aside", "next-blocker");
    blocker.append(pill("主要卡点", "warning"));
    blocker.append(node("h3", "", alert?.title || "当前待验证项"));
    blocker.append(node("p", "", alert?.detail || records[0]?.blockers?.[0] || "等待最新实测记录确认。"));

    const action = node("div", "next-action-card");
    action.append(node("span", "next-action-label", "下一步"));
    action.append(node("p", "", workflow?.nextAction || data.nextCandidateSummary || "等待下一轮验证计划。"));
    host.replaceChildren(candidate, blocker, action);
  }

  function navigateHash() {
    const hash = location.hash;
    const stageMatch = hash.match(/^#stage-(\d+)$/);
    const checkMatch = hash.match(/^#check-(\d+-\d+)$/);
    if (stageMatch || checkMatch) {
      const stage = stageById(Number(stageMatch?.[1] || checkMatch[1].split("-")[0]));
      if (!stage) return;
      const point = checkMatch && stage.checkpoints.find(item => item.id === checkMatch[1]);
      const trigger = point ? document.getElementById(`check-${point.id}`) : document.querySelector(`#stage-${stage.stage} .stage-button`);
      showDetail(stage, point || null, trigger);
    } else {
      const aliases = { "#milestones": "acceptance-matrix", "#principle-map": "focus-area", "#workflow-overview": "focus-area", "#development-timeline": "next-step", "#test-records": "next-step", "#acceptance": "next-step" };
      document.getElementById(aliases[hash])?.scrollIntoView({ block: "start" });
    }
  }
  installLineageStyles();
  renderBrief();
  const recentProgress = renderRecent();
  renderNext();
  renderAcceptance();
  const main = $("#overview").parentElement;
  main.append($("#overview"), recentProgress, $("#next-step"), $("#focus-area"), $("#acceptance-matrix"));
  window.addEventListener("hashchange", navigateHash);
  navigateHash();
})();
