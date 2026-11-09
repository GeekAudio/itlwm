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
  const evidenceMatches = records.length === 1 && records[0].version === data?.runningCandidate &&
    records[0].state === data?.validationLabel &&
    shortVersion(data?.validationLabel) === shortVersion(data?.runningCandidate);
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
  const next = shortVersion(data.nextCandidate);
  const workflow = data.workflow?.candidate === data.runningCandidate ? data.workflow : null;
  const counts = Object.fromEntries(Object.keys(labels).map(result =>
    [result, checkpoints.filter(point => point.current_result === result).length]));
  const stageById = id => stages.find(stage => stage.stage === id);
  const workflowStep = id => workflow?.steps?.find(step => step.stage === id);
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
    body.append(node("span", "detail-label", `${running} 实测${checkpoint ? " · " + labels[checkpoint.current_result] : ""}`));
    body.append(node("p", "", checkpoint ? checkpoint.current_detail : stage.current_summary || stage.evidence));
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
    const title = node("h2", "", `${running} · 本轮实测结果`);
    title.id = "acceptance-title";
    heading.append(title);
    overview.replaceChildren(node("div", "section-eyebrow", "CURRENT TEST ROUND"), heading);

    const summary = node("div", "progress-summary");
    Object.entries(labels).forEach(([key, label]) => {
      const stat = node("span", key);
      stat.append(node("strong", "count", String(counts[key])), node("span", "label", label));
      summary.append(stat);
    });
    const evidenceCount = checkpoints.length - counts.not_covered;
    overview.append(summary, node("p", "scope-note",
      `这是 ${running} 这一轮的 40 项固定检查，不是项目完成度。本轮有 ${evidenceCount} 项取得直接结果：${counts.passed} 项通过、${counts.partial} 项部分通过、${counts.regressed} 项未通过。未覆盖表示本轮没有直接证据，不等于失败；历史记录单独保留。`));

    const evidenceStages = stages.filter(stage =>
      stage.checkpoints.some(point => point.current_result !== "not_covered"));
    const highlights = node("section", "stage-highlights");
    highlights.setAttribute("aria-labelledby", "stage-evidence-heading");
    const highlightsHeader = node("div", "stage-highlights-heading");
    const headingCopy = node("div", "stage-highlights-copy");
    const evidenceHeading = node("h3", "", "本轮有直接结果的阶段");
    evidenceHeading.id = "stage-evidence-heading";
    headingCopy.append(evidenceHeading, node("p", "", "只显示本轮取得结果的阶段；其他检查仍保留在完整验收表中。"));
    highlightsHeader.append(headingCopy, node("span", "stage-highlights-count", `${evidenceStages.length} / ${stages.length} 个阶段`));
    highlights.append(highlightsHeader);
    const grid = node("div", "stage-evidence-grid");
    evidenceStages.forEach(stage => {
      const stageCounts = Object.fromEntries(Object.keys(labels).map(result =>
        [result, stage.checkpoints.filter(point => point.current_result === result).length]));
      const resultCount = stageCounts.passed + stageCounts.partial + stageCounts.regressed;
      const tone = stageCounts.regressed ? "warning" : stageCounts.partial ? "warning" : "success";
      const card = node("article", "stage-evidence-card");
      card.append(node("span", "stage-evidence-kicker", `阶段 ${String(stage.stage).padStart(2, "0")}`));
      card.append(node("h4", "", stageNames[stage.stage] || stage.name));
      const badges = node("div", "stage-evidence-status");
      [["passed", "success"], ["partial", "warning"], ["regressed", "warning"]].forEach(([key, badgeTone]) => {
        if (stageCounts[key]) badges.append(pill(`${stageCounts[key]} ${labels[key]}`, badgeTone));
      });
      card.append(badges, node("p", "", stage.current_summary || stage.evidence || stage.name));
      card.append(node("span", "stage-evidence-count", `${resultCount} / 5 项有本轮结果`));
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
    toggle.append(toggleCopy, node("span", "acceptance-toggle-count", `${counts.not_covered} 项本轮未覆盖`));
    matrixDetails.append(toggle, node("p", "matrix-note",
      "未覆盖以中性灰色显示，表示本轮没有直接证据，不等于失败。点击任一检查项可查看本轮依据与待验证内容。"));

    const table = node("table", "acceptance-matrix");
    table.append(node("caption", "sr-only", `${running} 本轮 8 阶段、40 项固定验收`));
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
      const evidenceCount = stage.checkpoints.filter(point => point.current_result !== "not_covered").length;
      button.append(node("small", "", `${evidenceCount} / 5 有本轮结果 · 查看阶段`));
      button.addEventListener("click", () => showDetail(stage, null, button));
      th.append(button);
      row.append(th);
      stage.checkpoints.forEach(point => {
        const cell = node("td");
        const button = node("button", "matrix-cell");
        button.type = "button";
        button.id = `check-${point.id}`;
        button.dataset.result = point.current_result;
        button.setAttribute("aria-pressed", "false");
        button.setAttribute("aria-controls", "matrix-detail");
        button.setAttribute("aria-label", `${point.id} ${point.name}：${labels[point.current_result]}`);
        button.append(node("span", "cell-index", symbols[point.current_result]), node("span", "cell-name", shortNames[point.id] || point.name), node("span", "cell-status", labels[point.current_result]));
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
  renderBrief();
  const recentProgress = renderRecent();
  renderNext();
  renderAcceptance();
  const main = $("#overview").parentElement;
  main.append($("#overview"), recentProgress, $("#next-step"), $("#focus-area"), $("#acceptance-matrix"));
  window.addEventListener("hashchange", navigateHash);
  navigateHash();
})();
