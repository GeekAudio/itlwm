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
    const message = "本轮验收数据尚未与运行版本对齐，暂不显示通过率。请稍后重新检查页面更新。";
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
    $("#current-summary").textContent = workflow?.headline || data.currentRuntimeLabel;
    const panel = $("#version-panel");
    const current = node("div", "version-item");
    current.append(node("span", "label", "最近完整诊断"), node("strong", "version-code", running), pill("已有实测记录", "success"));
    panel.append(current);
    if (data.nextCandidate && data.nextCandidate !== data.runningCandidate) {
      const candidate = node("div", "version-item");
      candidate.append(node("span", "label", "下一版"), node("strong", "version-code", next));
      const deployed = data.nextCandidateRole === "deployed_not_boot_verified";
      candidate.append(pill(deployed ? "已部署 · 待启动验收" : "待实机验收", "warning"));
      candidate.append(node("p", "muted", data.nextCandidateState));
      panel.append(candidate);
    }
    const date = new Date(data.updatedAt);
    const time = $("#updated-at");
    time.dateTime = data.updatedAt;
    time.textContent = Number.isNaN(date.getTime()) ? "待确认" : new Intl.DateTimeFormat("zh-CN", {
      timeZone: "Asia/Shanghai", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false
    }).format(date) + " UTC+8";

    const cards = [
      { stage: 1, title: "Wi-Fi 日常连接", tag: "稳定性验证" },
      { stage: 4, title: "AWDL 真实数据", tag: "数据通路验证" },
      { stage: 8, title: "原生 AirDrop", tag: "端到端验收" }
    ];
    cards.forEach((item, index) => {
      const stage = stageById(item.stage);
      const card = node("article", "focus-card" + (index === 1 ? " is-blocked" : ""));
      card.append(node("span", "card-index", `0${index + 1}`), pill(item.tag, index === 1 ? "warning" : "neutral"));
      card.append(node("h3", "", item.title), node("p", "", workflowStep(item.stage)?.detail || stage.current_summary));
      card.append(link("查看实测依据 ↗", `#stage-${stage.stage}`, "card-next"));
      $("#focus-area").append(card);
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
  const detail = node("section", "evidence-panel");
  detail.id = "matrix-detail";
  detail.hidden = true;
  detail.tabIndex = -1;
  detail.setAttribute("aria-label", "所选项目实测依据");

  function showDetail(stage, checkpoint, trigger, scroll = true) {
    if (activeButton) activeButton.setAttribute("aria-pressed", "false");
    activeButton = trigger;
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
    const title = node("h2", "", `${running} · 最近保存的验收`);
    title.id = "acceptance-title";
    heading.append(title);
    const total = node("div", "count-total");
    total.append(node("strong", "", String(counts.passed)), node("span", "", " / 40 项通过"));
    heading.append(total);
    overview.replaceChildren(node("div", "section-eyebrow", "CURRENT VERIFICATION"), heading);
    const summary = node("div", "progress-summary");
    Object.entries(labels).forEach(([key, label]) => {
      const stat = node("span", key);
      stat.append(node("strong", "count", String(counts[key])), node("span", "label", label));
      summary.append(stat);
    });
    const track = node("div", "progress-track");
    const percent = counts.passed / checkpoints.length * 100;
    track.setAttribute("role", "progressbar");
    track.setAttribute("aria-label", `${running} 本轮验收通过率`);
    track.setAttribute("aria-valuemin", "0");
    track.setAttribute("aria-valuemax", "100");
    track.setAttribute("aria-valuenow", String(percent));
    track.setAttribute("aria-valuetext", `${counts.passed} / 40 项通过，${percent}%，另有 ${counts.partial} 项部分通过`);
    const complete = node("span", "progress-fill");
    complete.style.width = `${percent}%`;
    const partial = node("span", "partial-fill");
    partial.style.width = `${counts.partial / checkpoints.length * 100}%`;
    track.append(complete, partial);
    overview.append(summary, track, node("p", "scope-note", `本轮通过率 ${percent}%。未覆盖表示本轮没测，不代表退步；这不是项目完成率。点击任一项目查看依据。`));

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
      const passed = stage.checkpoints.filter(point => point.current_result === "passed").length;
      button.append(node("small", "", `${passed} / 5 通过 · 查看阶段`));
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
    $("#matrix-content").replaceChildren(node("p", "matrix-scroll-hint", "左右滑动查看全部检查项 →"), scroll, detail);
  }

  function renderNext() {
    const host = $("#next-content");
    const intro = node("div", "next-intro");
    intro.append(pill(data.nextCandidate ? next : running, "neutral"), node("h3", "", "先闭合真实单包，再接持续服务。"));
    intro.append(node("p", "", data.nextCandidateSummary || workflow?.nextAction));
    const list = node("ol", "next-list");
    const tasks = [
      { title: "联网与快速切换", text: stageById(1).pending },
      { title: "定位真实回包的第一处阻塞", text: stageById(4).pending },
      { title: "数据通路通过后，再验收 AirDrop", text: stageById(8).acceptance }
    ];
    tasks.forEach((task, index) => {
      const li = node("li");
      const content = node("div");
      content.append(node("h4", "", task.title), node("p", "", task.text));
      li.append(node("span", "step-number", `0${index + 1}`), content);
      list.append(li);
    });
    const extra = node("details", "extra-evidence");
    extra.append(node("summary", "", "查看本轮采集范围"), node("p", "", data.evidenceScopeLabel));
    host.replaceChildren(intro, list, extra);
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
  renderAcceptance();
  renderNext();
  window.addEventListener("hashchange", navigateHash);
  navigateHash();
})();
