(() => {
  "use strict";

  const data = window.PROGRESS_DATA;
  const sourceRecords = window.TEST_RECORDS || [];
  const $ = (selector, root = document) => root.querySelector(selector);
  let activeFilter = "all";
  const referenceRuntime = String(data?.deploymentState || "").startsWith("brcm_reference_runtime");
  const evidenceScope = referenceRuntime ? data?.evidenceScopeLabel : null;

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

  const workflowStatusLabels = {
    verified: "本轮通过",
    blocked: "当前卡点",
    waiting: "待验证",
    partial: "部分通过",
    attention: "出现异常"
  };

  function currentWorkflow() {
    const workflow = data?.workflow;
    return workflow && workflow.candidate === data?.runningCandidate ? workflow : null;
  }

  function stageHref(stage) {
    if (stage === undefined || stage === null || stage === "") return null;
    const value = String(stage);
    return value.startsWith("stage-") ? `#${value}` : `#stage-${value}`;
  }

  function stageKey(stage) {
    return String(stage ?? "").replace(/^stage-/, "");
  }

  function renderWorkflow() {
    const target = $("#workflow-overview");
    if (!target) return;
    target.replaceChildren();

    const workflow = currentWorkflow();
    const heading = node("div", "workflow-heading");
    const title = node("div", "workflow-title");
    title.append(node("div", "section-kicker", "CURRENT WORKFLOW"));
    title.append(node("h2", "", workflow?.headline || "本轮流程摘要待更新"));
    if (workflow?.phaseLabel) title.append(node("span", "workflow-label", workflow.phaseLabel));
    heading.append(title);

    const legend = node("div", "workflow-legend");
    for (const [status, label] of Object.entries(workflowStatusLabels)) {
      legend.append(node("span", `workflow-legend-item is-${status}`, label));
    }
    heading.append(legend);
    target.append(heading);

    if (!workflow) {
      target.append(node("p", "workflow-stale", "当前流程候选与正在运行的版本不匹配，等待本轮摘要更新。"));
      return;
    }

    const layout = node("div", "workflow-layout");
    const route = node("section", "workflow-route");
    route.setAttribute("aria-label", "本轮流程步骤");
    const steps = node("ol");
    for (const [index, step] of (workflow.steps || []).entries()) {
      const status = Object.prototype.hasOwnProperty.call(workflowStatusLabels, step?.status) ? step.status : "waiting";
      const item = node("li", `flow-step is-${status}`);
      const anchor = node("a", "flow-link");
      const href = stageHref(step?.stage);
      if (href) anchor.href = href;
      else anchor.setAttribute("aria-disabled", "true");
      anchor.append(node("span", "flow-marker", status === "verified" ? "✓" : String(index + 1)));
      const copy = node("div", "flow-copy");
      copy.append(node("h3", "", step?.title || "步骤待补充"));
      copy.append(node("p", "flow-detail", step?.detail || "本步骤说明待更新。"));
      anchor.append(copy, node("span", "flow-state", workflowStatusLabels[status]));
      item.append(anchor);
      steps.append(item);
    }
    if (!workflow.steps?.length) steps.append(node("li", "flow-empty", "本轮步骤待更新。"));
    route.append(steps);

    const focus = node("section", "workflow-focus");
    focus.append(node("div", "focus-kicker", workflow.phaseLabel || "本轮进度"));
    const primaryStep = (workflow.steps || []).find(step => stageKey(step?.stage) === stageKey(workflow.primaryStage));
    focus.append(node("h2", "", primaryStep?.title || workflow.headline || "当前焦点待更新"));
    focus.append(node("p", "focus-summary", workflow.summary || "本轮摘要待更新。"));

    const next = node("div", "focus-next");
    next.append(node("strong", "", "下一步"));
    next.append(node("p", "", workflow.nextAction || "下一步待更新。"));
    focus.append(next);

    if (workflow.facts?.length) {
      const facts = node("dl", "flow-facts");
      for (const fact of workflow.facts) {
        const cell = node("div");
        cell.append(node("dt", "", fact?.label || "状态"));
        cell.append(node("dd", "", fact?.value ?? "待更新"));
        facts.append(cell);
      }
      focus.append(facts);
    }

    const evidenceHref = stageHref(workflow.primaryStage);
    if (evidenceHref) {
      const evidence = node("a", "focus-evidence-link", "查看本阶段验收详情 ↗");
      evidence.href = evidenceHref;
      focus.append(evidence);
    }

    if (workflow.alert?.title || workflow.alert?.detail) {
      const alert = node("aside", "focus-alert");
      alert.append(node("strong", "", workflow.alert.title || "待复核事项"));
      alert.append(node("p", "", workflow.alert.detail || "异常详情待更新。"));
      const alertHref = stageHref(workflow.alert.stage);
      if (alertHref) {
        const link = node("a", "", "查看相关阶段");
        link.href = alertHref;
        alert.append(link);
      }
      focus.append(alert);
    }

    layout.append(route, focus);
    target.append(layout);
  }

  const timelineStatusLabels = {
    done: "已完成",
    current: "进行中",
    pending: "待验收"
  };

  function formatTimelineTime(value) {
    if (!value) return null;
    const dateOnly = String(value).match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (dateOnly) return `${dateOnly[1]}/${dateOnly[2]}/${dateOnly[3]}`;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    const parts = new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Shanghai",
      year: "numeric",
      month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", hourCycle: "h23"
    }).formatToParts(date);
    const valueFor = type => parts.find(part => part.type === type)?.value;
    return `${valueFor("year")}/${valueFor("month")}/${valueFor("day")} ${valueFor("hour")}:${valueFor("minute")}`;
  }

  function renderTimeline() {
    const target = $("#development-timeline");
    if (!target) return;
    target.replaceChildren();

    const timeline = data?.timeline;
    if (!timeline || timeline.scope !== "project" || !Array.isArray(timeline.steps) || !timeline.steps.length) {
      target.hidden = true;
      return;
    }

    target.hidden = false;
    const heading = node("div", "timeline-heading");
    const headingCopy = node("div");
    headingCopy.append(node("div", "section-kicker", "PROJECT DEVELOPMENT"));
    headingCopy.append(node("h2", "", timeline.title || "开发总时间线"));
    headingCopy.append(node("p", "timeline-intro", timeline.summary || "记录关键开发阶段与首次进展，当前验收结果见本轮实测。"));
    const meta = node("div", "timeline-head-meta");
    meta.append(node("span", "timeline-scope", "项目全程"));
    meta.append(node("span", "timeline-timezone", "北京时间"));
    if (timeline.candidate) meta.append(node("span", "timeline-candidate", `数据快照 ${timeline.candidate}`));
    heading.append(headingCopy, meta);
    target.append(heading);

    const list = node("ol", "timeline-list");
    for (const [index, step] of timeline.steps.entries()) {
      if (!step || !Object.prototype.hasOwnProperty.call(timelineStatusLabels, step.status)) continue;
      const item = node("li", `timeline-step is-${step.status}`);
      const marker = node("span", "timeline-marker", step.status === "done" ? "✓" : String(index + 1));
      marker.setAttribute("aria-hidden", "true");
      const body = node("div", "timeline-entry");
      const top = node("div", "timeline-entry-top");
      top.append(node("h3", "timeline-label", step.label || "步骤待补充"));
      const entryMeta = node("div", "timeline-event-meta");
      if (step.candidate) entryMeta.append(node("span", "timeline-version", step.candidate));
      const stateLabel = step.stateLabel || timelineStatusLabels[step.status];
      entryMeta.append(node("span", "timeline-state", stateLabel));
      top.append(entryMeta);
      body.append(top);

      if (step.time && step.status !== "pending") {
        const formatted = formatTimelineTime(step.time);
        if (formatted) {
          const time = node("time", "timeline-time", formatted);
          time.dateTime = step.time;
          body.append(time);
        }
      } else if (step.status === "done" && !step.time) {
        body.append(node("span", "timeline-time timeline-time-unknown", "日期未记录"));
      }

      if (step.detail) body.append(node("p", "timeline-detail", step.detail));
      const href = stageHref(step.stage);
      if (href) {
        const link = node("a", "timeline-stage-link", "查看相关里程碑 ↗");
        link.href = href;
        body.append(link);
      }

      item.append(marker, body);
      list.append(item);
    }
    target.append(list);
  }

  function chip(label, tone = "pending") {
    return node("span", `status-chip tone-${tone}`, label || "待更新");
  }

  function nextCandidateStatus() {
    const next = data?.nextCandidate;
    const deployed = Boolean(next && /deployed.*waiting[_-]reboot|deployed_waiting_reboot/i.test(data?.deploymentState || ""));
    return {
      deployed,
      label: referenceRuntime ? (data?.nextCandidateRole || "当前博通对照") : (deployed ? "已部署候选" : "下一候选"),
      state: data?.nextCandidateState || (deployed ? "待重启验收" : "候选待验收"),
      tone: deployed ? "pending" : "working",
      subtitle: data?.nextCandidateSummary || (deployed ? "候选已部署，等待下一启动验收。" : "候选验收状态见本轮记录。")
    };
  }

  function nextCandidatePresentation() {
    const running = data?.runningCandidate || "当前版本";
    const next = data?.nextCandidate;
    const nextStatus = nextCandidateStatus();
    const workflow = currentWorkflow();

    if (nextStatus.deployed) {
      return {
        badge: `${next} 已部署 · 待重启验收`,
        ...nextStatus
      };
    }
    if (workflow) {
      return {
        badge: workflow.phaseLabel || "本轮实测",
        recordLabel: "本轮运行记录",
        recordState: data?.deploymentState === "test069_runtime_psf_anchor_missing"
          ? "本轮诊断完成"
          : workflow.phaseLabel || "本轮实测",
        tone: "working",
        subtitle: `${workflow.phaseLabel || "本轮实测"}，详情见本轮记录。`
      };
    }
    if (next) {
      return {
        badge: `${running} · 本轮流程摘要待更新`,
        recordLabel: "下一候选",
        recordState: "候选状态待更新",
        tone: "pending",
        subtitle: "候选状态待更新。"
      };
    }
    return {
      badge: `${running} · 本轮流程摘要待更新`,
      recordLabel: "本轮运行记录",
      recordState: "状态待更新",
      tone: "pending",
      subtitle: "本轮状态待更新。"
    };
  }

  function renderHeader() {
    const updated = $("#updated-at");
    const deployment = $("#deployment-label");
    const version = $("#current-version");
    if (version) version.textContent = (referenceRuntime && data?.currentRuntimeLabel) || data?.runningCandidate || "当前版本待核对";
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
    if (!cards) return;
    const section = cards.closest(".version-section");
    if (section) section.hidden = !data?.nextCandidate;
    const currentRecord = sourceRecords.find(record => record.version === data?.runningCandidate);
    const current = node("article", "version-card current");
    const currentState = data?.deploymentState === "test069_runtime_psf_anchor_missing"
      ? "本轮诊断完成"
      : currentRecord?.state || "运行状态待核验";
    const currentTop = node("div", "version-card-top");
    currentTop.append(node("span", "", referenceRuntime ? (data?.currentRecordRole || "最近Intel实测") : "当前运行"), node("span", `version-chip status-chip tone-${statusTone(currentState)}`, currentState));
    current.append(currentTop);
    current.append(node("h2", "version-id", data?.runningCandidate || "版本待补充"));
    const currentSummary = data?.deploymentState === "test069_runtime_psf_anchor_missing"
      ? "本轮诊断已结束；详情见流程摘要与版本记录。"
      : currentRecord?.short_summary || "运行证据与验收细节见版本记录。";
    current.append(node("p", "version-subtitle", currentSummary));

    const cardsToRender = [current];
    if (data?.nextCandidate && data.nextCandidate !== data?.runningCandidate) {
      const nextStatus = nextCandidateStatus();
      const next = node("article", "version-card next");
      const nextTop = node("div", "version-card-top");
      nextTop.append(node("span", "", nextStatus.label), node("span", `version-chip status-chip tone-${nextStatus.tone}`, nextStatus.state));
      next.append(nextTop);
      next.append(node("h2", "version-id", data.nextCandidate));
      next.append(node("p", "version-subtitle", nextStatus.subtitle));
      cardsToRender.push(next);
    }

    cards.replaceChildren(...cardsToRender);
  }

  const verdictLabels = {
    passed: "本轮通过", regressed: "本轮未通过", partial: "部分通过",
    not_covered: "未覆盖", not_implemented: "未覆盖"
  };
  const verdictTones = {
    passed: "success", regressed: "warning", partial: "working",
    not_covered: "pending", not_implemented: "pending"
  };
  function acceptanceCounts(checks, scope = "current") {
    const total = checks.length;
    const passed = scope === "history"
      ? checks.filter(check => check.history_verified === true).length
      : checks.filter(check => check.current_result === "passed").length;
    const percent = total ? Math.round(passed / total * 1000) / 10 : 0;
    return { total, passed, percent };
  }
  function acceptanceBar(checks, label, scope = "current") {
    const count = acceptanceCounts(checks, scope);
    const historical = scope === "history";
    const block = node("div", `acceptance-progress ${historical ? "history-progress" : "current-progress"}`);
    const heading = node("div", "progress-heading");
    heading.append(node("span", "progress-caption", label),
      node("strong", "progress-value", `${count.percent}%`));
    const track = node("div", "progress-track");
    track.setAttribute("role", "progressbar");
    track.setAttribute("aria-label", label);
    track.setAttribute("aria-valuemin", "0");
    track.setAttribute("aria-valuemax", "100");
    track.setAttribute("aria-valuenow", String(count.percent));
    track.setAttribute("aria-valuetext", historical
      ? `历史曾验收 ${count.passed} / ${count.total} 项，历史证据覆盖 ${count.percent}%，不代表当前版本已复验`
      : `${label} ${count.passed} / ${count.total} 项，${count.percent}%`);
    const fill = node("span", "progress-fill");
    fill.style.width = `${count.percent}%`;
    track.append(fill);
    const countText = historical
      ? `历史曾验收 ${count.passed} / ${count.total} 项 · 仅表示历史证据覆盖`
      : `本轮复验通过 ${count.passed} / ${count.total} 项`;
    block.append(heading, track, node("div", "progress-count", countText));
    return block;
  }
  function renderProgress() {
    const target = $("#progress-overview");
    if (!target) return;
    const checks = (data?.milestones || []).flatMap(m => m.checkpoints || []);
    if (!checks.length) return;
    const currentCounts = acceptanceCounts(checks);
    const history = acceptanceCounts(checks, "history");
    target.append(node("div", "section-kicker", "EVIDENCE COVERAGE · CURRENT RETEST"));
    const comparison = node("div", "progress-comparison");
    comparison.append(
      acceptanceBar(checks, "历史证据覆盖 · 历史曾验收", "history"),
      acceptanceBar(checks, evidenceScope || `${String(data?.runningCandidate || "本轮").split("-").pop()} · 本轮复验通过`)
    );
    target.append(comparison);
    target.append(node("p", "progress-explanation", referenceRuntime
      ? `当前使用博通采集对照；40项表保留最近一次Intel Test078实测 ${currentCounts.passed}/${currentCounts.total}，本次博通成功不计入Intel通过项。历史覆盖也不代表项目完成率。`
      : `历史曾验收 ${history.passed}/${history.total} 仅表示保留了历史证据，不代表当前版本复验，也不是项目完成率；本轮复验 ${currentCounts.passed}/${currentCounts.total} 只统计当前运行版本通过项。部分通过、未覆盖和未通过分别列出，未覆盖不代表失败。`));
    const sequence = node("div", "progress-sequence");
    sequence.append(node("span", "progress-sequence-label", "功能依赖顺序"),
      node("span", "progress-sequence-flow", "Wi-Fi / 资源 → 控制与时序 → 数据收发 → IPv6 / 服务发现 → 文件传输"));
    target.append(sequence);
    const current = node("div", "current-result-counts");
    current.append(node("span", "current-result-label", data?.validationLabel || `${data.runningCandidate} 本轮`));
    const countFor = keys => checks.filter(check => keys.includes(check.current_result)).length;
    current.append(chip(`本轮通过 ${countFor(["passed"])} 项`, verdictTones.passed));
    current.append(chip(`部分通过 ${countFor(["partial"])} 项`, verdictTones.partial));
    current.append(chip(`本轮未通过 ${countFor(["regressed"])} 项`, verdictTones.regressed));
    current.append(chip(`未覆盖 ${countFor(["not_covered", "not_implemented"])} 项`, verdictTones.not_covered));
    target.append(current);
  }

  function renderAcceptanceMatrix() {
    const target = $("#acceptance-matrix");
    const milestones = [...(data?.milestones || [])].sort((a, b) => a.stage - b.stage);
    const checks = milestones.flatMap(item => item.checkpoints || []);
    if (!target || milestones.length !== 8 || checks.length !== 40) return;

    let mode = "current";
    let selected = null;
    const heading = node("div", "matrix-heading");
    const titleCopy = node("div", "matrix-title-copy");
    titleCopy.append(node("div", "section-kicker", "FIXED ACCEPTANCE CHECKLIST"));
    const title = node("h2", "", `40 项固定验收 · ${evidenceScope || `${data.runningCandidate || "当前版本"} 本轮结果`}`);
    titleCopy.append(title, node("p", "", "按 8 个阶段查看 40 项验收。点选方格可查看证据和待补条件。"));
    const switcher = node("div", "matrix-switcher");
    switcher.setAttribute("role", "group");
    switcher.setAttribute("aria-label", "验收结果范围");
    const currentButton = node("button", "matrix-mode is-selected");
    currentButton.type = "button";
    currentButton.textContent = evidenceScope || `${data.runningCandidate || "本轮"} 本轮`;
    currentButton.setAttribute("aria-pressed", "true");
    const historyButton = node("button", "matrix-mode");
    historyButton.type = "button";
    historyButton.textContent = "历史曾验收";
    historyButton.setAttribute("aria-pressed", "false");
    switcher.append(currentButton, historyButton);
    heading.append(titleCopy, switcher);

    const summary = node("p", "matrix-summary");
    summary.setAttribute("aria-live", "polite");
    const legend = node("div", "matrix-legend");
    const scroll = node("div", "matrix-scroll");
    const table = node("table", "acceptance-matrix");
    table.setAttribute("aria-label", "8 阶段 40 项固定验收表");
    const thead = node("thead");
    const headerRow = node("tr");
    const firstHeader = node("th", "matrix-stage-head", "阶段");
    firstHeader.scope = "col";
    headerRow.append(firstHeader);
    for (let index = 1; index <= 5; index++) {
      const th = node("th", "matrix-col-head", `验收 ${index}`);
      th.scope = "col";
      headerRow.append(th);
    }
    thead.append(headerRow);
    const tbody = node("tbody");
    const detail = node("section", "matrix-detail");
    detail.id = "acceptance-matrix-detail";
    detail.hidden = true;
    detail.setAttribute("aria-live", "polite");

    const clearDetail = () => {
      selected = null;
      detail.hidden = true;
      detail.replaceChildren();
      table.querySelectorAll(".matrix-cell[aria-expanded='true']").forEach(button => button.setAttribute("aria-expanded", "false"));
    };

    const showDetail = (check, stage, button) => {
      const key = `${stage.stage}:${check.id}`;
      if (selected === key) {
        clearDetail();
        return;
      }
      table.querySelectorAll(".matrix-cell[aria-expanded='true']").forEach(item => item.setAttribute("aria-expanded", "false"));
      selected = key;
      button.setAttribute("aria-expanded", "true");
      detail.hidden = false;
      const currentStatus = verdictLabels[check.current_result] || "未覆盖";
      detail.replaceChildren(
        node("h3", "", check.name || "验收项"),
        node("p", "matrix-detail-label", `${stage.name} · ${mode === "current" ? currentStatus : (check.history_verified === true ? "历史曾验收" : "尚无完整验收记录")}`)
      );
      if (mode === "current") {
        detail.append(node("p", "", check.current_detail || "本轮证据待补充。"));
        if (check.history_verified === true) {
          detail.append(node("p", "matrix-detail-history", `历史曾验收：${check.verified_in || "历史版本记录"}。这不代表当前版本已复验。`));
        }
      } else {
        detail.append(node("p", "", check.history_verified === true
          ? `曾通过记录：${check.verified_in || "历史版本，详情待补充。"}`
          : "尚无完整历史验收记录。"));
        detail.append(node("p", "matrix-detail-current", `${data.runningCandidate || "本轮"} 当前结果：${currentStatus}。${check.current_detail || "本轮证据待补充。"}`));
      }
    };

    const updateSummary = () => {
      const counts = { passed: 0, partial: 0, regressed: 0, uncovered: 0 };
      for (const check of checks) {
        if (mode === "history") {
          if (check.history_verified === true) counts.passed++;
          else counts.uncovered++;
        } else if (check.current_result === "passed") counts.passed++;
        else if (check.current_result === "partial") counts.partial++;
        else if (check.current_result === "regressed") counts.regressed++;
        else counts.uncovered++;
      }
      summary.textContent = mode === "history"
        ? `历史曾验收 ${counts.passed} · 尚无完整验收记录 ${counts.uncovered}（不代表当前版本已通过）`
        : `${data.runningCandidate || "本轮"}：通过 ${counts.passed} · 部分通过 ${counts.partial} · 未通过 ${counts.regressed} · 未覆盖 ${counts.uncovered}（未覆盖不代表失败）`;
      const legendItems = mode === "history"
        ? [["passed", "✓", "历史曾验收"], ["not_covered", "", "尚无完整验收记录"]]
        : [["passed", "✓", "本轮通过"], ["partial", "−", "部分通过"], ["regressed", "!", "本轮未通过"], ["not_covered", "", "未覆盖（不是失败）"]];
      legend.replaceChildren(...legendItems.map(([status, symbol, label]) => {
        const item = node("span", "matrix-legend-item");
        const swatch = node("span", `matrix-swatch matrix-${status}`, symbol);
        swatch.setAttribute("aria-hidden", "true");
        item.append(swatch, node("span", "", label));
        return item;
      }));
    };

    const drawRows = () => {
      clearDetail();
      tbody.replaceChildren();
      for (const stage of milestones) {
        const row = node("tr");
        const rowHead = node("th", "matrix-row-head", stage.name || `阶段 ${stage.stage}`);
        rowHead.scope = "row";
        row.append(rowHead);
        for (const check of stage.checkpoints || []) {
          const verdict = mode === "history"
            ? (check.history_verified === true ? "passed" : "not_covered")
            : check.current_result;
          const statusText = mode === "history"
            ? (check.history_verified === true ? `历史曾验收：${check.verified_in || "版本详情未记录"}` : "尚无完整历史验收记录")
            : (verdictLabels[verdict] || "未覆盖");
          const button = node("button", `matrix-cell matrix-${verdict || "not_covered"}`);
          button.type = "button";
          button.setAttribute("aria-controls", detail.id);
          button.setAttribute("aria-expanded", "false");
          button.setAttribute("aria-label", `${stage.name}，${check.name}；${statusText}`);
          button.title = `${check.name}：${statusText}`;
          const symbol = verdict === "passed" ? "✓" : verdict === "partial" ? "−" : verdict === "regressed" ? "!" : "";
          if (symbol) {
            const icon = node("span", "matrix-symbol", symbol);
            icon.setAttribute("aria-hidden", "true");
            button.append(icon);
          }
          button.addEventListener("click", () => showDetail(check, stage, button));
          const cell = node("td", "matrix-cell-wrap");
          cell.append(button);
          row.append(cell);
        }
        tbody.append(row);
      }
      table.replaceChildren(thead, tbody);
      updateSummary();
    };

    currentButton.addEventListener("click", () => {
      mode = "current";
      currentButton.classList.add("is-selected");
      historyButton.classList.remove("is-selected");
      currentButton.setAttribute("aria-pressed", "true");
      historyButton.setAttribute("aria-pressed", "false");
      title.textContent = `40 项固定验收 · ${evidenceScope || `${data.runningCandidate || "当前版本"} 本轮结果`}`;
      drawRows();
    });
    historyButton.addEventListener("click", () => {
      mode = "history";
      historyButton.classList.add("is-selected");
      currentButton.classList.remove("is-selected");
      historyButton.setAttribute("aria-pressed", "true");
      currentButton.setAttribute("aria-pressed", "false");
      title.textContent = "40 项固定验收 · 历史曾验收";
      drawRows();
    });

    target.replaceChildren(heading, summary, legend, scroll, detail);
    scroll.append(table);
    drawRows();
  }

  function renderMilestones() {
    const list = $("#milestone-list");
    const items = Array.isArray(data?.milestones) ? data.milestones : [];
    const workflow = currentWorkflow();
    if (!items.length) {
      list.append(node("li", "empty-state", "当前没有可显示的里程碑记录。"));
      return;
    }

    for (const milestone of items) {
      const tone = verdictTones[milestone.current_result] || milestone.status_tone || "pending";
      const item = node("li", `milestone-item tone-${tone}`);
      item.id = `stage-${milestone.stage}`;
      item.dataset.verified = String(milestone.current_result === "passed");
      item.dataset.pending = String(milestone.has_pending_work !== false);
      item.dataset.currentResult = milestone.current_result || "";
      item.append(node("span", "stage-node"));

      const details = node("details", "milestone-card");
      details.open = Boolean(workflow && stageKey(workflow.primaryStage) === stageKey(milestone.stage));
      const summary = node("summary", "milestone-summary");
      summary.append(node("span", "stage-number", String(milestone.stage).padStart(2, "0")));
      const copy = node("div", "summary-copy");
      copy.append(node("strong", "", milestone.name || "未命名阶段"));
      const summaryBadges = node("span", "stage-statuses");
      const checks = milestone.checkpoints || [];
      if (checks.length) {
        const currentCounts = acceptanceCounts(checks);
        summaryBadges.append(chip(`本轮通过 ${currentCounts.passed}/${currentCounts.total}`, currentCounts.passed ? "success" : "pending"));
      }
      const currentVerdict = verdictLabels[milestone.current_result] || milestone.current_result_label || milestone.status;
      summaryBadges.append(chip(currentVerdict, tone));
      copy.append(summaryBadges);
      const brief = node("div", "stage-brief");
      brief.append(node("p", "", milestone.stage_brief || milestone.current_result_label || milestone.status || "本轮摘要待更新"));
      copy.append(brief);
      summary.append(copy, node("span", "disclosure-chevron"));
      details.append(summary);
      if (checks.length) {
        const proof = node("div", "stage-proof");
        proof.append(acceptanceBar(checks, `本轮实测通过 ${acceptanceCounts(checks).passed} / ${checks.length}`));
        const checklist = node("details", "checkpoint-details");
        checklist.append(node("summary", "", "查看固定验收清单 · 5 项"));
        const entries = node("ul", "checkpoint-list");
        for (const check of checks) {
          const entry = node("li", "checkpoint-item");
          const name = node("div", "checkpoint-title");
          const passed = check.current_result === "passed";
          name.append(node("span", passed ? "checkpoint-verified" : "checkpoint-open", passed ? "✓" : "○"), node("strong", "", check.name));
          const current = node("div", "checkpoint-current");
          current.append(chip(verdictLabels[check.current_result], verdictTones[check.current_result]), node("span", "", check.current_detail));
          entry.append(name, current); entries.append(entry);
        }
        checklist.append(entries); proof.append(checklist); details.append(proof);
      }

      const body = node("dl", "milestone-details");
      const fields = [
        ["本轮实测", milestone.current_summary, "current_summary"],
        ["当前缺口", milestone.unfinished_summary, "unfinished_summary"],
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
      empty.textContent = filter === "verified" ? "本轮没有通过项。" : "目前没有待解决阶段。";
    }
    const summary = $("#filter-summary");
    if (summary) summary.textContent = `显示 ${visibleCount} / ${items.length} 个阶段`;
  }

  function installMilestoneControls() {
    document.querySelectorAll("[data-stage-filter]").forEach(button => {
      if (button.dataset.stageFilter === "regressed") button.textContent = "本轮未通过";
      if (button.dataset.stageFilter === "verified") button.textContent = "本轮通过";
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
    return nextCandidateStatus();
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
        summary: `${state.subtitle || "候选状态待更新。"} 尚无该版本运行验收结果。`,
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
      record.label = "本轮运行记录";
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
    const currentVersion = data?.runningCandidate;
    const nextVersion = data?.nextCandidate;

    if (currentVersion) {
      const current = recordForCandidate(currentVersion, "current");
      entries.push(current);
    }
    if (nextVersion && nextVersion !== currentVersion) {
      const next = recordForCandidate(nextVersion, "next");
      entries.push(next);
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
    if (!nav) return;
    nav.replaceChildren();
    for (const entry of entries) {
      const link = node("a");
      link.href = `#${entry.id}`;
      link.append(node("span", "record-jump-version", entry.version || "版本待补充"));
      link.append(node("span", "", entry.label || "测试记录"));
      nav.append(link);
    }
  }

  function createRecordCard(record) {
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
    return card;
  }

  function renderRecords(entries) {
    const list = $("#record-list");
    if (!list) return;
    if (!entries.length) {
      list.append(node("p", "empty-state", "测试记录将在证据确认后补充。"));
      return;
    }

    for (const record of entries) list.append(createRecordCard(record));
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
    let target = null;
    if (/^#(?:stage-|record-)/.test(hash)) {
      target = document.getElementById(hash.slice(1));
      if (target?.closest(".milestone-item")) {
        const milestone = target.closest(".milestone-item");
        if (milestone.hidden) applyFilter("all");
        const details = milestone.querySelector(".milestone-card");
        if (details) details.open = true;
      }
      if (target) requestAnimationFrame(() => target.scrollIntoView({ block: "start" }));
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
  renderWorkflow();
  renderTimeline();
  renderProgress();
  renderAcceptanceMatrix();
  renderMilestones();
  installMilestoneControls();
  const recordEntries = getRecordEntries();
  renderRecordJump(recordEntries);
  renderRecords(recordEntries);
  renderAcceptance();
  applyFilter("all");
  installHashNavigation();
})();
