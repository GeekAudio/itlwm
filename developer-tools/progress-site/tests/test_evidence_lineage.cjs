const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

const SITE = path.resolve(__dirname, "..");
const asset = relative => fs.readFileSync(path.join(SITE, "dist", relative), "utf8");

function snapshot() {
  const window = {};
  vm.runInNewContext(asset("data.js"), { window });
  vm.runInNewContext(asset("assets/test-records.js"), { window });
  return {
    data: structuredClone(window.PROGRESS_DATA),
    records: structuredClone(window.TEST_RECORDS)
  };
}

class ElementStub {
  constructor(tagName = "div") {
    this.tagName = tagName;
    this.children = [];
    this.dataset = {};
    this.attributes = {};
    this.className = "";
    this.classList = { add: (...names) => {
      this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(" ");
    } };
    this.parentElement = null;
    this._text = "";
  }

  get childNodes() { return this.children; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(""); }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }

  append(...children) {
    for (const child of children) {
      if (child.parentElement) {
        const oldIndex = child.parentElement.children.indexOf(child);
        if (oldIndex >= 0) child.parentElement.children.splice(oldIndex, 1);
      }
      child.parentElement = this;
      this.children.push(child);
    }
  }

  replaceChildren(...children) { this.children = []; this._text = ""; this.append(...children); }
  before(child) {
    if (!this.parentElement) return;
    const siblings = this.parentElement.children;
    const index = siblings.indexOf(this);
    if (child.parentElement) {
      const oldIndex = child.parentElement.children.indexOf(child);
      if (oldIndex >= 0) child.parentElement.children.splice(oldIndex, 1);
    }
    child.parentElement = this.parentElement;
    siblings.splice(index, 0, child);
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener() {}
  scrollIntoView() {}
  focus() {}
}

function render({ data, records }) {
  const root = new ElementStub("document");
  const head = new ElementStub("head");
  const main = new ElementStub("main");
  root.append(head, main);
  const elements = new Map();
  const add = (id, parent = main) => {
    const element = new ElementStub();
    element.id = id;
    elements.set(`#${id}`, element);
    parent.append(element);
    return element;
  };
  const overview = add("overview");
  add("current-summary", overview);
  add("progress-overview", overview);
  for (const id of ["version-panel", "updated-at", "focus-area", "matrix-content", "next-content", "next-step", "acceptance-matrix"])
    add(id);

  const findById = id => {
    const visit = node => node.id === id ? node : node.children.map(visit).find(Boolean);
    return visit(root);
  };
  const document = {
    head,
    createElement: tag => new ElementStub(tag),
    querySelector: selector => elements.get(selector) || null,
    getElementById: findById
  };
  const window = { PROGRESS_DATA: data, TEST_RECORDS: records, addEventListener() {} };
  vm.runInNewContext(asset("assets/site.js"), {
    window,
    document,
    location: { hash: "" },
    history: { replaceState() {} }
  });
  const all = [];
  const visit = node => { all.push(node); node.children.forEach(visit); };
  visit(root);
  return { window, all, findById };
}

function test132Fixture() {
  const { data, records } = snapshot();
  const record = records[0];
  data.runningCandidate = "25G416-Test132";
  data.validationLabel = "Test132 实机验证";
  record.id = "record-fixture-test132";
  record.version = data.runningCandidate;
  record.label = "Fixture Test132 provenance alignment";
  record.state = "Test132 fixture TX completion evidence";
  record.summary = "TEST132_RECORD_SENTINEL: fixture only; not a historical result.";
  record.provenance.driverCandidate = data.runningCandidate;
  record.provenance.driverSourceCommit = "a".repeat(40);
  record.provenance.driverUuid = "11111111-2222-3333-4444-555555555555";
  record.provenance.toolRound = "Test132";
  record.provenance.toolSourceCommit = "b".repeat(40);
  record.provenance.sources = [{ label: "Fixture source", url: "https://example.test/test132" }];
  record.evidence = ["queue4/station3/descriptor0 TX completion被观察到，固件状态报告成功，27.934 ms"];
  const tx = data.milestones.flatMap(stage => stage.checkpoints).find(point => point.id === "5-3");
  tx.current_result = "passed";
  tx.current_detail = "queue4/station3/descriptor0 TX completion=1，帧状态报告成功。";
  data.milestones.flatMap(stage => stage.checkpoints).find(point => point.id === "6-4").current_result = "not_covered";
  return { data, records };
}

test("current snapshot passes the gate and renders its 40-checkpoint core", () => {
  const fixture = snapshot();
  const result = render(fixture);
  assert.equal(result.findById("acceptance-title")?.textContent, `${fixture.data.validationLabel} · 40 项验收`);
  assert.equal(result.all.filter(element => /^check-\d+-\d+$/.test(element.id || "")).length,
    fixture.data.milestones.flatMap(stage => stage.checkpoints || []).length);
  assert.match(result.findById("recent-progress-title")?.textContent || "", /最近实测进展/);
});

test("matching Test132 provenance is accepted without inheriting Test129 indirect evidence", () => {
  const fixture = test132Fixture();
  const result = render(fixture);
  assert.match(result.findById("acceptance-title")?.textContent || "", /Test132.*40 项验收/);
  assert.equal(result.all.filter(element => /^check-\d+-\d+$/.test(element.id || "")).length, 40);
  assert.equal(result.window.PROGRESS_EVIDENCE_MODEL.classify(
    fixture.data,
    fixture.data.milestones.flatMap(stage => stage.checkpoints).find(point => point.id === "6-4"),
    fixture.records
  ).kind, "scope");
  assert.equal(result.all.filter(element => element.dataset.lineage === "derived").length, 0);
});

test("mismatched record provenance is rejected before its evidence can be rendered", () => {
  const { data, records } = snapshot();
  records[0].summary = "WRONG_VERSION_EVIDENCE_SENTINEL";
  records[0].evidence = ["WRONG_VERSION_EVIDENCE_SENTINEL"];
  records[0].provenance.driverCandidate = "25G416-Test132";
  const result = render({ data, records });
  assert.match(result.findById("current-summary")?.textContent || "", /尚未与运行版本对齐/);
  assert.equal(result.findById("acceptance-title")?.textContent, "验收数据待同步");
  assert.doesNotMatch(result.all.map(element => element._text).join(" "), /WRONG_VERSION_EVIDENCE_SENTINEL/);
});

test("round labels use an exact Test number, not a Test13 prefix", () => {
  const { data, records } = snapshot();
  const currentRound = data.runningCandidate.match(/Test(\d+)$/)?.[1];
  assert.ok(currentRound, "fixture candidate should carry a Test round");
  data.validationLabel = `Test${Number(currentRound) + 1} 实机验证`;
  const result = render({ data, records });
  assert.match(result.findById("current-summary")?.textContent || "", /尚未与运行版本对齐/);
  assert.equal(result.findById("acceptance-title")?.textContent, "验收数据待同步");
});
