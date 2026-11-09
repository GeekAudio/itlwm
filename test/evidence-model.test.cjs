const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.join(__dirname, "..");
const siteSource = fs.readFileSync(path.join(root, "assets", "site.js"), "utf8");
const context = { window: {} };
vm.runInNewContext(fs.readFileSync(path.join(root, "data.js"), "utf8"), context);
vm.runInNewContext(fs.readFileSync(path.join(root, "assets", "test-records.js"), "utf8"), context);
const data = JSON.parse(JSON.stringify(context.window.PROGRESS_DATA));
const records = JSON.parse(JSON.stringify(context.window.TEST_RECORDS));
const scopeStart = siteSource.indexOf("  const lineageScope = Object.freeze({");
const scopeEnd = siteSource.indexOf("  const evidenceMatches =", scopeStart);
const sourceStart = siteSource.indexOf("  const evidenceModel = {");
const marker = "  window.PROGRESS_EVIDENCE_MODEL = evidenceModel;";
const sourceEnd = siteSource.indexOf(marker, sourceStart) + marker.length;
assert.ok(scopeStart >= 0 && scopeEnd > scopeStart && sourceStart > scopeEnd && sourceEnd > sourceStart, "evidence model and scope can be extracted");
const modelContext = { window: {}, labels: { passed: "通过", partial: "部分通过", regressed: "未通过", not_covered: "未覆盖" } };
const modelSource = siteSource.slice(scopeStart, scopeEnd) + siteSource.slice(sourceStart, sourceEnd);
new Function("window", "labels", modelSource)(modelContext.window, modelContext.labels);
const model = modelContext.window.PROGRESS_EVIDENCE_MODEL;
const points = data.milestones.flatMap(stage => stage.checkpoints);
const point = (id, sourceData = data) => sourceData.milestones.flatMap(stage => stage.checkpoints).find(item => item.id === id);
const rawCounts = () => Object.fromEntries(["passed", "partial", "regressed", "not_covered"]
  .map(state => [state, points.filter(item => item.current_result === state).length]));

test("exact Test127 driver provenance and Test128 receipt derives only 2-1 and 2-3", () => {
  assert.equal(model.aligned(data, records), true);
  assert.equal(model.classify(data, point("2-1"), records).kind, "derived");
  assert.equal(model.classify(data, point("2-1"), records).status, "间接验证通过");
  assert.equal(model.classify(data, point("2-3"), records).kind, "derived");
  assert.equal(model.classify(data, point("5-3"), records).kind, "direct");
  assert.equal(model.classify(data, point("3-1"), records).kind, "direct");
  assert.equal(model.classify(data, point("6-4"), records).kind, "direct");
  assert.equal(model.classify(data, point("2-2"), records).kind, "scope");
  assert.equal(model.relations.find(edge => edge.from === "2-1").to, "5-3");
  assert.equal(model.relations.find(edge => edge.from === "2-3").to, "5-3");
});

test("the fixed 40 raw statuses and their counts are preserved", () => {
  const before = JSON.stringify(data.milestones);
  assert.equal(points.length, 40);
  assert.deepEqual(rawCounts(), { passed: 10, partial: 4, regressed: 1, not_covered: 25 });
  assert.equal(points.filter(item => model.classify(data, item, records).kind === "derived").length, 2);
  assert.equal(JSON.stringify(data.milestones), before, "classification does not mutate raw records");
});

test("cross-round, wrong build, wrong UUID, wrong tool commit, and missing provenance do not transfer", () => {
  const cases = [
    { data, records: records.map(r => ({ ...r, provenance: { ...r.provenance, toolRound: "Test129" } })) },
    { data: { ...data, validationLabel: "Test127 驱动 · Test129 对照实测" }, records },
    { data, records: records.map(r => ({ ...r, provenance: { ...r.provenance, driverSourceCommit: "other" } })) },
    { data, records: records.map(r => ({ ...r, provenance: { ...r.provenance, driverUuid: "other" } })) },
    { data, records: records.map(r => ({ ...r, provenance: { ...r.provenance, toolSourceCommit: "other" } })) },
    { data, records: records.map(r => ({ id: r.id, version: r.version, state: r.state })) }
  ];
  for (const fixture of cases)
    assert.equal(model.classify(fixture.data, point("2-1"), fixture.records).kind, "scope");
});

test("completion must match the exact queue, station, descriptor, status, and round receipt", () => {
  const mutate = change => {
    const next = JSON.parse(JSON.stringify(data));
    change(point("5-3", next), next);
    return next;
  };
  const wrongIdentity = mutate(tx => { tx.current_detail = tx.current_detail.replace("queue4/station3/descriptor0", "queue5/station3/descriptor0"); });
  const noCompletion = mutate(tx => { tx.current_detail = tx.current_detail.replace("TX completion=1", "TX completion=0"); });
  const noSuccess = mutate(tx => { tx.current_result = "partial"; });
  const noElapsedReceipt = records.map(r => ({ ...r, summary: r.summary.replaceAll("49.364 ms", "48.000 ms"), evidence: r.evidence.map(e => e.replaceAll("49.364 ms", "48.000 ms")) }));
  assert.equal(model.classify(wrongIdentity, point("2-3", wrongIdentity), records).kind, "scope");
  assert.equal(model.classify(noCompletion, point("2-1", noCompletion), records).kind, "scope");
  assert.equal(model.classify(noSuccess, point("2-1", noSuccess), records).kind, "scope");
  assert.equal(model.classify(data, point("2-1"), noElapsedReceipt).kind, "scope");
});

test("partial and negative raw statuses are never promoted", () => {
  const altered = JSON.parse(JSON.stringify(data));
  point("2-1", altered).current_result = "regressed";
  point("2-3", altered).current_result = "partial";
  assert.equal(model.classify(altered, point("2-1", altered), records).kind, "direct");
  assert.equal(model.classify(altered, point("2-1", altered), records).status, "未通过");
  assert.equal(model.classify(altered, point("2-3", altered), records).status, "部分通过");
  assert.equal(model.classify(data, point("2-4"), records).status, "未通过");
  assert.equal(model.classify(data, point("5-4"), records).status, "部分通过");
});

test("one successful TX does not infer broadcast, cleanup, radio ACK, repeat, or AirDrop", () => {
  for (const id of ["2-2", "2-4", "5-4", "5-5", "8-1", "8-2", "8-3", "8-4", "8-5"])
    assert.notEqual(model.classify(data, point(id), records).kind, "derived", id);
  assert.equal(model.classify(data, point("2-4"), records).status, "未通过");
  assert.equal(model.classify(data, point("5-4"), records).status, "部分通过");
});

test("every dependency edge has a correct direction, explicit scope, and pinned code links", () => {
  for (const edge of model.relations) {
    assert.ok(edge.from && edge.to);
    assert.match(edge.scope, /本轮/);
    assert.ok(edge.sources.length > 0);
    assert.ok(edge.sources.every(source =>
      /^https:\/\/github\.com\/GeekAudio\/itlwm\/blob\/(d667e9edeaf06c14bc798016d2c2f80f835f294c|1196bfa7b01cb3d0dc0ce06ec95096021292fcc5)\//.test(source.url)));
  }
});
