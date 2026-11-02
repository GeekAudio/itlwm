const assert = require("node:assert/strict");
const { test } = require("node:test");
const { installFreshness } = require("../dist/assets/freshness.js");

const oldVersion = "a".repeat(64);
const newVersion = "b".repeat(64);
function browser({ loaded = oldVersion, latest = newVersion, url = "https://example.test/itlwm/milestones.html?other=1#stage-6", failure = false } = {}) {
  const label = { dataset: {} }, retry = { hidden: true };
  const events = {}, docEvents = {}, requests = [], redirects = [];
  let serial = 0;
  const win = {
    document: {
      visibilityState: "visible",
      querySelector: () => ({ content: loaded }),
      getElementById: id => id === "site-freshness" ? label : retry,
      addEventListener: (name, fn) => { docEvents[name] = fn; }
    },
    location: { href: url, protocol: new URL(url).protocol, replace: target => redirects.push(target) },
    crypto: { randomUUID: () => `request-${++serial}` },
    AbortController, setTimeout, clearTimeout,
    addEventListener: (name, fn) => { events[name] = fn; },
    fetch: async (target, options) => {
      requests.push({ target, options });
      if (failure) throw new Error("offline");
      return { ok: true, json: async () => ({ schema: 1, version: latest }) };
    }
  };
  return { win, label, retry, events, docEvents, requests, redirects, app: installFreshness(win) };
}

test("cached old entry requests a fresh manifest and keeps chapter/query when updating", async () => {
  const b = browser();
  await b.app.checkLatest();
  assert.equal(b.requests.length, 1);
  assert.equal(b.requests[0].options.cache, "no-store");
  assert.equal(b.requests[0].options.credentials, "omit");
  assert.ok(new URL(b.requests[0].target).searchParams.get("check"));
  const target = new URL(b.redirects[0]);
  assert.equal(target.hash, "#stage-6");
  assert.equal(target.searchParams.get("other"), "1");
  assert.equal(target.searchParams.get("v"), newVersion);
  assert.ok(target.searchParams.get("fresh"));
});

test("current entry checks on each pageshow including bfcache, without a reload", async () => {
  const b = browser({ latest: oldVersion });
  await b.events.pageshow({ persisted: false });
  await b.events.pageshow({ persisted: true });
  assert.equal(b.requests.length, 2);
  assert.notEqual(b.requests[0].target, b.requests[1].target);
  assert.deepEqual(b.redirects, []);
  assert.equal(b.label.dataset.state, "current");
});

test("CDN propagation mismatch stops automatic reloads; explicit retry remains available", async () => {
  const b = browser({ url: `https://example.test/itlwm/milestones.html?v=${newVersion}&fresh=previous#stage-4` });
  await b.app.checkLatest();
  assert.deepEqual(b.redirects, []);
  assert.equal(b.label.dataset.state, "pending");
  assert.equal(b.retry.hidden, false);
  await b.retry.onclick();
  assert.equal(b.redirects.length, 1);
});

test("returning to a visible tab and reconnecting each check the live revision", async () => {
  const b = browser({ latest: oldVersion });
  b.win.document.visibilityState = "hidden";
  b.docEvents.visibilitychange();
  assert.equal(b.requests.length, 0);
  b.win.document.visibilityState = "visible";
  b.docEvents.visibilitychange();
  await new Promise(setImmediate);
  assert.equal(b.label.dataset.state, "current");
  await b.events.online();
  assert.equal(b.requests.length, 2);
  assert.notEqual(b.requests[0].target, b.requests[1].target);
  assert.deepEqual(b.redirects, []);
});

test("offline or malformed manifest never reports current and never loops", async () => {
  for (const config of [{ failure: true }, { latest: "https://outside.invalid/" }]) {
    const b = browser(config);
    await b.app.checkLatest();
    assert.deepEqual(b.redirects, []);
    assert.equal(b.label.dataset.state, "unverified");
    assert.equal(b.retry.hidden, false);
  }
});

test("local standalone file remains usable without network requests", async () => {
  const b = browser({ url: "file:///saved/milestones.html#overview" });
  await b.app.checkLatest();
  assert.deepEqual(b.requests, []);
  assert.deepEqual(b.redirects, []);
  assert.equal(b.label.dataset.state, "offline");
});

test("pagehide cancels old fetch so it cannot overwrite a newly restored page check", async () => {
  const b = browser({ latest: oldVersion });
  let resolveOld;
  b.win.fetch = () => new Promise(resolve => { resolveOld = resolve; });
  const old = b.app.checkLatest();
  b.events.pagehide();
  b.win.fetch = async () => ({ ok: true, json: async () => ({ schema: 1, version: oldVersion }) });
  await b.events.pageshow({ persisted: true });
  resolveOld({ ok: true, json: async () => ({ schema: 1, version: newVersion }) });
  await old;
  assert.equal(b.label.dataset.state, "current");
  assert.deepEqual(b.redirects, []);
});
