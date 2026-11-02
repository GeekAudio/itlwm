/* Check the live manifest on each visit, including back/forward restoration. */
(function () {
  "use strict";

  function installFreshness(win) {
    const doc = win.document;
    const loaded = doc.querySelector('meta[name="iw-site-version"]')?.content;
    let active = null;
    let state = { text: "正在检查更新", tone: "checking", retry: false };

    function paint() {
      const label = doc.getElementById("site-freshness");
      const button = doc.getElementById("site-refresh-retry");
      if (label) {
        label.textContent = state.text;
        label.dataset.state = state.tone;
      }
      if (button) {
        button.hidden = !state.retry;
        button.onclick = () => checkLatest(true);
      }
    }

    function status(text, tone, retry = false) {
      state = { text, tone, retry };
      paint();
    }

    function nonce() {
      return win.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`;
    }

    async function checkLatest(manual = false) {
      if (!/^https?:$/.test(win.location.protocol)) {
        status("离线文件，未检查线上更新", "offline");
        return;
      }
      if (active) return;
      const controller = new win.AbortController();
      active = controller;
      const timer = win.setTimeout(() => controller.abort(), 8000);
      status("正在检查更新", "checking");
      try {
        const manifestURL = new URL("./site-version.json", win.location.href);
        manifestURL.searchParams.set("check", nonce());
        const response = await win.fetch(manifestURL.href, {
          cache: "no-store", credentials: "omit", signal: controller.signal
        });
        if (!response.ok) throw new Error("manifest unavailable");
        const manifest = await response.json();
        if (active !== controller) return;
        if (manifest.schema !== 1 || !/^[a-f0-9]{64}$/.test(manifest.version)) {
          throw new Error("invalid manifest");
        }
        if (loaded === manifest.version) {
          status("已核对最新发布", "current");
          return;
        }
        const target = new URL(win.location.href);
        // If the edge served old HTML even for the requested revision, stop
        // instead of creating an automatic reload loop during publication.
        if (!manual && target.searchParams.get("v") === manifest.version &&
            target.searchParams.has("fresh")) {
          status("新版正在同步，当前显示旧版", "pending", true);
          return;
        }
        target.searchParams.set("v", manifest.version);
        target.searchParams.set("fresh", nonce());
        status("发现新版，正在更新", "updating");
        win.location.replace(target.href); // Preserves the current chapter hash.
      } catch (_) {
        if (active === controller) {
          status("未能检查更新，当前版本可能已过期", "unverified", true);
        }
      } finally {
        win.clearTimeout(timer);
        if (active === controller) active = null;
      }
    }

    doc.addEventListener("DOMContentLoaded", paint);
    win.addEventListener("pageshow", () => checkLatest());
    win.addEventListener("online", () => checkLatest());
    win.addEventListener("pagehide", () => {
      const previous = active;
      active = null;
      previous?.abort();
    });
    doc.addEventListener("visibilitychange", () => {
      if (doc.visibilityState === "visible") checkLatest();
    });
    paint();
    return { checkLatest };
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { installFreshness };
  } else {
    installFreshness(window);
  }
})();
