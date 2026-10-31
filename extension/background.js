/* Service worker: performs the inspect call so the content script never needs
   cross-origin fetch from the page context. Config comes from chrome.storage. */
"use strict";

async function getManaged(keys) {
  // Enterprise policy (chrome.storage.managed) overrides per-user settings.
  // Absent or unsupported: return {} so behavior falls back to storage.sync.
  try {
    if (chrome.storage && chrome.storage.managed) {
      const m = await chrome.storage.managed.get(keys);
      const out = {};
      for (const k of keys) if (m && m[k] !== undefined && m[k] !== null) out[k] = m[k];
      return out;
    }
  } catch (e) { /* managed storage unavailable */ }
  return {};
}

async function getConfig() {
  const keys = ["apiBase", "apiKey", "enabled", "failMode"];
  const sync = await chrome.storage.sync.get(keys);
  const managed = await getManaged(keys);
  const d = Object.assign({}, sync, managed);  // policy wins when set
  return {
    apiBase: (d.apiBase || "").replace(/\/$/, ""),
    apiKey: d.apiKey || "",
    enabled: d.enabled !== false,
    failMode: d.failMode || "block"   // if the API is unreachable: "block" (safe) or "allow"
  };
}

async function inspect(payload) {
  const cfg = await getConfig();
  if (!cfg.enabled) return { action: "allow", _skipped: true };
  if (!cfg.apiBase || !cfg.apiKey) return { action: "allow", _unconfigured: true };
  try {
    const r = await fetch(cfg.apiBase + "/v1/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": cfg.apiKey },
      body: JSON.stringify(payload)
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    return await r.json();
  } catch (e) {
    // Fail safe by default: when we cannot verify, block rather than leak.
    if (cfg.failMode === "allow") return { action: "allow", _error: String(e) };
    return { action: "block", message: "AX필터 서버에 연결할 수 없어 전송을 보류했습니다. (" + e + ")",
             findings: [], _error: String(e) };
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "axfilter:inspect") {
    inspect(msg.payload).then(sendResponse);
    return true;  // async
  }
});
