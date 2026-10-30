/* Service worker: performs the inspect call so the content script never needs
   cross-origin fetch from the page context. Config comes from chrome.storage. */
"use strict";

async function getConfig() {
  const d = await chrome.storage.sync.get(["apiBase", "apiKey", "enabled", "failMode"]);
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
