"use strict";
const $ = (id) => document.getElementById(id);
const KEYS = ["apiBase", "apiKey", "enabled", "failMode"];

// Managed (enterprise-policy) values are read-only and take precedence over the
// per-user chrome.storage.sync values. When no policy is set, chrome.storage.managed
// returns an empty object (or is unavailable), so behavior is unchanged.
async function getManaged() {
  try {
    if (chrome.storage && chrome.storage.managed) {
      const m = await chrome.storage.managed.get(KEYS);
      // Keep only keys an admin actually set (drop undefined / null).
      const out = {};
      for (const k of KEYS) if (m && m[k] !== undefined && m[k] !== null) out[k] = m[k];
      return out;
    }
  } catch (e) { /* managed storage not available: fall back to sync */ }
  return {};
}

(async () => {
  const managed = await getManaged();
  const sync = await chrome.storage.sync.get(KEYS);
  const eff = Object.assign({}, sync, managed); // managed wins when present

  $("apiBase").value = eff.apiBase || "";
  $("apiKey").value = eff.apiKey || "";
  $("enabled").checked = eff.enabled !== false;
  $("failMode").value = eff.failMode || "block";

  // Lock down any field an administrator has fixed via policy.
  const locked = [];
  for (const k of KEYS) {
    if (!(k in managed)) continue;
    const el = $(k);
    if (!el) continue;
    el.disabled = true;
    el.title = "조직 정책으로 설정됨 (관리자 전용)";
    locked.push(k);
  }

  if (locked.length) {
    const banner = $("managed");
    if (banner) {
      banner.textContent = "일부 설정이 조직 정책으로 고정되어 있습니다 (관리자 전용): " + locked.join(", ");
      banner.hidden = false;
    }
    // If every setting is policy-managed, there is nothing left for the user to save.
    if (locked.length === KEYS.length) {
      const btn = $("save");
      if (btn) btn.disabled = true;
    }
  }

  $("save").addEventListener("click", async () => {
    // Only persist fields that are NOT managed; managed values are read-only.
    const cfg = {
      apiBase: $("apiBase").value.trim().replace(/\/$/, ""),
      apiKey: $("apiKey").value.trim(),
      enabled: $("enabled").checked,
      failMode: $("failMode").value
    };
    const toSave = {};
    for (const k of KEYS) if (!(k in managed)) toSave[k] = cfg[k];
    if (Object.keys(toSave).length) await chrome.storage.sync.set(toSave);

    // Effective values used for the connection check (managed overrides saved).
    const effCfg = Object.assign({}, cfg, managed);
    effCfg.apiBase = (effCfg.apiBase || "").replace(/\/$/, "");

    const s = $("status");
    if (!effCfg.apiBase || !effCfg.apiKey) { s.className = "status bad"; s.textContent = "주소와 키를 입력하세요."; return; }
    s.className = "status"; s.textContent = "연결 확인 중...";
    try {
      const r = await fetch(effCfg.apiBase + "/v1/inspect", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": effCfg.apiKey },
        body: JSON.stringify({ service: "ChatGPT", ip: "0.0.0.0", user: "options", text: "연결 확인" })
      });
      if (r.ok) { s.className = "status ok"; s.textContent = "저장됨 · 서버 연결 정상"; }
      else { s.className = "status bad"; s.textContent = "저장됨 · 서버 응답 오류 HTTP " + r.status; }
    } catch (e) {
      s.className = "status bad"; s.textContent = "저장됨 · 연결 실패: " + e.message;
    }
  });
})();
