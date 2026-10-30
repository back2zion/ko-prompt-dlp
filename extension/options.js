"use strict";
const $ = (id) => document.getElementById(id);

chrome.storage.sync.get(["apiBase", "apiKey", "enabled", "failMode"]).then((d) => {
  $("apiBase").value = d.apiBase || "";
  $("apiKey").value = d.apiKey || "";
  $("enabled").checked = d.enabled !== false;
  $("failMode").value = d.failMode || "block";
});

$("save").addEventListener("click", async () => {
  const cfg = {
    apiBase: $("apiBase").value.trim().replace(/\/$/, ""),
    apiKey: $("apiKey").value.trim(),
    enabled: $("enabled").checked,
    failMode: $("failMode").value
  };
  await chrome.storage.sync.set(cfg);
  const s = $("status");
  if (!cfg.apiBase || !cfg.apiKey) { s.className = "status bad"; s.textContent = "주소와 키를 입력하세요."; return; }
  s.className = "status"; s.textContent = "연결 확인 중...";
  try {
    const r = await fetch(cfg.apiBase + "/v1/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": cfg.apiKey },
      body: JSON.stringify({ service: "ChatGPT", ip: "0.0.0.0", user: "options", text: "연결 확인" })
    });
    if (r.ok) { s.className = "status ok"; s.textContent = "저장됨 · 서버 연결 정상"; }
    else { s.className = "status bad"; s.textContent = "저장됨 · 서버 응답 오류 HTTP " + r.status; }
  } catch (e) {
    s.className = "status bad"; s.textContent = "저장됨 · 연결 실패: " + e.message;
  }
});
