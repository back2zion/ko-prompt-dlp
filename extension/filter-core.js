/* Shared logic, free of DOM and extension APIs so it can be unit-tested.
   Exposed on window.AXFilterCore (browser) and module.exports (Node). */
(function (root) {
  "use strict";

  // Which editable + send-button selectors to try, per host. First match wins.
  var SITES = [
    { host: /(^|\.)chatgpt\.com$|(^|\.)chat\.openai\.com$/, service: "ChatGPT",
      editors: ["#prompt-textarea", "div[contenteditable='true']", "textarea"],
      sendButtons: ["button[data-testid='send-button']", "button[aria-label*='Send']"] },
    { host: /(^|\.)claude\.ai$/, service: "Claude",
      editors: ["div[contenteditable='true']", "textarea"],
      sendButtons: ["button[aria-label*='Send']", "button[aria-label*='전송']"] },
    { host: /(^|\.)gemini\.google\.com$/, service: "Gemini",
      editors: ["div[contenteditable='true']", "textarea.ql-editor", "textarea"],
      sendButtons: ["button[aria-label*='Send']", "button.send-button"] }
  ];

  function siteFor(hostname) {
    for (var i = 0; i < SITES.length; i++) if (SITES[i].host.test(hostname)) return SITES[i];
    return null;
  }

  // Interpret an /v1/inspect response into a UI action.
  function interpret(resp) {
    if (resp.action === "block") {
      return { kind: "block", message: resp.message || "전송이 차단되었습니다.",
               findings: resp.findings || [] };
    }
    if (resp.action === "mask") {
      return { kind: "mask", text: resp.text, findings: resp.findings || [],
               message: "민감정보를 마스킹했습니다. 확인 후 전송하세요." };
    }
    return { kind: "allow", findings: resp.findings || [] };
  }

  var api = { SITES: SITES, siteFor: siteFor, interpret: interpret };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.AXFilterCore = api;
})(typeof window !== "undefined" ? window : globalThis);
