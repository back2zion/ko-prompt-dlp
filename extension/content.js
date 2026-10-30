/* Intercepts the submit action on supported AI chat pages, sends the prompt to
   the AX Filter API through the background worker, and applies the verdict.

   Note: these sites are React apps whose DOM changes often; the selectors in
   filter-core.js are best-effort and may need updates when a site's UI changes. */
(function () {
  "use strict";
  var Core = window.AXFilterCore;
  var site = Core && Core.siteFor(location.hostname);
  if (!site) return;

  var bypassOnce = false;   // set after an "allow" verdict so the real send goes through
  var busy = false;

  function findEditor() {
    for (var i = 0; i < site.editors.length; i++) {
      var el = document.querySelector(site.editors[i]);
      if (el) return el;
    }
    return null;
  }
  function findSendButton() {
    for (var i = 0; i < site.sendButtons.length; i++) {
      var el = document.querySelector(site.sendButtons[i]);
      if (el) return el;
    }
    return null;
  }
  function readText(el) {
    if (!el) return "";
    return (el.value != null ? el.value : el.innerText || el.textContent || "").trim();
  }
  function writeText(el, text) {
    if (!el) return;
    if (el.value != null) {
      el.value = text;
      el.dispatchEvent(new Event("input", { bubbles: true }));
    } else {
      el.innerText = text;
      el.dispatchEvent(new InputEvent("input", { bubbles: true }));
    }
  }

  function banner(kind, message, findings) {
    var id = "axfilter-banner";
    var old = document.getElementById(id);
    if (old) old.remove();
    var el = document.createElement("div");
    el.id = id;
    var color = kind === "block" ? "#e03131" : (kind === "mask" ? "#e8a13a" : "#2f9e6f");
    var types = (findings || []).map(function (f) { return f.label; });
    var uniq = types.filter(function (v, i) { return types.indexOf(v) === i; });
    el.setAttribute("role", "alert");
    el.style.cssText = [
      "position:fixed", "left:50%", "top:18px", "transform:translateX(-50%)",
      "z-index:2147483647", "max-width:560px", "width:calc(100% - 32px)",
      "background:#fff", "color:#1a2233", "border:1px solid " + color,
      "border-left:5px solid " + color, "border-radius:10px", "padding:12px 14px",
      "box-shadow:0 8px 28px rgba(20,30,60,.18)", "font:14px/1.5 system-ui,sans-serif"
    ].join(";");
    var head = kind === "block" ? "전송 차단" : (kind === "mask" ? "마스킹 적용됨" : "검사 통과");
    el.innerHTML = '<strong style="color:' + color + '">AX필터 · ' + head + "</strong>" +
      '<div style="margin-top:4px">' + message + "</div>" +
      (uniq.length ? '<div style="margin-top:6px;color:#6b7687;font-size:12px">검출: ' +
        uniq.join(", ") + "</div>" : "");
    document.documentElement.appendChild(el);
    if (kind !== "block") setTimeout(function () { if (el.parentNode) el.remove(); }, 5000);
  }

  function inspect(text) {
    return new Promise(function (resolve) {
      chrome.runtime.sendMessage({
        type: "axfilter:inspect",
        payload: { service: site.service, ip: "0.0.0.0", user: "extension", text: text, direction: "input" }
      }, resolve);
    });
  }

  async function guard(triggerSend) {
    if (busy) return;
    var editor = findEditor();
    var text = readText(editor);
    if (!text) { if (triggerSend) triggerSend(); return; }
    busy = true;
    try {
      var resp = await inspect(text);
      var action = Core.interpret(resp);
      if (action.kind === "allow") {
        bypassOnce = true;
        if (triggerSend) triggerSend();
      } else if (action.kind === "mask") {
        writeText(editor, action.text);
        banner("mask", action.message, action.findings);   // user reviews, then sends again
      } else {
        banner("block", action.message, action.findings);
      }
    } finally {
      busy = false;
    }
  }

  // Enter to send (without Shift). Capture phase so we run before the site handler.
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
    var editor = findEditor();
    if (!editor || !(e.target === editor || editor.contains(e.target))) return;
    if (bypassOnce) { bypassOnce = false; return; }   // let the allowed send through
    e.preventDefault();
    e.stopImmediatePropagation();
    guard(function () {
      // replay the Enter so the site sends the (now cleared) prompt
      editor.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
    });
  }, true);

  // Send button click.
  document.addEventListener("click", function (e) {
    var btn = findSendButton();
    if (!btn) return;
    if (!(e.target === btn || btn.contains(e.target))) return;
    if (bypassOnce) { bypassOnce = false; return; }
    e.preventDefault();
    e.stopImmediatePropagation();
    guard(function () { btn.click(); });
  }, true);
})();
