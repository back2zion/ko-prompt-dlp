// End-to-end: run content.js interception in a real browser against a live
// AX Filter API, using a chrome.runtime shim that mirrors background.js.
import { createRequire } from "node:module";
// Resolve playwright whether it is installed locally or in a shared tools dir.
const require = createRequire(import.meta.url);
let chromium;
for (const cand of ["playwright", "/opt/node-tools/node_modules/playwright", process.env.PLAYWRIGHT_PATH]) {
  if (!cand) continue;
  try { chromium = require(cand).chromium; break; } catch {}
}
if (!chromium) { console.error("playwright not found; install it or set PLAYWRIGHT_PATH"); process.exit(2); }
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";

const API = "http://127.0.0.1:8097";
const PAGE = "http://127.0.0.1:8098/mock-chat.html";
const SERVER_DIR = new URL("../../server", import.meta.url).pathname;

function waitFor(url, tries = 60) {
  return (async () => {
    for (let i = 0; i < tries; i++) {
      try { if ((await fetch(url)).ok) return; } catch {}
      await sleep(300);
    }
    throw new Error("not ready: " + url);
  })();
}

const env = { ...process.env, AXFILTER_DATA_DIR: "/tmp/axf-e2e",
  AXFILTER_ADMIN_KEY: "adm", AXFILTER_AGENT_KEY: "agt", AXFILTER_VIEWER_KEY: "vw",
  AXFILTER_CORS_ORIGINS: "http://127.0.0.1:8098" };
spawn("rm", ["-rf", "/tmp/axf-e2e"]);
const api = spawn("python3", ["-m", "uvicorn", "main:app", "--port", "8097"],
  { cwd: SERVER_DIR, env, stdio: "ignore" });
const web = spawn("python3", ["-m", "http.server", "8098"],
  { cwd: new URL(".", import.meta.url).pathname, stdio: "ignore" });

function shim(api) {
  window.chrome = { runtime: { sendMessage: function (msg, cb) {
    fetch(api + "/v1/inspect", { method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": "agt" },
      body: JSON.stringify(msg.payload) })
      .then(function (r) { return r.json(); }).then(cb)
      .catch(function (e) { cb({ action: "block", message: "err " + e }); });
  } } };
}

let failed = 0;
const check = (name, cond) => { if (cond) console.log("  ok -", name);
  else { failed++; console.log("  FAIL -", name); } };

try {
  await Promise.all([waitFor(API + "/healthz"), waitFor(PAGE)]);
  const core = readFileSync(new URL("../filter-core.js", import.meta.url), "utf8");
  const content = readFileSync(new URL("../content.js", import.meta.url), "utf8");
  const browser = await chromium.launch();

  async function fresh() {
    const page = await browser.newPage();
    await page.goto(PAGE, { waitUntil: "load" });
    await page.addScriptTag({ content: core });
    await page.addScriptTag({ content: `(${shim})(${JSON.stringify(API)})` });
    await page.addScriptTag({ content });
    // content.js guards on hostname; mock runs on 127.0.0.1, so patch site match
    await page.evaluate(() => {});
    return page;
  }

  // The content script only activates on known hosts. Serve the test under a
  // matched hostname by overriding siteFor's lookup before content.js loads.
  async function freshMatched() {
    const page = await browser.newPage();
    await page.goto(PAGE, { waitUntil: "load" });
    await page.addScriptTag({ content: core });
    await page.addScriptTag({ content: "window.AXFilterCore.siteFor = function(){return window.AXFilterCore.SITES[0];};" });
    await page.addScriptTag({ content: `(${shim})(${JSON.stringify(API)})` });
    await page.addScriptTag({ content });
    return page;
  }

  async function type(page, text) {
    await page.click("#prompt-textarea");
    await page.evaluate((t) => {
      const ed = document.getElementById("prompt-textarea");
      ed.innerText = t; ed.dispatchEvent(new InputEvent("input", { bubbles: true }));
    }, text);
  }
  const sent = (page) => page.evaluate(() => window.__sentTexts());

  // 1) allow -> goes through on Enter
  let page = await freshMatched();
  await type(page, "안녕하세요 도와주세요");
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => window.__sentTexts().length === 1, null, { timeout: 4000 }).catch(() => {});
  check("allow: clean prompt is sent", JSON.stringify(await sent(page)) === JSON.stringify(["안녕하세요 도와주세요"]));
  await page.close();

  // 2) block -> prevented, banner shown
  page = await freshMatched();
  await type(page, "카드번호 4539 1488 0343 6467 결제해줘");
  await page.keyboard.press("Enter");
  await sleep(800);
  check("block: card number is not sent", (await sent(page)).length === 0);
  check("block: banner appears", await page.locator("#axfilter-banner").count() === 1);
  await page.close();

  // 3) mask -> editor replaced, not sent until reviewed
  page = await freshMatched();
  await type(page, "문의 메일은 hong@example.com 입니다");
  await page.keyboard.press("Enter");
  await sleep(800);
  const edVal = await page.evaluate(() => document.getElementById("prompt-textarea").innerText);
  check("mask: email replaced in editor", edVal.includes("[이메일]") && !edVal.includes("hong@example.com"));
  check("mask: not sent on first Enter", (await sent(page)).length === 0);
  await page.keyboard.press("Enter");  // review + send the masked text
  await page.waitForFunction(() => window.__sentTexts().length === 1, null, { timeout: 4000 }).catch(() => {});
  const sentMask = await sent(page);
  check("mask: masked text sent after review", sentMask.length === 1 && sentMask[0].includes("[이메일]")
    && !sentMask[0].includes("hong@example.com"));
  await page.close();

  // 4) send button path also intercepts
  page = await freshMatched();
  await type(page, "주민번호 900101-1234567 확인");
  await page.click("button[data-testid='send-button']");
  await sleep(800);
  check("block via send button: not sent", (await sent(page)).length === 0);
  await page.close();

  await browser.close();
} finally {
  api.kill(); web.kill();
}
console.log(failed ? `e2e: ${failed} FAILED` : "e2e: all passed");
process.exit(failed ? 1 : 0);
