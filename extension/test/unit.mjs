// Pure unit tests for filter-core.js and background.js (no browser).
import assert from "node:assert";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const tests = [];
const t = (name, fn) => tests.push([name, fn]);

// ---- filter-core.js ----
const core = {};
new vm.Script(readFileSync(new URL("../filter-core.js", import.meta.url)))
  .runInNewContext(Object.assign(core, { window: core, globalThis: core, module: { exports: {} } }));
const Core = core.AXFilterCore;

t("siteFor maps known hosts", () => {
  assert.equal(Core.siteFor("chatgpt.com").service, "ChatGPT");
  assert.equal(Core.siteFor("claude.ai").service, "Claude");
  assert.equal(Core.siteFor("gemini.google.com").service, "Gemini");
  assert.equal(Core.siteFor("example.com"), null);
});
t("interpret block/mask/allow", () => {
  assert.equal(Core.interpret({ action: "block", message: "m" }).kind, "block");
  assert.equal(Core.interpret({ action: "mask", text: "[이메일]", findings: [] }).text, "[이메일]");
  assert.equal(Core.interpret({ action: "allow", text: "hi" }).kind, "allow");
});

// ---- background.js inspect() fail-safe ----
function loadBackground(storage, fetchImpl) {
  const ctx = {
    chrome: {
      storage: { sync: { get: async () => storage } },
      runtime: { onMessage: { addListener: () => {} } }
    },
    fetch: fetchImpl, console
  };
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  new vm.Script(readFileSync(new URL("../background.js", import.meta.url))).runInContext(ctx);
  return ctx;
}

t("background: unconfigured allows (nothing configured to check against)", async () => {
  const ctx = loadBackground({ enabled: true }, async () => { throw new Error("should not fetch"); });
  const r = await ctx.inspect({ text: "x" });
  assert.equal(r.action, "allow"); assert.ok(r._unconfigured);
});
t("background: server error fails safe to block by default", async () => {
  const ctx = loadBackground({ enabled: true, apiBase: "http://x", apiKey: "k" },
    async () => ({ ok: false, status: 500 }));
  assert.equal((await ctx.inspect({ text: "x" })).action, "block");
});
t("background: failMode allow lets through on error", async () => {
  const ctx = loadBackground({ enabled: true, apiBase: "http://x", apiKey: "k", failMode: "allow" },
    async () => { throw new Error("down"); });
  assert.equal((await ctx.inspect({ text: "x" })).action, "allow");
});
t("background: disabled skips", async () => {
  const ctx = loadBackground({ enabled: false }, async () => { throw new Error("no"); });
  assert.ok((await ctx.inspect({ text: "x" }))._skipped);
});
t("background: forwards API verdict when reachable", async () => {
  const ctx = loadBackground({ enabled: true, apiBase: "http://x", apiKey: "k" },
    async () => ({ ok: true, json: async () => ({ action: "mask", text: "[이메일]" }) }));
  assert.equal((await ctx.inspect({ text: "a@b.com" })).text, "[이메일]");
});

let pass = 0;
for (const [name, fn] of tests) { await fn(); pass++; console.log("  ok -", name); }
console.log(`unit: ${pass} passed`);
