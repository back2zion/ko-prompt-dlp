"""mitmproxy addon: enforce AX Filter on outbound LLM API traffic (transparent proxy).

This is the network-level enforcement option for traffic the browser extension and
the egress gateway do not cover. It intercepts requests to configured LLM hosts,
inspects the prompt via the AX Filter API, and blocks or masks before the request
leaves the network.

Caveats (read before deploying):
- Requires mitmproxy and its CA certificate trusted on every client device (MDM).
  TLS interception of third-party services must comply with your policy and law.
- Selectors/paths below are examples; adjust per provider API shape.
- Not verified in this repository's test suite (needs a live proxy + clients).

Run:  mitmdump -s deploy/mitmproxy_addon.py
Env:  AXFILTER_API=https://axfilter.internal  AXFILTER_AGENT_KEY=...
"""
import json
import os

import requests  # mitmproxy ships requests

API = os.environ.get("AXFILTER_API", "http://127.0.0.1:8000").rstrip("/")
KEY = os.environ.get("AXFILTER_AGENT_KEY", "")
HOSTS = ("api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com")


def _inspect(text: str) -> dict:
    r = requests.post(f"{API}/v1/inspect", timeout=10,
                      headers={"X-API-Key": KEY, "Content-Type": "application/json"},
                      json={"service": "proxy", "ip": "0.0.0.0", "user": "proxy", "text": text})
    r.raise_for_status()
    return r.json()


def _extract(body: dict) -> str:
    msgs = body.get("messages")
    if isinstance(msgs, list):
        return "\n".join(m.get("content", "") for m in msgs if isinstance(m.get("content"), str))
    return body.get("prompt", "") or ""


def request(flow):
    if flow.request.pretty_host not in HOSTS or not flow.request.content:
        return
    try:
        body = json.loads(flow.request.get_text())
    except (ValueError, UnicodeDecodeError):
        return
    text = _extract(body)
    if not text:
        return
    try:
        verdict = _inspect(text)
    except Exception:
        # fail safe: block when the filter cannot be reached
        from mitmproxy import http
        flow.response = http.Response.make(403, b"AX Filter unavailable", {"Content-Type": "text/plain"})
        return
    if verdict["action"] == "block":
        from mitmproxy import http
        flow.response = http.Response.make(
            403, json.dumps({"error": verdict.get("message", "blocked by AX Filter")}).encode(),
            {"Content-Type": "application/json"})
    elif verdict["action"] == "mask" and verdict.get("text"):
        if isinstance(body.get("messages"), list):
            for m in body["messages"]:
                if isinstance(m.get("content"), str) and m["content"]:
                    r = _inspect(m["content"])
                    if r["action"] == "mask" and r.get("text"):
                        m["content"] = r["text"]
                    elif r["action"] == "block":
                        from mitmproxy import http
                        flow.response = http.Response.make(403, b"blocked by AX Filter")
                        return
        else:
            body["prompt"] = verdict["text"]
        flow.request.set_text(json.dumps(body))
