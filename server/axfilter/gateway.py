"""LLM egress gateway: an OpenAI-compatible reverse proxy that enforces inspection.

Internal apps point their OpenAI base_url at this gateway instead of the provider.
Every prompt is inspected before it leaves the network: blocked prompts never
reach the provider, masked prompts are rewritten, allowed prompts pass through.
Unlike the browser extension this cannot be bypassed by the calling app when
network egress to providers is restricted to the gateway.
"""
from __future__ import annotations

import time

import httpx
from fastapi import Depends, Header, HTTPException, Request

from .logging_setup import request_id
from .policy import evaluate


def register_gateway(app, cfg, store, siem, require):
    client: httpx.Client = cfg.http_client or httpx.Client(
        base_url=cfg.gateway_upstream.rstrip("/"), timeout=60.0)
    upstream_headers = {}
    if cfg.gateway_upstream_key:
        upstream_headers["Authorization"] = "Bearer " + cfg.gateway_upstream_key

    def _inspect_messages(policy, messages, ip):
        """Inspect each user/system message; return (action, types, rewritten_messages)."""
        worst = "allow"
        all_types: set[str] = set()
        out = []
        for m in messages:
            content = m.get("content")
            if m.get("role") in ("user", "system") and isinstance(content, str) and content:
                d = evaluate(policy, service="gateway", ip=ip, text=content)
                all_types |= {f.type for f in d.findings}
                if d.action == "block":
                    worst = "block"
                elif d.action == "mask":
                    worst = "block" if worst == "block" else "mask"
                    m = {**m, "content": d.forward_text}
            out.append(m)
        return worst, sorted(all_types), out

    @app.post("/gateway/v1/chat/completions")
    def chat_completions(body: dict, request: Request,
                         x_axfilter_user: str = Header(default="gateway"),
                         _=Depends(require("agent"))):
        t0 = time.perf_counter()
        ip = request.client.host if request.client else "0.0.0.0"  # nosec B104 - fallback IP label, not a socket bind
        policy = store.get_policy()
        messages = body.get("messages") or []
        action, types, new_messages = _inspect_messages(policy, messages, ip)
        latency = (time.perf_counter() - t0) * 1000
        joined = "\n".join(m.get("content", "") for m in messages if isinstance(m.get("content"), str))
        store.add_event(service="gateway", user=x_axfilter_user, ip=ip, group="gateway",
                        direction="input", action=action,
                        reason=("PII_BLOCKED" if action == "block" else
                                "PII_MASKED" if action == "mask" else None),
                        finding_types=types, latency_ms=latency,
                        masked_text=None if action == "block" else "forwarded", original=joined)
        if types or action != "allow":
            siem.emit("gateway." + action, action=action, name=f"gateway {action}",
                      service="gateway", user=x_axfilter_user, src=ip,
                      types=",".join(types), rid=request_id.get())
        if action == "block":
            raise HTTPException(403, {"message": policy.block_message, "findings": types,
                                      "blocked_by": "axfilter-gateway"})
        body = {**body, "messages": new_messages}
        r = client.post("/v1/chat/completions", json=body, headers=upstream_headers)
        return r.json()

    return app
