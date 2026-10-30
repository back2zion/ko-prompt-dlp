"""AX Filter prototype API."""
from __future__ import annotations

import hmac
import os
import secrets
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from .keys import KeyProvider, LocalMasterKeyProvider, provider_from_env
from .policy import Policy, evaluate
from .store import Store, load_or_create_key

PERIOD_DAYS = {"today": 1, "week": 7, "month": 30, "quarter": 90}
ROLE_RANK = {"agent": 0, "viewer": 1, "admin": 2}


@dataclass
class Config:
    db_path: str
    data_key: bytes
    api_keys: dict[str, str]  # role -> key
    max_auth_failures: int = 10      # per client IP within the window
    auth_window_seconds: float = 300.0
    auth_lockout_seconds: float = 300.0
    key_provider: KeyProvider | None = None   # default: local master key = data_key
    require_tls: bool = False                 # reject plain-HTTP requests
    trusted_proxy: bool = False               # honour X-Forwarded-Proto from a TLS-terminating proxy


def config_from_env() -> Config:
    data_dir = Path(os.environ.get("AXFILTER_DATA_DIR", "data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    keys = {}
    for role in ROLE_RANK:
        k = os.environ.get(f"AXFILTER_{role.upper()}_KEY")
        if not k:
            k = secrets.token_urlsafe(24)
            print(f"[axfilter] AXFILTER_{role.upper()}_KEY not set; temporary {role} key: {k}")
        keys[role] = k
    local_key = load_or_create_key(data_dir / "data.key")
    return Config(str(data_dir / "axfilter.db"), local_key, keys,
                  key_provider=provider_from_env(local_key),
                  require_tls=os.environ.get("AXFILTER_REQUIRE_TLS", "0") == "1",
                  trusted_proxy=os.environ.get("AXFILTER_TRUSTED_PROXY", "0") == "1")


class InspectRequest(BaseModel):
    service: str = Field(min_length=1, max_length=64)
    user: str = Field(default="unknown", max_length=128)
    ip: str = Field(max_length=64)
    text: str = Field(max_length=200_000)
    direction: Literal["input", "output"] = "input"


def create_app(cfg: Config) -> FastAPI:
    app = FastAPI(title="AX Filter prototype")
    provider = cfg.key_provider or LocalMasterKeyProvider(cfg.data_key)
    store = Store(cfg.db_path, provider)

    def _is_https(request: Request) -> bool:
        if request.url.scheme == "https":
            return True
        return cfg.trusted_proxy and request.headers.get("x-forwarded-proto", "").lower() == "https"
    fails: dict[str, deque] = {}          # client ip -> timestamps of bad keys
    locked: dict[str, float] = {}         # client ip -> lock-until monotonic time

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if cfg.require_tls and not _is_https(request):
            resp = Response("TLS required", status_code=426, media_type="text/plain")
            resp.headers["Upgrade"] = "TLS/1.2, HTTP/1.1"
        else:
            resp = await call_next(request)
        if _is_https(request):
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return resp

    def _client(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def _note_failure(ip: str, now: float) -> None:
        dq = fails.setdefault(ip, deque())
        dq.append(now)
        while dq and now - dq[0] > cfg.auth_window_seconds:
            dq.popleft()
        if len(dq) >= cfg.max_auth_failures:
            locked[ip] = now + cfg.auth_lockout_seconds
            dq.clear()

    def require(min_role: str):
        def dep(request: Request, x_api_key: str = Header(default="")) -> str:
            ip, now = _client(request), time.monotonic()
            until = locked.get(ip)
            if until is not None:
                if now < until:
                    raise HTTPException(429, "too many failed authentications; try again later")
                del locked[ip]
            for role, key in cfg.api_keys.items():
                if hmac.compare_digest(x_api_key, key):
                    fails.pop(ip, None)
                    if ROLE_RANK[role] >= ROLE_RANK[min_role]:
                        return role
                    raise HTTPException(403, "insufficient role")
            _note_failure(ip, now)
            raise HTTPException(401, "invalid api key")
        return dep

    @app.post("/v1/inspect")
    def inspect(req: InspectRequest, _: str = Depends(require("agent"))):
        t0 = time.perf_counter()
        policy = store.get_policy()
        d = evaluate(policy, service=req.service, ip=req.ip, text=req.text)
        types = sorted({f.type for f in d.findings})
        latency = (time.perf_counter() - t0) * 1000
        event_id = store.add_event(
            service=req.service.strip().lower(), user=req.user, ip=req.ip, group=d.group,
            direction=req.direction, action=d.action, reason=d.reason, finding_types=types,
            latency_ms=latency, masked_text=d.forward_text, original=req.text)
        return {
            "event_id": event_id, "action": d.action, "reason": d.reason,
            "text": d.forward_text,  # None when blocked
            "message": policy.block_message if d.action == "block" else None,
            "findings": [{"type": f.type, "label": f.label, "start": f.start, "end": f.end}
                         for f in d.findings],
        }

    # ---- statistics (viewer+) -------------------------------------------
    def since(period: str) -> int:
        if period not in PERIOD_DAYS:
            raise HTTPException(422, f"period must be one of {sorted(PERIOD_DAYS)}")
        return int(time.time()) - PERIOD_DAYS[period] * 86400

    Direction = Literal["all", "input", "output"]

    @app.get("/v1/stats/summary")
    def summary(period: str = "week", direction: Direction = "all",
                _: str = Depends(require("viewer"))):
        cur = store.summary(since(period), direction)
        prev_since = since(period) - PERIOD_DAYS[period] * 86400
        prev_total = store.summary(prev_since, direction)["total"] - cur["total"]
        change = None if prev_total <= 0 else round((cur["total"] / prev_total - 1) * 100, 1)
        t = cur["total"] or 1
        return {**cur, "detect_rate": round(cur["detected"] / t * 100, 1),
                "allow_rate": round(cur["allowed"] / t * 100, 1),
                "block_rate": round(cur["blocked"] / t * 100, 1),
                "mask_rate": round(cur["masked"] / t * 100, 1),
                "prev_period_change_pct": change}

    @app.get("/v1/stats/daily")
    def daily(period: str = "week", direction: Direction = "all",
              _: str = Depends(require("viewer"))):
        return store.daily(since(period), direction)

    @app.get("/v1/stats/services")
    def services(period: str = "week", direction: Direction = "all",
                 _: str = Depends(require("viewer"))):
        return store.by_service(since(period), direction)

    @app.get("/v1/stats/top")
    def top(by: Literal["group", "ip"] = "group", period: str = "week",
            direction: Direction = "all", n: int = Query(5, ge=1, le=50),
            _: str = Depends(require("viewer"))):
        return store.top(since(period), direction, by, n)

    @app.get("/v1/events")
    def events(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
               action: Literal["allow", "mask", "block"] | None = None,
               _: str = Depends(require("viewer"))):
        return store.list_events(limit, offset, action)

    # ---- admin ----------------------------------------------------------
    @app.get("/v1/events/{event_id}/original")
    def original(event_id: int, role: str = Depends(require("admin"))):
        row = store.get_event(event_id)
        if row is None:
            raise HTTPException(404, "event not found")
        store.audit(role, "VIEW_ORIGINAL", f"event:{event_id}")
        return {"event_id": event_id, "original": store.decrypt_original(row)}

    @app.get("/v1/policy")
    def get_policy(_: str = Depends(require("viewer"))):
        return store.get_policy()

    @app.put("/v1/policy")
    def put_policy(policy: Policy, role: str = Depends(require("admin"))):
        store.set_policy(policy)
        store.audit(role, "UPDATE_POLICY", "policy")
        return policy

    @app.post("/v1/keys/rotate")
    def rotate_key(role: str = Depends(require("admin"))):
        n = store.rotate_data_key()
        store.audit(role, "ROTATE_DATA_KEY", f"reencrypted:{n}")
        return {"reencrypted": n, "provider": store.key_provider_name}

    @app.get("/v1/audit")
    def audit(_: str = Depends(require("admin"))):
        return {"verify": store.verify_audit(), "entries": store.audit_entries()}

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    return app
