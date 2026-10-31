"""AX Filter prototype API."""
from __future__ import annotations

import hmac
import time
from collections import deque
from dataclasses import dataclass
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

import logging

from .keys import KeyProvider, LocalMasterKeyProvider, provider_from_env
from . import compliance
from .oidc import Principal, ROLE_RANK as OIDC_RANK, verifier_from_settings
from .siem import SiemForwarder
from .logging_setup import log_event, new_request_id, request_id, setup_logging
from .policy import Policy, evaluate
from .settings import Settings
from .store import Store, load_or_create_key

PERIOD_DAYS = {"today": 1, "week": 7, "month": 30, "quarter": 90}
Direction = Literal["all", "input", "output"]
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
    cors_origins: tuple[str, ...] = ()        # dashboard origins allowed to call the API
    siem: SiemForwarder | None = None
    oidc: object | None = None                # oidc.Verifier or None
    gateway_upstream: str = ""                # LLM provider base URL; enables the egress gateway
    gateway_upstream_key: str = ""            # provider API key injected by the gateway
    http_client: object | None = None         # injected httpx.Client (testing)
    ner_recognizers: list | None = None       # extra recognizer callables (e.g. transformer NER)


def config_from_env(settings: Settings | None = None) -> Config:
    st = settings or Settings()
    st.data_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(st.log_level, st.log_json)
    # Local master key lives in the data dir (or AXFILTER_DATA_KEY); KMS needs no local key.
    local_key = load_or_create_key(st.data_dir / "data.key")
    db = st.database_url or str(st.data_dir / "axfilter.db")
    ner_recognizers = None
    if st.ner_model:
        from .ner_models import TransformerNerRecognizer
        ner_recognizers = [TransformerNerRecognizer(st.ner_model, threshold=st.ner_threshold)]
    return Config(db, local_key, st.resolved_keys(),
                  key_provider=provider_from_env(local_key),
                  require_tls=st.require_tls, trusted_proxy=st.trusted_proxy,
                  cors_origins=st.cors_list(),
                  max_auth_failures=st.max_auth_failures,
                  auth_window_seconds=st.auth_window_seconds,
                  auth_lockout_seconds=st.auth_lockout_seconds,
                  siem=SiemForwarder(sink=st.siem_sink, fmt=st.siem_format, target=st.siem_target),
                  oidc=verifier_from_settings(st),
                  gateway_upstream=st.gateway_upstream, gateway_upstream_key=st.gateway_upstream_key,
                  ner_recognizers=ner_recognizers)


class InspectRequest(BaseModel):
    service: str = Field(min_length=1, max_length=64)
    user: str = Field(default="unknown", max_length=128)
    ip: str = Field(max_length=64)
    text: str = Field(max_length=200_000)
    direction: Literal["input", "output"] = "input"


def create_app(cfg: Config) -> FastAPI:
    app = FastAPI(title="AX Filter prototype")
    if cfg.cors_origins:
        from fastapi.middleware.cors import CORSMiddleware
        app.add_middleware(CORSMiddleware, allow_origins=list(cfg.cors_origins),
                           allow_methods=["GET", "POST", "PUT"], allow_headers=["X-API-Key", "Content-Type"])
    provider = cfg.key_provider or LocalMasterKeyProvider(cfg.data_key)
    store = Store(cfg.db_path, provider)
    siem = cfg.siem or SiemForwarder()
    verifier = cfg.oidc
    ner_recognizers = cfg.ner_recognizers or None

    def _is_https(request: Request) -> bool:
        if request.url.scheme == "https":
            return True
        return cfg.trusted_proxy and request.headers.get("x-forwarded-proto", "").lower() == "https"
    fails: dict[str, deque] = {}          # client ip -> timestamps of bad keys
    locked: dict[str, float] = {}         # client ip -> lock-until monotonic time

    log = logging.getLogger("axfilter.access")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or new_request_id()
        request_id.set(rid)
        t0 = time.perf_counter()
        if cfg.require_tls and not _is_https(request):
            resp = Response("TLS required", status_code=426, media_type="text/plain")
            resp.headers["Upgrade"] = "TLS/1.2, HTTP/1.1"
        else:
            resp = await call_next(request)
        resp.headers["X-Request-ID"] = rid
        if _is_https(request):
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # metadata only — never the prompt text or detected values
        log_event(log, "request", method=request.method, path=request.url.path,
                  status=resp.status_code, ms=round((time.perf_counter() - t0) * 1000, 1))
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
        def dep(request: Request, x_api_key: str = Header(default=""),
                authorization: str = Header(default="")) -> Principal:
            # OIDC bearer (SSO) takes precedence when a token is presented.
            if verifier and authorization.lower().startswith("bearer "):
                try:
                    pr = verifier.verify(authorization[7:].strip())
                except Exception:
                    raise HTTPException(401, "invalid bearer token")
                if OIDC_RANK[pr.role] >= ROLE_RANK[min_role]:
                    return pr
                raise HTTPException(403, "insufficient role")
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
                        return Principal(role, role)
                    raise HTTPException(403, "insufficient role")
            _note_failure(ip, now)
            raise HTTPException(401, "invalid api key")
        return dep

    @app.post("/v1/inspect")
    def inspect(req: InspectRequest, _: str = Depends(require("agent"))):
        t0 = time.perf_counter()
        policy = store.get_policy()
        d = evaluate(policy, service=req.service, ip=req.ip, text=req.text, extra=ner_recognizers)
        types = sorted({f.type for f in d.findings})
        latency = (time.perf_counter() - t0) * 1000
        event_id = store.add_event(
            service=req.service.strip().lower(), user=req.user, ip=req.ip, group=d.group,
            direction=req.direction, action=d.action, reason=d.reason, finding_types=types,
            latency_ms=latency, masked_text=d.forward_text, original=req.text)
        if d.action != "allow" or types:
            siem.emit("prompt." + d.action, action=d.action, name=f"prompt {d.action}",
                      service=req.service, user=req.user, src=req.ip, group=d.group,
                      types=",".join(types), reason=d.reason or "", rid=request_id.get())
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
    def original(event_id: int, principal: Principal = Depends(require("admin"))):
        row = store.get_event(event_id)
        if row is None:
            raise HTTPException(404, "event not found")
        store.audit(str(principal), "VIEW_ORIGINAL", f"event:{event_id}")
        siem.emit("audit.view_original", name="original viewed",
                  actor=str(principal), target=f"event:{event_id}", rid=request_id.get())
        return {"event_id": event_id, "original": store.decrypt_original(row)}

    @app.get("/v1/policy")
    def get_policy(_: str = Depends(require("viewer"))):
        return store.get_policy()

    @app.put("/v1/policy")
    def put_policy(policy: Policy, principal: Principal = Depends(require("admin"))):
        store.set_policy(policy, actor=str(principal))
        store.audit(str(principal), "UPDATE_POLICY", "policy")
        siem.emit("audit.update_policy", name="policy updated", actor=str(principal), rid=request_id.get())
        return policy

    @app.post("/v1/keys/rotate")
    def rotate_key(principal: Principal = Depends(require("admin"))):
        n = store.rotate_data_key()
        store.audit(str(principal), "ROTATE_DATA_KEY", f"reencrypted:{n}")
        return {"reencrypted": n, "provider": store.key_provider_name}

    @app.get("/v1/audit")
    def audit(_: str = Depends(require("admin"))):
        return {"verify": store.verify_audit(), "entries": store.audit_entries()}

    @app.get("/v1/audit/search")
    def audit_search(actor: str | None = None,
                     action: str | None = None,
                     period: str | None = None,
                     limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                     _: str = Depends(require("admin"))):
        kw = {"actor": actor, "action": action, "limit": limit, "offset": offset}
        if period:
            kw["since"] = since(period)
        return store.audit_search(**kw)

    @app.get("/v1/policy/history")
    def policy_history(limit: int = Query(100, ge=1, le=1000), _: str = Depends(require("admin"))):
        return store.policy_history(limit)

    @app.get("/v1/policy/history/{version_id}")
    def policy_version(version_id: int, _: str = Depends(require("admin"))):
        v = store.policy_version(version_id)
        if v is None:
            raise HTTPException(404, "version not found")
        return v

    def _report(period: str, framework: str | None):
        return compliance.build_report(
            store, {"key_provider": store.key_provider_name, "tls_required": cfg.require_tls},
            period_days=PERIOD_DAYS.get(period, 30), framework=framework, sign_key=cfg.data_key)

    @app.get("/v1/compliance/report")
    def compliance_report(period: str = "month", framework: str | None = None,
                          principal: Principal = Depends(require("admin"))):
        store.audit(str(principal), "EXPORT_COMPLIANCE_REPORT", f"framework={framework or 'all'};period={period}")
        return _report(period, framework)

    @app.get("/v1/compliance/report.csv")
    def compliance_report_csv(period: str = "month", framework: str | None = None,
                              principal: Principal = Depends(require("admin"))):
        store.audit(str(principal), "EXPORT_COMPLIANCE_REPORT", f"csv;framework={framework or 'all'};period={period}")
        csv_text = compliance.to_csv(_report(period, framework))
        return Response(csv_text, media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": "attachment; filename=axfilter-compliance.csv"})

    @app.post("/v1/compliance/verify")
    def compliance_verify(report: dict, _: str = Depends(require("admin"))):
        return {"valid": compliance.verify(report, cfg.data_key)}

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    if cfg.gateway_upstream:
        from .gateway import register_gateway
        register_gateway(app, cfg, store, siem, require)

    return app
