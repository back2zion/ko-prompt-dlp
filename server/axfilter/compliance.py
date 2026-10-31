"""Compliance evidence report.

Assembles operational evidence (access control, audit-log integrity, encryption,
masking activity, policy-change history) and maps it to representative ISMS-P and
ISO/IEC 27001:2022 control items. The report is HMAC-signed so an auditor can
detect tampering.

This is supporting evidence material, not a certification or a compliance
guarantee. Control mappings are indicative and should be reviewed by the
organisation's auditor.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import time
import uuid
from datetime import datetime, timezone

KST = timezone.utc  # label only; day math done on epoch
_TZ = __import__("zoneinfo").ZoneInfo("Asia/Seoul")

# Each control: which evidence feeds it and a predicate for the status.
CONTROLS = [
    {"framework": "ISMS-P", "control_id": "2.5", "control_name": "인증 및 권한관리",
     "requirement": "역할 기반 접근통제와 권한 분리",
     "evidence_key": "access_control"},
    {"framework": "ISMS-P", "control_id": "2.7", "control_name": "암호화 적용",
     "requirement": "개인정보의 저장·전송 시 암호화",
     "evidence_key": "encryption"},
    {"framework": "ISMS-P", "control_id": "2.9.4", "control_name": "로그 및 접속기록 관리",
     "requirement": "접속기록의 위·변조 방지 및 보관",
     "evidence_key": "audit_integrity"},
    {"framework": "ISMS-P", "control_id": "2.10", "control_name": "전송구간 보안",
     "requirement": "전송구간 암호화(TLS) 적용",
     "evidence_key": "transport"},
    {"framework": "ISMS-P", "control_id": "3.2", "control_name": "개인정보 최소수집·마스킹",
     "requirement": "불필요한 개인정보 노출 차단·가명처리",
     "evidence_key": "masking"},
    {"framework": "ISMS-P", "control_id": "1.2", "control_name": "정책·지침 변경관리",
     "requirement": "보안정책 변경 이력 관리",
     "evidence_key": "policy_changes"},
    {"framework": "ISO 27001", "control_id": "A.8.24", "control_name": "Use of cryptography",
     "requirement": "암호화 통제 적용 및 키 관리",
     "evidence_key": "encryption"},
    {"framework": "ISO 27001", "control_id": "A.8.15", "control_name": "Logging",
     "requirement": "이벤트 로그 생성·보호",
     "evidence_key": "audit_integrity"},
    {"framework": "ISO 27001", "control_id": "A.5.15", "control_name": "Access control",
     "requirement": "접근통제 정책 수립·이행",
     "evidence_key": "access_control"},
    {"framework": "ISO 27001", "control_id": "A.8.11", "control_name": "Data masking",
     "requirement": "데이터 마스킹 적용",
     "evidence_key": "masking"},
]


def _status(evidence_key: str, ev: dict) -> tuple[str, str]:
    """Return (status, evidence_summary) for a control from gathered evidence."""
    if evidence_key == "access_control":
        return "충족", f"역할 {', '.join(ev['access_control']['roles'])} / 원문열람 {ev['access_control']['original_access_count']}건 기록"
    if evidence_key == "encryption":
        e = ev["encryption"]
        return "충족", f"저장 {e['at_rest']}, 봉투암호화(키공급자={e['key_provider']})"
    if evidence_key == "audit_integrity":
        a = ev["audit_integrity"]
        return ("충족" if a["verified"] else "미충족"), \
               f"해시체인 검증 {'정상' if a['verified'] else '손상@'+str(a['broken_at'])}, 항목 {a['entries']}건"
    if evidence_key == "transport":
        t = ev["transport"]
        return ("충족" if t["tls_required"] else "부분충족"), \
               ("TLS 강제(HSTS)" if t["tls_required"] else "TLS 미강제(프록시 종단 가정)")
    if evidence_key == "masking":
        m = ev["masking"]
        return "충족", f"기간 내 마스킹 {m['masked']}건 / 차단 {m['blocked']}건 / 검출 {m['detected']}건"
    if evidence_key == "policy_changes":
        p = ev["policy_changes"]
        return "충족", f"정책 변경 이력 {p['versions']}건(최근 변경자 {p['last_actor']})"
    return "해당없음", ""


def gather_evidence(store, system_info: dict, period_days: int, now: int | None = None) -> dict:
    now = now or int(time.time())
    since = now - period_days * 86400
    summ = store.summary(since, "all")
    audit_v = store.verify_audit()
    views = store.audit_search(action="VIEW_ORIGINAL", since=since, until=now + 1, limit=1000)
    hist = store.policy_history(limit=1000)
    return {
        "access_control": {"roles": ["agent", "viewer", "admin"],
                           "original_access_count": len(views)},
        "encryption": {"at_rest": "AES-256-GCM", "key_provider": system_info.get("key_provider", "local")},
        "audit_integrity": {"verified": audit_v["ok"], "broken_at": audit_v["broken_at"],
                            "entries": len(store.audit_search(limit=100000))},
        "transport": {"tls_required": bool(system_info.get("tls_required"))},
        "masking": {"masked": summ["masked"], "blocked": summ["blocked"],
                    "detected": summ["detected"], "total": summ["total"]},
        "policy_changes": {"versions": len(hist),
                           "last_actor": hist[0]["actor"] if hist else "-"},
        "original_access_log": [{"ts": v["ts"], "actor": v["actor"], "target": v["target"]} for v in views],
    }


def build_report(store, system_info: dict, period_days: int = 30,
                 framework: str | None = None, sign_key: bytes | None = None,
                 now: int | None = None) -> dict:
    now = now or int(time.time())
    ev = gather_evidence(store, system_info, period_days, now)
    controls = []
    for c in CONTROLS:
        if framework and c["framework"] != framework:
            continue
        status, summary = _status(c["evidence_key"], ev)
        controls.append({k: c[k] for k in ("framework", "control_id", "control_name", "requirement")}
                        | {"status": status, "evidence_summary": summary})
    report = {
        "report_id": uuid.uuid4().hex,
        "generated_at": datetime.fromtimestamp(now, _TZ).isoformat(),
        "period": {"days": period_days,
                   "from": datetime.fromtimestamp(now - period_days * 86400, _TZ).isoformat(),
                   "to": datetime.fromtimestamp(now, _TZ).isoformat()},
        "disclaimer": "본 문서는 심사 대응용 증적 자료이며, 인증 획득이나 컴플라이언스 충족을 보장하지 않습니다. 통제 매핑은 참고용입니다.",
        "evidence": ev,
        "controls": controls,
    }
    if sign_key:
        report["signature"] = sign(report, sign_key)
    return report


def _canonical(report: dict) -> bytes:
    body = {k: v for k, v in report.items() if k != "signature"}
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sign(report: dict, key: bytes) -> dict:
    mac = hmac.new(key, _canonical(report), hashlib.sha256).hexdigest()
    return {"alg": "HMAC-SHA256", "value": mac}


def verify(report: dict, key: bytes) -> bool:
    sig = report.get("signature")
    if not sig or sig.get("alg") != "HMAC-SHA256":
        return False
    expected = hmac.new(key, _canonical(report), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig.get("value", ""))


def to_csv(report: dict) -> str:
    import csv
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["framework", "control_id", "control_name", "requirement", "status", "evidence_summary"])
    for c in report["controls"]:
        w.writerow([c["framework"], c["control_id"], c["control_name"],
                    c["requirement"], c["status"], c["evidence_summary"]])
    return buf.getvalue()
