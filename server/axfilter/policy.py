"""Policy model and decision logic."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from zoneinfo import ZoneInfo

from pydantic import BaseModel, Field

from .detector import Finding, detect, mask

Action = Literal["allow", "mask", "block"]
TZ = ZoneInfo("Asia/Seoul")


class GroupDef(BaseModel):
    name: str
    cidrs: list[str] = Field(default_factory=list)


class TimeRule(BaseModel):
    """Allow use of AI services for ``group`` only between start and end (HH:MM, KST)."""
    group: str
    start: str = "09:00"
    end: str = "18:00"


class Policy(BaseModel):
    default_service: Literal["allow", "block"] = "allow"
    services: dict[str, Literal["allow", "block"]] = Field(default_factory=dict)
    type_actions: dict[str, Action] = Field(default_factory=lambda: {
        "RRN": "block", "CARD": "block", "PHONE": "mask",
        "EMAIL": "mask", "BIZNO": "mask", "PASSPORT": "block",
        "SECRET": "block", "KEYWORD": "block",
    })
    keywords: list[str] = Field(default_factory=list)
    groups: list[GroupDef] = Field(default_factory=list)
    time_rules: list[TimeRule] = Field(default_factory=list)
    block_message: str = "개인정보 또는 사내 민감정보가 포함되어 전송이 차단되었습니다. 내용을 수정한 뒤 다시 시도해 주세요."


@dataclass
class Decision:
    action: Action
    reason: str | None
    group: str
    findings: list[Finding] = field(default_factory=list)
    forward_text: str | None = None


def resolve_group(policy: Policy, ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "기타"
    for g in policy.groups:
        for cidr in g.cidrs:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return g.name
    return "기타"


def _minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def _within(rule: TimeRule, now: datetime) -> bool:
    cur, start, end = now.hour * 60 + now.minute, _minutes(rule.start), _minutes(rule.end)
    return start <= cur < end if start <= end else (cur >= start or cur < end)


def evaluate(policy: Policy, *, service: str, ip: str, text: str,
             now: datetime | None = None) -> Decision:
    now = (now or datetime.now(TZ)).astimezone(TZ)
    group = resolve_group(policy, ip)
    svc = service.strip().lower()

    if policy.services.get(svc, policy.default_service) == "block":
        return Decision("block", "SERVICE_BLOCKED", group)

    for rule in policy.time_rules:
        if rule.group == group and not _within(rule, now):
            return Decision("block", "TIME_RESTRICTED", group)

    findings = detect(text, policy.keywords)
    actions = {f.type: policy.type_actions.get(f.type, "mask") for f in findings}
    if "block" in actions.values():
        return Decision("block", "PII_BLOCKED", group, findings)
    to_mask = {t for t, a in actions.items() if a == "mask"}
    if to_mask:
        return Decision("mask", "PII_MASKED", group, findings, mask(text, findings, to_mask))
    return Decision("allow", None, group, findings, text)
