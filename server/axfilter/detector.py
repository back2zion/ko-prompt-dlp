"""Korean-oriented PII detection and masking for prompts."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

LABELS = {
    "RRN": "주민등록번호",
    "CARD": "신용카드번호",
    "PHONE": "전화번호",
    "EMAIL": "이메일",
    "BIZNO": "사업자등록번호",
    "KEYWORD": "사내 키워드",
}


@dataclass(frozen=True)
class Finding:
    type: str
    start: int
    end: int

    @property
    def label(self) -> str:
        return LABELS[self.type]


def _digits(s: str) -> str:
    return "".join(c for c in s if c.isdigit())


def _valid_birth(yy: int, mm: int, dd: int, gender: int) -> bool:
    century = {1: 1900, 2: 1900, 5: 1900, 6: 1900, 3: 2000, 4: 2000, 7: 2000, 8: 2000,
               9: 1800, 0: 1800}[gender]
    try:
        date(century + yy, mm, dd)
    except ValueError:
        return False
    return True


def _rrn_checksum_ok(d: str) -> bool:
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    check = (11 - sum(int(a) * w for a, w in zip(d, weights)) % 11) % 10
    if int(d[6]) >= 5:  # foreigner registration number
        check = (check + 2) % 10
    return check == int(d[12])


def _luhn_ok(d: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _bizno_ok(d: str) -> bool:
    weights = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    s = sum(int(a) * w for a, w in zip(d[:9], weights))
    s += (int(d[8]) * 5) // 10
    return (10 - s % 10) % 10 == int(d[9])


# Digit groups must not be glued to other digits.
_RRN = re.compile(r"(?<!\d)(\d{2})(\d{2})(\d{2})([-\s]?)([0-9])\d{6}(?!\d)")
_CARD = re.compile(r"(?<!\d)\d{4}([-\s]?)\d{4}\1\d{4}\1\d{1,7}(?!\d)")
_PHONE = re.compile(r"(?<!\d)(?:01[016789]|0(?:2|[3-6][1-5]|70|80))[-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_BIZNO = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{5}(?!\d)")


def _scan(text: str, keywords: list[str]) -> list[Finding]:
    out: list[Finding] = []

    for m in _RRN.finditer(text):
        yy, mm, dd, sep, g = m.groups()
        digits = _digits(m.group(0))
        if not _valid_birth(int(yy), int(mm), int(dd), int(g)):
            continue
        # Numbers issued since Oct 2020 no longer carry a valid checksum, so a
        # separator is enough; a bare 13-digit run must pass the checksum.
        if sep or _rrn_checksum_ok(digits):
            out.append(Finding("RRN", m.start(), m.end()))

    for m in _CARD.finditer(text):
        d = _digits(m.group(0))
        if 13 <= len(d) <= 19 and _luhn_ok(d):
            out.append(Finding("CARD", m.start(), m.end()))

    for m in _BIZNO.finditer(text):
        if _bizno_ok(_digits(m.group(0))):
            out.append(Finding("BIZNO", m.start(), m.end()))

    for m in _PHONE.finditer(text):
        out.append(Finding("PHONE", m.start(), m.end()))

    for m in _EMAIL.finditer(text):
        out.append(Finding("EMAIL", m.start(), m.end()))

    lowered = text.lower()
    for kw in keywords:
        kw = kw.strip().lower()
        if not kw:
            continue
        pos = lowered.find(kw)
        while pos != -1:
            out.append(Finding("KEYWORD", pos, pos + len(kw)))
            pos = lowered.find(kw, pos + len(kw))

    return out


def detect(text: str, keywords: list[str] | None = None) -> list[Finding]:
    """Return non-overlapping findings ordered by position (longest wins)."""
    found = sorted(_scan(text, keywords or []), key=lambda f: (f.start, -(f.end - f.start)))
    result: list[Finding] = []
    for f in found:
        if result and f.start < result[-1].end:
            continue
        result.append(f)
    return result


def mask(text: str, findings: list[Finding], only: set[str] | None = None) -> str:
    """Replace findings (optionally only the given types) with ``[라벨]`` tokens."""
    out, cursor = [], 0
    for f in findings:
        if only is not None and f.type not in only:
            continue
        out.append(text[cursor:f.start])
        out.append(f"[{f.label}]")
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out)
