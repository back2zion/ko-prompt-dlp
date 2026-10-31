"""Context + dictionary recognizers for Korean names and addresses.

Rule/gazetteer based, so they run offline with no model download. They are
deliberately conservative — a name is reported only when a context cue
(이름/담당자...) precedes it or an honorific (님/씨/과장...) follows it — which
keeps precision high; recall is measured by the benchmark (axfilter/bench.py).

An external model (transformer NER, Presidio, ...) can be added by passing extra
callables to ``recognize``; each returns Span tuples, so the rest of the pipeline
is unchanged.
"""
from __future__ import annotations

import re
from typing import Callable, NamedTuple


class Span(NamedTuple):
    type: str
    start: int
    end: int
    score: float


SURNAMES_2 = {"남궁", "황보", "제갈", "사공", "선우", "서문", "독고", "동방"}
SURNAMES_1 = set("김이박최정강조윤장임한오서신권황안송류전홍고문양손배백허유남심노"
                 "하곽성차주우구민진지엄채원천방공현함변염여추도소석설마길연위표명기반왕금옥육인맹제모탁국어은편용")

_NAME_CUES = ("이름", "성명", "성함", "담당자", "담당", "수신", "받는사람", "받는 사람",
              "보내는사람", "보내는 사람", "작성자", "신청자", "신청인", "환자", "고객명",
              "예약자", "대표자", "입금자", "예금주", "서명", "연락처")
_HONORIFIC = ("과장", "부장", "차장", "대리", "사원", "주임", "팀장", "실장", "이사", "상무",
              "전무", "대표", "선생", "교수", "박사", "원장", "국장", "본부장", "님", "씨", "군", "양")
_PARTICLE_HEADS = set("은는이가을를의에도만와과께서님씨")   # first syllable after a name
# tokens that look like surname+syllable but are titles or common words, never names
_NAME_STOP = {"이사", "부장", "과장", "차장", "대리", "사원", "주임", "팀장", "실장", "상무",
              "전무", "대표", "원장", "국장", "선생", "교수", "박사", "본부장", "회장", "사장",
              "정말", "조금", "박스", "김밥", "성공", "안녕", "문의", "전화", "오늘", "내일",
              "서류", "자료", "신청", "확인", "고객", "회의", "보고", "결정", "정부", "강조",
              "최고", "최근", "조직", "한국", "오전", "오후", "조치", "검토", "수신", "참고"}


def _is_hangul(c: str) -> bool:
    return "가" <= c <= "힣"


def _name_spans(text: str) -> list[Span]:
    out: list[Span] = []
    n = len(text)
    i = 0
    while i < n:
        if not _is_hangul(text[i]) or (i > 0 and _is_hangul(text[i - 1])):
            i += 1
            continue
        surlen = 2 if text[i:i + 2] in SURNAMES_2 else (1 if text[i] in SURNAMES_1 else 0)
        if surlen == 0:
            i += 1
            continue
        chosen = 0
        for glen in (2, 1):                      # prefer a 2-char given name
            end = i + surlen + glen
            if end <= n and all(_is_hangul(c) for c in text[i + surlen:end]):
                nxt = text[end] if end < n else ""
                if not _is_hangul(nxt) or nxt in _PARTICLE_HEADS:
                    chosen = end
                    break
        if not chosen:
            i += 1
            continue
        s, e = i, chosen
        if text[s:e] in _NAME_STOP:
            i = e
            continue
        before, after = text[max(0, s - 6):s], text[e:e + 7].lstrip()
        has_cue = any(c in before for c in _NAME_CUES)
        has_hon = after.startswith(_HONORIFIC)
        if has_cue and has_hon:
            out.append(Span("NAME", s, e, 0.95))
        elif has_cue or has_hon:
            out.append(Span("NAME", s, e, 0.8))
        i = e
    return out


_SIDO = (r"(?:서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남|전북|전남|경북|경남|제주)"
         r"(?:특별자치시|특별자치도|특별시|광역시|도)?")
_GUGUN = r"[가-힣]{1,6}(?:시|군|구)"
_DONG = r"[가-힣0-9]{1,8}(?:읍|면|동|리|가)"
_ROAD = r"[가-힣0-9]{1,10}(?:로|길)"
_NUM = r"\d{1,4}(?:-\d{1,4})?(?:\s*(?:번길|번지|번|호))?(?:\s*\d{1,4}\s*호?)?"
_ADDR = re.compile(
    rf"(?:{_SIDO}\s*)?(?:{_GUGUN}\s*){{1,2}}(?:{_DONG}\s*)?(?:{_ROAD}\s*)?{_NUM}")


def _address_spans(text: str) -> list[Span]:
    out = []
    for m in re.finditer(_ADDR, text):
        span = m.group(0)
        if re.search(r"(로|길)\s*\d", span) or re.search(r"[가-힣](?:읍|면|동|리)", span) \
                or re.search(r"\d+(?:번지|번길|호)", span):
            out.append(Span("ADDRESS", m.start(), m.start() + len(span.rstrip()), 0.85))
    return out


def recognize(text: str, *, names: bool = True, addresses: bool = True,
              extra: list[Callable[[str], list[Span]]] | None = None) -> list[Span]:
    spans: list[Span] = []
    if names:
        spans += _name_spans(text)
    if addresses:
        spans += _address_spans(text)
    for fn in (extra or []):
        spans += fn(text)
    return spans
