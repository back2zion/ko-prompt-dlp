"""Benchmark the detector against a labeled dataset: precision / recall / F1.

A prediction counts as a true positive when it overlaps a gold span of the same
type (each gold and each prediction is matched at most once). Dataset is JSONL:
{"text": "...", "spans": [{"start":int,"end":int,"type":"RRN"}, ...]}.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .detector import detect


def _overlap(a, b) -> bool:
    return max(a[0], b[0]) < min(a[1], b[1])


def score_file(path: str | Path, keywords: list[str] | None = None) -> dict:
    tp = defaultdict(int); fp = defaultdict(int); fn = defaultdict(int)
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            gold = [(s["start"], s["end"], s["type"]) for s in row["spans"]]
            preds = [(x.start, x.end, x.type) for x in detect(row["text"], keywords or [])]
            used = set()
            for p in preds:
                hit = next((i for i, g in enumerate(gold)
                            if i not in used and g[2] == p[2] and _overlap(p, g)), None)
                if hit is None:
                    fp[p[2]] += 1
                else:
                    used.add(hit); tp[p[2]] += 1
            for i, g in enumerate(gold):
                if i not in used:
                    fn[g[2]] += 1
    types = sorted(set(tp) | set(fp) | set(fn))
    per = {}
    for t in types:
        p = tp[t] / (tp[t] + fp[t]) if tp[t] + fp[t] else 0.0
        r = tp[t] / (tp[t] + fn[t]) if tp[t] + fn[t] else 0.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        per[t] = {"tp": tp[t], "fp": fp[t], "fn": fn[t],
                  "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3)}
    TP, FP, FN = sum(tp.values()), sum(fp.values()), sum(fn.values())
    P = TP / (TP + FP) if TP + FP else 0.0
    R = TP / (TP + FN) if TP + FN else 0.0
    F = 2 * P * R / (P + R) if P + R else 0.0
    return {"per_type": per,
            "overall": {"tp": TP, "fp": FP, "fn": FN,
                        "precision": round(P, 3), "recall": round(R, 3), "f1": round(F, 3)}}


def format_report(m: dict) -> str:
    lines = [f"{'type':<10}{'prec':>7}{'recall':>8}{'f1':>7}{'tp':>5}{'fp':>5}{'fn':>5}", "-" * 47]
    for t, s in m["per_type"].items():
        lines.append(f"{t:<10}{s['precision']:>7.3f}{s['recall']:>8.3f}{s['f1']:>7.3f}"
                     f"{s['tp']:>5}{s['fp']:>5}{s['fn']:>5}")
    o = m["overall"]
    lines += ["-" * 47,
              f"{'OVERALL':<10}{o['precision']:>7.3f}{o['recall']:>8.3f}{o['f1']:>7.3f}"
              f"{o['tp']:>5}{o['fp']:>5}{o['fn']:>5}"]
    return "\n".join(lines)
