"""Regression guard on detection quality. Keeps structured-PII at perfect score and
holds name/address recall above a floor, so a change that quietly worsens detection
or introduces false positives fails CI."""
import pathlib

from axfilter.bench import score_file

DATASET = pathlib.Path(__file__).resolve().parents[1] / "bench" / "dataset.jsonl"


def test_detection_quality_thresholds():
    m = score_file(DATASET)
    per, overall = m["per_type"], m["overall"]
    # structured PII (regex + checksum) must stay perfect
    for t in ("RRN", "CARD", "EMAIL", "PHONE", "BIZNO", "PASSPORT", "SECRET"):
        assert per[t]["f1"] == 1.0, (t, per[t])
    # no false positives anywhere (precision-first design, incl. title+님 traps)
    assert overall["fp"] == 0, overall
    # name/address are recall-limited by design but must not regress below the floor
    assert per["NAME"]["recall"] >= 0.75, per["NAME"]
    assert per["ADDRESS"]["recall"] >= 0.45, per["ADDRESS"]
    assert overall["f1"] >= 0.9, overall
