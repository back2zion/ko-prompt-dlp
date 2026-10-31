"""Unit-test the transformer NER adapter with a stub pipeline (no model download)."""
from axfilter.detector import detect
from axfilter.ner_models import TransformerNerRecognizer


def stub_pipeline(text):
    # mimics transformers token-classification output (aggregation_strategy="simple")
    out = []
    if "김철수" in text:
        i = text.index("김철수"); out.append({"entity_group": "PS", "start": i, "end": i + 3, "score": 0.98, "word": "김철수"})
    if "서울특별시 종로구" in text:
        i = text.index("서울특별시 종로구"); out.append({"entity_group": "LC", "start": i, "end": i + len("서울특별시 종로구"), "score": 0.9})
    if "저신뢰" in text:
        i = text.index("저신뢰"); out.append({"entity_group": "PER", "start": i, "end": i + 3, "score": 0.3})  # below threshold
    if "회사" in text:
        i = text.index("회사"); out.append({"entity_group": "OG", "start": i, "end": i + 2, "score": 0.99})    # unmapped label
    return out


def test_label_mapping_and_threshold():
    rec = TransformerNerRecognizer(pipeline=stub_pipeline, threshold=0.5)
    spans = rec("김철수 고객, 서울특별시 종로구, 저신뢰 사람, 우리 회사")
    kinds = sorted((s.type for s in spans))
    assert kinds == ["ADDRESS", "NAME"]              # PS->NAME, LC->ADDRESS; low-score & OG dropped


def test_bio_prefix_stripping():
    def pipe(t):
        return [{"entity_group": "B-PER", "start": 0, "end": 3, "score": 0.95}]
    assert TransformerNerRecognizer(pipeline=pipe)("김철수")[0].type == "NAME"


def test_model_recall_beyond_rules_via_detect_extra():
    # a bare name the rule recognizer intentionally misses (no cue/honorific)
    text = "김철수 보고서를 검토"
    assert [f.type for f in detect(text)] == []                      # rules: no NAME
    rec = TransformerNerRecognizer(pipeline=stub_pipeline, threshold=0.5)
    types = [f.type for f in detect(text, extra=[rec])]
    assert "NAME" in types                                           # model recovers it


def test_requires_model_or_pipeline():
    import pytest
    with pytest.raises(ValueError):
        TransformerNerRecognizer()
