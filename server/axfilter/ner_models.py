"""Pluggable transformer NER adapter.

Wraps a Hugging Face token-classification pipeline and maps its entity labels to
AX Filter types, so a trained Korean NER model can raise name/address recall
beyond the rule-based recognizers. The model is injected (or built lazily from a
model name), and the adapter is a plain ``Callable[[str], list[Span]]`` that plugs
into ``detector.detect(text, extra=[adapter])`` and ``recognizers.recognize``.

Running a real model needs the optional dependency and model weights:
    pip install "axfilter[ner]"      # transformers + torch
Weights are downloaded from the model hub on first use, so this requires an
environment with model access. The label mapping and merge logic below are unit
-tested with a stub pipeline; see tests/test_ner_adapter.py.
"""
from __future__ import annotations

from typing import Callable

from .recognizers import Span

# Common Korean/English NER label schemes -> AX Filter types.
DEFAULT_LABEL_MAP = {
    "PER": "NAME", "PS": "NAME", "PERSON": "NAME", "NAME": "NAME",
    "LOC": "ADDRESS", "LC": "ADDRESS", "LOCATION": "ADDRESS", "ADDRESS": "ADDRESS",
}


class TransformerNerRecognizer:
    def __init__(self, model_name: str = "", *, pipeline: Callable | None = None,
                 label_map: dict[str, str] | None = None, threshold: float = 0.5,
                 device: int = -1):
        self.label_map = {k.upper(): v for k, v in (label_map or DEFAULT_LABEL_MAP).items()}
        self.threshold = threshold
        if pipeline is not None:
            self._pipe = pipeline
        else:
            if not model_name:
                raise ValueError("model_name or an injected pipeline is required")
            try:
                from transformers import pipeline as hf_pipeline
            except ImportError as e:
                raise ImportError('transformers is not installed; run: pip install "axfilter[ner]"') from e
            self._pipe = hf_pipeline("token-classification", model=model_name,
                                     aggregation_strategy="simple", device=device)

    def _map(self, group: str) -> str | None:
        g = (group or "").upper().split("-")[-1]       # strip BIO prefixes like B-PER
        return self.label_map.get(g)

    def __call__(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for ent in self._pipe(text):
            score = float(ent.get("score", 0.0))
            if score < self.threshold:
                continue
            typ = self._map(ent.get("entity_group") or ent.get("entity", ""))
            if typ is None:
                continue
            start, end = ent.get("start"), ent.get("end")
            if start is None or end is None or start >= end:
                continue
            spans.append(Span(typ, int(start), int(end), round(score, 3)))
        return spans
