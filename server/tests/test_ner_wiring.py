"""Wire the transformer NER adapter into the running app via an injected stub.

No model download: Config carries ``ner_recognizers`` directly, so create_app
uses it and the inspect path forwards it to detection. Proves that a bare name
the rule recognizers intentionally miss ("김철수" with no cue/honorific) is
recovered as a NAME finding only when a recognizer is configured.
"""
from fastapi.testclient import TestClient

from axfilter.app import Config, create_app
from axfilter.recognizers import Span

KEYS = {"agent": "a-key", "viewer": "v-key", "admin": "d-key"}
TEXT = "김철수 보고서 제출"


def stub_recognizer(text):
    if "김철수" in text:
        i = text.index("김철수")
        return [Span("NAME", i, i + 3, 0.98)]
    return []


def _client(tmp_path, recognizers=None):
    cfg = Config(str(tmp_path / "t.db"), b"\x01" * 32, KEYS, ner_recognizers=recognizers)
    return TestClient(create_app(cfg))


def _inspect(client, text):
    return client.post("/v1/inspect", headers={"X-API-Key": KEYS["agent"]},
                       json={"service": "ChatGPT", "user": "kim",
                             "ip": "192.168.1.101", "text": text}).json()


def test_rules_alone_miss_the_bare_name(tmp_path):
    r = _inspect(_client(tmp_path), TEXT)
    assert r["action"] == "allow"
    assert not any(f["type"] == "NAME" for f in r["findings"])


def test_injected_recognizer_recovers_the_name(tmp_path):
    r = _inspect(_client(tmp_path, [stub_recognizer]), TEXT)
    # default policy masks NAME
    assert r["action"] == "mask"
    names = [f for f in r["findings"] if f["type"] == "NAME"]
    assert names and names[0]["label"] == "이름"
    assert r["text"] == "[이름] 보고서 제출"
    assert "김철수" not in str(r)


def test_config_default_has_no_recognizer():
    cfg = Config("x.db", b"\x01" * 32, KEYS)
    assert cfg.ner_recognizers is None
