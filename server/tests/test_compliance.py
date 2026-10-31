import pytest
from fastapi.testclient import TestClient

from axfilter import compliance
from axfilter.app import Config, create_app

KEYS = {"agent": "a-key", "viewer": "v-key", "admin": "d-key"}


@pytest.fixture
def client(tmp_path):
    cfg = Config(str(tmp_path / "c.db"), b"\x31" * 32, KEYS)
    return TestClient(create_app(cfg))


def h(r):
    return {"X-API-Key": KEYS[r]}


def seed(client):
    client.post("/v1/inspect", headers=h("agent"),
                json={"service": "ChatGPT", "user": "kim", "ip": "10.0.0.1", "text": "mail a@b.com"})
    client.post("/v1/inspect", headers=h("agent"),
                json={"service": "ChatGPT", "user": "kim", "ip": "10.0.0.1", "text": "카드 4539 1488 0343 6467"})
    client.put("/v1/policy", headers=h("admin"), json={})          # policy change -> history
    client.get("/v1/events/1/original", headers=h("admin"))        # VIEW_ORIGINAL -> audit


def test_sign_verify_roundtrip_and_tamper():
    r = compliance.build_report(_FakeStore(), {"key_provider": "local", "tls_required": True},
                                sign_key=b"k" * 32)
    assert compliance.verify(r, b"k" * 32)
    assert not compliance.verify(r, b"x" * 32)
    r["controls"][0]["status"] = "미충족"           # tamper
    assert not compliance.verify(r, b"k" * 32)


def test_report_endpoint_structure_and_signature(client):
    seed(client)
    r = client.get("/v1/compliance/report?period=month", headers=h("admin")).json()
    assert r["controls"] and "signature" in r and r["signature"]["alg"] == "HMAC-SHA256"
    assert r["evidence"]["audit_integrity"]["verified"] is True
    assert r["evidence"]["masking"]["masked"] >= 1 and r["evidence"]["masking"]["blocked"] >= 1
    assert r["evidence"]["policy_changes"]["versions"] >= 1
    assert r["evidence"]["access_control"]["original_access_count"] >= 1
    # server re-verifies its own signature
    assert client.post("/v1/compliance/verify", headers=h("admin"), json=r).json()["valid"] is True
    r["controls"][0]["status"] = "미충족"
    assert client.post("/v1/compliance/verify", headers=h("admin"), json=r).json()["valid"] is False


def test_report_csv_and_framework_filter(client):
    seed(client)
    csv = client.get("/v1/compliance/report.csv?framework=ISMS-P", headers=h("admin"))
    assert csv.status_code == 200 and "text/csv" in csv.headers["content-type"]
    assert "framework,control_id" in csv.text and "ISO 27001" not in csv.text and "ISMS-P" in csv.text


def test_policy_history_and_audit_search(client):
    seed(client)
    hist = client.get("/v1/policy/history", headers=h("admin")).json()
    assert len(hist) >= 1 and hist[0]["actor"] == "admin"
    views = client.get("/v1/audit/search?action=VIEW_ORIGINAL", headers=h("admin")).json()
    assert len(views) >= 1 and all(v["action"] == "VIEW_ORIGINAL" for v in views)
    # viewer cannot reach compliance endpoints
    assert client.get("/v1/compliance/report", headers=h("viewer")).status_code == 403
    assert client.get("/v1/policy/history", headers=h("viewer")).status_code == 403


class _FakeStore:
    """Minimal store for the pure sign/verify unit test."""
    key_provider_name = "local"
    def summary(self, *a): return {"masked": 1, "blocked": 1, "detected": 2, "total": 3}
    def verify_audit(self): return {"ok": True, "broken_at": None}
    def audit_search(self, **k): return []
    def policy_history(self, limit=100): return []
