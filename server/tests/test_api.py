import pytest
from fastapi.testclient import TestClient

from axfilter.app import Config, create_app

KEYS = {"agent": "a-key", "viewer": "v-key", "admin": "d-key"}


@pytest.fixture
def client(tmp_path):
    cfg = Config(str(tmp_path / "t.db"), b"\x01" * 32, KEYS)
    return TestClient(create_app(cfg))


def h(role):
    return {"X-API-Key": KEYS[role]}


def inspect(client, text, service="ChatGPT", ip="192.168.1.101"):
    return client.post("/v1/inspect", headers=h("agent"),
                       json={"service": service, "user": "kim", "ip": ip, "text": text}).json()


def test_requires_key_and_role(client):
    assert client.post("/v1/inspect", json={}).status_code == 401
    assert client.get("/v1/stats/summary", headers=h("agent")).status_code == 403
    assert client.put("/v1/policy", headers=h("viewer"), json={}).status_code == 403


def test_mask_block_allow(client):
    r = inspect(client, "문의: a@b.com")
    assert r["action"] == "mask" and r["text"] == "문의: [이메일]"
    r = inspect(client, "카드 4539 1488 0343 6467")
    assert r["action"] == "block" and r["text"] is None and r["message"]
    r = inspect(client, "안녕하세요")
    assert r["action"] == "allow" and r["text"] == "안녕하세요"


def test_response_never_echoes_raw_values(client):
    r = inspect(client, "a@b.com")
    assert "a@b.com" not in str(r)


def test_policy_service_block_groups_and_time(client):
    policy = {"services": {"perplexity": "block"},
              "groups": [{"name": "연구소", "cidrs": ["192.168.1.110/30"]}],
              "time_rules": [{"group": "연구소", "start": "00:00", "end": "00:00"}]}
    assert client.put("/v1/policy", headers=h("admin"), json=policy).status_code == 200
    assert inspect(client, "hi", service="Perplexity")["reason"] == "SERVICE_BLOCKED"
    # start == end -> window never contains "now" ... 00:00-00:00 is treated as empty
    r = inspect(client, "hi", ip="192.168.1.111")
    assert r["action"] == "block" and r["reason"] == "TIME_RESTRICTED"
    assert inspect(client, "hi", ip="10.0.0.1")["action"] == "allow"


def test_stats_and_original_access_is_audited(client):
    inspect(client, "a@b.com")
    inspect(client, "카드 4539 1488 0343 6467")
    inspect(client, "hello", service="Claude", ip="192.168.1.102")
    s = client.get("/v1/stats/summary?period=today", headers=h("viewer")).json()
    assert (s["total"], s["detected"], s["blocked"], s["masked"], s["allowed"]) == (3, 2, 1, 1, 2)
    svc = {x["service"]: x["total"] for x in client.get("/v1/stats/services", headers=h("viewer")).json()}
    assert svc == {"chatgpt": 2, "claude": 1}
    top = client.get("/v1/stats/top?by=ip", headers=h("viewer")).json()
    assert top[0]["ip"] == "192.168.1.101" and top[0]["total"] == 2
    assert len(client.get("/v1/stats/daily", headers=h("viewer")).json()) == 1

    ev = client.get("/v1/events?action=mask", headers=h("viewer")).json()
    assert "original" not in ev[0] and ev[0]["masked_text"] == "[이메일]"
    assert client.get(f"/v1/events/{ev[0]['id']}/original", headers=h("viewer")).status_code == 403
    o = client.get(f"/v1/events/{ev[0]['id']}/original", headers=h("admin")).json()
    assert o["original"] == "a@b.com"
    a = client.get("/v1/audit", headers=h("admin")).json()
    assert a["verify"]["ok"] and a["entries"][0]["action"] == "VIEW_ORIGINAL"


def test_original_is_encrypted_at_rest(tmp_path):
    import sqlite3
    cfg = Config(str(tmp_path / "t.db"), b"\x02" * 32, KEYS)
    c = TestClient(create_app(cfg))
    inspect(c, "비밀 a@b.com")
    raw = sqlite3.connect(cfg.db_path).execute("SELECT original_enc FROM events").fetchone()[0]
    assert b"a@b.com" not in raw


def test_audit_tamper_detected(client, tmp_path):
    import sqlite3
    inspect(client, "a@b.com")
    client.put("/v1/policy", headers=h("admin"), json={})
    client.get("/v1/events/1/original", headers=h("admin"))
    assert client.get("/v1/audit", headers=h("admin")).json()["verify"]["ok"]
    db = sqlite3.connect(str(tmp_path / "t.db"))
    db.execute("UPDATE audit SET actor='nobody' WHERE id=1")
    db.commit()
    assert client.get("/v1/audit", headers=h("admin")).json()["verify"] == {"ok": False, "broken_at": 1}
