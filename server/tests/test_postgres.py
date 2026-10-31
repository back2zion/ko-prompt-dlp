"""Integration tests against a real PostgreSQL, run only when AXFILTER_TEST_DATABASE_URL is set.

Proves the SQLAlchemy store and the API behave identically on Postgres: stats
aggregation, KST day bucketing, key rotation, audit tamper detection, and the
reserved-word column `user`.
"""
import os
import time

import pytest
from fastapi.testclient import TestClient

from axfilter.app import Config, create_app
from axfilter.keys import LocalMasterKeyProvider
from axfilter.store import Store, metadata

URL = os.environ.get("AXFILTER_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="set AXFILTER_TEST_DATABASE_URL to run")
KEYS = {"agent": "a-key", "viewer": "v-key", "admin": "d-key"}


def _reset():
    from sqlalchemy import create_engine
    eng = create_engine(URL, future=True)
    metadata.drop_all(eng)          # clean slate for each test
    eng.dispose()


def _fresh_store():
    _reset()
    return Store(URL, LocalMasterKeyProvider(b"\x21" * 32))


def h(role):
    return {"X-API-Key": KEYS[role]}


def test_store_stats_and_rotation_on_postgres():
    s = _fresh_store()
    now = int(time.time())
    def add(action, ftypes, svc="chatgpt", grp="g1", user="u1", ip="10.0.0.1", ts=None):
        s.add_event(service=svc, user=user, ip=ip, group=grp, direction="input",
                    action=action, reason=None, finding_types=ftypes, latency_ms=100.0,
                    masked_text="[m]" if ftypes else "x", original="orig-text", ts=ts or now)
    add("allow", [])
    add("mask", ["EMAIL"])
    add("block", ["RRN"], svc="claude", grp="g2", user="u2", ip="10.0.0.2")
    summ = s.summary(now - 3600, "all")
    assert (summ["total"], summ["detected"], summ["blocked"], summ["masked"], summ["allowed"]) == (3, 2, 1, 1, 2)
    svc = {r["service"]: r["total"] for r in s.by_service(now - 3600, "all")}
    assert svc == {"chatgpt": 2, "claude": 1}
    top = s.top(now - 3600, "all", "group", 5)
    assert {r["grp"] for r in top} == {"g1", "g2"}
    days = s.daily(now - 3600, "all")
    assert len(days) == 1 and len(days[0]["day"]) == 10   # YYYY-MM-DD, KST bucket
    # rotation re-encrypts and keeps originals readable
    n = s.rotate_data_key()
    assert n == 2
    enc_rows = [r for r in [s.get_event(i) for i in (2, 3)]]
    assert all(s.decrypt_original(r) == "orig-text" for r in enc_rows)


def test_audit_chain_on_postgres():
    s = _fresh_store()
    s.audit("admin", "VIEW_ORIGINAL", "event:1")
    s.audit("admin", "UPDATE_POLICY", "policy")
    assert s.verify_audit()["ok"]
    # tamper directly in the DB
    from sqlalchemy import create_engine, text
    eng = create_engine(URL, future=True)
    with eng.begin() as c:
        c.execute(text("UPDATE audit SET actor='nobody' WHERE id=1"))
    assert s.verify_audit() == {"ok": False, "broken_at": 1}


def test_api_end_to_end_on_postgres():
    _reset()  # the app opens its own store (own key) on a clean schema
    cfg = Config(URL, b"\x22" * 32, KEYS)
    c = TestClient(create_app(cfg))
    assert c.post("/v1/inspect", headers=h("agent"),
                  json={"service": "ChatGPT", "user": "kim", "ip": "192.168.1.1",
                        "text": "mail a@b.com"}).json()["action"] == "mask"
    assert c.post("/v1/inspect", headers=h("agent"),
                  json={"service": "ChatGPT", "user": "kim", "ip": "192.168.1.1",
                        "text": "카드 4539 1488 0343 6467"}).json()["action"] == "block"
    s = c.get("/v1/stats/summary?period=today&direction=input", headers=h("viewer")).json()
    assert s["total"] == 2 and s["blocked"] == 1 and s["masked"] == 1
    o = c.get("/v1/events/1/original", headers=h("admin")).json()
    assert o["original"] == "mail a@b.com"
