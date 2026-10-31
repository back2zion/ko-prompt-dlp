import time

import pytest
from fastapi.testclient import TestClient

from axfilter.app import Config, create_app
from axfilter.keys import LocalMasterKeyProvider
from axfilter.store import Store, retention_run

KEYS = {"agent": "a-key", "viewer": "v-key", "admin": "d-key"}
DAY = 86400


def h(role):
    return {"X-API-Key": KEYS[role]}


def _store(tmp_path, name="r.db"):
    return Store(str(tmp_path / name), LocalMasterKeyProvider(b"\x07" * 32))


def _add(store, *, ts, text="mail a@b.com", findings=("EMAIL",)):
    return store.add_event(
        service="chatgpt", user="kim", ip="10.0.0.1", group="all",
        direction="input", action="mask", reason=None, finding_types=list(findings),
        latency_ms=1.0, masked_text="[이메일]", original=text, ts=ts)


# ---- Store.purge_original_text --------------------------------------------
def test_purge_original_text_drops_old_keeps_new_and_metadata(tmp_path):
    now = int(time.time())
    store = _store(tmp_path)
    old = _add(store, ts=now - 200 * DAY, text="old a@b.com")
    new = _add(store, ts=now - 1 * DAY, text="new c@d.com")

    n = store.purge_original_text(now - 90 * DAY)
    assert n == 1

    # old: row + metadata remain, but the recoverable original is gone
    old_row = store.get_event(old)
    assert old_row is not None
    assert old_row["original_enc"] is None and old_row["nonce"] is None
    assert old_row["finding_count"] == 1 and old_row["masked_text"] == "[이메일]"
    assert store.decrypt_original(old_row) is None

    # new: still decryptable
    new_row = store.get_event(new)
    assert store.decrypt_original(new_row) == "new c@d.com"

    # idempotent: nothing left older to purge
    assert store.purge_original_text(now - 90 * DAY) == 0


# ---- Store.purge_events ----------------------------------------------------
def test_purge_events_deletes_old_rows_entirely(tmp_path):
    now = int(time.time())
    store = _store(tmp_path, "r2.db")
    old = _add(store, ts=now - 200 * DAY)
    new = _add(store, ts=now - 1 * DAY)

    assert store.count_events_older_than(now - 90 * DAY) == 1
    deleted = store.purge_events(now - 90 * DAY)
    assert deleted == 1
    assert store.get_event(old) is None
    assert store.get_event(new) is not None


# ---- retention_run helper + append-only audit ------------------------------
def test_retention_run_writes_audit_and_keeps_chain(tmp_path):
    now = int(time.time())
    store = _store(tmp_path, "r3.db")
    _add(store, ts=now - 200 * DAY)
    _add(store, ts=now - 150 * DAY)
    _add(store, ts=now - 1 * DAY)

    res = retention_run(store, original_days=90, event_days=120, actor="admin:tester")
    assert res == {"purged_originals": 2, "purged_events": 2}

    # audit chain intact and holds both purge records with counts
    assert store.verify_audit()["ok"] is True
    actions = [e["action"] for e in store.audit_entries()]
    assert "PURGE_ORIGINAL" in actions and "PURGE_EVENTS" in actions
    pe = store.audit_search(action="PURGE_EVENTS")[0]
    assert "count=2" in pe["target"]


def test_retention_run_event_days_zero_keeps_events(tmp_path):
    now = int(time.time())
    store = _store(tmp_path, "r4.db")
    _add(store, ts=now - 200 * DAY)

    res = retention_run(store, original_days=90, event_days=0)
    assert res == {"purged_originals": 1, "purged_events": 0}
    assert store.count_events_older_than(now + DAY) == 1  # row still present
    # only PURGE_ORIGINAL was recorded
    assert store.audit_search(action="PURGE_EVENTS") == []
    assert len(store.audit_search(action="PURGE_ORIGINAL")) == 1


# ---- endpoint --------------------------------------------------------------
def test_retention_endpoint_requires_admin_and_runs(tmp_path):
    now = int(time.time())
    cfg = Config(str(tmp_path / "api.db"), b"\x08" * 32, KEYS,
                 retention_original_days=90, retention_event_days=0)
    app = create_app(cfg)
    client = TestClient(app)

    # seed via the store the app uses (same db/key) at old + new timestamps
    store = Store(cfg.db_path, LocalMasterKeyProvider(cfg.data_key))
    old = _add(store, ts=now - 200 * DAY, text="old a@b.com")
    new = _add(store, ts=now - 1 * DAY, text="new c@d.com")

    # viewer/agent are refused
    assert client.post("/v1/retention/run", headers=h("viewer")).status_code == 403
    assert client.post("/v1/retention/run", headers=h("agent")).status_code == 403
    assert client.post("/v1/retention/run").status_code == 401

    r = client.post("/v1/retention/run", headers=h("admin"))
    assert r.status_code == 200
    assert r.json() == {"purged_originals": 1, "purged_events": 0}

    # old original gone, new untouched, both rows still present (event_days=0)
    assert client.get(f"/v1/events/{old}/original", headers=h("admin")).json()["original"] is None
    assert client.get(f"/v1/events/{new}/original", headers=h("admin")).json()["original"] == "new c@d.com"

    # audit record written and chain still verifies
    a = client.get("/v1/audit", headers=h("admin")).json()
    assert a["verify"]["ok"] is True
    assert any(e["action"] == "PURGE_ORIGINAL" for e in a["entries"])
