"""Database-backed named API keys: Store unit tests and API/auth integration."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from axfilter import apikeys
from axfilter.app import Config, create_app
from axfilter.keys import LocalMasterKeyProvider
from axfilter.oidc import Principal
from axfilter.store import Store

KEYS = {"agent": "a-key", "viewer": "v-key", "admin": "d-key"}


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "t.db")


@pytest.fixture
def client(db_path):
    return TestClient(create_app(Config(db_path, b"\x01" * 32, KEYS)))


def h(role):
    return {"X-API-Key": KEYS[role]}


# ---- Store unit tests ---------------------------------------------------
def test_store_issue_lookup_revoke(db_path):
    store = Store(db_path, LocalMasterKeyProvider(b"\x07" * 32))
    token = store.issue_key("alice", "viewer")
    assert isinstance(token, str) and len(token) > 20

    pr = store.lookup_key(token)
    assert isinstance(pr, Principal) and pr == Principal("alice", "viewer")

    # wrong / empty token -> no principal
    assert store.lookup_key("not-the-token") is None
    assert store.lookup_key("") is None

    key_id = store.list_keys()[0]["id"]
    assert store.revoke_key(key_id) is True
    assert store.lookup_key(token) is None            # revoked no longer authenticates
    assert store.revoke_key(key_id) is False          # idempotent: already revoked


def test_store_only_hash_is_persisted(db_path):
    store = Store(db_path, LocalMasterKeyProvider(b"\x08" * 32))
    token = store.issue_key("bob", "admin")
    rows = sqlite3.connect(db_path).execute(
        "SELECT name, role, token_sha256, created_ts, revoked_ts FROM api_keys").fetchall()
    assert len(rows) == 1
    name, role, token_sha256, created_ts, revoked_ts = rows[0]
    assert name == "bob" and role == "admin" and revoked_ts is None
    assert token not in token_sha256 and token_sha256 != token
    assert token_sha256 == apikeys._hash(token)       # exactly the SHA-256 of the raw token
    # the raw token appears nowhere in the database file
    with open(db_path, "rb") as f:
        assert token.encode() not in f.read()


def test_store_issue_rejects_unknown_role(db_path):
    store = Store(db_path, LocalMasterKeyProvider(b"\x09" * 32))
    with pytest.raises(ValueError):
        store.issue_key("carol", "superuser")


# ---- API integration ----------------------------------------------------
def test_issue_authenticate_revoke_via_api(client):
    # admin issues a viewer key
    r = client.post("/v1/keys", headers=h("admin"), json={"name": "dana", "role": "viewer"})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"id", "name", "role", "token"}
    assert body["name"] == "dana" and body["role"] == "viewer"
    token = body["token"]
    key_id = body["id"]

    # the issued viewer key authenticates against a viewer endpoint
    kh = {"X-API-Key": token}
    assert client.get("/v1/stats/summary", headers=kh).status_code == 200
    # but a viewer key is refused on an admin endpoint (role enforcement)
    assert client.get("/v1/policy", headers=kh).status_code == 200   # viewer may read policy
    assert client.put("/v1/policy", headers=kh, json={}).status_code == 403

    # revoke -> now 401
    assert client.delete(f"/v1/keys/{key_id}", headers=h("admin")).status_code == 200
    assert client.get("/v1/stats/summary", headers=kh).status_code == 401
    # revoking again -> 404
    assert client.delete(f"/v1/keys/{key_id}", headers=h("admin")).status_code == 404


def test_admin_key_authenticates_admin_endpoint(client):
    r = client.post("/v1/keys", headers=h("admin"), json={"name": "erin", "role": "admin"})
    token = r.json()["token"]
    kh = {"X-API-Key": token}
    # admin-issued admin key can read + write policy
    assert client.get("/v1/policy", headers=kh).status_code == 200
    assert client.put("/v1/policy", headers=kh, json={}).status_code == 200


def test_list_has_no_secrets(client):
    client.post("/v1/keys", headers=h("admin"), json={"name": "frank", "role": "agent"})
    listing = client.get("/v1/keys", headers=h("admin")).json()
    assert len(listing) == 1
    row = listing[0]
    assert set(row) == {"id", "name", "role", "created_ts", "revoked_ts"}
    assert "token" not in row and "token_sha256" not in row


def test_key_endpoints_require_admin(client):
    # viewer/agent static keys may not manage keys
    assert client.post("/v1/keys", headers=h("viewer"),
                       json={"name": "x", "role": "agent"}).status_code == 403
    assert client.get("/v1/keys", headers=h("agent")).status_code == 403
    assert client.delete("/v1/keys/1", headers=h("viewer")).status_code == 403
    # no key at all -> 401
    assert client.get("/v1/keys").status_code == 401


def test_static_keys_still_work_alongside_db_keys(client):
    # static role keys keep working after DB keys exist
    client.post("/v1/keys", headers=h("admin"), json={"name": "g", "role": "viewer"})
    assert client.get("/v1/stats/summary", headers=h("viewer")).status_code == 200
    assert client.get("/v1/policy", headers=h("admin")).status_code == 200
    assert client.get("/v1/stats/summary", headers=h("agent")).status_code == 403


def test_issue_and_revoke_are_audited(client):
    r = client.post("/v1/keys", headers=h("admin"), json={"name": "heidi", "role": "viewer"})
    key_id = r.json()["id"]
    client.delete(f"/v1/keys/{key_id}", headers=h("admin"))
    actions = [e["action"] for e in client.get("/v1/audit", headers=h("admin")).json()["entries"]]
    assert "ISSUE_API_KEY" in actions and "REVOKE_API_KEY" in actions
