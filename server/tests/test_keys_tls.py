"""Regression tests for envelope encryption, key rotation and TLS enforcement."""
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from axfilter.app import Config, create_app
from axfilter.keys import AwsKmsKeyProvider, LocalMasterKeyProvider, provider_from_env
from axfilter.store import Store

KEYS = {"agent": "a-key", "viewer": "v-key", "admin": "d-key"}


def h(role):
    return {"X-API-Key": KEYS[role]}


class FakeKms:
    """In-memory stand-in for a boto3 KMS client. Stores plaintext DEKs by handle."""

    def __init__(self):
        self._vault = {}
        self._n = 0
        self.encrypt_calls = 0
        self.decrypt_calls = 0

    def encrypt(self, KeyId, Plaintext, EncryptionContext):
        self.encrypt_calls += 1
        self._n += 1
        handle = f"{KeyId}#{self._n}".encode()
        self._vault[handle] = (Plaintext, EncryptionContext)
        return {"CiphertextBlob": handle}

    def decrypt(self, CiphertextBlob, EncryptionContext):
        self.decrypt_calls += 1
        plaintext, ctx = self._vault[CiphertextBlob]
        assert ctx == EncryptionContext, "EncryptionContext must match on decrypt"
        return {"Plaintext": plaintext}


# ---- LocalMasterKeyProvider ----------------------------------------------
def test_local_provider_roundtrip():
    p = LocalMasterKeyProvider(b"\x07" * 32)
    dek = b"\x11" * 32
    assert p.unwrap(p.wrap(dek)) == dek


def test_local_provider_rejects_tampered_blob():
    p = LocalMasterKeyProvider(b"\x07" * 32)
    blob = bytearray(p.wrap(b"\x11" * 32))
    blob[-1] ^= 1
    with pytest.raises(Exception):
        p.unwrap(bytes(blob))


def test_local_provider_requires_32_byte_key():
    with pytest.raises(ValueError):
        LocalMasterKeyProvider(b"short")


# ---- AwsKmsKeyProvider (fake client) -------------------------------------
def test_kms_wraps_dek_and_plaintext_key_never_stored(tmp_path):
    kms = FakeKms()
    prov = AwsKmsKeyProvider("alias/axfilter", client=kms)
    db = tmp_path / "k.db"
    s = Store(db, prov)
    s.add_event(service="chatgpt", user="u", ip="10.0.0.1", group="g", direction="input",
                action="mask", reason="PII_MASKED", finding_types=["EMAIL"], latency_ms=1.0,
                masked_text="[label]", original="secret-original")
    assert kms.encrypt_calls == 1
    raw = sqlite3.connect(str(db))
    stored_dek = bytes.fromhex(raw.execute("SELECT v FROM kv WHERE k='dek'").fetchone()[0])
    assert stored_dek.startswith(b"alias/axfilter#")       # only the KMS handle is stored
    enc = raw.execute("SELECT original_enc FROM events").fetchone()[0]
    assert b"secret-original" not in enc


def test_kms_reopen_uses_decrypt_and_reads_original(tmp_path):
    kms = FakeKms()
    db = tmp_path / "k.db"
    s1 = Store(db, AwsKmsKeyProvider("alias/axfilter", client=kms))
    eid = s1.add_event(service="chatgpt", user="u", ip="10.0.0.1", group="g", direction="input",
                       action="mask", reason="PII_MASKED", finding_types=["EMAIL"], latency_ms=1.0,
                       masked_text="[label]", original="hello-world")
    s2 = Store(db, AwsKmsKeyProvider("alias/axfilter", client=kms))  # reopen
    assert kms.decrypt_calls >= 1
    assert s2.decrypt_original(s2.get_event(eid)) == "hello-world"


def test_provider_from_env_selects_local_and_kms(monkeypatch):
    monkeypatch.delenv("AXFILTER_KEY_PROVIDER", raising=False)
    assert provider_from_env(b"\x01" * 32).name == "local"
    monkeypatch.setenv("AXFILTER_KEY_PROVIDER", "awskms")
    monkeypatch.delenv("AXFILTER_KMS_KEY_ID", raising=False)
    with pytest.raises(RuntimeError):
        provider_from_env(b"\x01" * 32)  # key id required


# ---- key rotation --------------------------------------------------------
def test_rotate_reencrypts_all_originals_and_keeps_readable(tmp_path):
    db = tmp_path / "r.db"
    s = Store(db, LocalMasterKeyProvider(b"\x09" * 32))
    ids = [s.add_event(service="chatgpt", user="u", ip="10.0.0.1", group="g", direction="input",
                       action="mask", reason="PII_MASKED", finding_types=["EMAIL"], latency_ms=1.0,
                       masked_text="[label]", original=f"original-{i}") for i in range(3)]
    before = sqlite3.connect(str(db)).execute(
        "SELECT original_enc FROM events ORDER BY id").fetchall()
    n = s.rotate_data_key()
    assert n == 3
    after = sqlite3.connect(str(db)).execute(
        "SELECT original_enc FROM events ORDER BY id").fetchall()
    assert all(b[0] != a[0] for b, a in zip(before, after))   # ciphertext changed
    for i, eid in enumerate(ids):
        assert s.decrypt_original(s.get_event(eid)) == f"original-{i}"


def test_rotate_endpoint_requires_admin_and_is_audited(tmp_path):
    cfg = Config(str(tmp_path / "a.db"), b"\x0a" * 32, KEYS)
    c = TestClient(create_app(cfg))
    c.post("/v1/inspect", headers=h("agent"),
           json={"service": "ChatGPT", "user": "u", "ip": "10.0.0.1", "text": "mail a@b.com"})
    assert c.post("/v1/keys/rotate", headers=h("viewer")).status_code == 403
    r = c.post("/v1/keys/rotate", headers=h("admin")).json()
    assert r["reencrypted"] == 1 and r["provider"] == "local"
    audit = c.get("/v1/audit", headers=h("admin")).json()
    assert audit["verify"]["ok"] and "ROTATE_DATA_KEY" in [e["action"] for e in audit["entries"]]
    # original still readable after rotation through the API
    assert c.get("/v1/events/1/original", headers=h("admin")).json()["original"] == "mail a@b.com"


# ---- TLS enforcement -----------------------------------------------------
def test_require_tls_rejects_plain_http(tmp_path):
    cfg = Config(str(tmp_path / "t.db"), b"\x0b" * 32, KEYS, require_tls=True)
    c = TestClient(create_app(cfg))  # TestClient speaks http
    r = c.get("/healthz")
    assert r.status_code == 426 and "TLS" in r.text


def test_trusted_proxy_forwarded_proto_allows_request(tmp_path):
    cfg = Config(str(tmp_path / "t.db"), b"\x0c" * 32, KEYS, require_tls=True, trusted_proxy=True)
    c = TestClient(create_app(cfg))
    r = c.get("/healthz", headers={"X-Forwarded-Proto": "https"})
    assert r.status_code == 200
    assert r.headers["Strict-Transport-Security"].startswith("max-age=")


def test_untrusted_forwarded_proto_is_ignored(tmp_path):
    cfg = Config(str(tmp_path / "t.db"), b"\x0d" * 32, KEYS, require_tls=True, trusted_proxy=False)
    c = TestClient(create_app(cfg))
    assert c.get("/healthz", headers={"X-Forwarded-Proto": "https"}).status_code == 426
