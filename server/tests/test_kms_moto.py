"""Validate AwsKmsKeyProvider against moto's in-process KMS (real boto3 code path,
faithful Encrypt/Decrypt + EncryptionContext enforcement). No AWS account needed."""
import sqlite3

import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from axfilter.keys import AwsKmsKeyProvider  # noqa: E402
from axfilter.store import Store  # noqa: E402


@mock_aws
def _make_key():
    import boto3
    kms = boto3.client("kms", region_name="ap-northeast-2")
    return kms.create_key()["KeyMetadata"]["KeyId"]


@mock_aws
def test_kms_envelope_wrap_unwrap_roundtrip():
    import boto3
    key_id = boto3.client("kms", region_name="ap-northeast-2").create_key()["KeyMetadata"]["KeyId"]
    prov = AwsKmsKeyProvider(key_id, client=boto3.client("kms", region_name="ap-northeast-2"))
    dek = b"\x11" * 32
    blob = prov.wrap(dek)
    assert blob != dek
    assert prov.unwrap(blob) == dek


@mock_aws
def test_kms_encryption_context_is_enforced():
    import boto3
    kms = boto3.client("kms", region_name="ap-northeast-2")
    key_id = kms.create_key()["KeyMetadata"]["KeyId"]
    prov = AwsKmsKeyProvider(key_id, client=kms)
    blob = prov.wrap(b"\x22" * 32)
    # decrypting the same ciphertext under a different context must fail
    with pytest.raises(Exception):
        kms.decrypt(CiphertextBlob=blob, EncryptionContext={"app": "evil"})


@mock_aws
def test_store_uses_kms_and_rotation_works(tmp_path):
    import boto3
    kms = boto3.client("kms", region_name="ap-northeast-2")
    key_id = kms.create_key()["KeyMetadata"]["KeyId"]
    db = tmp_path / "kms.db"
    s = Store(db, AwsKmsKeyProvider(key_id, client=kms))
    eid = s.add_event(service="chatgpt", user="u", ip="10.0.0.1", group="g", direction="input",
                      action="mask", reason="PII_MASKED", finding_types=["EMAIL"], latency_ms=1.0,
                      masked_text="[이메일]", original="hong@corp.com")
    # original is encrypted at rest; the stored DEK is a KMS ciphertext blob, not the raw key
    raw = sqlite3.connect(str(db))
    assert b"hong@corp.com" not in raw.execute("SELECT original_enc FROM events").fetchone()[0]
    # reopen (forces KMS Decrypt of the wrapped DEK) and read back
    s2 = Store(db, AwsKmsKeyProvider(key_id, client=kms))
    assert s2.decrypt_original(s2.get_event(eid)) == "hong@corp.com"
    # key rotation re-encrypts under a fresh DEK and stays readable
    assert s2.rotate_data_key() == 1
    s3 = Store(db, AwsKmsKeyProvider(key_id, client=kms))
    assert s3.decrypt_original(s3.get_event(eid)) == "hong@corp.com"
