"""Envelope encryption key providers.

A master key (local or AWS KMS) wraps a per-database data encryption key (DEK).
Only the wrapped DEK is stored; the master key never touches the database.
"""
from __future__ import annotations

import os
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyProvider(Protocol):
    name: str

    def wrap(self, dek: bytes) -> bytes: ...
    def unwrap(self, blob: bytes) -> bytes: ...


class LocalMasterKeyProvider:
    """Master key held in memory (from env or a 0600 file). Dev / single-node use."""
    name = "local"

    def __init__(self, master_key: bytes):
        if len(master_key) != 32:
            raise ValueError("master key must be 32 bytes")
        self._aes = AESGCM(master_key)

    def wrap(self, dek: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, dek, b"axfilter-dek")

    def unwrap(self, blob: bytes) -> bytes:
        return self._aes.decrypt(blob[:12], blob[12:], b"axfilter-dek")


class AwsKmsKeyProvider:
    """Wrap/unwrap the DEK with an AWS KMS key (envelope encryption)."""
    name = "awskms"

    def __init__(self, key_id: str, client=None):
        if client is None:
            import boto3  # optional dependency, imported lazily
            client = boto3.client("kms")
        self._kms, self._key_id = client, key_id
        self._ctx = {"app": "axfilter", "purpose": "dek"}

    def wrap(self, dek: bytes) -> bytes:
        r = self._kms.encrypt(KeyId=self._key_id, Plaintext=dek, EncryptionContext=self._ctx)
        return r["CiphertextBlob"]

    def unwrap(self, blob: bytes) -> bytes:
        return self._kms.decrypt(CiphertextBlob=blob, EncryptionContext=self._ctx)["Plaintext"]


def provider_from_env(local_key: bytes) -> KeyProvider:
    kind = os.environ.get("AXFILTER_KEY_PROVIDER", "local").lower()
    if kind == "awskms":
        key_id = os.environ.get("AXFILTER_KMS_KEY_ID")
        if not key_id:
            raise RuntimeError("AXFILTER_KMS_KEY_ID is required when AXFILTER_KEY_PROVIDER=awskms")
        return AwsKmsKeyProvider(key_id)
    if kind != "local":
        raise RuntimeError(f"unknown AXFILTER_KEY_PROVIDER: {kind}")
    return LocalMasterKeyProvider(local_key)
