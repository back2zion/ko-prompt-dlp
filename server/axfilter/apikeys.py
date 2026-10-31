"""Database-backed, per-user named API keys.

These complement the static role keys configured via settings: an admin can
issue a named key for a user (``issue_key``), revoke it (``revoke_key``), and
list the issued keys without exposing any secret (``list_keys``). Authentication
hashes the presented token and matches a non-revoked row (``lookup``).

Only the SHA-256 of each token is stored; the raw token is returned exactly once
at issue time and is never persisted or logged.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from sqlalchemy import BigInteger, Column, Integer, Table, Text, select

from .oidc import ROLE_RANK, Principal
from .store import metadata

# Defined on the shared metadata so Store.metadata.create_all() provisions it
# alongside events/kv/policy_history/audit, across SQLite and PostgreSQL.
api_keys = Table(
    "api_keys", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", Text, nullable=False),
    Column("role", Text, nullable=False),
    Column("token_sha256", Text, nullable=False, unique=True),
    Column("created_ts", BigInteger, nullable=False),
    Column("revoked_ts", BigInteger),   # nullable: NULL means active
)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_key(store, name: str, role: str) -> str:
    """Create a named key, store only its hash, and return the raw token once."""
    if role not in ROLE_RANK:
        raise ValueError(f"role must be one of {sorted(ROLE_RANK)}")
    token = secrets.token_urlsafe(32)
    with store._lock, store._engine.begin() as conn:
        conn.execute(api_keys.insert().values(
            name=name, role=role, token_sha256=_hash(token),
            created_ts=int(time.time()), revoked_ts=None))
    return token


def revoke_key(store, key_id: int) -> bool:
    """Mark a key revoked. Returns True if an active key was revoked."""
    with store._lock, store._engine.begin() as conn:
        r = conn.execute(api_keys.update()
                         .where(api_keys.c.id == key_id)
                         .where(api_keys.c.revoked_ts.is_(None))
                         .values(revoked_ts=int(time.time())))
    return r.rowcount > 0


def list_keys(store) -> list[dict]:
    """List issued keys without secrets: id/name/role/created/revoked only."""
    q = select(api_keys.c.id, api_keys.c.name, api_keys.c.role,
               api_keys.c.created_ts, api_keys.c.revoked_ts).order_by(api_keys.c.id.desc())
    with store._engine.connect() as conn:
        rows = conn.execute(q).mappings().all()
    return [dict(r) for r in rows]


def lookup(store, token: str) -> Principal | None:
    """Hash the presented token and match a non-revoked row (constant-time)."""
    if not token:
        return None
    presented = _hash(token)
    q = select(api_keys.c.name, api_keys.c.role, api_keys.c.token_sha256).where(
        api_keys.c.revoked_ts.is_(None))
    with store._engine.connect() as conn:
        rows = conn.execute(q).mappings().all()
    for r in rows:
        if hmac.compare_digest(r["token_sha256"], presented):
            return Principal(r["name"], r["role"])
    return None
