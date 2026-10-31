"""Backend-agnostic storage (SQLite or PostgreSQL) via SQLAlchemy Core.

Holds events (original prompt text encrypted at rest), the policy, the wrapped
data key, and a hash-chained audit log. Column names and the public API are the
same across backends so the rest of the app does not care which is in use.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import (BigInteger, Column, Float, Index, Integer, LargeBinary,
                        MetaData, String, Table, Text, case, create_engine,
                        distinct, func, select)

from .keys import KeyProvider
from .policy import Policy

GENESIS = "0" * 64
metadata = MetaData()

events = Table(
    "events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", BigInteger, nullable=False),
    Column("service", Text, nullable=False),
    Column("user", Text, nullable=False),      # SQLAlchemy quotes this reserved word per dialect
    Column("ip", Text, nullable=False),
    Column("grp", Text, nullable=False),
    Column("direction", Text, nullable=False),
    Column("action", Text, nullable=False),
    Column("reason", Text),
    Column("finding_types", Text, nullable=False),
    Column("finding_count", Integer, nullable=False),
    Column("latency_ms", Float, nullable=False),
    Column("masked_text", Text),
    Column("nonce", LargeBinary),
    Column("original_enc", LargeBinary),
)
Index("idx_events_ts", events.c.ts)

kv = Table("kv", metadata,
           Column("k", String(64), primary_key=True),
           Column("v", Text, nullable=False))

policy_history = Table(
    "policy_history", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", BigInteger, nullable=False),
    Column("actor", Text, nullable=False),
    Column("policy_json", Text, nullable=False),
    Column("hash", Text, nullable=False),
)

audit = Table(
    "audit", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", BigInteger, nullable=False),
    Column("actor", Text, nullable=False),
    Column("action", Text, nullable=False),
    Column("target", Text, nullable=False),
    Column("prev_hash", Text, nullable=False),
    Column("hash", Text, nullable=False),
)


def _clean(mapping) -> dict:
    """RowMapping to dict, with NULL aggregates (SUM/AVG over no rows) turned into 0."""
    return {k: (0 if v is None else v) for k, v in mapping.items()}


def load_or_create_key(path: Path) -> bytes:
    """32-byte data key from AXFILTER_DATA_KEY (hex) or a 0600 key file."""
    env = os.environ.get("AXFILTER_DATA_KEY")
    if env:
        key = bytes.fromhex(env)
    elif path.exists():
        key = bytes.fromhex(path.read_text().strip())
    else:
        key = os.urandom(32)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key.hex())
    if len(key) != 32:
        raise ValueError("data key must be 32 bytes (64 hex chars)")
    return key


def _to_url(db_path_or_url: str | Path) -> str:
    s = str(db_path_or_url)
    return s if "://" in s else "sqlite:///" + s


class Store:
    def __init__(self, db_path_or_url: str | Path, provider: KeyProvider):
        self._provider = provider
        self._lock = threading.Lock()
        url = _to_url(db_path_or_url)
        kwargs = {"future": True}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        self._engine = create_engine(url, **kwargs)
        self._dialect = self._engine.dialect.name
        metadata.create_all(self._engine)
        self._aes = AESGCM(self._load_or_create_dek())

    # ---- small helpers ------------------------------------------------
    def _kv_set(self, conn, k: str, v: str) -> None:
        r = conn.execute(kv.update().where(kv.c.k == k).values(v=v))
        if r.rowcount == 0:
            conn.execute(kv.insert().values(k=k, v=v))

    def _kv_get(self, conn, k: str):
        return conn.execute(select(kv.c.v).where(kv.c.k == k)).scalar_one_or_none()

    _AGG = None

    def _agg(self):
        return [
            func.count().label("total"),
            func.sum(case((events.c.finding_count > 0, 1), else_=0)).label("detected"),
            func.sum(case((events.c.action.in_(["allow", "mask"]), 1), else_=0)).label("allowed"),
            func.sum(case((events.c.action == "block", 1), else_=0)).label("blocked"),
            func.sum(case((events.c.action == "mask", 1), else_=0)).label("masked"),
        ]

    def _where(self, since: int, direction: str):
        cond = events.c.ts >= since
        if direction != "all":
            cond = cond & (events.c.direction == direction)
        return cond

    def _day_expr(self):
        if self._dialect == "postgresql":
            return func.to_char(func.timezone("Asia/Seoul", func.to_timestamp(events.c.ts)),
                                "YYYY-MM-DD")
        return func.date(events.c.ts, "unixepoch", "+9 hours")

    # ---- data encryption key (envelope) -------------------------------
    def _load_or_create_dek(self) -> bytes:
        with self._engine.begin() as conn:
            cur = self._kv_get(conn, "dek")
            if cur:
                try:
                    return self._provider.unwrap(bytes.fromhex(cur))
                except Exception as e:
                    raise RuntimeError(
                        "cannot unwrap the stored data key — the master key (AXFILTER_DATA_KEY "
                        "or the KMS key) does not match the one this database was created with"
                    ) from e
            dek = os.urandom(32)
            self._kv_set(conn, "dek", self._provider.wrap(dek).hex())
            return dek

    def rotate_data_key(self) -> int:
        """New DEK, re-encrypt every stored original, store the new wrapped DEK, atomically."""
        new_dek = os.urandom(32)
        new_aes = AESGCM(new_dek)
        with self._lock, self._engine.begin() as conn:
            rows = conn.execute(
                select(events.c.id, events.c.nonce, events.c.original_enc)
                .where(events.c.original_enc.is_not(None))).mappings().all()
            for r in rows:
                plain = self._aes.decrypt(r["nonce"], r["original_enc"], None)
                nonce = os.urandom(12)
                conn.execute(events.update().where(events.c.id == r["id"]).values(
                    nonce=nonce, original_enc=new_aes.encrypt(nonce, plain, None)))
            self._kv_set(conn, "dek", self._provider.wrap(new_dek).hex())
            self._aes = new_aes
        return len(rows)

    @property
    def key_provider_name(self) -> str:
        return self._provider.name

    # ---- policy -------------------------------------------------------
    def get_policy(self) -> Policy:
        with self._engine.connect() as conn:
            v = self._kv_get(conn, "policy")
        return Policy.model_validate_json(v) if v else Policy()

    def set_policy(self, policy: Policy, actor: str = "system") -> None:
        pj = policy.model_dump_json()
        digest = hashlib.sha256(pj.encode()).hexdigest()
        with self._lock, self._engine.begin() as conn:
            self._kv_set(conn, "policy", pj)
            conn.execute(policy_history.insert().values(
                ts=int(time.time()), actor=actor, policy_json=pj, hash=digest))

    def policy_history(self, limit: int = 100) -> list[dict]:
        with self._engine.connect() as conn:
            rows = conn.execute(select(
                policy_history.c.id, policy_history.c.ts, policy_history.c.actor,
                policy_history.c.hash).order_by(policy_history.c.id.desc()).limit(limit)).mappings().all()
        return [dict(r) for r in rows]

    def policy_version(self, version_id: int) -> dict | None:
        with self._engine.connect() as conn:
            r = conn.execute(select(policy_history).where(
                policy_history.c.id == version_id)).mappings().first()
        return dict(r) if r else None

    # ---- events -------------------------------------------------------
    def add_event(self, *, service, user, ip, group, direction, action, reason,
                  finding_types, latency_ms, masked_text, original, ts=None) -> int:
        nonce = os.urandom(12)
        enc = self._aes.encrypt(nonce, original.encode(), None) if finding_types else None
        with self._lock, self._engine.begin() as conn:
            r = conn.execute(events.insert().values(
                ts=ts or int(time.time()), service=service, user=user, ip=ip, grp=group,
                direction=direction, action=action, reason=reason,
                finding_types=json.dumps(finding_types), finding_count=len(finding_types),
                latency_ms=latency_ms, masked_text=masked_text,
                nonce=nonce if enc else None, original_enc=enc))
            return r.inserted_primary_key[0]

    def get_event(self, event_id: int):
        with self._engine.connect() as conn:
            return conn.execute(select(events).where(events.c.id == event_id)).mappings().first()

    def decrypt_original(self, row) -> str | None:
        if row is None or row["original_enc"] is None:
            return None
        return self._aes.decrypt(row["nonce"], row["original_enc"], None).decode()

    def list_events(self, limit: int, offset: int, action: str | None) -> list[dict]:
        q = select(events.c.id, events.c.ts, events.c.service, events.c.user, events.c.ip,
                   events.c.grp, events.c.direction, events.c.action, events.c.reason,
                   events.c.finding_types, events.c.masked_text)
        if action:
            q = q.where(events.c.action == action)
        q = q.order_by(events.c.id.desc()).limit(limit).offset(offset)
        with self._engine.connect() as conn:
            rows = conn.execute(q).mappings().all()
        return [{**dict(r), "finding_types": json.loads(r["finding_types"])} for r in rows]

    # ---- retention / purge --------------------------------------------
    def count_events_older_than(self, ts: int) -> int:
        """Number of events with ts < the given epoch-seconds cutoff."""
        with self._engine.connect() as conn:
            return conn.execute(select(func.count()).where(events.c.ts < ts)).scalar_one()

    def purge_original_text(self, before_ts: int) -> int:
        """Null out original_enc/nonce for events older than before_ts, keeping the
        row and its metadata (stats/audit stay intact; only the recoverable original
        is dropped). Returns the number of rows whose original was removed."""
        with self._lock, self._engine.begin() as conn:
            r = conn.execute(events.update()
                             .where((events.c.ts < before_ts) & events.c.original_enc.is_not(None))
                             .values(original_enc=None, nonce=None))
            return r.rowcount

    def purge_events(self, before_ts: int) -> int:
        """Delete events older than before_ts entirely. Returns the count deleted.
        The append-only audit log is never touched (integrity chain preserved)."""
        with self._lock, self._engine.begin() as conn:
            r = conn.execute(events.delete().where(events.c.ts < before_ts))
            return r.rowcount

    # ---- stats --------------------------------------------------------
    def summary(self, since: int, direction: str) -> dict:
        with self._engine.connect() as conn:
            r = conn.execute(select(*self._agg()).where(self._where(since, direction))).mappings().first()
        return _clean(r)

    def daily(self, since: int, direction: str) -> list[dict]:
        day = self._day_expr().label("day")
        q = (select(day, *self._agg()).where(self._where(since, direction))
             .group_by(day).order_by(day))
        with self._engine.connect() as conn:
            return [_clean(r) for r in conn.execute(q).mappings().all()]

    def by_service(self, since: int, direction: str) -> list[dict]:
        total = func.count().label("total")
        q = (select(events.c.service, *self._agg(),
                    func.avg(events.c.latency_ms).label("avg_latency_ms"))
             .where(self._where(since, direction)).group_by(events.c.service).order_by(total.desc()))
        with self._engine.connect() as conn:
            return [_clean(r) for r in conn.execute(q).mappings().all()]

    def top(self, since: int, direction: str, by: str, n: int) -> list[dict]:
        total = func.count().label("total")
        if by == "group":
            cols = [events.c.grp.label("grp"), func.count(distinct(events.c.user)).label("users")]
            group_col = events.c.grp
        else:
            cols = [events.c.ip, func.max(events.c.user).label("user"), func.max(events.c.grp).label("grp")]
            group_col = events.c.ip
        q = (select(*cols, *self._agg()).where(self._where(since, direction))
             .group_by(group_col).order_by(total.desc()).limit(n))
        with self._engine.connect() as conn:
            return [_clean(r) for r in conn.execute(q).mappings().all()]

    # ---- audit log (hash chain) ---------------------------------------
    def audit(self, actor: str, action: str, target: str) -> None:
        with self._lock, self._engine.begin() as conn:
            last = conn.execute(select(audit.c.hash).order_by(audit.c.id.desc()).limit(1)).scalar_one_or_none()
            prev, ts = (last or GENESIS), int(time.time())
            digest = hashlib.sha256(f"{prev}|{ts}|{actor}|{action}|{target}".encode()).hexdigest()
            conn.execute(audit.insert().values(ts=ts, actor=actor, action=action, target=target,
                                               prev_hash=prev, hash=digest))

    def audit_entries(self, limit: int = 100) -> list[dict]:
        return self.audit_search(limit=limit)

    def audit_search(self, *, actor: str | None = None, action: str | None = None,
                     since: int | None = None, until: int | None = None,
                     limit: int = 100, offset: int = 0) -> list[dict]:
        q = select(audit)
        if actor:
            q = q.where(audit.c.actor == actor)
        if action:
            q = q.where(audit.c.action == action)
        if since is not None:
            q = q.where(audit.c.ts >= since)
        if until is not None:
            q = q.where(audit.c.ts < until)
        q = q.order_by(audit.c.id.desc()).limit(limit).offset(offset)
        with self._engine.connect() as conn:
            return [dict(r) for r in conn.execute(q).mappings().all()]

    def verify_audit(self) -> dict:
        prev = GENESIS
        with self._engine.connect() as conn:
            for r in conn.execute(select(audit).order_by(audit.c.id)).mappings():
                want = hashlib.sha256(
                    f"{prev}|{r['ts']}|{r['actor']}|{r['action']}|{r['target']}".encode()).hexdigest()
                if r["prev_hash"] != prev or r["hash"] != want:
                    return {"ok": False, "broken_at": r["id"]}
                prev = r["hash"]
        return {"ok": True, "broken_at": None}


def retention_run(store: Store, *, original_days: int, event_days: int,
                  actor: str = "system", now: int | None = None) -> dict:
    """Apply retention to a Store: purge recoverable originals older than
    original_days, and (when event_days > 0) delete events older than event_days.
    Each purge writes an append-only audit record with its count. The audit log
    itself is never purged. Returns {"purged_originals": n, "purged_events": m}."""
    now = int(time.time()) if now is None else now
    out = {"purged_originals": 0, "purged_events": 0}
    if original_days and original_days > 0:
        before = now - original_days * 86400
        n = store.purge_original_text(before)
        store.audit(actor, "PURGE_ORIGINAL", f"before_ts={before};count={n}")
        out["purged_originals"] = n
    if event_days and event_days > 0:
        before = now - event_days * 86400
        m = store.purge_events(before)
        store.audit(actor, "PURGE_EVENTS", f"before_ts={before};count={m}")
        out["purged_events"] = m
    return out
