"""SQLite storage: events (original text encrypted), policy, hash-chained audit log."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .policy import Policy

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  service TEXT NOT NULL, user TEXT NOT NULL, ip TEXT NOT NULL, grp TEXT NOT NULL,
  direction TEXT NOT NULL, action TEXT NOT NULL, reason TEXT,
  finding_types TEXT NOT NULL, finding_count INTEGER NOT NULL,
  latency_ms REAL NOT NULL,
  masked_text TEXT, nonce BLOB, original_enc BLOB
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
"""
GENESIS = "0" * 64


def _clean(row: sqlite3.Row) -> dict:
    """Row to dict, with NULL aggregates (SUM over no rows) turned into 0."""
    return {k: 0 if row[k] is None else row[k] for k in row.keys()}


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


class Store:
    def __init__(self, db_path: str | Path, key: bytes):
        self._aes = AESGCM(key)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)

    # ---- policy -------------------------------------------------------
    def get_policy(self) -> Policy:
        row = self._db.execute("SELECT v FROM kv WHERE k='policy'").fetchone()
        return Policy.model_validate_json(row["v"]) if row else Policy()

    def set_policy(self, policy: Policy) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO kv(k,v) VALUES('policy',?)",
                             (policy.model_dump_json(),))

    # ---- events -------------------------------------------------------
    def add_event(self, *, service, user, ip, group, direction, action, reason,
                  finding_types, latency_ms, masked_text, original, ts=None) -> int:
        nonce = os.urandom(12)
        enc = self._aes.encrypt(nonce, original.encode(), None) if finding_types else None
        with self._lock, self._db:
            cur = self._db.execute(
                "INSERT INTO events(ts,service,user,ip,grp,direction,action,reason,"
                "finding_types,finding_count,latency_ms,masked_text,nonce,original_enc) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ts or int(time.time()), service, user, ip, group, direction, action, reason,
                 json.dumps(finding_types), len(finding_types), latency_ms, masked_text,
                 nonce if enc else None, enc))
            return cur.lastrowid

    def get_event(self, event_id: int) -> sqlite3.Row | None:
        return self._db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()

    def decrypt_original(self, row: sqlite3.Row) -> str | None:
        if row["original_enc"] is None:
            return None
        return self._aes.decrypt(row["nonce"], row["original_enc"], None).decode()

    def list_events(self, limit: int, offset: int, action: str | None) -> list[dict]:
        q = ("SELECT id,ts,service,user,ip,grp,direction,action,reason,finding_types,"
             "masked_text FROM events")
        args: list = []
        if action:
            q += " WHERE action=?"
            args.append(action)
        q += " ORDER BY id DESC LIMIT ? OFFSET ?"
        rows = self._db.execute(q, (*args, limit, offset)).fetchall()
        return [{**dict(r), "finding_types": json.loads(r["finding_types"])} for r in rows]

    # ---- stats --------------------------------------------------------
    @staticmethod
    def _where(since: int, direction: str) -> tuple[str, list]:
        w, a = "ts >= ?", [since]
        if direction != "all":
            w += " AND direction = ?"
            a.append(direction)
        return w, a

    _AGG = ("COUNT(*) total, SUM(finding_count>0) detected, "
            "SUM(action IN ('allow','mask')) allowed, SUM(action='block') blocked, "
            "SUM(action='mask') masked")

    def summary(self, since: int, direction: str) -> dict:
        w, a = self._where(since, direction)
        r = self._db.execute(f"SELECT {self._AGG} FROM events WHERE {w}", a).fetchone()
        return _clean(r)

    def daily(self, since: int, direction: str) -> list[dict]:
        w, a = self._where(since, direction)
        rows = self._db.execute(
            f"SELECT date(ts,'unixepoch','+9 hours') day, {self._AGG} FROM events "
            f"WHERE {w} GROUP BY day ORDER BY day", a).fetchall()
        return [_clean(r) for r in rows]

    def by_service(self, since: int, direction: str) -> list[dict]:
        w, a = self._where(since, direction)
        rows = self._db.execute(
            f"SELECT service, {self._AGG}, AVG(latency_ms) avg_latency_ms FROM events "
            f"WHERE {w} GROUP BY service ORDER BY total DESC", a).fetchall()
        return [_clean(r) for r in rows]

    def top(self, since: int, direction: str, by: str, n: int) -> list[dict]:
        w, a = self._where(since, direction)
        if by == "group":
            cols, grp = "grp AS grp", "grp"
            extra = ", COUNT(DISTINCT user) users"
        else:
            cols, grp = "ip, MAX(user) user, MAX(grp) grp", "ip"
            extra = ""
        rows = self._db.execute(
            f"SELECT {cols}{extra}, {self._AGG} FROM events WHERE {w} "
            f"GROUP BY {grp} ORDER BY total DESC LIMIT ?", (*a, n)).fetchall()
        return [_clean(r) for r in rows]

    # ---- audit log (hash chain) ---------------------------------------
    def audit(self, actor: str, action: str, target: str) -> None:
        with self._lock, self._db:
            last = self._db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev, ts = (last["hash"] if last else GENESIS), int(time.time())
            digest = hashlib.sha256(f"{prev}|{ts}|{actor}|{action}|{target}".encode()).hexdigest()
            self._db.execute(
                "INSERT INTO audit(ts,actor,action,target,prev_hash,hash) VALUES(?,?,?,?,?,?)",
                (ts, actor, action, target, prev, digest))

    def audit_entries(self, limit: int = 100) -> list[dict]:
        rows = self._db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    def verify_audit(self) -> dict:
        prev = GENESIS
        for r in self._db.execute("SELECT * FROM audit ORDER BY id"):
            want = hashlib.sha256(
                f"{prev}|{r['ts']}|{r['actor']}|{r['action']}|{r['target']}".encode()).hexdigest()
            if r["prev_hash"] != prev or r["hash"] != want:
                return {"ok": False, "broken_at": r["id"]}
            prev = r["hash"]
        return {"ok": True, "broken_at": None}
