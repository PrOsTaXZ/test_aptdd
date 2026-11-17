"""SQLite history of investigations and remembered consent decisions.

Privacy properties:

* the database and its directory are private to the user (0600 / 0700);
* ``PRAGMA secure_delete`` overwrites deleted content, and :meth:`Storage.purge` runs ``VACUUM``
  so removed investigations do not linger in free pages;
* with ``store_targets=False`` only a keyed hash (HMAC-SHA256 with a local random key) of the target
  and a status summary are stored — no raw identifier, no findings. A plain hash would be useless
  for phone numbers, which can be brute-forced in seconds.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from osint_toolkit.config import ensure_private_dir
from osint_toolkit.core.models import Investigation, Target, utcnow

SCHEMA_VERSION = 1

_MIGRATIONS: dict[int, str] = {
    1: """
    CREATE TABLE investigations (
        id            TEXT PRIMARY KEY,
        created_at    TEXT NOT NULL,
        mode          TEXT NOT NULL,
        status        TEXT NOT NULL,
        target_type   TEXT NOT NULL,
        target        TEXT,              -- NULL when store_targets is off
        target_hash   TEXT NOT NULL,
        summary       TEXT NOT NULL,     -- JSON: module statuses and finding counts
        payload       TEXT               -- full Investigation JSON, NULL when store_targets is off
    );
    CREATE INDEX idx_investigations_created ON investigations(created_at DESC);
    CREATE INDEX idx_investigations_hash ON investigations(target_hash);
    CREATE TABLE consents (
        module      TEXT PRIMARY KEY,
        allowed     INTEGER NOT NULL,
        decided_at  TEXT NOT NULL
    );
    """,
}


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    id: str
    created_at: datetime
    mode: str
    status: str
    target_type: str
    target: str | None
    summary: dict[str, int]
    has_payload: bool


class Storage:
    def __init__(self, path: Path, *, store_targets: bool = True) -> None:
        self.path = path
        self.store_targets = store_targets
        ensure_private_dir(path.parent)
        if not path.exists():
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600))
        path.chmod(0o600)
        self._key = self._load_or_create_key(path.parent / "history.key")
        self._migrate()

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _load_or_create_key(key_path: Path) -> bytes:
        if key_path.exists():
            return bytes.fromhex(key_path.read_text(encoding="ascii").strip())
        key = secrets.token_bytes(32)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(key.hex())
        return key

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA secure_delete = ON")
            with conn:
                yield conn
        finally:
            conn.close()

    def _migrate(self) -> None:
        with self._connect() as conn:
            current = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if current > SCHEMA_VERSION:
                raise RuntimeError(
                    f"History DB schema v{current} is newer than this app (v{SCHEMA_VERSION})"
                )
            for version in range(current + 1, SCHEMA_VERSION + 1):
                conn.executescript(_MIGRATIONS[version])
                conn.execute(f"PRAGMA user_version = {version}")

    def target_hash(self, target: Target) -> str:
        return hmac.new(self._key, target.key.encode("utf-8"), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------ investigations
    def save(self, investigation: Investigation) -> None:
        investigation = investigation.persistable()
        summary: dict[str, int] = {s.value: n for s, n in investigation.status_counts().items()}
        summary["findings"] = len(investigation.findings())
        summary["contradictions"] = len(investigation.contradictions)
        target = investigation.target
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO investigations VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    investigation.id,
                    investigation.created_at.isoformat(),
                    investigation.mode.value,
                    investigation.status.value,
                    target.type.value,
                    target.normalized if self.store_targets else None,
                    self.target_hash(target),
                    json.dumps(summary),
                    investigation.model_dump_json() if self.store_targets else None,
                ),
            )

    def list(self, limit: int = 50) -> list[HistoryEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, created_at, mode, status, target_type, target, summary,"
                " payload IS NOT NULL AS has_payload"
                " FROM investigations ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            HistoryEntry(
                id=row["id"],
                created_at=datetime.fromisoformat(row["created_at"]),
                mode=row["mode"],
                status=row["status"],
                target_type=row["target_type"],
                target=row["target"],
                summary=json.loads(row["summary"]),
                has_payload=bool(row["has_payload"]),
            )
            for row in rows
        ]

    def resolve_id(self, prefix: str) -> str | None:
        """Full id for an id or unique id prefix (min 4 chars)."""
        if len(prefix) < 4 or not all(c in "0123456789abcdef" for c in prefix.lower()):
            return None
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id FROM investigations WHERE id LIKE ? LIMIT 2", (prefix.lower() + "%",)
            ).fetchall()
        return rows[0]["id"] if len(rows) == 1 else None

    def get(self, investigation_id: str) -> Investigation | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
        if row is None or row["payload"] is None:
            return None
        return Investigation.model_validate_json(row["payload"])

    def delete(self, investigation_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))
        return cur.rowcount > 0

    def purge(self) -> int:
        """Delete the whole history and compact the file. Returns the number of removed rows."""
        with self._connect() as conn:
            count = conn.execute("DELETE FROM investigations").rowcount
        conn = sqlite3.connect(self.path)
        try:
            conn.execute("VACUUM")
        finally:
            conn.close()
        return int(count)

    def count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0])

    # ------------------------------------------------------------------ consents
    def consents(self) -> dict[str, bool]:
        with self._connect() as conn:
            rows = conn.execute("SELECT module, allowed FROM consents ORDER BY module").fetchall()
        return {row["module"]: bool(row["allowed"]) for row in rows}

    def set_consent(self, module: str, allowed: bool) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO consents VALUES (?,?,?)",
                (module, int(allowed), utcnow().isoformat()),
            )

    def revoke_consent(self, module: str | None = None) -> int:
        with self._connect() as conn:
            if module is None:
                return int(conn.execute("DELETE FROM consents").rowcount)
            return int(conn.execute("DELETE FROM consents WHERE module = ?", (module,)).rowcount)
