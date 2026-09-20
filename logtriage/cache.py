"""SQLite cache of Jev answers keyed by (model, schema, canonical state)."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from logtriage.batch import Batch
from logtriage.decide import _to_jsonable


def default_cache_path() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    root = Path(xdg) if xdg else Path.home() / ".cache"
    return root / "jev-logtriage" / "answers.sqlite3"


def volume_bucket(n: int) -> str:
    if n <= 1:
        return "1"
    if n <= 9:
        return "2-9"
    if n <= 99:
        return "10-99"
    if n <= 999:
        return "100-999"
    return "1000+"


def canonical_state(batch: Batch) -> dict[str, Any]:
    """Judgment-relevant projection of a batch. Timestamps and exact counts are dropped."""
    patterns = sorted(
        ({"level": p.level, "key": p.key} for p in batch.patterns),
        key=lambda item: item["key"],
    )
    by_level = {
        level: volume_bucket(count) for level, count in sorted(batch.by_level.items())
    }
    return {
        "source": {
            "namespace": batch.labels.get("namespace", ""),
            "app": batch.labels.get("app") or batch.source,
        },
        "patterns": patterns,
        "volume": {"matched": volume_bucket(batch.total_lines), "by_level": by_level},
    }


def canonical_questions(questions: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _to_jsonable(questions[key]) for key in sorted(questions)}


def sha256_json(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AnswerCache:
    def __init__(self, path: Path | str):
        if path == ":memory:":
            self.conn = sqlite3.connect(":memory:")
        else:
            db = Path(path)
            db.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(db)
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS answers (
              model       TEXT NOT NULL,
              schema_hash TEXT NOT NULL,
              state_hash  TEXT NOT NULL,
              answers     TEXT NOT NULL,
              seen_at     TEXT NOT NULL,
              PRIMARY KEY (model, schema_hash, state_hash)
            )
            """
        )
        self.hits = 0
        self.misses = 0

    def get(self, model: str, schema_hash: str, state_hash: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT answers FROM answers WHERE model = ? AND schema_hash = ? AND state_hash = ?",
            (model, schema_hash, state_hash),
        ).fetchone()
        if row is None:
            self.misses += 1
            return None
        self.hits += 1
        self.conn.execute(
            "UPDATE answers SET seen_at = ? WHERE model = ? AND schema_hash = ? AND state_hash = ?",
            (_now(), model, schema_hash, state_hash),
        )
        self.conn.commit()
        payload = json.loads(row[0])
        return payload if isinstance(payload, dict) else None

    def put(self, model: str, schema_hash: str, state_hash: str, answers: Mapping[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO answers (model, schema_hash, state_hash, answers, seen_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (model, schema_hash, state_hash, json.dumps(_to_jsonable(answers)), _now()),
        )
        self.conn.commit()

    def clear(self) -> None:
        self.conn.execute("DELETE FROM answers")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
