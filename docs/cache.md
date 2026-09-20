# Answer cache

Skip repeat Jev calls when the same judgment comes up again. Cache **answers**, then run `decide()` locally so `--confidence-floor` and the other gates still apply.

Key: `(model, schema, state)`. Each part is the judgment, not the raw HTTP body.

## The three columns

**model.** The id sent to the API, for example `jev-latest`. Pin `jev-1.13.0` in cron if hits should survive an alias bump. Do not mix them.

**schema.** SHA-256 of the questions as Jev sees them: `type`, `instructions`, `criteria`, sorted by question id. Adding, removing, or editing a question is a miss. Hashing the id map is simpler than stripping ids; either is fine if it is stable.

**state.** Not `json.dumps(build_state(batch))`. That blob has timestamps, windows, and exact counts, so it would almost never hit.

Hash a **canonical state** instead:

```json
{
  "source": {"namespace": "kube-system", "app": "coredns"},
  "patterns": [
    {"level": "warn", "key": "warn|[WARNING] No files matching import glob..."}
  ],
  "volume": {"matched": "100-999", "by_level": {"warn": "100-999"}}
}
```

- `key` is the collapse key already used in batching: `level|normalize_line(...)`.
- `patterns` is sorted by `key`.
- Volume uses buckets: `1`, `2-9`, `10-99`, `100-999`, `1000+`. Six CoreDNS warnings and 282 of the same pattern are different judgments.

## SQLite

File: `~/.cache/jev-logtriage/answers.sqlite3` (`$XDG_CACHE_HOME` on Linux). Override with `--cache-db`.

```sql
CREATE TABLE answers (
  model       TEXT NOT NULL,
  schema_hash TEXT NOT NULL,
  state_hash  TEXT NOT NULL,
  answers     TEXT NOT NULL,
  seen_at     TEXT NOT NULL,
  PRIMARY KEY (model, schema_hash, state_hash)
);

PRAGMA journal_mode = WAL;
```

`answers` is the JSON `answers` map from the API. `seen_at` is ISO UTC, updated on hit and miss.

WAL so a cron job and a laptop run can share the file. One writer at a time is enough.

No TTL. A hit means this judgment was already asked. `--cache-clear` deletes rows. A later cleanup pass can `DELETE` where `seen_at` is old if the file grows.

Do not store `decision`, `priority`, or the Loki payload.

## Lookup

```text
schema_hash = sha256(canonical_questions)
state_hash  = sha256(canonical_state)
SELECT answers FROM answers
 WHERE model = ? AND schema_hash = ? AND state_hash = ?
```

Hit: `json.loads`, then `decide(batch, answers, state, cfg)`. No HTTP.  
Miss: `system_one`, then `INSERT OR REPLACE`.

A new pattern on that source changes `state_hash` and misses. That is correct. Jev scores the mix, not each line.

## CLI

- `--cache` on, `--no-cache` off. Default on once this ships.
- `--cache-db PATH`
- `--cache-clear`

Stderr can show `cache hit 5  miss 2` so a too-strict key is obvious.

## Out of scope

- Per-line rows. Wrong grain.
- Hashing the live `state` object. Dead cache.
- Caching `suppress` / `page`. Then `--page-priority` cannot change without a bust.
- Redis, TTL heuristics, or a sidecar.
