# Answer cache

Cache Jev's **answers**, then run `decide()` again. Changing a threshold does not require another model call.

## What makes a hit

The key combines the requested model, the question schema, and a canonical batch:

- Loki URL and tenant (demo fixtures have a separate identity).
- All source labels, including cluster and namespace.
- Sorted normalized patterns, with a count bucket for each pattern.
- Total and per-level count buckets, sampling omissions, and window length rounded to tenths of a minute.

Normalization removes timestamps, IDs, UUIDs, and long hexadecimal tokens. It preserves HTTP status codes, durations, resource measurements, and the full normalized line rather than just its prefix.

Count buckets are `0`, `1`, `2-9`, `10-99`, `100-999`, and `1000+`. Five occurrences and eight can reuse an answer; five and fifty cannot. Counts within a bucket are deliberately approximate. Use `--no-cache` when that approximation is inappropriate.

Editing a question's ID, type, instructions, or criteria causes a miss. Changing the canonical key format also invalidates old entries; old rows remain until cleared.

## Model aliases

The key uses the model ID requested, not the version returned by Jev. An alias such as `jev-latest` can move without invalidating existing answers. Use a pinned version for repeatable results, or clear/disable caching when you need fresh answers from an alias. There is no TTL or automatic alias-change detection.

## Storage and failures

The default file is `~/.cache/jev-logtriage/answers.sqlite3`, or under `$XDG_CACHE_HOME` when set. Override it with `--cache-db PATH`.

SQLite stores hashes and answer JSON, not the Loki payload or the resulting decisions. WAL permits concurrent readers, with one writer at a time. `seen_at` updates on successful reads and writes.

An unavailable cache produces a warning and the run continues uncached. Malformed JSON rows are discarded and fetched again. Invalid Jev answers produce an analysis error rather than a success decision and are not cached.

- `--no-cache`: skip cache reads and writes.
- `--cache-db PATH`: use a different database.
- `--cache-clear`: delete cached answers before analysis.

## Compare cached and uncached runs

```bash
scripts/bench-cache.sh
```

Requires `TYPESAFE_API_KEY`. The script uses its own temporary database and removes it afterward. It times the bundled demo with an empty cache, a warm cache, and caching disabled. Cold and uncached runs make API calls; warm should show hits and zero input tokens. These are single-run timings, not an accuracy benchmark. See [the live verification notes](verification.md) for a sanitized-snapshot run.
