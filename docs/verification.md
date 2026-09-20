# Live verification: September 20, 2026

Fetched 180 recent warning/error log entries from Loki. Reduced them to reviewed diagnostic templates before sending anything to Jev: generated source labels, no real hosts, addresses, paths, image digests, headers, or credentials. Unrelated entries were excluded.

The retained snapshot had 156 entries across seven sources. It was served through a local Loki-format HTTP endpoint so all three runs saw identical input. The CLI used the real TypeSafe SDK and API; `jev-latest` resolved to `jev-1.13.0`.

| Run | API calls | Input tokens | Elapsed |
| --- | ---: | ---: | ---: |
| Empty cache | 7 | 8,789 | 1.005 s |
| Warm cache | 0 | 0 | 0.010 s |
| Cache disabled | 7 | 8,789 | 1.009 s |

All runs exited successfully with no batch errors. Warm-cache decisions matched the cold run exactly. Uncached decision labels also matched:

- Endpoint deprecation: `suppress`.
- RSS 304 responses: `watch`.
- Registry lookup, image-signature, release-schema, scrape-configuration, and notification-delivery failures: `notify`.

These are observed model judgments, not verified accuracy labels. Each time is one in-process CLI invocation, excluding initial log capture and Python startup. This is an operation check, not a general performance benchmark. Nothing was remediated or notified externally.

## Public sample

`logtriage/fixtures/observed.json` contains 16 representative lines, with duplicates capped at two. Diagnostic status codes and timeout values are retained; identifying context is not. The private raw capture was deleted. The reduced fixture is not enough to reproduce the exact timing or count-dependent judgments above.

The offline batching tests load both this fixture and the original demo. They do not call Jev or assert model predictions. To inspect the additional sample locally:

```python
from logtriage.batch import build_batches, demo_fixture_path, load_demo_streams

streams = load_demo_streams(demo_fixture_path().with_name("observed.json"))
batches = build_batches(streams)
```

For repeatable cold/warm/uncached timing with the original bundled demo, use `scripts/bench-cache.sh`.
