"""Answer cache: same judgment hits, volume/schema/model changes miss."""

from __future__ import annotations

import unittest
from dataclasses import replace

from logtriage import Config, Pattern, build_state, decide
from logtriage.cache import (
    AnswerCache,
    canonical_questions,
    canonical_state,
    sha256_json,
    volume_bucket,
)

from tests.factories import make_batch


class VolumeBucketTests(unittest.TestCase):
    def test_boundaries(self):
        cases = [(0, "0"), (1, "1"), (2, "2-9"), (9, "2-9"), (10, "10-99"), (99, "10-99"), (100, "100-999"), (1000, "1000+")]
        for n, expected in cases:
            with self.subTest(n=n):
                self.assertEqual(volume_bucket(n), expected)


class AnswerCacheTests(unittest.TestCase):
    def test_same_key_hits_and_count_bucket_change_misses(self):
        with AnswerCache(":memory:") as cache:
            small = make_batch(lines=5)
            same_bucket = make_batch(lines=8)
            big = make_batch(lines=50)
            schema = sha256_json(canonical_questions({"q": {"type": "noul", "instructions": "x"}}))
            payload = {"needs_action": {"type": "noul", "noul": 0.2}}
            small_hash = sha256_json(canonical_state(small))
            same_hash = sha256_json(canonical_state(same_bucket))
            big_hash = sha256_json(canonical_state(big))
            self.assertEqual(small_hash, same_hash)
            self.assertNotEqual(small_hash, big_hash)
            cache.put("jev-latest", schema, small_hash, payload)
            self.assertEqual(cache.get("jev-latest", schema, same_hash)["needs_action"]["noul"], 0.2)
            self.assertIsNone(cache.get("jev-latest", schema, big_hash))
            self.assertEqual(cache.hits, 1)
            self.assertEqual(cache.misses, 1)

    def test_source_mix_and_sampling_changes_miss_but_order_does_not(self):
        batch = replace(
            make_batch(lines=10),
            patterns=[
                Pattern(key="error|timeout", text="timeout", level="error", count=9),
                Pattern(key="error|refused", text="refused", level="error", count=1),
            ],
            distinct_patterns=2,
        )
        state_hash = sha256_json(canonical_state(batch, "http://loki", "tenant-a"))
        variants = [
            ("cluster", replace(batch, labels={**batch.labels, "cluster": "other"})),
            ("volume distribution", replace(batch, patterns=[
                replace(batch.patterns[0], count=1), replace(batch.patterns[1], count=9),
            ])),
            ("rate", replace(batch, end_ns=batch.start_ns + 1_000_000_000)),
            ("omitted evidence", replace(batch, distinct_patterns=3, omitted_lines=1, truncated=True)),
        ]
        with AnswerCache(":memory:") as cache:
            cache.put("m", "s", state_hash, {"ok": True})
            reordered = replace(batch, patterns=list(reversed(batch.patterns)))
            self.assertEqual(
                cache.get("m", "s", sha256_json(canonical_state(reordered, "http://loki/", "tenant-a"))),
                {"ok": True},
            )
            for name, changed in variants:
                with self.subTest(name):
                    key = sha256_json(canonical_state(changed, "http://loki", "tenant-a"))
                    self.assertIsNone(cache.get("m", "s", key))
            for url, tenant in [("http://other-loki", "tenant-a"), ("http://loki", "tenant-b")]:
                with self.subTest(url=url, tenant=tenant):
                    self.assertIsNone(cache.get("m", "s", sha256_json(canonical_state(batch, url, tenant))))

    def test_question_or_model_change_misses(self):
        with AnswerCache(":memory:") as cache:
            batch = make_batch()
            state_hash = sha256_json(canonical_state(batch))
            schema_a = sha256_json(canonical_questions({"q": {"type": "noul", "instructions": "a"}}))
            schema_b = sha256_json(canonical_questions({"q": {"type": "noul", "instructions": "b"}}))
            cache.put("jev-latest", schema_a, state_hash, {"ok": True})
            self.assertIsNotNone(cache.get("jev-latest", schema_a, state_hash))
            self.assertIsNone(cache.get("jev-latest", schema_b, state_hash))
            self.assertIsNone(cache.get("jev-1.13.0", schema_a, state_hash))

    def test_corrupt_rows_are_misses_and_can_be_replaced(self):
        for invalid_json in ("{broken", "[]", "null"):
            with self.subTest(payload=invalid_json), AnswerCache(":memory:") as cache:
                cache.put("m", "s", "t", {"ok": True})
                cache.conn.execute("UPDATE answers SET answers = ?", (invalid_json,))
                cache.conn.commit()
                self.assertIsNone(cache.get("m", "s", "t"))
                cache.put("m", "s", "t", {"ok": True})
                self.assertEqual(cache.get("m", "s", "t"), {"ok": True})
                self.assertEqual((cache.hits, cache.misses), (1, 1))

    def test_clear_drops_rows(self):
        with AnswerCache(":memory:") as cache:
            cache.put("m", "s", "t", {"ok": True})
            cache.clear()
            self.assertIsNone(cache.get("m", "s", "t"))

    def test_cached_json_answers_still_decide(self):
        answers = {
            "severity": {"score": 0.5, "confidence": 0.9},
            "impact_scope": {"score": 1.0, "confidence": 0.9},
            "category": {"choice": "infra", "confidence": 0.9},
            "needs_action": {"noul": 0.2},
            "is_routine_noise": {"noul": 0.95},
            "auto_remediable": {"noul": 0.1},
        }
        got = decide(make_batch(), answers, build_state(make_batch()), Config())
        self.assertEqual(got.decision, "suppress")
