"""Answer cache: same judgment hits, volume/schema/model changes miss."""

from __future__ import annotations

import unittest

from logtriage import Config, build_state, decide
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
        cases = [(1, "1"), (2, "2-9"), (9, "2-9"), (10, "10-99"), (99, "10-99"), (100, "100-999"), (1000, "1000+")]
        for n, expected in cases:
            with self.subTest(n=n):
                self.assertEqual(volume_bucket(n), expected)


class AnswerCacheTests(unittest.TestCase):
    def test_same_key_hits_and_count_bucket_change_misses(self):
        cache = AnswerCache(":memory:")
        small = make_batch(lines=5)
        big = make_batch(lines=50)
        schema = sha256_json(canonical_questions({"q": {"type": "noul", "instructions": "x"}}))
        payload = {"needs_action": {"type": "noul", "noul": 0.2}}
        small_hash = sha256_json(canonical_state(small))
        big_hash = sha256_json(canonical_state(big))
        self.assertNotEqual(small_hash, big_hash)
        cache.put("jev-latest", schema, small_hash, payload)
        self.assertEqual(cache.get("jev-latest", schema, small_hash)["needs_action"]["noul"], 0.2)
        self.assertIsNone(cache.get("jev-latest", schema, big_hash))
        self.assertEqual(cache.hits, 1)
        self.assertEqual(cache.misses, 1)
        cache.close()

    def test_question_or_model_change_misses(self):
        cache = AnswerCache(":memory:")
        batch = make_batch()
        state_hash = sha256_json(canonical_state(batch))
        schema_a = sha256_json(canonical_questions({"q": {"type": "noul", "instructions": "a"}}))
        schema_b = sha256_json(canonical_questions({"q": {"type": "noul", "instructions": "b"}}))
        cache.put("jev-latest", schema_a, state_hash, {"ok": True})
        self.assertIsNotNone(cache.get("jev-latest", schema_a, state_hash))
        self.assertIsNone(cache.get("jev-latest", schema_b, state_hash))
        self.assertIsNone(cache.get("jev-1.13.0", schema_a, state_hash))
        cache.close()

    def test_clear_drops_rows(self):
        cache = AnswerCache(":memory:")
        cache.put("m", "s", "t", {"ok": True})
        cache.clear()
        self.assertIsNone(cache.get("m", "s", "t"))
        cache.close()

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
