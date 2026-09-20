"""Collapsing, levels, and the bundled demo fixture."""

from __future__ import annotations

import unittest

from logtriage import build_batches, detect_level, load_demo_streams, normalize_line

from tests.factories import make_streams


class CollapseTests(unittest.TestCase):
    def test_same_event_with_different_ids_is_one_pattern(self):
        streams = make_streams(
            values=[
                ["1700000000000000000", "request completed in 12ms id=abc"],
                ["1700000000000000001", "request completed in 13ms id=def"],
                ["1700000000000000002", "request completed in 14ms id=ghi"],
            ]
        )
        batch = build_batches(streams)[0]
        self.assertEqual(batch.distinct_patterns, 1)
        self.assertEqual(batch.patterns[0].count, 3)

    def test_over_budget_patterns_are_omitted_not_silently_kept(self):
        words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]
        values = [[str(1_700_000_000_000_000_000 + i), f"error: failure mode {words[i]}"] for i in range(6)]
        over = build_batches(make_streams(values=values, level="error"), max_lines=3)[0]
        under = build_batches(make_streams(values=values, level="error"), max_lines=6)[0]
        self.assertTrue(over.truncated)
        self.assertEqual(over.omitted_patterns, 3)
        self.assertFalse(under.truncated)
        self.assertEqual(under.omitted_patterns, 0)

    def test_exclude_list_drops_only_named_apps(self):
        streams = make_streams(app="loki") + make_streams(app="vikunja")
        kept = build_batches(streams, exclude_apps=("loki",))
        all_apps = build_batches(streams)
        self.assertEqual([b.source for b in kept], ["vikunja"])
        self.assertEqual({b.source for b in all_apps}, {"loki", "vikunja"})

    def test_normalize_strips_color_and_volatile_tokens(self):
        colored = normalize_line("\x1b[31merror:\x1b[0m failed")
        a = normalize_line("2026-09-19T21:59:40.780Z level=info id=550e8400-e29b-41d4-a716-446655440000 took 237.471µs")
        b = normalize_line("2026-09-19T22:04:11.001Z level=info id=550e8400-e29b-41d4-a716-446655440001 took 51.002µs")
        self.assertNotIn("\x1b", colored)
        self.assertEqual(a, b)

    def test_level_comes_from_label_else_the_line(self):
        cases = [
            ("label wins", "info noise", {"detected_level": "critical"}, "critical"),
            ("logfmt", "level=ERROR boom", None, "error"),
            ("klog", "W0919 21:51:40.388 warnings.go:70] deprecated", None, "warn"),
            ("no signal", "all good", None, "unknown"),
        ]
        for name, line, labels, expected in cases:
            with self.subTest(name):
                self.assertEqual(detect_level(line, labels), expected)


class DemoTests(unittest.TestCase):
    def test_bundled_fixture_is_multiple_sources_not_one_blob(self):
        batches = build_batches(load_demo_streams())
        names = {b.source for b in batches}
        self.assertIn("coredns", names)
        self.assertGreater(len(names), 1)
