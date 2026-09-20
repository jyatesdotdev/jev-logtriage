"""Collapsing, levels, and the bundled demo fixture."""

from __future__ import annotations

import unittest

from logtriage import build_batches, detect_level, load_demo_streams, normalize_line
from logtriage.batch import demo_fixture_path

from tests.factories import make_streams


class CollapseTests(unittest.TestCase):
    def test_collapse_ignores_identity_but_keeps_diagnostic_values(self):
        prefix = "context=" + "x" * 300
        cases = [
            (
                "timestamps, ids, and color",
                "\x1b[31m2026-09-19T21:59:40Z request_id=abc took 12ms\x1b[0m",
                "2026-09-19T22:04:11Z request_id=def took 12ms",
                1,
            ),
            (
                "klog timestamps and process ids",
                "W0919 21:59:55.391047       1 warnings.go:70] deprecated in v1.33",
                "W0920 22:04:55.401112       9 warnings.go:70] deprecated in v1.33",
                1,
            ),
            ("HTTP status", "GET /api status=200", "GET /api status=500", 2),
            ("memory", "usage=50MiB", "usage=950MiB", 2),
            ("latency", "request took 12ms", "request took 5000ms", 2),
            ("valid is not an id", "input valid=true", "input valid=false", 2),
            ("long common prefix", prefix + " accepted", prefix + " rejected", 2),
        ]
        for name, first, second, distinct in cases:
            with self.subTest(name):
                values = [["1700000000000000000", first], ["1700000000000000001", second]]
                batch = build_batches(make_streams(values=values))[0]
                self.assertEqual(batch.distinct_patterns, distinct)
                self.assertEqual(sum(p.count for p in batch.patterns), 2)

    def test_timestamp_only_repeats_do_not_crowd_out_a_distinct_failure(self):
        start = 1_700_000_000_000_000_000
        values = [[str(start), "E0919 21:59:00.000000 1 client.go:20] connection refused"]]
        values.extend(
            [str(start + i + 1), f"W0919 22:00:{i:02d}.000000 1 warnings.go:70] deprecated"]
            for i in range(40)
        )
        batch = build_batches(make_streams(values=values, level=None))[0]
        self.assertEqual(batch.omitted_lines, 0)
        self.assertEqual({p.level: p.count for p in batch.patterns}, {"warn": 40, "error": 1})

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
        a = normalize_line("2026-09-19T21:59:40.780Z level=info id=550e8400-e29b-41d4-a716-446655440000 took 51µs")
        b = normalize_line("2026-09-19T22:04:11.001Z level=info id=550e8400-e29b-41d4-a716-446655440001 took 51µs")
        self.assertNotIn("\x1b", colored)
        self.assertEqual(a, b)

    def test_level_comes_from_label_else_the_line(self):
        cases = [
            ("label wins", "info noise", {"detected_level": "critical"}, "critical"),
            ("logfmt", "level=ERROR boom", None, "error"),
            ("JSON level wins over message", '{"level":"info","message":"error resolved"}', None, "info"),
            ("klog", "W0919 21:51:40.388 warnings.go:70] deprecated", None, "warn"),
            ("no signal", "all good", None, "unknown"),
        ]
        for name, line, labels, expected in cases:
            with self.subTest(name):
                self.assertEqual(detect_level(line, labels), expected)


class DemoTests(unittest.TestCase):
    def test_fixtures_preserve_sources_and_collapse_repeated_warnings(self):
        fixtures = [
            (None, "kube-state-metrics"),
            (demo_fixture_path().with_name("observed.json"), "example-metrics-exporter"),
        ]
        for path, warning_source in fixtures:
            with self.subTest(path=path):
                streams = load_demo_streams(path)
                batches = build_batches(streams)
                self.assertEqual({b.source for b in batches}, {s["stream"]["app"] for s in streams})
                self.assertGreater(len(batches), 1)
                metrics = next(batch for batch in batches if batch.source == warning_source)
                self.assertEqual(metrics.distinct_patterns, 1)
                self.assertEqual(metrics.patterns[0].count, 2)
