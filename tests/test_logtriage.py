"""Behavior of collapsing, selectors, key loading, and the decision table.

No network. Run: uv run python -m unittest discover -s tests -t . -v
"""

from __future__ import annotations

import argparse
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from logtriage import (
    Batch,
    Config,
    Pattern,
    build_batches,
    build_selector,
    build_state,
    decide,
    detect_level,
    load_api_key,
    load_demo_streams,
    normalize_line,
    parse_duration,
)


def fake_answers(**overrides):
    answers = {
        "severity": SimpleNamespace(type="score", score=2.0, confidence=0.9),
        "impact_scope": SimpleNamespace(type="score", score=1.0, confidence=0.9),
        "category": SimpleNamespace(type="choice", choice="infra", confidence=0.9),
        "needs_action": SimpleNamespace(type="noul", noul=0.8),
        "is_routine_noise": SimpleNamespace(type="noul", noul=0.1),
        "auto_remediable": SimpleNamespace(type="noul", noul=0.1),
    }
    fields = {
        "severity": ("severity", "score"),
        "severity_conf": ("severity", "confidence"),
        "impact": ("impact_scope", "score"),
        "impact_conf": ("impact_scope", "confidence"),
        "category": ("category", "choice"),
        "category_conf": ("category", "confidence"),
        "needs_action": ("needs_action", "noul"),
        "is_noise": ("is_routine_noise", "noul"),
        "auto_remediable": ("auto_remediable", "noul"),
    }
    for key, value in overrides.items():
        attr = fields[key]
        setattr(answers[attr[0]], attr[1], value)
    return answers


def make_batch(source="app", lines=5):
    return Batch(
        source=source,
        labels={"namespace": "services", "app": source},
        patterns=[Pattern(key="error|x", text="error: something failed", level="error", count=lines)],
        total_lines=lines,
        distinct_patterns=1,
        omitted_patterns=0,
        omitted_lines=0,
        by_level={"error": lines},
        start_ns=1_700_000_000_000_000_000,
        end_ns=1_700_000_060_000_000_000,
        truncated=False,
    )


def make_streams(app="myapp", namespace="services", values=None, level="info"):
    values = values or [
        ["1700000000000000000", "request completed in 12ms id=abc123"],
        ["1700000000000000001", "boom: connection refused"],
    ]
    stream = {"namespace": namespace, "app": app, "container": app}
    if level:
        stream["detected_level"] = level
    return [{"stream": stream, "values": values}]


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


class SelectorTests(unittest.TestCase):
    def test_filters_compose_unless_a_raw_query_is_set(self):
        cases = [
            ("default", Config(), '{namespace=~".+"}'),
            (
                "labels and pipeline",
                Config(
                    namespaces=("services", "monitoring"),
                    levels=("error", "warn"),
                    line_filter='|~ "timeout"',
                ),
                '{namespace=~"services|monitoring"} | detected_level =~ "error|warn" |~ "timeout"',
            ),
            (
                "filter without leading pipe",
                Config(line_filter='~ "timeout"'),
                '{namespace=~".+"} | ~ "timeout"',
            ),
            ("raw query wins", Config(query='{app="x"}', namespaces=("ignored",)), '{app="x"}'),
        ]
        for name, cfg, expected in cases:
            with self.subTest(name):
                self.assertEqual(build_selector(cfg), expected)


class DurationTests(unittest.TestCase):
    def test_accepts_unit_suffixes_and_rejects_garbage(self):
        self.assertEqual(parse_duration("30m").total_seconds(), 1800)
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_duration("tomorrow")


class ApiKeyTests(unittest.TestCase):
    def test_env_beats_file_and_file_is_used_when_env_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".typesafe"
            path.write_text("apikey_file\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "apikey_env"}):
                self.assertEqual(load_api_key(str(path)), "apikey_env")
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(load_api_key(str(path)), "apikey_file")


class DemoTests(unittest.TestCase):
    def test_bundled_fixture_is_multiple_sources_not_one_blob(self):
        batches = build_batches(load_demo_streams())
        names = {b.source for b in batches}
        self.assertIn("coredns", names)
        self.assertGreater(len(names), 1)


class DecisionTests(unittest.TestCase):
    """The if/elif chain is one policy. Spec it as a table, including near-misses."""

    def test_gates_choose_the_decision(self):
        cfg = Config()
        state = build_state(make_batch())
        cases = [
            ("high noise, low severity", dict(severity=0.5, is_noise=0.95), "suppress"),
            (
                "high noise but page-level severity still pages",
                dict(severity=3.0, impact=3.0, is_noise=0.95, needs_action=0.9),
                "page",
            ),
            ("needs_action below threshold", dict(needs_action=0.2), "watch"),
            ("needs_action at threshold is not watch", dict(needs_action=0.5, severity=1.6), "notify"),
            ("low confidence", dict(severity_conf=0.3, needs_action=0.9), "review"),
            ("confidence at floor is not review", dict(severity_conf=0.5, needs_action=0.9, severity=1.6), "notify"),
            ("severity and priority both high", dict(severity=3.0, impact=3.0, needs_action=0.95), "page"),
            (
                "page-level severity without priority does not page",
                dict(severity=2.2, impact=0.0, needs_action=0.9),
                "notify",
            ),
            (
                "safe category with high auto score",
                dict(severity=2.2, impact=1.0, category="resource", auto_remediable=0.95, needs_action=0.9),
                "auto_remediate_candidate",
            ),
            (
                "security is never auto-remediated",
                dict(severity=2.2, impact=1.0, category="security", auto_remediable=0.99, needs_action=0.9),
                "notify",
            ),
        ]
        for name, overrides, expected in cases:
            with self.subTest(name):
                got = decide(make_batch(), fake_answers(**overrides), state, cfg)
                self.assertEqual(got.decision, expected)


if __name__ == "__main__":
    unittest.main()
