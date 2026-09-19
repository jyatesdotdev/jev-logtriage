"""Unit tests for logtriage. No network calls; decision logic uses fake answers.

Run with:  python -m unittest discover -s tests -t . -v
"""

from __future__ import annotations

import json
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


def fake_answers(
    *,
    severity=2.0,
    severity_conf=0.9,
    impact=1.0,
    impact_conf=0.9,
    category="infra",
    category_conf=0.9,
    needs_action=0.8,
    is_noise=0.1,
    auto_remediable=0.1,
):
    return {
        "severity": SimpleNamespace(type="score", score=severity, confidence=severity_conf),
        "impact_scope": SimpleNamespace(type="score", score=impact, confidence=impact_conf),
        "category": SimpleNamespace(type="choice", choice=category, confidence=category_conf),
        "needs_action": SimpleNamespace(type="noul", noul=needs_action),
        "is_routine_noise": SimpleNamespace(type="noul", noul=is_noise),
        "auto_remediable": SimpleNamespace(type="noul", noul=auto_remediable),
    }


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
        ["1700000000000000001", "request completed in 13ms id=def456"],
        ["1700000000000000002", "boom: connection refused"],
    ]
    stream = {"namespace": namespace, "app": app, "container": app}
    if level:
        stream["detected_level"] = level
    return [{"stream": stream, "values": values}]


class NormalizeTests(unittest.TestCase):
    def test_collapses_volatile_tokens(self):
        a = normalize_line("2026-09-19T21:59:40.780Z level=info id=550e8400-e29b-41d4-a716-446655440000 took 237.471µs")
        b = normalize_line("2026-09-19T22:04:11.001Z level=info id=550e8400-e29b-41d4-a716-446655440001 took 51.002µs")
        self.assertEqual(a, b)
        self.assertIn("<ts>", a)
        self.assertIn("<id>", a)

    def test_strips_ansi(self):
        self.assertNotIn("\x1b", normalize_line("\x1b[31merror:\x1b[0m failed"))

    def test_detects_levels(self):
        self.assertEqual(detect_level("level=ERROR boom"), "error")
        self.assertEqual(detect_level('{"level":"warning","msg":"x"}'), "warn")
        self.assertEqual(detect_level("W0919 21:51:40.388 warnings.go:70] deprecated"), "warn")
        self.assertEqual(detect_level("2026-09-19 - news_linker - WARNING - rss: skip"), "warn")
        self.assertEqual(detect_level("all good"), "unknown")
        self.assertEqual(detect_level("anything", {"detected_level": "critical"}), "critical")


class BatchTests(unittest.TestCase):
    def test_collapses_duplicates_and_counts_levels(self):
        streams = make_streams(
            values=[
                ["1700000000000000000", "request completed in 12ms id=abc"],
                ["1700000000000000001", "request completed in 13ms id=def"],
                ["1700000000000000002", "request completed in 14ms id=ghi"],
            ],
            level="info",
        )
        batches = build_batches(streams)
        self.assertEqual(len(batches), 1)
        batch = batches[0]
        self.assertEqual(batch.source, "myapp")
        self.assertEqual(batch.total_lines, 3)
        self.assertEqual(batch.distinct_patterns, 1)
        self.assertEqual(batch.patterns[0].count, 3)
        self.assertEqual(batch.by_level, {"info": 3})

    def test_respects_max_lines_and_marks_truncated(self):
        words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet"]
        values = [[str(1_700_000_000_000_000_000 + i), f"error: failure mode {words[i]}"] for i in range(10)]
        batches = build_batches(make_streams(values=values, level="error"), max_lines=3)
        batch = batches[0]
        self.assertEqual(len(batch.patterns), 3)
        self.assertTrue(batch.truncated)
        self.assertEqual(batch.omitted_patterns, 7)
        self.assertEqual(batch.total_lines, 10)

    def test_excludes_apps(self):
        streams = make_streams(app="loki") + make_streams(app="vikunja")
        batches = build_batches(streams, exclude_apps=("loki",))
        self.assertEqual([b.source for b in batches], ["vikunja"])

    def test_groups_by_namespace_and_app(self):
        streams = make_streams(app="a") + make_streams(app="b", namespace="other")
        batches = build_batches(streams)
        self.assertEqual({b.source for b in batches}, {"a", "b"})

    def test_state_shape(self):
        batch = make_batch()
        state = build_state(batch)
        self.assertEqual(state["source"]["app"], "app")
        self.assertEqual(state["volume"]["matched_lines"], 5)
        self.assertEqual(state["window"]["minutes"], 1.0)
        json.dumps(state)  # must be JSON serializable


class DemoFixtureTests(unittest.TestCase):
    def test_demo_fixture_builds_seven_sources(self):
        streams = load_demo_streams()
        batches = build_batches(streams)
        sources = {b.source for b in batches}
        self.assertEqual(len(streams), 7)
        self.assertEqual(
            sources,
            {
                "coredns",
                "news-linker",
                "kube-state-metrics",
                "authentik",
                "alertmanager",
                "helm-controller",
                "forgejo-runner",
            },
        )
        coredns = next(b for b in batches if b.source == "coredns")
        self.assertLess(coredns.distinct_patterns, coredns.total_lines)


class SelectorTests(unittest.TestCase):
    def test_defaults_to_all_namespaces(self):
        self.assertEqual(build_selector(Config()), '{namespace=~".+"}')

    def test_namespace_levels_and_filter(self):
        cfg = Config(namespaces=("services", "monitoring"), levels=("error", "warn"), line_filter='|~ "timeout"')
        self.assertEqual(
            build_selector(cfg),
            '{namespace=~"services|monitoring"} | detected_level =~ "error|warn" |~ "timeout"',
        )

    def test_raw_query_wins(self):
        self.assertEqual(build_selector(Config(query='{app="x"}')), '{app="x"}')

    def test_duration_parsing(self):
        self.assertEqual(parse_duration("30m").total_seconds(), 1800)
        self.assertEqual(parse_duration("2h").total_seconds(), 7200)
        self.assertEqual(parse_duration("1d").total_seconds(), 86400)


class ApiKeyTests(unittest.TestCase):
    def test_env_wins(self):
        with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "apikey_env"}, clear=False):
            self.assertEqual(load_api_key(), "apikey_env")

    def test_raw_token_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".typesafe"
            path.write_text("apikey_123456\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(load_api_key(str(path)), "apikey_123456")

    def test_key_value_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".typesafe"
            path.write_text("TYPESAFE_API_KEY=apikey_abc\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(load_api_key(str(path)), "apikey_abc")


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.cfg = Config()
        self.state = build_state(make_batch())

    def test_noise_is_suppressed(self):
        d = decide(make_batch(), fake_answers(severity=0.5, is_noise=0.95), self.state, self.cfg)
        self.assertEqual(d.decision, "suppress")

    def test_low_action_probability_watches(self):
        d = decide(make_batch(), fake_answers(needs_action=0.2), self.state, self.cfg)
        self.assertEqual(d.decision, "watch")

    def test_low_confidence_routes_to_review(self):
        d = decide(
            make_batch(),
            fake_answers(severity_conf=0.3, needs_action=0.9),
            self.state,
            self.cfg,
        )
        self.assertEqual(d.decision, "review")

    def test_high_severity_and_priority_pages(self):
        d = decide(
            make_batch(),
            fake_answers(severity=3.0, impact=3.0, needs_action=0.95),
            self.state,
            self.cfg,
        )
        self.assertEqual(d.decision, "page")

    def test_safe_auto_remediation_candidate(self):
        d = decide(
            make_batch(),
            fake_answers(
                severity=2.2,
                impact=1.0,
                category="resource",
                auto_remediable=0.95,
                needs_action=0.9,
            ),
            self.state,
            self.cfg,
        )
        self.assertEqual(d.decision, "auto_remediate_candidate")

    def test_security_is_never_auto_remediated(self):
        d = decide(
            make_batch(),
            fake_answers(
                severity=2.2,
                impact=1.0,
                category="security",
                auto_remediable=0.99,
                needs_action=0.9,
            ),
            self.state,
            self.cfg,
        )
        self.assertEqual(d.decision, "notify")

    def test_plain_signal_notifies(self):
        d = decide(
            make_batch(),
            fake_answers(severity=1.6, impact=1.0, auto_remediable=0.2, needs_action=0.9),
            self.state,
            self.cfg,
        )
        self.assertEqual(d.decision, "notify")

    def test_rationale_records_numbers(self):
        d = decide(make_batch(), fake_answers(), self.state, self.cfg)
        joined = " ".join(d.rationale)
        self.assertIn("priority=", joined)
        self.assertIn("needs_action=", joined)


if __name__ == "__main__":
    unittest.main()