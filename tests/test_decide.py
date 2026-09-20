"""Decision table: one policy, including near-misses on each gate."""

from __future__ import annotations

import unittest

from logtriage import Config, build_state, decide

from tests.factories import fake_answers, make_batch


class DecisionTests(unittest.TestCase):
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
