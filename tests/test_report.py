"""Console output must agree with the confidence used to route a decision."""

from __future__ import annotations

import unittest
from dataclasses import asdict
from unittest import mock

from logtriage import Config, build_state, decide
from logtriage.report import render_summary

from tests.factories import fake_answers, make_batch


class SummaryTests(unittest.TestCase):
    @mock.patch("logtriage.report.use_color", return_value=False)
    def test_review_shows_the_lowest_confidence_not_a_reassuring_one(self, _use_color):
        batch = make_batch()
        for field in ("severity_conf", "impact_conf", "category_conf"):
            with self.subTest(field=field):
                decision = decide(batch, fake_answers(**{field: 0.3}), build_state(batch), Config())
                output = render_summary({"decisions": [asdict(decision)]})
                row = output.splitlines()[2].split()
                self.assertEqual(row[0], "review")
                self.assertEqual(row[3], "0.30")
