"""CLI helpers: durations and API key loading."""

from __future__ import annotations

import argparse
import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from logtriage import load_api_key, main, parse_duration

from tests.factories import fake_answers, make_streams


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


class RunTests(unittest.TestCase):
    def run_demo(self, db, *options, answers=None):
        if answers is None:
            answers = {key: vars(value) for key, value in fake_answers().items()}
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch("logtriage.cli.TypeSafeClient") as client,
            mock.patch("logtriage.cli.load_api_key", return_value="test-key"),
            mock.patch("logtriage.cli.load_demo_streams", return_value=make_streams()),
            redirect_stdout(stdout), redirect_stderr(stderr),
        ):
            client.return_value.system_one.return_value = SimpleNamespace(
                answers=answers, usage={"input_tokens": 42},
            )
            code = main(["--demo", "--json", "--no-report", "--cache-db", str(db), *options])
            client.return_value.close.assert_called_once()
            calls = client.return_value.system_one.call_count
        return code, json.loads(stdout.getvalue()), calls, stderr.getvalue()

    def test_cache_reuses_answers_but_reapplies_current_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "answers.sqlite3"
            cases = [
                ("cold", (), "notify", 1),
                ("warm with stricter policy", ("--confidence-floor", "0.95"), "review", 0),
                ("disabled", ("--no-cache",), "notify", 1),
            ]
            for name, options, expected, calls in cases:
                with self.subTest(name):
                    code, report, actual_calls, _ = self.run_demo(db, *options)
                    self.assertEqual(code, 0)
                    self.assertEqual(report["decisions"][0]["decision"], expected)
                    self.assertEqual(actual_calls, calls)
                    self.assertEqual(report["totals"]["usage"].get("input_tokens", 0), 42 * calls)

    def test_invalid_answers_are_errors_not_cached_successes(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "answers.sqlite3"
            code, report, _, _ = self.run_demo(db, answers={})
            self.assertEqual(code, 1)
            self.assertEqual(report["decisions"][0]["decision"], "error")
            code, report, calls, _ = self.run_demo(db)
            self.assertEqual((code, report["decisions"][0]["decision"], calls), (0, "notify", 1))

    def test_cache_failures_do_not_discard_live_decisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            blocker = root / "not-a-directory"
            blocker.write_text("", encoding="utf-8")
            corrupt = root / "corrupt.sqlite3"
            corrupt.write_text("not a SQLite database", encoding="utf-8")
            for db in (blocker / "answers.sqlite3", corrupt):
                with self.subTest(path=db.name):
                    code, report, calls, stderr = self.run_demo(db)
                    self.assertEqual((code, report["decisions"][0]["decision"], calls), (0, "notify", 1))
                    self.assertIn("cache disabled", stderr)
            for method in ("get", "put"):
                with self.subTest(method=method), mock.patch(
                    f"logtriage.cli.AnswerCache.{method}",
                    side_effect=sqlite3.OperationalError("cache unavailable"),
                ):
                    code, report, calls, stderr = self.run_demo(root / f"{method}.sqlite3")
                    self.assertEqual((code, report["decisions"][0]["decision"], calls), (0, "notify", 1))
                    self.assertIn("cache disabled", stderr)
