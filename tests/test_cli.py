"""CLI helpers: durations and API key loading."""

from __future__ import annotations

import argparse
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from logtriage import load_api_key, parse_duration


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
