"""LogQL selector construction."""

from __future__ import annotations

import unittest

from logtriage import Config, build_selector


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
                '{namespace=~".+"} |~ "timeout"',
            ),
            ("negative filter", Config(line_filter='!~ "noise"'), '{namespace=~".+"} !~ "noise"'),
            ("parser stage", Config(line_filter="json"), '{namespace=~".+"} | json'),
            (
                "literal label values need regex and string escaping",
                Config(namespaces=("team-a",), apps=('api.worker+v1"',)),
                r'{namespace=~"team\\-a", app=~"api\\.worker\\+v1\""}',
            ),
            ("raw query wins", Config(query='{app="x"}', namespaces=("ignored",)), '{app="x"}'),
        ]
        for name, cfg, expected in cases:
            with self.subTest(name):
                self.assertEqual(build_selector(cfg), expected)
