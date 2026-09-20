"""Builders for tests. Not collected by unittest (name does not start with test)."""

from __future__ import annotations

from types import SimpleNamespace

from logtriage import Batch, Pattern


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
