"""Normalize log lines, collapse repeats, and size batches for one jev call."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from logtriage.loki import LokiError

# ---------------------------------------------------------------------------
# Normalization + batching
# ---------------------------------------------------------------------------
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_NORMALIZERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^([IWEF])\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+(?:\d+\s+)?"), r"\1<ts> "),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<ts>"),
    (re.compile(r"(?i)\b((?:[a-z_]+_)?id|requestid|traceid|spanid|sessionid|userid)\s*[:=]\s*[A-Za-z0-9._-]+"), r"\1=<id>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<hex>"),
    # Keep numeric values: status codes, durations, and resource usage can change the judgment.
)
_KLOG_RE = re.compile(r"^([IWEF])\d{4}\b")
_LEVEL_TOKEN_RE = re.compile(
    r"(?i)\b(?:level|severity)['\"]?[\s:=]+['\"]?(error|err|fatal|panic|critical|warn|warning|notice|info|debug|trace)\b"
)
_LEVEL_WORD_RE = re.compile(
    r"(?i)^\s*\[?(error|err|fatal|panic|critical|warn|warning|notice|info|debug|trace)\]?\b"
)

_LEVEL_ALIASES = {
    "err": "error",
    "warning": "warn",
    "critical": "critical",
    "panic": "fatal",
    "notice": "info",
}


def normalize_level(value: str | None) -> str:
    if not value:
        return "unknown"
    value = value.strip().lower()
    return _LEVEL_ALIASES.get(value, value)


def detect_level(line: str, stream_labels: Mapping[str, str] | None = None) -> str:
    for label in ("detected_level", "level", "severity"):
        if stream_labels and stream_labels.get(label):
            return normalize_level(stream_labels[label])
    head = line[:300]
    match = _LEVEL_TOKEN_RE.search(head)
    if match:
        return normalize_level(match.group(1))
    match = _KLOG_RE.match(line)
    if match:
        return {"I": "info", "W": "warn", "E": "error", "F": "fatal"}[match.group(1)]
    match = _LEVEL_WORD_RE.match(head)
    if match:
        return normalize_level(match.group(1))
    match = re.search(
        r"(?i)\b(error|fatal|panic|critical|warn|warning)\b", line[:160]
    )
    if match:
        return normalize_level(match.group(1))
    return "unknown"


def normalize_line(line: str) -> str:
    """Collapse volatile tokens so repeated log lines share one pattern key."""
    cleaned = ANSI_RE.sub("", line).strip()
    for pattern, replacement in _NORMALIZERS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def source_name(labels: Mapping[str, str]) -> str:
    for key in ("app", "service_name", "container", "pod", "instance"):
        value = labels.get(key)
        if value:
            return value
    return "unknown"


@dataclass
class Pattern:
    """One distinct log pattern, with how often it occurred."""

    key: str
    text: str
    level: str
    count: int = 0
    first_ts_ns: int = 0
    last_ts_ns: int = 0


@dataclass
class Batch:
    """A per-source group of collapsed patterns, sized for one jev call."""

    source: str
    labels: dict[str, str]
    patterns: list[Pattern]
    total_lines: int
    distinct_patterns: int
    omitted_patterns: int
    omitted_lines: int
    by_level: dict[str, int]
    start_ns: int
    end_ns: int
    truncated: bool = False


def group_streams(
    streams: Iterable[Mapping[str, Any]], group_by: Sequence[str]
) -> dict[tuple[str, ...], dict[str, Any]]:
    groups: dict[tuple[str, ...], dict[str, Any]] = {}
    for stream in streams:
        labels = dict(stream.get("stream") or {})
        key: list[str] = []
        for label in group_by:
            value = labels.get(label)
            if not value and label == "app":
                value = source_name(labels)
            key.append(value or "")
        group_key = tuple(key)

        group = groups.setdefault(
            group_key,
            {
                "labels": labels,
                "patterns": {},
                "by_level": Counter(),
                "total_lines": 0,
                "start_ns": None,
                "end_ns": None,
            },
        )
        for raw in stream.get("values") or []:
            try:
                ts_ns = int(raw[0])
                line = str(raw[1])
            except (IndexError, TypeError, ValueError):
                continue
            level = detect_level(line, labels)
            pattern_key = f"{level}|{normalize_line(line)}"
            pattern = group["patterns"].get(pattern_key)
            if pattern is None:
                group["patterns"][pattern_key] = Pattern(
                    key=pattern_key,
                    text=ANSI_RE.sub("", line).strip()[:800],
                    level=level,
                    count=1,
                    first_ts_ns=ts_ns,
                    last_ts_ns=ts_ns,
                )
            else:
                pattern.count += 1
                pattern.first_ts_ns = min(pattern.first_ts_ns, ts_ns)
                pattern.last_ts_ns = max(pattern.last_ts_ns, ts_ns)
            group["by_level"][level] += 1
            group["total_lines"] += 1
            group["start_ns"] = ts_ns if group["start_ns"] is None else min(group["start_ns"], ts_ns)
            group["end_ns"] = ts_ns if group["end_ns"] is None else max(group["end_ns"], ts_ns)
    return groups


def build_batches(
    streams: Iterable[Mapping[str, Any]],
    group_by: Sequence[str] = ("namespace", "app"),
    max_lines: int = 40,
    max_chars: int = 24_000,
    exclude_apps: Sequence[str] = (),
) -> list[Batch]:
    """Collapse streams into per-source batches that fit the state budget."""
    skip = {name.lower() for name in exclude_apps}
    batches: list[Batch] = []
    for group in group_streams(streams, group_by).values():
        patterns = sorted(
            group["patterns"].values(), key=lambda p: (-p.count, -p.last_ts_ns)
        )
        selected: list[Pattern] = []
        used_chars = 0
        omitted_lines = 0
        for pattern in patterns:
            if len(selected) >= max_lines:
                omitted_lines += pattern.count
                continue
            cost = len(pattern.text) + 80  # text + JSON envelope
            if selected and used_chars + cost > max_chars:
                omitted_lines += pattern.count
                continue
            selected.append(pattern)
            used_chars += cost

        if group["total_lines"] == 0:
            continue
        omitted_patterns = max(0, len(patterns) - len(selected))
        labels = dict(group["labels"])
        if skip and source_name(labels).lower() in skip:
            continue
        batches.append(
            Batch(
                source=source_name(labels),
                labels=labels,
                patterns=selected,
                total_lines=group["total_lines"],
                distinct_patterns=len(patterns),
                omitted_patterns=omitted_patterns,
                omitted_lines=omitted_lines,
                by_level=dict(group["by_level"].most_common()),
                start_ns=group["start_ns"] or 0,
                end_ns=group["end_ns"] or 0,
                truncated=omitted_patterns > 0,
            )
        )
    # Biggest first, so --max-batches keeps the loudest sources.
    batches.sort(key=lambda b: b.total_lines, reverse=True)
    return batches


def build_state(batch: Batch) -> dict[str, Any]:
    """The exact state object sent to jev (also kept in the report for audit)."""
    window_minutes = 0.0
    if batch.end_ns > batch.start_ns:
        window_minutes = round((batch.end_ns - batch.start_ns) / 60e9, 1)
    return {
        "source": {**batch.labels, "app": batch.labels.get("app") or batch.source},
        "window": {
            "from": ns_to_iso(batch.start_ns),
            "to": ns_to_iso(batch.end_ns),
            "minutes": window_minutes,
        },
        "volume": {
            "matched_lines": batch.total_lines,
            "distinct_patterns": batch.distinct_patterns,
            "by_level": batch.by_level,
            "sampled_patterns": len(batch.patterns),
            "omitted_lines": batch.omitted_lines,
            "truncated": batch.truncated,
        },
        "log_lines": [
            {"count": p.count, "level": p.level, "text": p.text} for p in batch.patterns
        ],
    }


def ns_to_iso(ts_ns: int) -> str:
    if not ts_ns:
        return ""
    return datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat(timespec="seconds")


def demo_fixture_path() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "demo.json"


def _demo_fixture_text(path: Path | None = None) -> str:
    if path is not None:
        return Path(path).read_text(encoding="utf-8")
    try:
        from importlib.resources import files

        return (files("logtriage") / "fixtures" / "demo.json").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return demo_fixture_path().read_text(encoding="utf-8")


def load_demo_streams(path: Path | None = None) -> list[dict[str, Any]]:
    """Load bundled fixtures as Loki-shaped streams. Timestamps are filled at load."""
    payload = json.loads(_demo_fixture_text(path))
    now_ns = int(datetime.now(timezone.utc).timestamp() * 1e9)
    streams: list[dict[str, Any]] = []
    for item in payload.get("streams") or []:
        lines = item.get("lines") or []
        values = []
        for i, line in enumerate(lines):
            if isinstance(line, (list, tuple)) and len(line) >= 2:
                values.append([str(line[0]), str(line[1])])
                continue
            ts_ns = now_ns - (len(lines) - i) * 1_000_000_000
            values.append([str(ts_ns), str(line)])
        streams.append({"stream": dict(item.get("stream") or {}), "values": values})
    if not streams:
        raise LokiError(f"demo fixture is empty: {path or demo_fixture_path()}")
    return streams
