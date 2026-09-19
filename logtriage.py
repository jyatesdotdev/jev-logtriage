#!/usr/bin/env python3
"""logtriage.py - pull logs from Loki, ask jev what matters, decide whether to act.

Pipeline
--------
1. Query Loki's HTTP API (``/loki/api/v1/query_range``) for a recent window.
2. Normalize + collapse repeated lines, group into per-source batches that fit
   jev's state budget.
3. Send every batch to TypeSafe System One (model ``jev-latest``) with a
   *speculative fan-out* of typed questions: is this noise, how severe, how
   wide, does it need action, is it auto-remediable, what category.
4. Combine the answers in code with a composite priority score and
   confidence-gated routing, and emit one decision per batch:
   ``suppress | watch | review | notify | auto_remediate_candidate | page``.

Nothing is executed. Automated remediation is emitted as a *candidate* so a
separate, deliberate executor can act on it later.

Usage
-----
    python logtriage.py --demo
    python logtriage.py --since 30m --errors-only   # Loki at localhost:3100

Docs: https://docs.typesafe.ai/patterns
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

# ---------------------------------------------------------------------------
# TypeSafe SDK is optional at import time so the pure-logic parts (batching,
# decision rules) can be unit-tested without the dependency installed.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - exercised by integration, not unit tests
    from typesafe_sdk import (  # type: ignore
        Choice,
        Noul,
        RetryPolicy,
        Score,
        TypeSafeClient,
    )

    SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    SDK_AVAILABLE = False


VERSION = "0.1.0"
DEFAULT_LOKI_URL = "http://127.0.0.1:3100"
DEFAULT_MODEL = "jev-latest"

# Decision vocabulary, from quietest to loudest (error is not part of the rank).
DECISIONS = (
    "suppress",
    "watch",
    "review",
    "notify",
    "auto_remediate_candidate",
    "page",
)
DECISION_RANK = {name: i for i, name in enumerate(DECISIONS)}

# Categories for which an automated fix *may* be worth proposing. Security and
# data-loss never land here regardless of the model's answer.
SAFE_AUTO_CATEGORIES = {"app_error", "resource", "config", "expected_noise"}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass
class Config:
    loki_url: str = DEFAULT_LOKI_URL
    loki_org_id: str | None = None
    loki_timeout: float = 30.0
    query: str | None = None
    namespaces: Sequence[str] = ()
    apps: Sequence[str] = ()
    levels: Sequence[str] = ()
    line_filter: str | None = None
    since: str = "30m"
    until: str | None = None
    loki_limit: int = 5000
    group_by: Sequence[str] = ("namespace", "app")
    max_batches: int = 25
    max_lines_per_batch: int = 40
    max_chars_per_batch: int = 24_000
    exclude_apps: Sequence[str] = ()

    model: str = DEFAULT_MODEL
    api_key: str = ""
    api_timeout: float = 60.0

    # Decision thresholds (see docs: confidence-gated routing, thresholds scale
    # with risk). All are configurable from the CLI.
    confidence_floor: float = 0.50
    noise_threshold: float = 0.80
    action_probability: float = 0.50
    auto_remediate_probability: float = 0.85
    page_priority: float = 0.70
    page_severity: float = 2.0
    severity_weight: float = 0.60
    impact_weight: float = 0.40

    report_path: str | None = None
    write_report: bool = True
    json_output: bool = False
    fail_on: Sequence[str] = ()
    print_questions: bool = False
    list_sources: bool = False
    demo: bool = False


# ---------------------------------------------------------------------------
# TypeSafe questions (the speculative fan-out)
# ---------------------------------------------------------------------------
def build_questions() -> dict[str, Any]:
    """Typed questions asked of every batch in one System One call.

    Per the docs, question ids are not sent to the model: each ``instructions``
    is self-contained. The state fields are referenced by path in backticks.
    """
    if not SDK_AVAILABLE:  # pragma: no cover
        raise RuntimeError(
            "typesafe-sdk is not installed. Run: uv pip install typesafe-sdk"
        )

    return {
        "is_routine_noise": Noul(
            instructions=(
                "`log_lines` is a sample of log lines emitted by `source` in a "
                "Kubernetes cluster, collected by Loki. `volume` summarizes how "
                "many lines matched. Would an experienced on-call engineer "
                "dismiss this batch as routine noise that needs no action "
                "(repeated benign warnings, expected restarts, liveness/readiness "
                "probe chatter, deprecation notices, retry loops that recover)? "
                "Answer yes if it is noise, no if it contains a real signal."
            ),
            criteria={
                "true": "Routine, expected, or self-healing; no action warranted.",
                "false": "Contains a real signal an operator may need to act on.",
            },
        ),
        "severity": Score(
            instructions=(
                "How severe is the worst real condition described in `log_lines`? "
                "Judge the condition itself, not the wording; ignore lines that "
                "are pure noise. Use `volume.by_level` for context."
            ),
            criteria=[
                "Routine or benign - expected behavior, no user impact.",
                "Minor - degraded or noteworthy, but no clear user impact yet.",
                "Major - a service is failing, erroring, or degraded for users.",
                "Critical - outage, data loss, security incident, or cluster-wide failure.",
            ],
        ),
        "impact_scope": Score(
            instructions=(
                "How wide is the blast radius of the condition, based on "
                "`source`, `volume.by_level` and `log_lines`?"
            ),
            criteria=[
                "Single process or pod; self-healing or retrying.",
                "One service or namespace.",
                "Several services or namespaces.",
                "Cluster-wide or the whole user-facing platform.",
            ],
        ),
        "needs_action": Noul(
            instructions=(
                "Do these logs indicate a condition a human operator should act "
                "on (investigate, fix, restart, scale, roll back)? Answer yes if "
                "action is warranted; no if the batch is informational."
            ),
            criteria={
                "true": "An operator should do something about this.",
                "false": "Informational only; no operator action needed.",
            },
        ),
        "auto_remediable": Noul(
            instructions=(
                "Is there a well-understood, safe, automated remediation for the "
                "condition in `log_lines` - for example restarting a crashed pod, "
                "retrying a failed job, or scaling a saturated resource? Answer "
                "yes only when the fix is unambiguous and low-risk."
            ),
            criteria={
                "true": "A single, standard, low-risk automated fix clearly applies.",
                "false": "Requires human judgment, investigation, or is risky to automate.",
            },
        ),
        "category": Choice(
            instructions="What is the primary category of the condition in `log_lines`?",
            criteria={
                "app_error": "Application bug, exception, or failed request in a service's own code.",
                "resource": "CPU/memory/disk saturation, OOM kill, or capacity exhaustion.",
                "infra": "Kubernetes, node, scheduler, storage, or DNS problem.",
                "network": "Connectivity, timeout, TLS, ingress, or service routing problem.",
                "config": "Misconfiguration, bad manifest, image pull failure, or failed rollout.",
                "security": "Auth failures, intrusion attempts, certificate or credential issues.",
                "expected_noise": "Benign or expected behavior with no action needed.",
            },
        ),
    }


# ---------------------------------------------------------------------------
# Loki client (stdlib only)
# ---------------------------------------------------------------------------
class LokiError(RuntimeError):
    pass


class LokiClient:
    def __init__(self, base_url: str, org_id: str | None = None, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.org_id = org_id
        self.timeout = timeout

    # -- low level ----------------------------------------------------------
    def _get(self, path: str, params: Mapping[str, Any] | None = None) -> dict:
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        if self.org_id:
            request.add_header("X-Scope-OrgID", self.org_id)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            raise LokiError(f"Loki HTTP {exc.code} for {path}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LokiError(f"Loki unreachable at {self.base_url}: {exc}") from exc
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise LokiError(f"Loki returned non-JSON for {path}: {body[:200]!r}") from exc
        if payload.get("status") != "success":
            raise LokiError(f"Loki error for {path}: {payload.get('error', payload)}")
        return payload

    # -- public API ---------------------------------------------------------
    def ready(self) -> bool:
        try:
            url = f"{self.base_url}/ready"
            with urllib.request.urlopen(url, timeout=2.0) as response:
                return response.status == 200
        except Exception:
            return False

    def label_values(self, label: str) -> list[str]:
        payload = self._get(f"/loki/api/v1/label/{urllib.parse.quote(label)}/values")
        return list(payload.get("data") or [])

    def query_range(
        self,
        query: str,
        start_ns: int,
        end_ns: int,
        limit: int = 5000,
        direction: str = "backward",
    ) -> list[dict]:
        """Return raw Loki stream objects: [{stream: {...}, values: [[ts, line], ...]}]"""
        payload = self._get(
            "/loki/api/v1/query_range",
            {
                "query": query,
                "start": str(start_ns),
                "end": str(end_ns),
                "limit": str(limit),
                "direction": direction,
            },
        )
        return list(payload.get("data", {}).get("result", []))


class LokiPortForward:
    """Manage ``kubectl port-forward`` for the duration of a run."""

    def __init__(
        self,
        namespace: str = "monitoring",
        service: str = "loki",
        local_port: int = 3100,
        remote_port: int = 3100,
        timeout: float = 20.0,
    ):
        self.namespace = namespace
        self.service = service
        self.local_port = local_port
        self.remote_port = remote_port
        self.timeout = timeout
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        cmd = [
            "kubectl",
            "port-forward",
            "-n",
            self.namespace,
            f"svc/{self.service}",
            f"{self.local_port}:{self.remote_port}",
        ]
        self.process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        deadline = time.monotonic() + self.timeout
        client = LokiClient(f"http://127.0.0.1:{self.local_port}")
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                output = self.process.stdout.read() if self.process.stdout else ""
                raise LokiError(f"kubectl port-forward exited: {output.strip()[:400]}")
            if client.ready():
                return
            time.sleep(0.4)
        self.stop()
        raise LokiError("timed out waiting for kubectl port-forward to become ready")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self.process.kill()


# ---------------------------------------------------------------------------
# Normalization + batching
# ---------------------------------------------------------------------------
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_NORMALIZERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<ts>"),
    (re.compile(r"(?i)\b((?:[a-z_]*id|requestid|traceid|spanid|sessionid|userid))\s*[:=]\s*[A-Za-z0-9._-]+"), r"\1=<id>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<hex>"),
    (re.compile(r"\b\d+(?:\.\d+)?(?:ms|µs|us|ns|s|m|h|MiB|GiB|KiB|MB|GB|KB|B|%)\b"), "<num>"),
    (re.compile(r"\b\d+\b"), "<n>"),
)
_KLOG_RE = re.compile(r"^([IWEF])\d{4}\b")
_LEVEL_TOKEN_RE = re.compile(
    r"(?i)\blevel[\s:=]+['\"]?(error|err|fatal|panic|critical|warn|warning|notice|info|debug|trace)"
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
    return cleaned[:240]


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


# ---------------------------------------------------------------------------
# Decision engine: composite score + confidence-gated routing
# ---------------------------------------------------------------------------
@dataclass
class Decision:
    source: str
    decision: str
    priority: float
    severity: float
    severity_confidence: float
    impact: float
    impact_confidence: float
    category: str
    category_confidence: float
    needs_action: float
    is_noise: float
    auto_remediable: float
    rationale: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    answers: dict[str, Any] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def _field(answers: Mapping[str, Any], question_id: str, name: str, default: Any) -> Any:
    answer = answers.get(question_id)
    if answer is None:
        return default
    if isinstance(answer, Mapping):
        return answer.get(name, default)
    return getattr(answer, name, default)


def _confidence(answers: Mapping[str, Any], question_id: str) -> float:
    value = _field(answers, question_id, "confidence", None)
    return float(value) if value is not None else 1.0


def decide(batch: Batch, answers: Mapping[str, Any], state: dict[str, Any], cfg: Config) -> Decision:
    """Map typed answers to one action decision.

    Gates apply in order: noise suppression, action probability, confidence
    floor (never act on an answer the model is unsure about), then composite
    priority for page vs. notify vs. auto-remediation candidate.
    """
    severity = float(_field(answers, "severity", "score", 0.0))
    impact = float(_field(answers, "impact_scope", "score", 0.0))
    severity_conf = _confidence(answers, "severity")
    impact_conf = _confidence(answers, "impact_scope")
    category_conf = _confidence(answers, "category")
    category = str(_field(answers, "category", "choice", "unknown"))
    needs_action = float(_field(answers, "needs_action", "noul", 0.0))
    is_noise = float(_field(answers, "is_routine_noise", "noul", 0.0))
    auto_remediable = float(_field(answers, "auto_remediable", "noul", 0.0))

    severity_norm = severity / 3.0
    impact_norm = impact / 3.0
    priority = round(cfg.severity_weight * severity_norm + cfg.impact_weight * impact_norm, 3)
    min_conf = min(severity_conf, impact_conf, category_conf)

    rationale = [
        f"severity={severity:.2f}/3 (confidence {severity_conf:.2f})",
        f"impact_scope={impact:.2f}/3 (confidence {impact_conf:.2f})",
        f"category={category} (confidence {category_conf:.2f})",
        f"needs_action={needs_action:.2f} is_routine_noise={is_noise:.2f} "
        f"auto_remediable={auto_remediable:.2f}",
        f"priority={priority:.3f} "
        f"(weights severity {cfg.severity_weight:.2f}, impact {cfg.impact_weight:.2f})",
    ]

    if is_noise >= cfg.noise_threshold and severity < cfg.page_severity:
        # Model is confident this is routine noise: don't wake anyone.
        decision = "suppress"
        rationale.append(
            f"gate: is_routine_noise {is_noise:.2f} >= {cfg.noise_threshold:.2f} "
            f"and severity {severity:.2f} < {cfg.page_severity:.2f} -> suppress"
        )
    elif needs_action < cfg.action_probability:
        decision = "watch"
        rationale.append(
            f"gate: needs_action {needs_action:.2f} < {cfg.action_probability:.2f} -> watch"
        )
    elif min_conf < cfg.confidence_floor:
        decision = "review"
        rationale.append(
            f"gate: min confidence {min_conf:.2f} < floor {cfg.confidence_floor:.2f} "
            "-> human review, no automated action"
        )
    elif severity >= cfg.page_severity and priority >= cfg.page_priority:
        decision = "page"
        rationale.append(
            f"gate: severity {severity:.2f} >= {cfg.page_severity:.2f} and "
            f"priority {priority:.3f} >= {cfg.page_priority:.3f} -> page"
        )
    elif auto_remediable >= cfg.auto_remediate_probability and category in SAFE_AUTO_CATEGORIES:
        decision = "auto_remediate_candidate"
        rationale.append(
            f"gate: auto_remediable {auto_remediable:.2f} >= "
            f"{cfg.auto_remediate_probability:.2f} and category '{category}' is "
            "auto-safe -> candidate (dry run; nothing executed)"
        )
    else:
        decision = "notify"
        rationale.append(
            f"gate: needs_action met but no stronger gate fired -> notify "
            f"(priority {priority:.3f}, auto_remediable {auto_remediable:.2f})"
        )

    return Decision(
        source=batch.source,
        decision=decision,
        priority=priority,
        severity=severity,
        severity_confidence=severity_conf,
        impact=impact,
        impact_confidence=impact_conf,
        category=category,
        category_confidence=category_conf,
        needs_action=needs_action,
        is_noise=is_noise,
        auto_remediable=auto_remediable,
        rationale=rationale,
        labels=batch.labels,
        answers={k: _to_jsonable(v) for k, v in answers.items()},
        state=state,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def ns_to_iso(ts_ns: int) -> str:
    if not ts_ns:
        return ""
    return datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat(timespec="seconds")


def _to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(k): _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(v) for v in value]
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return _to_jsonable(dump())
    if hasattr(value, "__dataclass_fields__"):
        return _to_jsonable(asdict(value))
    return str(value)


def parse_duration(value: str) -> timedelta:
    """Parse a lookback duration: ``30s`` / ``15m`` / ``2h`` / ``1d`` / ``1w``."""
    value = value.strip()
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(s|m|h|d|w)", value.lower())
    if not match:
        raise argparse.ArgumentTypeError(
            f"invalid duration '{value}': use 30s, 15m, 2h, 1d, or 1w"
        )
    amount = float(match.group(1))
    unit = match.group(2)
    seconds = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
    return timedelta(seconds=amount * seconds)


def parse_instant(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid timestamp '{value}': use ISO-8601, e.g. 2026-09-19T21:00:00Z"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def resolve_window(since: str, until: str | None) -> tuple[int, int]:
    now = datetime.now(timezone.utc)
    end = parse_instant(until) if until else now
    try:
        start = end - parse_duration(since)
    except argparse.ArgumentTypeError:
        start = parse_instant(since)
    if start >= end:
        raise argparse.ArgumentTypeError("window start must be before end")
    return int(start.timestamp() * 1e9), int(end.timestamp() * 1e9)


def build_selector(cfg: Config) -> str:
    if cfg.query:
        return cfg.query
    parts: list[str] = []
    if cfg.namespaces:
        parts.append(f'namespace=~"{regex_alternation(cfg.namespaces)}"')
    else:
        parts.append('namespace=~".+"')
    if cfg.apps:
        parts.append(f'app=~"{regex_alternation(cfg.apps)}"')
    selector = "{" + ", ".join(parts) + "}"
    # detected_level is structured metadata in this Loki install, so it has to
    # be a pipeline filter rather than a stream-selector match.
    if cfg.levels:
        selector = f'{selector} | detected_level =~ "{regex_alternation(cfg.levels)}"'
    if cfg.line_filter:
        filter_text = cfg.line_filter.strip()
        if not filter_text.startswith("|"):
            filter_text = f"| {filter_text}"
        selector = f"{selector} {filter_text}"
    return selector


def demo_fixture_path() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "demo.json"


def load_demo_streams(path: Path | None = None) -> list[dict[str, Any]]:
    """Load bundled fixtures as Loki-shaped streams. Timestamps are filled at load."""
    fixture = path or demo_fixture_path()
    payload = json.loads(fixture.read_text(encoding="utf-8"))
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
        raise LokiError(f"demo fixture is empty: {fixture}")
    return streams


def regex_alternation(values: Sequence[str]) -> str:
    escaped = [re.escape(v) for v in values if v]
    if not escaped:
        return ".+"
    return "|".join(escaped)


def load_api_key(explicit_file: str | None = None) -> str:
    """Read the key from TYPESAFE_API_KEY, then from an api key file.

    Accepts a raw token (``apikey_...``) or ``TYPESAFE_API_KEY=...`` lines.
    """
    env_key = os.environ.get("TYPESAFE_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()
    candidates = []
    if explicit_file:
        candidates.append(Path(explicit_file).expanduser())
    candidates.append(Path.cwd() / ".typesafe")
    candidates.append(Path(__file__).resolve().parent / ".typesafe")
    for path in candidates:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8").strip()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                name, _, value = line.partition("=")
                if name.strip() in {"TYPESAFE_API_KEY", "API_KEY", "api_key"}:
                    return value.strip().strip("'\"")
            elif line.startswith(("apikey_", "sk-", "ts_")):
                return line
        if text and not any(line.startswith("#") for line in text.splitlines()):
            return text.splitlines()[0].strip().strip("'\"")
    raise SystemExit(
        "No TypeSafe API key found. Set TYPESAFE_API_KEY or place the key in "
        "./typesafe (or pass --api-key-file)."
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
_COLORS = {
    "suppress": "\033[2m",
    "watch": "\033[36m",
    "review": "\033[33m",
    "notify": "\033[34m",
    "auto_remediate_candidate": "\033[35m",
    "page": "\033[1;31m",
    "error": "\033[1;31m",
    "reset": "\033[0m",
}


def use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def render_summary(report: Mapping[str, Any]) -> str:
    decisions = report.get("decisions", [])
    lines: list[str] = []
    counts = Counter(d["decision"] for d in decisions)
    color = use_color()
    header = f"{'DECISION':<24} {'SEV':>4} {'PRIO':>5} {'CONF':>5} {'CATEGORY':<16} SOURCE"
    lines.append(header)
    lines.append("-" * len(header))
    for item in sorted(
        decisions,
        key=lambda d: (-DECISION_RANK.get(d["decision"], -1), -d.get("priority", 0)),
    ):
        name = item["decision"]
        label = f"{_COLORS.get(name, '')}{name:<24}{_COLORS['reset']}" if color else f"{name:<24}"
        source = item["source"]
        if len(source) > 40:
            source = source[:37] + "..."
        lines.append(
            f"{label} {item.get('severity', 0):>4.1f} {item.get('priority', 0):>5.2f} "
            f"{min(item.get('severity_confidence', 1), item.get('category_confidence', 1)):>5.2f} "
            f"{item.get('category', '-'):<16} {source}"
        )
    lines.append("")
    if counts:
        summary = ", ".join(
            f"{name}={counts[name]}" for name in DECISIONS if counts.get(name)
        )
        if counts.get("error"):
            summary += f", error={counts['error']}"
        lines.append(f"decisions: {summary}")
    usage = report.get("totals", {}).get("usage", {})
    lines.append(
        f"batches={report.get('totals', {}).get('batches', 0)} "
        f"lines={report.get('loki', {}).get('lines', 0)} "
        f"tokens_in={usage.get('input_tokens', 0)} "
        f"tokens_out={usage.get('output_tokens', 0)} "
        f"model={report.get('model', '-')}"
    )
    return "\n".join(lines)


def build_report(
    cfg: Config,
    query: str,
    window: tuple[int, int],
    streams: Sequence[Mapping[str, Any]],
    batches: Sequence[Batch],
    decisions: Sequence[Decision],
    errors: Sequence[dict[str, str]],
    usage_totals: Mapping[str, int],
    started_at: datetime,
    skipped_batches: int = 0,
) -> dict[str, Any]:
    line_count = sum(len(stream.get("values") or []) for stream in streams)
    return {
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "started_at": started_at.isoformat(timespec="seconds"),
        "model": cfg.model,
        "loki": {
            "url": cfg.loki_url,
            "query": query,
            "window": {"from": ns_to_iso(window[0]), "to": ns_to_iso(window[1])},
            "limit": cfg.loki_limit,
            "streams": len(streams),
            "lines": line_count,
        },
        "totals": {
            "batches": len(batches),
            "skipped_batches": skipped_batches,
            "decisions": dict(Counter(d.decision for d in decisions)),
            "usage": dict(usage_totals),
        },
        "decisions": [_to_jsonable(asdict(d)) for d in decisions],
        "errors": list(errors),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="logtriage.py",
        description="Loki -> jev (TypeSafe System One) -> action decision.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    loki = parser.add_argument_group("Loki")
    loki.add_argument("--loki-url", default=os.environ.get("LOKI_URL", DEFAULT_LOKI_URL))
    loki.add_argument("--loki-org-id", default=os.environ.get("LOKI_ORG_ID"))
    loki.add_argument("--port-forward", action="store_true", help="manage kubectl port-forward if Loki is not reachable")
    loki.add_argument("--port-forward-namespace", default="monitoring")
    loki.add_argument("--port-forward-service", default="loki")
    loki.add_argument("--demo", action="store_true", help="run bundled fixtures instead of querying Loki")
    loki.add_argument("--query", help="raw LogQL query (overrides --namespace/--app/--levels)")
    loki.add_argument("--namespace", action="append", default=[], help="namespace to include (repeatable)")
    loki.add_argument("--app", action="append", default=[], help="app label to include (repeatable or comma-separated)")
    loki.add_argument("--exclude-app", action="append", default=[], help="app label to drop before analysis (repeatable)")
    loki.add_argument("--levels", help="comma-separated detected_level values, e.g. error,warn")
    loki.add_argument("--errors-only", action="store_true", help="shortcut for --levels error,warn,fatal,critical")
    loki.add_argument("--filter", help='extra LogQL line filter, e.g. \'|~ "timeout"\'')
    loki.add_argument("--since", default="30m", help="how far back to look (30m, 2h, 1d, ISO timestamp)")
    loki.add_argument("--until", help="end of the window (default: now)")
    loki.add_argument("--loki-limit", type=int, default=5000, help="max log lines Loki returns")

    batch = parser.add_argument_group("batching")
    batch.add_argument("--group-by", default="namespace,app", help="labels that define one source")
    batch.add_argument("--max-batches", type=int, default=25, help="max jev calls per run")
    batch.add_argument("--max-lines", type=int, default=40, help="max distinct patterns per batch")
    batch.add_argument("--max-chars", type=int, default=24_000, help="state character budget per batch")

    jev = parser.add_argument_group("jev (TypeSafe)")
    jev.add_argument("--model", default=os.environ.get("TYPESAFE_MODEL", DEFAULT_MODEL))
    jev.add_argument("--api-key-file", help="file containing the API key (default: ./.typesafe)")
    jev.add_argument("--api-timeout", type=float, default=60.0)
    jev.add_argument("--print-questions", action="store_true", help="print the question set and exit")

    rules = parser.add_argument_group("decision thresholds")
    rules.add_argument("--confidence-floor", type=float, default=0.50, help="below this -> human review")
    rules.add_argument("--noise-threshold", type=float, default=0.80, help="is_routine_noise at/above this -> suppress")
    rules.add_argument("--action-probability", type=float, default=0.50, help="needs_action below this -> watch")
    rules.add_argument("--auto-remediate-probability", type=float, default=0.85)
    rules.add_argument("--page-priority", type=float, default=0.70)
    rules.add_argument("--page-severity", type=float, default=2.0)
    rules.add_argument("--severity-weight", type=float, default=0.60)
    rules.add_argument("--impact-weight", type=float, default=0.40)

    out = parser.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="print the report as JSON")
    out.add_argument("--report", help="report path (default: reports/triage-<ts>.json)")
    out.add_argument("--no-report", action="store_true", help="do not write a report file")
    out.add_argument("--fail-on", default="", help="comma-separated decisions that should exit non-zero (e.g. page,auto_remediate_candidate)")
    out.add_argument("--list-sources", action="store_true", help="list namespaces/apps present in Loki and exit")
    out.add_argument("--quiet", action="store_true")
    out.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args(argv)


def split_csv(values: Sequence[str]) -> tuple[str, ...]:
    out: list[str] = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return tuple(out)


def cfg_from_args(args: argparse.Namespace) -> Config:
    levels = tuple(
        normalize_level(part)
        for part in (args.levels.split(",") if args.levels else [])
        if part.strip()
    )
    if args.errors_only:
        levels = tuple(dict.fromkeys((*levels, "error", "warn", "fatal", "critical")))
    return Config(
        loki_url=args.loki_url,
        loki_org_id=args.loki_org_id,
        query=args.query,
        namespaces=split_csv(args.namespace),
        apps=split_csv(args.app),
        exclude_apps=split_csv(args.exclude_app),
        levels=levels,
        line_filter=args.filter,
        since=args.since,
        until=args.until,
        loki_limit=args.loki_limit,
        group_by=tuple(part.strip() for part in args.group_by.split(",") if part.strip()),
        max_batches=args.max_batches,
        max_lines_per_batch=args.max_lines,
        max_chars_per_batch=args.max_chars,
        model=args.model,
        api_timeout=args.api_timeout,
        confidence_floor=args.confidence_floor,
        noise_threshold=args.noise_threshold,
        action_probability=args.action_probability,
        auto_remediate_probability=args.auto_remediate_probability,
        page_priority=args.page_priority,
        page_severity=args.page_severity,
        severity_weight=args.severity_weight,
        impact_weight=args.impact_weight,
        report_path=args.report,
        write_report=not args.no_report,
        json_output=args.json,
        fail_on=tuple(part.strip() for part in args.fail_on.split(",") if part.strip()),
        print_questions=args.print_questions,
        list_sources=args.list_sources,
        demo=args.demo,
    )


def run(cfg: Config, args: argparse.Namespace) -> int:
    started_at = datetime.now(timezone.utc)
    if cfg.print_questions:
        print(json.dumps(_to_jsonable(build_questions()), indent=2))
        return 0

    if cfg.list_sources:
        client = LokiClient(cfg.loki_url, cfg.loki_org_id, cfg.loki_timeout)
        namespaces = client.label_values("namespace")
        apps = client.label_values("app")
        if cfg.json_output:
            print(json.dumps({"namespaces": namespaces, "apps": apps}, indent=2))
        else:
            print("namespaces: " + ", ".join(namespaces))
            print("apps: " + ", ".join(apps))
        return 0

    if not SDK_AVAILABLE:
        raise SystemExit(
            "typesafe-sdk is not installed. Run: uv pip install typesafe-sdk"
        )
    cfg.api_key = load_api_key(args.api_key_file)
    window = resolve_window(cfg.since, cfg.until)
    query = "demo://fixtures" if cfg.demo else build_selector(cfg)

    port_forward: LokiPortForward | None = None
    try:
        if cfg.demo:
            streams = load_demo_streams()
        else:
            client = LokiClient(cfg.loki_url, cfg.loki_org_id, cfg.loki_timeout)
            if not client.ready():
                if args.port_forward:
                    port_forward = LokiPortForward(
                        namespace=args.port_forward_namespace,
                        service=args.port_forward_service,
                    )
                    port_forward.start()
                    client = LokiClient(
                        f"http://127.0.0.1:{port_forward.local_port}",
                        cfg.loki_org_id,
                        cfg.loki_timeout,
                    )
                else:
                    raise LokiError(
                        f"Loki is not reachable at {cfg.loki_url}. Start a port-forward "
                        "(scripts/loki-port-forward.sh) or pass --port-forward."
                    )
            streams = client.query_range(query, window[0], window[1], limit=cfg.loki_limit)
        if not streams:
            report = build_report(cfg, query, window, streams, [], [], [], {}, started_at)
            emit_report(cfg, report, quiet=args.quiet)
            return 0

        all_batches = build_batches(
            streams,
            cfg.group_by,
            cfg.max_lines_per_batch,
            cfg.max_chars_per_batch,
            cfg.exclude_apps,
        )
        skipped = max(0, len(all_batches) - cfg.max_batches)
        batches = all_batches[: cfg.max_batches]

        retry = RetryPolicy(max_retries=2, timeout=cfg.api_timeout)
        ts_client = TypeSafeClient(api_key=cfg.api_key, model=cfg.model, retry=retry, timeout=cfg.api_timeout)
        questions = build_questions()
        decisions: list[Decision] = []
        errors: list[dict[str, str]] = []
        usage_totals: Counter[str] = Counter()

        for index, batch in enumerate(batches, start=1):
            state = build_state(batch)
            if not args.quiet:
                print(
                    f"[{index}/{len(batches)}] {batch.source}: "
                    f"{batch.total_lines} lines / {batch.distinct_patterns} patterns",
                    file=sys.stderr,
                )
            try:
                response = ts_client.system_one(state=state, questions=questions)
                answers = dict(response.answers)
                usage = _to_jsonable(getattr(response, "usage", None)) or {}
                for key, value in (usage.items() if isinstance(usage, Mapping) else []):
                    if isinstance(value, (int, float)):
                        usage_totals[str(key)] += int(value)
                decisions.append(decide(batch, answers, state, cfg))
            except Exception as exc:  # noqa: BLE001 - report, don't lose the batch
                message = f"{type(exc).__name__}: {exc}"
                errors.append({"source": batch.source, "error": message})
                decisions.append(empty_error_decision(batch, state, message))

        report = build_report(
            cfg, query, window, streams, batches, decisions, errors,
            usage_totals, started_at, skipped,
        )
        emit_report(cfg, report, quiet=args.quiet)
        if cfg.fail_on:
            matched = [d.decision for d in decisions if d.decision in cfg.fail_on]
            if matched:
                if not args.quiet:
                    print(
                        f"fail-on matched: {', '.join(sorted(set(matched)))}",
                        file=sys.stderr,
                    )
                return 2
        if errors and len(errors) == len(decisions):
            return 1
        return 0
    finally:
        if port_forward:
            port_forward.stop()


def empty_error_decision(batch: Batch, state: dict[str, Any], message: str) -> Decision:
    return Decision(
        source=batch.source,
        decision="error",
        priority=0.0,
        severity=0.0,
        severity_confidence=0.0,
        impact=0.0,
        impact_confidence=0.0,
        category="unknown",
        category_confidence=0.0,
        needs_action=0.0,
        is_noise=0.0,
        auto_remediable=0.0,
        rationale=[f"analysis failed: {message}"],
        labels=batch.labels,
        answers={},
        state=state,
        error=message,
    )


def emit_report(cfg: Config, report: Mapping[str, Any], quiet: bool) -> None:
    if cfg.json_output:
        print(json.dumps(report, indent=2))
    elif not quiet:
        print(render_summary(report))

    if not cfg.write_report:
        return
    if cfg.report_path:
        target = Path(cfg.report_path)
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = Path("reports") / f"triage-{stamp}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not quiet and not cfg.json_output:
        print(f"report: {target}")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = cfg_from_args(args)
    try:
        return run(cfg, args)
    except LokiError as exc:
        print(f"loki error: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())