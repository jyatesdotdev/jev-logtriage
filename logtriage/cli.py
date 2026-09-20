"""CLI entry: parse args, fetch logs, ask jev, print a decision table."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from logtriage.batch import build_batches, build_state, load_demo_streams, normalize_level
from logtriage.cache import (
    AnswerCache,
    canonical_questions,
    canonical_state,
    default_cache_path,
    sha256_json,
)
from logtriage.config import DEFAULT_LOKI_URL, DEFAULT_MODEL, VERSION, Config
from logtriage.decide import SDK_AVAILABLE, Decision, build_questions, decide, empty_error_decision
from logtriage.loki import LokiClient, LokiError, LokiPortForward, build_selector
from logtriage.report import build_report, emit_report
from logtriage.serialize import to_jsonable

try:  # pragma: no cover
    from typesafe_sdk import RetryPolicy, TypeSafeClient
except ImportError:  # pragma: no cover
    RetryPolicy = None  # type: ignore[misc, assignment]
    TypeSafeClient = None  # type: ignore[misc, assignment]


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
        "./.typesafe (or pass --api-key-file)."
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="logtriage",
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

    cache = parser.add_argument_group("cache")
    cache.add_argument("--no-cache", action="store_true", help="do not read or write cached answers")
    cache.add_argument("--cache-db", help="SQLite path (default: ~/.cache/jev-logtriage/answers.sqlite3)")
    cache.add_argument("--cache-clear", action="store_true", help="delete cached answers at the start of the run")
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
        cache=not args.no_cache,
        cache_db=args.cache_db,
        cache_clear=args.cache_clear,
    )


def run(cfg: Config, args: argparse.Namespace) -> int:
    started_at = datetime.now(timezone.utc)
    cache: AnswerCache | None = None
    with ExitStack() as resources:
        if cfg.print_questions:
            print(json.dumps(to_jsonable(build_questions()), indent=2))
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

        if cfg.cache or cfg.cache_clear:
            try:
                cache = resources.enter_context(AnswerCache(cfg.cache_db or default_cache_path()))
                if cfg.cache_clear:
                    cache.clear()
                    if not args.quiet:
                        print("cache cleared", file=sys.stderr)
                if not cfg.cache:
                    cache = None
            except (OSError, sqlite3.Error) as exc:
                cache = None
                print(f"cache disabled: {exc}", file=sys.stderr)

        if not SDK_AVAILABLE:
            raise SystemExit(
                "typesafe-sdk is not installed. Run: uv pip install typesafe-sdk"
            )
        cfg.api_key = load_api_key(args.api_key_file)
        window = resolve_window(cfg.since, cfg.until)
        query = "demo://fixtures" if cfg.demo else build_selector(cfg)
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
                    resources.callback(port_forward.stop)
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
        resources.callback(ts_client.close)
        questions = build_questions()
        schema_hash = sha256_json(canonical_questions(questions)) if cache is not None else ""
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
                answers = None
                state_hash = ""
                if cache is not None:
                    state_hash = sha256_json(canonical_state(
                        batch, "demo://fixtures" if cfg.demo else cfg.loki_url,
                        None if cfg.demo else cfg.loki_org_id,
                    ))
                    try:
                        answers = cache.get(cfg.model, schema_hash, state_hash)
                    except sqlite3.Error as exc:
                        cache = None
                        print(f"cache disabled: {exc}", file=sys.stderr)
                fetched_from_api = answers is None
                if fetched_from_api:
                    response = ts_client.system_one(state=state, questions=questions)
                    answers = dict(response.answers)
                    usage = to_jsonable(getattr(response, "usage", None)) or {}
                    for key, value in (usage.items() if isinstance(usage, Mapping) else []):
                        if isinstance(value, (int, float)):
                            usage_totals[str(key)] += int(value)
                decision = decide(batch, answers, state, cfg)
                if fetched_from_api and cache is not None:
                    try:
                        cache.put(cfg.model, schema_hash, state_hash, decision.answers)
                    except sqlite3.Error as exc:
                        cache = None
                        print(f"cache disabled: {exc}", file=sys.stderr)
                decisions.append(decision)
            except Exception as exc:  # noqa: BLE001 - report, don't lose the batch
                message = f"{type(exc).__name__}: {exc}"
                errors.append({"source": batch.source, "error": message})
                decisions.append(empty_error_decision(batch, state, message))

        report = build_report(
            cfg, query, window, streams, batches, decisions, errors,
            usage_totals, started_at, skipped,
        )
        emit_report(cfg, report, quiet=args.quiet)
        if cache is not None and not args.quiet:
            print(f"cache hit {cache.hits}  miss {cache.misses}", file=sys.stderr)
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


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = cfg_from_args(args)
    try:
        return run(cfg, args)
    except LokiError as exc:
        print(f"loki error: {exc}", file=sys.stderr)
        return 1
    except (RuntimeError, argparse.ArgumentTypeError, OSError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
