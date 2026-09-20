"""Console table and JSON report."""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from logtriage.batch import Batch, ns_to_iso
from logtriage.config import DECISION_RANK, DECISIONS, VERSION, Config
from logtriage.decide import Decision
from logtriage.serialize import to_jsonable

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
        confidence = min(item.get(f"{field}_confidence", 0) for field in ("severity", "impact", "category"))
        lines.append(
            f"{label} {item.get('severity', 0):>4.1f} {item.get('priority', 0):>5.2f} "
            f"{confidence:>5.2f} "
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
        "decisions": [to_jsonable(asdict(d)) for d in decisions],
        "errors": list(errors),
    }


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
