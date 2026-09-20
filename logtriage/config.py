"""CLI and decision configuration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

VERSION = "0.1.0"
DEFAULT_LOKI_URL = "http://127.0.0.1:3100"
DEFAULT_MODEL = "jev-latest"

DECISIONS = (
    "suppress",
    "watch",
    "review",
    "notify",
    "auto_remediate_candidate",
    "page",
)
DECISION_RANK = {name: i for i, name in enumerate(DECISIONS)}

SAFE_AUTO_CATEGORIES = {"app_error", "resource", "config", "expected_noise"}


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
