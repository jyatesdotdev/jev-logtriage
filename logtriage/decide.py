"""TypeSafe questions and confidence-gated routing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from logtriage.batch import Batch
from logtriage.config import SAFE_AUTO_CATEGORIES, Config
from logtriage.serialize import to_jsonable

try:  # pragma: no cover
    from typesafe_sdk import Choice, Noul, Score

    SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    SDK_AVAILABLE = False


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
        answers={k: to_jsonable(v) for k, v in answers.items()},
        state=state,
    )


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
