"""Loki HTTP client, optional kubectl port-forward, and LogQL selectors."""

from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping, Sequence

from logtriage.config import Config


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


def regex_alternation(values: Sequence[str]) -> str:
    escaped = [re.escape(v) for v in values if v]
    if not escaped:
        return ".+"
    return "|".join(escaped)
