"""JSON-friendly conversion for API models and dataclasses."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Mapping


def to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return to_jsonable(dump())
    if hasattr(value, "__dataclass_fields__"):
        return to_jsonable(asdict(value))
    return str(value)
