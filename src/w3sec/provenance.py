from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class ProvenanceRef:
    source: str
    locator: str
    commit: str | None = None
    line_start: int | None = None
    line_end: int | None = None

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "ProvenanceRef":
        return cls(
            source=str(value["source"]),
            locator=str(value["locator"]),
            commit=value.get("commit"),
            line_start=value.get("line_start"),
            line_end=value.get("line_end"),
        )


def iter_provenance(record: dict[str, Any]) -> Iterable[ProvenanceRef]:
    values = record.get("provenance", [])
    if isinstance(values, dict):
        values = [values]
    if not isinstance(values, list):
        return
    for value in values:
        if isinstance(value, dict) and "source" in value and "locator" in value:
            yield ProvenanceRef.from_mapping(value)
