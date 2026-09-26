from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ResearchStage(str, Enum):
    OBSERVED = "observed"
    MODELED = "modeled"
    FORMALIZED = "formalized"
    REPRODUCED = "reproduced"
    MEASURED = "measured"
    MITIGATED = "mitigated"
    REGRESSED = "regressed"
    GENERALIZED = "generalized"


STAGE_ORDER = (
    ResearchStage.OBSERVED,
    ResearchStage.MODELED,
    ResearchStage.FORMALIZED,
    ResearchStage.REPRODUCED,
    ResearchStage.MEASURED,
    ResearchStage.MITIGATED,
    ResearchStage.REGRESSED,
    ResearchStage.GENERALIZED,
)
@dataclass(frozen=True, slots=True)
class NodeRef:
    kind: str
    id: str

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.id}"

    @classmethod
    def parse(cls, value: str) -> "NodeRef":
        if ":" not in value:
            raise ValueError(f"node reference must be kind:id, got {value!r}")
        kind, node_id = value.split(":", 1)
        if not kind or not node_id:
            raise ValueError(f"invalid node reference {value!r}")
        return cls(kind, node_id)


@dataclass(frozen=True, slots=True)
class TimeContext:
    observed_at: str | None = None
    protocol_version: str | None = None
    commit: str | None = None
    block_height: int | None = None
    implementation_hash: str | None = None


@dataclass(frozen=True, slots=True)
class Evidence:
    id: str
    kind: str
    source: str
    locator: str
    commit: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    content_hash: str | None = None
@dataclass(frozen=True, slots=True)
class LineageEdge:
    source: NodeRef
    relation: str
    target: NodeRef
    evidence: tuple[str, ...] = ()
    valid_from: str | None = None
    valid_to: str | None = None


@dataclass(frozen=True, slots=True)
class ResearchSnapshot:
    subject: NodeRef
    stages: frozenset[ResearchStage] = frozenset()
    time: TimeContext = field(default_factory=TimeContext)
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def highest_stage(self) -> ResearchStage | None:
        return max(self.stages, key=STAGE_ORDER.index) if self.stages else None


def normalize_stages(values: Any) -> set[ResearchStage]:
    if values is None:
        return set()
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        raise ValueError("research stages must be a sequence")
    return {ResearchStage(value) for value in values}


def stage_gaps(values: Any) -> list[ResearchStage]:
    stages = normalize_stages(values)
    if not stages:
        return list(STAGE_ORDER)
    highest = max(STAGE_ORDER.index(stage) for stage in stages)
    return [stage for stage in STAGE_ORDER[:highest + 1] if stage not in stages]


@dataclass(frozen=True, slots=True)
class ResearchEvent:
    event_id: str
    event_type: str
    subject: NodeRef
    timestamp: str
    actor: str
    stage: ResearchStage | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    previous_hash: str | None = None
    event_hash: str | None = None
