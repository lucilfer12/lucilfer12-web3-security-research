from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from .model import NodeRef, ResearchEvent, ResearchStage


def _canonical(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False) + "\n").encode("utf-8")


def event_hash(payload: dict[str, Any], previous_hash: str | None) -> str:
    body = dict(payload)
    body["previous_hash"] = previous_hash
    return hashlib.sha256(_canonical(body)).hexdigest()


def last_event_hash(path: Path) -> str | None:
    previous = None
    for event in iter_events(path):
        previous = event.get("event_hash")
    return previous
def append_event(path: Path, *, event_type: str, subject: NodeRef,
                 timestamp: str, actor: str,
                 stage: ResearchStage | None = None,
                 payload: dict[str, Any] | None = None) -> ResearchEvent:
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = last_event_hash(path)
    body = {
        "event_id": hashlib.sha256(
            f"{subject.key}|{event_type}|{timestamp}|{actor}".encode()
        ).hexdigest()[:16],
        "event_type": event_type,
        "subject": {"kind": subject.kind, "id": subject.id},
        "timestamp": timestamp,
        "actor": actor,
        "stage": stage.value if stage else None,
        "payload": payload or {},
        "previous_hash": previous,
    }
    body["event_hash"] = event_hash(body, previous)
    event = ResearchEvent(
        event_id=body["event_id"], event_type=event_type, subject=subject,
        timestamp=timestamp, actor=actor, stage=stage,
        payload=body["payload"], previous_hash=previous,
        event_hash=body["event_hash"],
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(event), sort_keys=True,
                                ensure_ascii=False) + "\n")
    return event
def iter_events(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: event must be an object")
            yield value


def verify_chain(path: Path) -> list[str]:
    errors = []
    previous = None
    for line_no, raw in enumerate(iter_events(path), 1):
        base = dict(raw)
        stored = base.pop("event_hash", None)
        if base.get("previous_hash") != previous:
            errors.append(f"{path}:{line_no}: previous_hash mismatch")
        if stored != event_hash(base, previous):
            errors.append(f"{path}:{line_no}: event_hash mismatch")
        previous = stored
    return errors
