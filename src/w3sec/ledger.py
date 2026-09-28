from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from datetime import datetime
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


def _validate_timestamp(value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("event timestamp must be a non-empty ISO-8601 string")
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid event timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError("event timestamp must include an explicit timezone")


def _validate_event_shape(event: dict[str, Any]) -> None:
    required = {"event_id", "event_type", "subject", "timestamp", "actor", "payload", "previous_hash", "event_hash"}
    missing = sorted(required - set(event))
    if missing:
        raise ValueError(f"missing event fields: {', '.join(missing)}")
    if not re.fullmatch(r"[0-9a-f]{16}", str(event["event_id"])):
        raise ValueError("event_id must be a 16-character lowercase hex identifier")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", str(event["event_type"])):
        raise ValueError("event_type contains unsupported characters")
    if not str(event["actor"]).strip():
        raise ValueError("event actor must be non-empty")
    if not isinstance(event["subject"], dict) or not event["subject"].get("kind") or not event["subject"].get("id"):
        raise ValueError("event subject must contain kind and id")
    if not isinstance(event["payload"], dict):
        raise ValueError("event payload must be a mapping")
    _validate_timestamp(str(event["timestamp"]))
    previous = event["previous_hash"]
    if previous is not None and not re.fullmatch(r"[0-9a-f]{64}", str(previous)):
        raise ValueError("previous_hash must be null or a SHA-256 digest")
    digest = event["event_hash"]
    if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
        raise ValueError("event_hash must be a SHA-256 digest")


def last_event_hash(path: Path) -> str | None:
    previous = None
    for event in iter_events(path):
        previous = event.get("event_hash")
    return previous
def append_event(path: Path, *, event_type: str, subject: NodeRef,
                 timestamp: str, actor: str,
                 stage: ResearchStage | None = None,
                 payload: dict[str, Any] | None = None) -> ResearchEvent:
    _validate_timestamp(timestamp)
    if not str(actor).strip():
        raise ValueError("actor must be non-empty")
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
    seen_ids: set[str] = set()
    try:
        events = iter_events(path)
        for line_no, raw in enumerate(events, 1):
            try:
                _validate_event_shape(raw)
            except ValueError as exc:
                errors.append(f"{path}:{line_no}: {exc}")
                continue
            event_id = str(raw["event_id"])
            if event_id in seen_ids:
                errors.append(f"{path}:{line_no}: duplicate event_id {event_id}")
            seen_ids.add(event_id)
            base = dict(raw)
            stored = base.pop("event_hash", None)
            if base.get("previous_hash") != previous:
                errors.append(f"{path}:{line_no}: previous_hash mismatch")
            if stored != event_hash(base, previous):
                errors.append(f"{path}:{line_no}: event_hash mismatch")
            previous = stored
    except ValueError as exc:
        errors.append(str(exc))
    return errors
