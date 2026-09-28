from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .intake import OperationCancelled

RUN_SCHEMA_VERSION = 1
RUN_STAGES = (
    "validate_repository", "verify_ledger", "knowledge_graph", "coverage",
    "federation", "versions", "promotion", "research_intelligence", "assemble_result",
)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str) + "\n").encode("utf-8")

def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()

def _atomic_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    os.replace(tmp, path)

def _new_run_id() -> str:
    return secrets.token_hex(12)

@dataclass
class ResearchRun:
    root: Path
    run_id: str
    state: dict[str, Any]

    @property
    def directory(self) -> Path:
        return self.root / "runs" / self.run_id

    @property
    def state_path(self) -> Path:
        return self.directory / "state.json"

    @property
    def events_path(self) -> Path:
        return self.directory / "events.jsonl"

    @classmethod
    def start(cls, root: Path, *, kind: str = "repository-audit", run_id: str | None = None) -> "ResearchRun":
        root = root.expanduser().resolve()
        rid = run_id or _new_run_id()
        directory = root / "runs" / rid
        if directory.exists():
            raise FileExistsError(f"research run already exists: {rid}")
        state = {
            "schema_version": RUN_SCHEMA_VERSION, "run_id": rid, "kind": kind,
            "status": "running", "created_at": _now(), "updated_at": _now(),
            "root": str(root), "stages": {}, "last_completed_stage": None,
            "result": None, "failure": None, "cancelled": False,
            "event_count": 0, "event_hash": None,
        }
        run = cls(root, rid, state)
        run._persist()
        run._event("run-started", payload={"kind": kind})
        run._persist()
        return run

    @classmethod
    def load(cls, root: Path, run_id: str) -> "ResearchRun":
        root = root.expanduser().resolve()
        path = root / "runs" / run_id / "state.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema_version") != RUN_SCHEMA_VERSION or data.get("run_id") != run_id:
            raise ValueError("invalid research run state")
        return cls(root, run_id, data)

    @classmethod
    def resumable(cls, root: Path) -> list["ResearchRun"]:
        base = root.expanduser().resolve() / "runs"
        if not base.exists():
            return []
        result = []
        for path in sorted(base.glob("*/state.json")):
            try:
                run = cls.load(root, path.parent.name)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if run.state.get("status") in {"running", "failed", "cancelled"}:
                result.append(run)
        return sorted(result, key=lambda item: str(item.state.get("updated_at", "")), reverse=True)

    def _persist(self) -> None:
        self.state["updated_at"] = _now()
        _atomic_write(self.state_path, self.state)

    def _event(self, event_type: str, *, stage: str | None = None, payload: Any = None) -> None:
        body = {
            "sequence": int(self.state.get("event_count", 0)) + 1,
            "timestamp": _now(), "run_id": self.run_id, "event_type": event_type,
            "stage": stage, "payload": payload, "previous_hash": self.state.get("event_hash"),
        }
        body["event_hash"] = _digest(body)
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(body, sort_keys=True, ensure_ascii=False, default=str) + "\n")
        self.state["event_count"] = body["sequence"]
        self.state["event_hash"] = body["event_hash"]

    def begin_stage(self, stage: str) -> None:
        if stage not in RUN_STAGES:
            raise ValueError(f"unknown research run stage: {stage}")
        self._check_status()
        if self.is_completed(stage):
            return
        self.state["stages"][stage] = {
            "status": "running", "started_at": _now(), "payload": None, "digest": None,
        }
        self._event("stage-started", stage=stage)
        self._persist()

    def checkpoint(self, stage: str, payload: Any) -> None:
        if stage not in RUN_STAGES:
            raise ValueError(f"unknown research run stage: {stage}")
        record = {"status": "completed", "completed_at": _now(), "payload": payload, "digest": _digest(payload)}
        self.state["stages"][stage] = record
        self.state["last_completed_stage"] = stage
        self._event("stage-checkpoint", stage=stage, payload={"digest": record["digest"]})
        self._persist()

    def is_completed(self, stage: str) -> bool:
        return self.state.get("stages", {}).get(stage, {}).get("status") == "completed"

    def result(self, stage: str) -> Any:
        return self.state.get("stages", {}).get(stage, {}).get("payload")

    def check_cancelled(self, cancel: Callable[[], bool] | None = None) -> None:
        if self.state.get("cancelled") or (cancel and cancel()):
            self.cancel()
            raise OperationCancelled(f"ATLAS research run {self.run_id} cancelled")

    def complete(self, result: dict[str, Any]) -> None:
        self.state["status"] = "completed"
        self.state["result"] = result
        self.state["cancelled"] = False
        self._event("run-completed", payload={"result_digest": _digest(result)})
        self._persist()

    def fail(self, error: BaseException) -> None:
        self.state["status"] = "failed"
        self.state["failure"] = {"type": type(error).__name__, "message": str(error)}
        self._event("run-failed", payload=self.state["failure"])
        self._persist()

    def cancel(self) -> None:
        if self.state.get("status") == "completed":
            return
        self.state["cancelled"] = True
        self.state["status"] = "cancelled"
        self._event("run-cancelled")
        self._persist()

    def resume(self) -> None:
        self.state["status"] = "running"
        self.state["cancelled"] = False
        self.state["failure"] = None
        self._event("run-resumed")
        self._persist()

    def _check_status(self) -> None:
        if self.state.get("status") == "completed":
            raise RuntimeError(f"research run {self.run_id} is already completed")
        if self.state.get("status") == "cancelled":
            raise OperationCancelled(f"ATLAS research run {self.run_id} is cancelled")

def resume_audit_run(root: Path, run_id: str, progress=None, cancel=None) -> dict[str, Any]:
    from .audit import audit_repo
    run = ResearchRun.load(root, run_id)
    run.resume()
    return audit_repo(root, progress=progress, cancel=cancel, run=run)
