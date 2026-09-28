from __future__ import annotations

from pathlib import Path
from typing import Any

from .promotion import PROMOTION_STEPS, build_promotion_engine as _legacy_engine
from .records import load_yaml_mapping
from .regression_evidence import regression_passed_for


def _registry(root: Path, stem: str, key: str) -> list[dict[str, Any]]:
    path = root / "corpus" / "knowledge" / f"{stem}.yaml"
    if not path.exists():
        return []
    value = load_yaml_mapping(path).get(key, [])
    return value if isinstance(value, list) else []


def _case_ids(root: Path, pattern_id: str) -> set[str]:
    for pattern in _registry(root, "patterns", "patterns"):
        if str(pattern.get("id")) == pattern_id:
            return {str(x) for x in pattern.get("cases", []) or []}
    return set()


def _recompute(decision: dict[str, Any], root: Path) -> dict[str, Any]:
    pattern_id = str(decision["pattern"])
    case_ids = _case_ids(root, pattern_id)
    evidence = regression_passed_for(case_ids, pattern_id, root)
    structured_pass = any(bool(item["validation"]["passed"]) for item in evidence)
    criteria = dict(decision["criteria"])
    criteria["regression_passed"] = structured_pass
    gate_map = {
        "candidate": ("statement", "case"),
        "observed": ("observation_or_evidence",),
        "reproduced": ("reproduction",),
        "corroborated": ("cross_case",),
        "generalized": ("scope", "cross_protocol", "counterexample_analysis"),
        "pattern": ("pattern_record",),
        "validated-pattern": ("independent_reproduction", "regression_passed", "negative_evidence"),
    }
    stage = "candidate"
    for candidate, requirements in gate_map.items():
        if all(criteria[name] for name in requirements):
            stage = candidate
        else:
            break
    index = [step.name for step in PROMOTION_STEPS].index(stage)
    missing = [] if index + 1 >= len(PROMOTION_STEPS) else [x for x in PROMOTION_STEPS[index + 1].required if not criteria[x]]
    updated = dict(decision)
    updated["criteria"] = criteria
    updated["computed_stage"] = stage
    updated["missing_requirements"] = missing
    updated["decision"] = "promote" if stage == "validated-pattern" else "hold"
    updated["reason"] = "All promotion gates are satisfied." if stage == "validated-pattern" else "One or more promotion gates remain unsatisfied."
    updated["regression_evidence_count"] = len(evidence)
    updated["regression_passed_evidence_ids"] = [x["evidence_id"] for x in evidence if x["validation"]["passed"]]
    return updated
def build_promotion_engine(root: Path) -> dict[str, Any]:
    legacy = _legacy_engine(root)
    decisions = [_recompute(item, root) for item in legacy["decisions"]]
    return {
        **legacy,
        "schema_version": 3,
        "engine": "explicit-state-machine-evidence-gated",
        "decisions": decisions,
        "promotable_count": sum(item["decision"] == "promote" for item in decisions),
        "blocked_count": sum(item["decision"] == "hold" for item in decisions),
        "regression_policy": "Only structured regression evidence can satisfy regression_passed; registry status alone is not proof.",
    }


def write_promotion_report(root: Path, output: Path | None = None) -> Path:
    import json
    target = output or root / "reports" / "longitudinal" / "promotion-decisions.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_promotion_engine(root), indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return target


__all__ = ["build_promotion_engine", "write_promotion_report"]
