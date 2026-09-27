from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .federation import normalized_candidate_records
from .records import discover_case_records, load_yaml_mapping


@dataclass(frozen=True)
class PromotionStep:
    name: str
    description: str
    required: tuple[str, ...]


PROMOTION_STEPS = (
    PromotionStep("candidate", "A stated pattern hypothesis linked to a case.", ("statement", "case")),
    PromotionStep("observed", "The pattern has directly cited observation/evidence.", ("observation_or_evidence",)),
    PromotionStep("reproduced", "The failure or security property is reproduced.", ("reproduction",)),
    PromotionStep("corroborated", "Independent cases or sources corroborate the pattern.", ("cross_case",)),
    PromotionStep("generalized", "Scope and boundary conditions are explicit across protocols.", ("scope", "cross_protocol", "counterexample_analysis")),
    PromotionStep("pattern", "A named pattern is represented as a first-class registry object.", ("pattern_record",)),
    PromotionStep("validated-pattern", "Independent reproduction, passed regression, and negative-evidence review exist.", ("independent_reproduction", "regression_passed", "negative_evidence")),
)


def _registry(root: Path, stem: str, key: str) -> list[dict[str, Any]]:
    path = root / "corpus" / "knowledge" / f"{stem}.yaml"
    if not path.exists():
        return []
    value = load_yaml_mapping(path).get(key, [])
    return value if isinstance(value, list) else []


def _cases(root: Path) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("id")): item
        for _, item in discover_case_records(root)
        if item.get("id")
    }


def _case_protocols(case: dict[str, Any]) -> set[str]:
    values = case.get("protocols", []) or []
    return {str(value) for value in values if value}


def _has_regression_passed(case_ids: set[str], regressions: list[dict[str, Any]]) -> bool:
    return any(
        str(item.get("case")) in case_ids and str(item.get("status")).lower() in {"passed", "verified", "green"}
        for item in regressions
    )


def _has_negative_evidence(pattern_id: str, negatives: list[dict[str, Any]]) -> bool:
    return any(
        pattern_id in {str(x) for x in item.get("patterns", []) or []}
        and str(item.get("status", "")).lower() in {"reviewed", "completed", "negative"}
        for item in negatives
    )


def evaluate_pattern(root: Path, pattern: dict[str, Any]) -> dict[str, Any]:
    cases = _cases(root)
    regressions = _registry(root, "regressions", "regressions")
    negatives = _registry(root, "negative_results", "negative_results")
    observations = _registry(root, "observations", "observations")
    experiments = _registry(root, "experiments", "experiments")
    counterexamples = _registry(root, "counterexamples", "counterexamples")
    external = normalized_candidate_records(root)

    pattern_id = str(pattern.get("id"))
    case_ids = {str(x) for x in pattern.get("cases", []) or [] if x in cases}
    linked_patterns = [p for p in _registry(root, "patterns", "patterns") if p.get("id") == pattern_id]
    direct_observations = [
        item for item in observations
        if pattern_id in {str(x) for x in item.get("patterns", []) or []}
    ]
    direct_experiments = [
        item for item in experiments
        if pattern_id in {str(x) for x in item.get("patterns", []) or []}
        and str(item.get("status", "")).lower() in {"passed", "completed", "reproduced"}
    ]
    direct_counterexamples = [
        item for item in counterexamples
        if pattern_id in {str(x) for x in item.get("patterns", []) or []}
    ]
    external_corrob = [
        item for item in external
        if pattern_id in {str(x) for x in item.get("candidate_pattern_links", [])}
    ]

    protocols = set()
    for case_id in case_ids:
        protocols |= _case_protocols(cases[case_id])
    independent_sources = {
        str(item.get("source"))
        for item in external_corrob
        if item.get("source")
    }
    criteria = {
        "statement": bool(pattern.get("statement")),
        "case": bool(case_ids),
        "observation_or_evidence": bool(
            direct_observations
            or any(cases[c].get("evidence") for c in case_ids)
        ),
        "reproduction": bool(
            direct_experiments
            or any("reproduced" in {str(s) for s in cases[c].get("stages", []) or []} for c in case_ids)
        ),
        "cross_case": len(case_ids) >= 2,
        "scope": bool(pattern.get("scope")),
        "cross_protocol": len(protocols) >= 2,
        "counterexample_analysis": bool(direct_counterexamples) and (
            bool(pattern.get("boundary_conditions")) or bool(pattern.get("limitations"))
        ),
        "pattern_record": bool(linked_patterns),
        "independent_reproduction": bool(pattern.get("independent_reproduction")) or len(direct_experiments) >= 2,
        "regression_passed": _has_regression_passed(case_ids, regressions),
        "negative_evidence": _has_negative_evidence(pattern_id, negatives),
    }

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
    for candidate_stage, requirements in gate_map.items():
        if all(criteria[name] for name in requirements):
            stage = candidate_stage
        else:
            break
    stage_index = [step.name for step in PROMOTION_STEPS].index(stage)
    if stage_index + 1 < len(PROMOTION_STEPS):
        next_stage = PROMOTION_STEPS[stage_index + 1]
        missing = [name for name in next_stage.required if not criteria[name]]
    else:
        missing = []


    return {
        "pattern": pattern_id,
        "declared_status": pattern.get("status"),
        "computed_stage": stage,
        "criteria": criteria,
        "missing_requirements": missing,
        "case_count": len(case_ids),
        "protocol_count": len(protocols),
        "external_corroborating_sources": sorted(independent_sources),
        "decision": "promote" if stage == "validated-pattern" else "hold",
        "reason": "All promotion gates are satisfied." if stage == "validated-pattern" else "One or more promotion gates remain unsatisfied.",
    }


def build_promotion_engine(root: Path) -> dict[str, Any]:
    patterns = _registry(root, "patterns", "patterns")
    decisions = [evaluate_pattern(root, pattern) for pattern in patterns]
    return {
        "schema_version": 2,
        "engine": "explicit-state-machine",
        "state_machine": [
            {
                "stage": step.name,
                "description": step.description,
                "requirements": list(step.required),
            }
            for step in PROMOTION_STEPS
        ],
        "decisions": decisions,
        "promotable_count": sum(item["decision"] == "promote" for item in decisions),
        "blocked_count": sum(item["decision"] == "hold" for item in decisions),
        "auto_mutation": False,
        "policy": "The engine computes eligibility but never rewrites canonical status without an explicit research event.",
    }


def write_promotion_report(root: Path, output: Path | None = None) -> Path:
    target = output or root / "reports" / "longitudinal" / "promotion-decisions.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_promotion_engine(root), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


__all__ = ["PROMOTION_STEPS", "evaluate_pattern", "build_promotion_engine", "write_promotion_report"]
