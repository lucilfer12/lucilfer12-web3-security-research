from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class GateResult:
    status: str
    gates: dict[str, bool]
    missing: tuple[str, ...]
    evidence_grade: str

    @property
    def validated(self) -> bool:
        return self.status in {"validated", "validated-regressed"}


_REQUIREMENTS = (
    "source_pinned",
    "security_property",
    "reproduction",
    "impact",
    "independent_verification",
)


def _truth(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {
        "1", "true", "yes", "passed", "verified", "reproduced", "measured", "complete",
    }


def evaluate_finding(finding: dict[str, Any]) -> GateResult:
    """Derive finding status exclusively from evidence fields.

    A detector may supply signals and severity, but those fields never satisfy
    reproduction, impact, or independent verification by themselves.
    """
    verification = finding.get("verification")
    verification = verification if isinstance(verification, dict) else {}

    source_pinned = bool(
        verification.get("source_pinned")
        or (
            finding.get("file")
            and finding.get("line")
            and (
                finding.get("commit")
                or finding.get("source_hash")
                or finding.get("target_revision")
            )
        )
    )
    security_property = bool(
        verification.get("security_property")
        or finding.get("security_property")
    )
    reproduction = _truth(verification.get("reproduction")) or _truth(
        finding.get("reproduction_status")
    )
    impact = _truth(verification.get("impact")) or _truth(
        finding.get("impact_status")
    )
    independent = _truth(
        verification.get("independent_verification")
    ) or _truth(finding.get("independent_verification"))
    regression = _truth(
        verification.get("regression")
    ) or _truth(finding.get("regression_status"))

    gates = {
        "source_pinned": source_pinned,
        "security_property": security_property,
        "reproduction": reproduction,
        "impact": impact,
        "independent_verification": independent,
        "regression": regression,
    }
    missing = tuple(name for name in _REQUIREMENTS if not gates[name])
    if all(gates[name] for name in _REQUIREMENTS):
        status = "validated-regressed" if regression else "validated"
    elif reproduction:
        status = "reproduced"
    elif source_pinned and security_property:
        status = "observed"
    else:
        status = "candidate"
    satisfied = sum(gates.values())
    evidence_grade = ("A" if status == "validated-regressed" else
                      "B" if status == "validated" else
                      "C" if status == "reproduced" else
                      "D" if satisfied >= 2 else "E")
    return GateResult(status, gates, missing, evidence_grade)



def attach_gate(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with a machine-derived verification block."""
    result = evaluate_finding(finding)
    copy = dict(finding)
    copy["status"] = result.status
    copy["verification"] = {
        **(finding.get("verification") if isinstance(finding.get("verification"), dict) else {}),
        "derived_status": result.status,
        "gates": result.gates,
        "missing": list(result.missing),
        "evidence_grade": result.evidence_grade,
        "authority": "evidence-derived",
    }
    return copy


def gate_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    results = [evaluate_finding(item) for item in findings]
    counts = {
        "candidate": 0,
        "observed": 0,
        "reproduced": 0,
        "validated": 0,
        "validated-regressed": 0,
    }
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    return {
        "finding_count": len(results),
        "status_counts": counts,
        "validated_count": counts["validated"] + counts["validated-regressed"],
        "regressed_validated_count": counts["validated-regressed"],
        "policy": "Scanner signals never promote a finding; validation is derived from explicit evidence gates.",
    }


__all__ = ["GateResult", "evaluate_finding", "attach_gate", "gate_summary"]
