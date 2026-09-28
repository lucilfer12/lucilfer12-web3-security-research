from __future__ import annotations

import hashlib
import json
from typing import Any

FABRIC_SCHEMA_VERSION = 1
EVIDENCE_ORDER = (
    "target", "revision", "threat_model", "invariant", "signal", "candidate",
    "reproduction", "trace", "state_delta", "economic_impact",
    "independent_verification", "validated_finding", "patch", "regression_proof",
)
PREREQUISITES = {
    "revision": ("target",), "threat_model": ("revision",),
    "invariant": ("threat_model",), "signal": ("invariant",),
    "candidate": ("signal",), "reproduction": ("candidate",),
    "trace": ("reproduction",), "state_delta": ("trace",),
    "economic_impact": ("state_delta",),
    "independent_verification": ("economic_impact",),
    "validated_finding": ("independent_verification",),
    "patch": ("validated_finding",), "regression_proof": ("patch",),
}

def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")

def evidence_digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()

def validate_evidence_chain(evidence: dict[str, Any]) -> dict[str, Any]:
    present = {stage for stage in EVIDENCE_ORDER if evidence.get(stage) not in (None, False, "", [], {})}
    gaps: list[str] = []
    highest = None
    for stage in EVIDENCE_ORDER:
        if stage not in present:
            break
        missing = [item for item in PREREQUISITES.get(stage, ()) if item not in present]
        if missing:
            gaps.extend(f"{stage} requires {item}" for item in missing)
            break
        highest = stage
    allowed = "validated_finding" in present and "independent_verification" in present and not gaps
    if "validated_finding" in present and not allowed:
        gaps.append("validated_finding requires independent_verification")
    return {
        "schema_version": FABRIC_SCHEMA_VERSION,
        "highest_proven_stage": highest,
        "allowed_validated": allowed,
        "gaps": sorted(set(gaps)),
        "digest": evidence_digest(evidence),
    }

def build_evidence_fabric(findings: list[dict[str, Any]]) -> dict[str, Any]:
    chains = []
    validated = 0
    for finding in findings:
        chain = dict(finding.get("evidence_chain") or {})
        for key in EVIDENCE_ORDER:
            if key in finding and key not in chain:
                chain[key] = finding[key]
        value = validate_evidence_chain(chain)
        item = {
            "finding_id": str(finding.get("id", "")),
            "highest_proven_stage": value["highest_proven_stage"],
            "validated": value["allowed_validated"],
            "gaps": value["gaps"],
            "digest": value["digest"],
        }
        chains.append(item)
        validated += int(item["validated"])
    return {
        "schema_version": FABRIC_SCHEMA_VERSION,
        "finding_count": len(chains),
        "validated_count": validated,
        "research_debt_count": len(chains) - validated,
        "chains": chains,
    }
