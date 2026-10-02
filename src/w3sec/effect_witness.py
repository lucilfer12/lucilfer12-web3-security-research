from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

EFFECT_PREFIX = "ATLAS-EFFECT:"


@dataclass(frozen=True, slots=True)
class EffectWitness:
    payload: dict[str, Any]
    raw: str

    def get(self, path: str, default: Any = None) -> Any:
        value: Any = self.payload
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                return default
            value = value[part]
        return value


def extract_effect_witness(stdout: str, stderr: str) -> EffectWitness | None:
    """Extract the last machine-readable ATLAS-EFFECT witness from a run."""
    candidate: EffectWitness | None = None
    for line in (f"{stdout}\n{stderr}").splitlines():
        normalized = line.strip()
        if not normalized.startswith(EFFECT_PREFIX):
            continue
        raw = normalized[len(EFFECT_PREFIX):].strip()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            candidate = EffectWitness(payload, raw)
    return candidate


def validate_effect_witness(
    witness: EffectWitness | None,
    required: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    """Validate required dotted-path values without guessing missing evidence."""
    if witness is None:
        return False, ["effect_witness_missing"]
    missing: list[str] = []
    for path, expected in (required or {}).items():
        actual = witness.get(path, object())
        if actual != expected:
            missing.append(path)
    return not missing, missing


def compare_effects(
    vulnerable: EffectWitness | None,
    fixed: EffectWitness | None,
    *,
    vulnerable_required: dict[str, Any] | None = None,
    fixed_required: dict[str, Any] | None = None,
) -> dict[str, Any]:
    vok, vmissing = validate_effect_witness(vulnerable, vulnerable_required)
    fok, fmissing = validate_effect_witness(fixed, fixed_required)
    return {
        "vulnerable_present": vulnerable is not None,
        "fixed_present": fixed is not None,
        "vulnerable_valid": vok,
        "fixed_valid": fok,
        "vulnerable_missing": vmissing,
        "fixed_missing": fmissing,
        "vulnerable": vulnerable.payload if vulnerable else None,
        "fixed": fixed.payload if fixed else None,
        "policy": "Effect witnesses are assertions emitted by the reproducer; missing or mismatched fields never count as proof.",
    }


__all__ = [
    "EFFECT_PREFIX",
    "EffectWitness",
    "extract_effect_witness",
    "validate_effect_witness",
    "compare_effects",
]
