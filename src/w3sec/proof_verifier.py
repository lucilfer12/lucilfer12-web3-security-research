from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .verification import VerificationResult, run_verification

PROOF_MARKER_PREFIX = "ATLAS-PROOF:"
PROOF_MARKER_SUFFIX = ":TARGET-ENGAGED"


def proof_marker(finding_id: str, challenge: str) -> str:
    return f"{PROOF_MARKER_PREFIX}{finding_id}:{challenge}{PROOF_MARKER_SUFFIX}"


@dataclass(frozen=True, slots=True)
class ProofVerificationResult:
    finding_id: str
    outcome: str
    security_property: str
    marker: str
    vulnerable: VerificationResult
    fixed: VerificationResult
    vulnerable_expected_exit: int
    fixed_expected_exit: int
    vulnerable_marker_present: bool
    fixed_marker_present: bool
    vulnerable_baseline_healthy: bool
    fixed_baseline_healthy: bool
    reproducer_hash: str
    fixed_target_hash: str
    fixed_target_hash_claim: str | None
    source_states_differ: bool
    duration_seconds: float

    @property
    def confirmed(self) -> bool:
        return self.outcome == "confirmed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "outcome": self.outcome,
            "security_property": self.security_property,
            "marker": self.marker,
            "vulnerable_expected_exit": self.vulnerable_expected_exit,
            "fixed_expected_exit": self.fixed_expected_exit,
            "vulnerable_marker_present": self.vulnerable_marker_present,
            "fixed_marker_present": self.fixed_marker_present,
            "vulnerable_baseline_healthy": self.vulnerable_baseline_healthy,
            "fixed_baseline_healthy": self.fixed_baseline_healthy,
            "reproducer_hash": self.reproducer_hash,
            "fixed_target_hash": self.fixed_target_hash,
            "fixed_target_hash_claim": self.fixed_target_hash_claim,
            "fixed_target_hash_match": (
                None
                if not self.fixed_target_hash_claim
                else self.fixed_target_hash == self.fixed_target_hash_claim
            ),
            "source_states_differ": self.source_states_differ,
            "duration_seconds": round(self.duration_seconds, 6),
            "vulnerable": self.vulnerable.as_dict(),
            "fixed": self.fixed.as_dict(),
            "proof_policy": (
                "confirmed only when the same reproducer executes tests on both source states, "
                "both baselines are healthy, the target-engagement marker appears in both runs, "
                "and the vulnerable/fixed exit expectations are both satisfied"
            ),
        }
def _file_hash(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _target_hash(path: Path) -> str:
    from .verification import target_source_hash, target_input_hash

    source = target_source_hash(path)
    return source or target_input_hash(path)


def _marker_present(result: VerificationResult, marker: str) -> bool:
    return marker in f"{result.stdout}\n{result.stderr}"


def _binding_ok(result: VerificationResult) -> bool:
    data = result.as_dict()
    binding = data.get("binding", {})
    execution = data.get("test_execution", {})
    return (
        binding.get("workspace_unchanged") is True
        and binding.get("target_input_unchanged") is True
        and binding.get("target_input_hash_present") is True
        and binding.get("source_hash_match") is not False
        and execution.get("tests_executed") is True
    )


def run_proof_verification(
    target: Path,
    fixed_target: Path,
    finding: dict[str, Any],
    command: Sequence[str],
    *,
    vulnerable_expected_exit: int,
    fixed_expected_exit: int = 0,
    baseline_expected_exit: int = 0,
    security_property: str = "",
    reproducer: Path | None = None,
    baseline_command: Sequence[str] | None = None,
    timeout_seconds: int = 300,
    max_output_bytes: int = 4 * 1024 * 1024,
    fixed_target_hash_claim: str | None = None,
    trusted_target_code: bool = False,
) -> ProofVerificationResult:
    started = time.perf_counter()
    target = target.expanduser().resolve()
    fixed_target = fixed_target.expanduser().resolve()
    reproducer = reproducer.expanduser().resolve() if reproducer is not None else None
    if not target.exists() or not fixed_target.exists():
        raise FileNotFoundError("Both vulnerable and fixed targets must exist.")
    if reproducer is None or not reproducer.exists():
        raise FileNotFoundError("A reproducer is required for proof-grade verification.")
    security_property = security_property.strip()
    if not security_property:
        raise ValueError("A security property is required for proof-grade verification.")
    finding_id = str(finding.get("id") or "unknown")
    reproducer_hash = _file_hash(reproducer)
    challenge = secrets.token_hex(16)
    marker = proof_marker(finding_id, challenge)
    proof_env = {
        "ATLAS_PROOF_MARKER": marker,
        "ATLAS_PROOF_REPRODUCER_SHA256": reproducer_hash,
    }
    vulnerable = run_verification(
        target,
        finding,
        command,
        expected_exit=vulnerable_expected_exit,
        mode="reproduction",
        baseline_expected_exit=baseline_expected_exit,
        security_property=security_property,
        reproducer=reproducer,
        baseline_command=baseline_command,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        extra_env=proof_env,
        trusted_target_code=trusted_target_code,
    )
    fixed_finding = dict(finding)
    fixed_finding.pop("source_hash", None)
    fixed_finding.pop("target_input_sha256", None)
    fixed = run_verification(
        fixed_target,
        fixed_finding,
        command,
        expected_exit=fixed_expected_exit,
        mode="reproduction",
        baseline_expected_exit=baseline_expected_exit,
        security_property=security_property,
        reproducer=reproducer,
        baseline_command=baseline_command,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        extra_env=proof_env,
        trusted_target_code=trusted_target_code,
    )
    fixed_marker = _marker_present(fixed, marker)
    vulnerable_target_hash = _target_hash(target)
    actual_fixed_hash = _target_hash(fixed_target)
    source_states_differ = vulnerable_target_hash != actual_fixed_hash
    if not source_states_differ:
        raise ValueError(
            "Proof verification requires distinct vulnerable and fixed source states."
        )
    if fixed_target_hash_claim and actual_fixed_hash != fixed_target_hash_claim:
        raise ValueError("Fixed target binding mismatch: supplied fixed hash does not match the fixed target.")
    vulnerable_marker = _marker_present(vulnerable, marker)
    vulnerable_baseline_healthy = bool(vulnerable.baseline and vulnerable.baseline.get("healthy"))
    fixed_baseline_healthy = bool(fixed.baseline and fixed.baseline.get("healthy"))
    vulnerable_ok = (
        vulnerable.returncode == vulnerable_expected_exit
        and not vulnerable.timed_out
        and not vulnerable.output_limited
        and vulnerable_marker
        and vulnerable_baseline_healthy
        and _binding_ok(vulnerable)
    )
    fixed_hash_ok = not fixed_target_hash_claim or actual_fixed_hash == fixed_target_hash_claim
    fixed_ok = (
        fixed.returncode == fixed_expected_exit
        and not fixed.timed_out
        and not fixed.output_limited
        and fixed_marker
        and fixed_baseline_healthy
        and fixed_hash_ok
        and _binding_ok(fixed)
    )
    if vulnerable_ok and fixed_ok:
        outcome = "confirmed"
    elif vulnerable.outcome == "inconclusive" or fixed.outcome == "inconclusive":
        outcome = "inconclusive"
    else:
        outcome = "not-confirmed"
    return ProofVerificationResult(
        finding_id=finding_id,
        outcome=outcome,
        security_property=security_property,
        marker=marker,
        vulnerable=vulnerable,
        fixed=fixed,
        vulnerable_expected_exit=vulnerable_expected_exit,
        fixed_expected_exit=fixed_expected_exit,
        vulnerable_marker_present=vulnerable_marker,
        fixed_marker_present=fixed_marker,
        vulnerable_baseline_healthy=vulnerable_baseline_healthy,
        fixed_baseline_healthy=fixed_baseline_healthy,
        reproducer_hash=reproducer_hash,
        fixed_target_hash=actual_fixed_hash,
        fixed_target_hash_claim=fixed_target_hash_claim,
        source_states_differ=source_states_differ,
        duration_seconds=time.perf_counter() - started,
    )


def write_proof_verification_result(
    repo: Path,
    result: ProofVerificationResult,
    report_path: Path | None = None,
) -> Path:
    out = repo / "reports" / "contract-audits" / "proof-verifications"
    out.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = out / f"{stamp}-{result.finding_id}-proof.json"
    payload = result.as_dict()
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    if report_path and report_path.is_file():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            report = None
        if isinstance(report, dict):
            for item in report.get("findings", []):
                if isinstance(item, dict) and str(item.get("id")) == result.finding_id:
                    item.setdefault("proof_verifications", []).append(payload)
                    break
            report["proof_verification_history"] = report.get("proof_verification_history", [])
            report["proof_verification_history"].append(payload)
            tmp = report_path.with_suffix(report_path.suffix + ".tmp")
            tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(report_path)
    return path


__all__ = [
    "PROOF_MARKER_PREFIX",
    "PROOF_MARKER_SUFFIX",
    "ProofVerificationResult",
    "proof_marker",
    "run_proof_verification",
    "write_proof_verification_result",
]
