"""Execution-isolation policy for verification runs.

Why this exists: `cargo test`, `forge test`, `pytest` and `python -m` execute code that the
*target* controls (build.rs, proc-macros, tests, conftest.py, foundry.toml `ffi`). Running that
with the researcher's own privileges exposes local files, credentials and the network. A copy of
the target in a temp directory plus a token denylist on the command line does not change that.

Policy (fail closed): verification only executes when
  1. the runner attests an isolated, disposable environment (remote ephemeral VM / container), or
  2. the operator explicitly declares the target code trusted for this run.
Anything else is refused.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

TRUST_ENV = "ATLAS_TRUST_TARGET_CODE"
ATTEST_ENV = "ATLAS_ISOLATION_ATTESTATION"
ATTESTED_ENVIRONMENTS = frozenset({"github-actions-ephemeral-vm", "container-no-network"})

REFUSAL = (
    "Verification refused: it would run target-controlled code (build scripts, tests, "
    "proc-macros, conftest.py) with your own user privileges, and this machine provides no "
    "OS-level isolation. Run it in an isolated ephemeral environment (see docs/VERIFICATION.md), "
    "or, only for code you already trust, pass --trust-target-code."
)


class VerificationRefused(RuntimeError):
    """Raised when neither attested isolation nor an explicit trust declaration exists."""


@dataclass(frozen=True, slots=True)
class IsolationDecision:
    allowed: bool
    mode: str
    reason: str


def decide(trusted_target_code: bool = False, environ: Mapping[str, str] | None = None) -> IsolationDecision:
    env = os.environ if environ is None else environ
    attestation = str(env.get(ATTEST_ENV, "")).strip()
    if attestation in ATTESTED_ENVIRONMENTS:
        return IsolationDecision(True, f"attested:{attestation}", "runner attests an isolated disposable environment")
    if trusted_target_code or str(env.get(TRUST_ENV, "")).strip() == "1":
        return IsolationDecision(
            True, "operator-trusted",
            "operator declared the target code trusted; it runs with this user's privileges",
        )
    return IsolationDecision(False, "refused", REFUSAL)


def require_isolation(trusted_target_code: bool = False, environ: Mapping[str, str] | None = None) -> IsolationDecision:
    decision = decide(trusted_target_code, environ)
    if not decision.allowed:
        raise VerificationRefused(decision.reason)
    return decision
