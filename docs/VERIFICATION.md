# ATLAS Local Verification

ATLAS can verify a selected finding by running a real test/build against a disposable copy of the target.

Verification never edits the original target. Directory/archive targets are copied to a temporary workspace; standalone Solidity and Rust files receive a minimal Foundry/Cargo harness when a reproducer is supplied.

## Supported runners

ATLAS currently permits only local test-oriented commands:

- cargo test, cargo check, and cargo build with --offline
- forge test and forge build with --offline
- python -m pytest or python -m unittest
- pytest

Network, deployment, publishing, remote access, shell chaining, and other high-risk operations are rejected by the command validator.

## Reproduction workflow
1. Audit the real target and select one production finding.
2. Provide a local reproducer/test when the target does not already contain one.
3. State the security property the test is intended to establish or break.
4. ATLAS runs a clean baseline first for reproduction mode.
5. ATLAS runs the reproducer on a fresh copy only when the baseline is healthy.
6. ATLAS records stdout/stderr, exit code, test classification, timing, toolchain, and before/after hashes.

A result of REPRODUCED means the stated test was executed and reproduced the declared condition on the pinned target copy. It is not by itself a complete vulnerability proof: impact and independent verification remain separate evidence gates.

## Windows trust decision

Local Windows execution does not provide an OS-level sandbox in the current ATLAS runtime. The GUI therefore asks for an explicit trust confirmation before running target-controlled tests, build scripts, or proc-macros.

For untrusted targets, run verification from an attested disposable environment instead. The CLI exposes the same explicit choice with --trust-target-code.

## Suggested commands

For a Foundry project, ATLAS suggests:

forge test --offline -vv

For a Cargo workspace, ATLAS suggests:

cargo test --workspace --offline

The operator may narrow these commands to a specific test while staying inside the same allowed runner policy.

## Evidence model

Finding status is derived from explicit evidence gates:

- source binding
- security property
- reproduction
- measured impact
- independent verification

A normal passing test does not automatically disprove a finding. A compile error or a run with no tests is INCONCLUSIVE, not a successful reproduction.

ATLAS keeps Rust, fuzz, test, benchmark, estimator, examples, and tooling evidence available to the audit pipeline. Production findings and supporting evidence are displayed separately so recall is preserved without treating every supporting location as production attack surface.
