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

## Proof-grade differential verification

For findings that have both a vulnerable and a fixed source state, ATLAS provides a stronger differential path:

    python -m w3sec verify-proof audit.json FINDING_ID \
      --fixed-target C:/path/to/fixed-repository \
      --reproducer C:/path/to/atlas-reproducer.py \
      --command "cargo test --test atlas_repro --offline" \
      --vulnerable-expected-exit 1 \
      --fixed-expected-exit 0 \
      --baseline-expected-exit 0 \
      --security-property "the invariant must fail on the vulnerable state and hold after the fix"

The same reproducer is copied into fresh disposable workspaces for both source states. Each side must first pass a clean baseline, execute at least one test, keep the target unchanged, and satisfy its expected outcome.

The reproducer receives a one-run challenge through ATLAS_PROOF_MARKER. It should print that exact value when the focused test is executing, for example:

    import os
    print(os.environ["ATLAS_PROOF_MARKER"])

ATLAS records the reproducer SHA-256, vulnerable/fixed target bindings, test classification, output, timing, and the fixed target hash. CONFIRMED means the specified property was demonstrated by the executed differential test on the two pinned source states; it does not claim that every possible environment or input is covered.
## CI execution sandbox

`.github/workflows/atlas-proof.yml` provides an operator-triggered proof runner on a fresh GitHub-hosted Linux VM. The workflow installs the ATLAS package, Rust, Foundry and bubblewrap, clones the selected vulnerable/fixed revisions without executing project code during checkout, and then runs proof verification with:

    ATLAS_ISOLATION_ATTESTATION=github-actions-ephemeral-vm
    ATLAS_EXECUTION_SANDBOX=bwrap

The sandbox uses Linux namespaces, a private network namespace, isolated PID/process visibility, a hidden home directory, a disposable writable target workspace, and read-only access to the system/toolchain and offline dependency caches needed for compilation/testing. Network-dependent deployment, publishing, broadcast, remote access, and FFI commands remain outside the allowed verification policy.

Use `verify-finding` for a single-state reproduction. Use `verify-proof` when a fixed state is available and the research question is whether the same focused reproducer distinguishes the vulnerable state from the fixed state.

A proof result is evidence for the declared security property and exact source states; impact and independent verification remain explicit evidence gates in the broader ATLAS model.
Proof verification also records the source/input binding, execution timing, test counts, and the exact reproducer SHA256.

## State-transition effect witnesses

For economic or invariant bypasses, exit codes alone can be too coarse. A finding may declare an `effect_witness` policy with exact fields that the reproducer must emit as a machine-readable state transition:

    ATLAS-EFFECT:{"breach":true,"shadow_path":true,"user_asset_delta":10000}

The value is parsed from stdout/stderr and recorded in the proof result. Missing or mismatched required fields prevent `CONFIRMED`; ATLAS never infers an effect from a passing test or from the finding description.

For a solvency-gate bypass such as the RAIN-USDR finding, the intended witness shape can distinguish the two economic paths without depending on prose: the vulnerable run must show the breach state plus the unauthorized/shadow path and positive user-asset extraction, while the fixed run must show the same breach state with the shadow path disabled and zero extraction. The official path's revert expectation remains a separate assertion in the same reproducer.

This creates a stronger evidence chain: source binding → healthy baseline → target engagement → exact security property → state-transition witness → vulnerable/fixed differential → evidence bundle. It is still evidence for the declared property, not a claim of universal exploitability across all environments.
Each verification now carries a `toolchain_manifest` containing the detected ATLAS toolchains, available tool versions (for example `forge`, `cargo`, `rustc`, `pytest`, `python`, and `solc`), and SHA256 hashes of dependency/lock manifests such as `Cargo.lock`, `foundry.lock`, `pyproject.toml`, and `requirements.txt`. This metadata is observational: ATLAS never installs dependencies during proof execution.
