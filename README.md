# Web3 Security Research

A durable, evidence-first operating system for adversarial analysis of decentralized
systems. This repository preserves research as structured, traceable knowledge rather
than a flat list of vulnerability claims.

## Research loop

Observe -> Model -> Hypothesize -> Formalize -> Attack -> Reproduce -> Measure ->
Harden -> Regress -> Generalize

## System architecture

The repository is organized as cooperating research layers:

1. Records: cases, invariants, counterexamples, patterns, protocols, evidence, hypotheses, claims, observations and experiments.
2. Knowledge graph: typed nodes and explicit lineage edges.
3. Provenance: source locators with optional commit, line range and content hash.
4. Temporal memory: hash-chained research events plus repository git chronology.
5. Federation: reproducible adapters for the sibling forensic and invariant repositories.
6. Research intelligence: cross-case intersections, candidate-network recurrence and research debt.
7. Promotion engine: explicit Candidate -> Observed -> Reproduced -> Corroborated -> Generalized -> Pattern -> Validated Pattern gates.
8. Protocol differential: source-backed security-model diffs across explicit protocol-version contexts.
9. Deterministic tooling: schema validation, referential integrity, inventory, queries, reports and bounded experiments.
10. Human analysis: interpretation stays above the evidence layer and never replaces it.
## Repository map

| Area | Purpose |
| --- | --- |
| case-studies/ | Durable sanitized research records |
| corpus/knowledge/ | Machine-readable invariants, evidence, hypotheses, protocols, patterns, counterexamples and lineage |
| schemas/ | JSON Schema contracts for the research model |
| experiments/ | Executable, bounded research manifests |
| invariants/ | Human-readable security properties |
| labs/ | Adversarial modeling and regression workspace |
| ledger/ | Research history and lessons |
| src/w3sec/ | Validation, graph, query, inventory, ledger and experiment CLI |
| docs/ | Methodology, architecture, disclosure and operating standards |
## CLI

Validate all record and reference contracts:

    python -m w3sec validate

Generate machine-readable inventory and research debt:

    python -m w3sec inventory --json

Run the full longitudinal research engines:

    python -m w3sec federate --write --candidates --network
    python -m w3sec research --json --write
    python -m w3sec history --json --write
    python -m w3sec versions --json --write
    python -m w3sec promotion --json --write

Query cases and research state:

    python -m w3sec query --category replay-protection
    python -m w3sec query --stage reproduced --invariant invariant.replay.nonce-monotonicity
    python -m w3sec query --status validated-fixed

Walk research lineage:

    python -m w3sec lineage case:near-neap-658 --depth 4

Inspect coverage, graph and unified audit:

    python -m w3sec coverage --json
    python -m w3sec graph --json
    python -m w3sec audit --json

Verify or append temporal ledger events:

    python -m w3sec ledger verify
    python -m w3sec ledger append case:near-neap-658 observation --stage reproduced

Check or explicitly run an experiment:

    python -m w3sec experiment check experiments/repository-validation.yaml
    python -m w3sec experiment run experiments/repository-validation.yaml --root .
## Evidence discipline

A case should remain traceable through:

Claim -> Source/Code -> Security Property -> Reproduction -> Observed Failure ->
Impact -> Mitigation -> Regression -> Generalize

Research stages are explicit. Missing stages are reported as research debt, not silently
invented. Candidate patterns remain candidates until stronger evidence supports promotion.

## Current corpus

The canonical layer covers 4 case studies, 5 invariants, 4 counterexamples, 4 hypotheses,
4 patterns, 3 protocol entities, 4 evidence records, 4 regression contracts, 3 protocol-version
contexts, 31 explicitly declared lineage edges, 4 questions, 3 claims, 4 observations and
2 executable experiment manifests. The deterministic graph materializes 70 typed nodes and
67 derived edges. Federation currently normalizes 262 external candidate records from the
four sibling research repositories; these remain secondary research leads until reviewed.

## Responsible disclosure

Do not publish private reports, client information, credentials, KYC data, unreleased
exploit details, or confidential triage material.

## Windows executable

The research OS can run as a portable Windows x64 executable without a local Python
installation. Build it from a Windows checkout with:

    powershell -ExecutionPolicy Bypass -File scripts/build_windows_exe.ps1

The resulting files are written to dist/:

    w3sec.exe
    w3sec.exe.sha256
    BUILD-MANIFEST.txt

The executable can be smoke-tested with:

    powershell -ExecutionPolicy Bypass -File scripts/test_windows_exe.ps1

GitHub Actions also builds and uploads the same artifact through
.github/workflows/windows-exe.yml.

## Verification

The CI pipeline installs dependencies, compiles the package, runs the complete unit suite,
validates repository contracts, verifies the temporal ledger, runs the longitudinal engines,
executes federated checks, and executes the bounded research-validation manifests.
