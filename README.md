# Web3 Security Research

A durable, evidence-first operating system for adversarial analysis of decentralized
systems. This repository preserves research as structured, traceable knowledge rather
than a flat list of vulnerability claims.

## Research loop

Observe -> Model -> Hypothesize -> Formalize -> Attack -> Reproduce -> Measure ->
Harden -> Regress -> Generalize

## System architecture

The repository is now organized as seven cooperating layers:

1. Records: cases, invariants, counterexamples, patterns, protocols, evidence, hypotheses and experiments.
2. Knowledge graph: typed nodes and explicit lineage edges.
3. Provenance: source locators with optional commit, line range and content hash.
4. Temporal memory: append-only hash-chained research events in the ledger.
5. Deterministic tooling: schema validation, referential integrity, inventory and queries.
6. Executable research: bounded experiment manifests with captured output and exit contracts.
7. Human analysis: interpretation stays above the evidence layer and never replaces it.
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

The integrated knowledge layer covers the existing four case studies and adds:
5 canonical invariants, 4 sanitized counterexamples, 4 candidate hypotheses, 4 candidate
patterns, 3 protocol entities, 4 evidence records, 8 repository sources, 4 regression
contracts, 3 protocol-version contexts, 31 explicit lineage edges, and 2 executable
experiment manifests. The graph currently materializes 43 typed nodes.

## Responsible disclosure

Do not publish private reports, client information, credentials, KYC data, unreleased
exploit details, or confidential triage material.

## Verification

The CI pipeline installs dependencies, compiles the package, runs the complete unit suite,
validates repository contracts, builds the deterministic inventory and executes the
research-validation manifests.
