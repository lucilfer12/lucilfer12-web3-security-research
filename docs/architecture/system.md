# Research Security OS

The repository is organized around durable evidence, not a flat vulnerability list.

## Layers

1. Records: case studies, invariants, experiments, counterexamples and patterns.
2. Graph: typed nodes plus lineage edges across those records.
3. Provenance: source locators, optional commit and line ranges, and content hashes.
4. Temporal ledger: append-only hash chained events for research history.
5. Deterministic tooling: schema validation, reference validation, inventory and query CLI.
6. Experiments: explicit manifests with hypotheses, bounded execution and captured output.
7. Human analysis: interpretation happens above the evidence layer and never becomes
the source of truth.

## Core chain

Observe -> Model -> Hypothesize -> Formalize -> Attack -> Reproduce -> Measure ->
Harden -> Regress -> Generalize

The repository stores only stages actually supported by its evidence. Missing later
stages are research debt, not proof of a security failure.

## Knowledge graph

Case -> Invariant -> Counterexample -> Pattern

Cases can also connect to Protocols, Experiments, Evidence and other Cases. Lineage
edges are explicit so future work can add competing hypotheses or historical versions
without rewriting the original claim.

## Temporal design

Protocol-version context, implementation commits, observed dates and research status
belong to records and ledger events. Historical state is additive: a later correction
adds a new event or record revision instead of erasing the earlier research trail.
