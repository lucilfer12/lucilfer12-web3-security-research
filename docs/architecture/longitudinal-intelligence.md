# Longitudinal Research Intelligence

This layer turns the repository from a static corpus into a continuously auditable
research system. It does not manufacture missing evidence. It computes state from
the canonical corpus, external federation roots, executable artifacts, and git history.

## Data flow

Canonical cases and knowledge registries feed the deterministic graph. Federation
adapters read sibling repositories as secondary candidate material. Cross-case analysis
builds intersections and recurrence. The promotion engine evaluates whether a pattern
can move through explicit research states. The protocol differential engine compares
only explicitly versioned security-model contexts. The history engine combines the
hash-chained ledger with repository git chronology.

## Promotion state machine

The promotion path is intentionally sequential:

Candidate -> Observed -> Reproduced -> Corroborated -> Generalized -> Pattern
-> Validated Pattern.

A state is not awarded because a later object exists. Each gate depends on the
previous gates being satisfied. The validated-pattern gate requires independent
reproduction, a passed regression, and a reviewed negative-evidence result.
## Federation policy

The four sibling repositories are read through local adapters:

- web3-smart-contract-forensics: finding metadata used as secondary leads.
- web3-zeroday-forensics: curated forensic cases used as external corroboration leads.
- security-invariant-lab: execution findings and properties used as evidence leads.
- smart-contract-security-lab: documented finding families and executable tests used
  as pattern/regression leads.

Normalized records are written under reports/federation when requested. They retain
their source identity and are never merged into canonical knowledge automatically.

## Protocol-version differential

A protocol-version record is a security-model context, not merely a software label.
It may contain assumptions, invariants, authorization rules, replay rules, accounting
rules, lifecycle rules, implementation references, and known changes. A differential
report is generated only when two or more source-backed contexts for the same protocol
are available.
Unknown protocol versions are reported as unresolved research debt. Filenames, incident
years, git timestamps, and model inference are not accepted as protocol versions.

## Temporal memory

The hash-chained ledger records explicit research actions. Git history is a second,
read-only temporal provenance source describing repository evolution. The system keeps
the distinction because a code commit is evidence of a repository change, not automatic
proof that a security hypothesis became true.

Historical event reconstruction therefore uses sourced timestamps only. Current-state
objects without historical timestamps remain explicitly time-unknown.

## Outputs

The primary machine-readable reports are:

- reports/longitudinal/research-intelligence.json
- reports/longitudinal/promotion-decisions.json
- reports/longitudinal/protocol-version-diffs.json
- reports/longitudinal/temporal-history.json
- reports/longitudinal/domain-evolution.json
- reports/federation/candidate-records.json
