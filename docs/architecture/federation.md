# Federated Research Sources

The central repository remains the canonical knowledge and evidence layer. Related
repositories are connected through reproducible adapters that preserve source identity,
repository revision, evidence level, and review status.

## Active adapters

- web3-smart-contract-forensics: 226 secondary audit-finding candidates across 90 projects.
- security-invariant-lab: 6 execution findings plus 2 properties from the final scan dataset.
- web3-zeroday-forensics: 20 curated forensic cases spanning 15 bug classes.
- smart-contract-security-lab: 4 documented finding families plus 4 executable Solidity tests.

The current federation run normalizes 262 external candidate records. These records are
research leads, not canonical evidence.

## Execution boundary

Federated sources are read-only from this repository. The adapter never mutates an external
repository and never promotes an external finding into canonical knowledge automatically.

Smart Contract Security Lab tests are executable through Foundry in CI. The central adapter
records whether the Foundry executable is available and retains the source repository revision
used for the snapshot.

## Provenance

Every federated source records its local path and git HEAD. Verification events are appended
to the central hash-chained ledger after a source snapshot is inspected.

A source reference does not upgrade the evidentiary status of a case automatically. Canonical
promotion requires local review, explicit provenance, and the promotion state machine.
