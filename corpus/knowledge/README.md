# Knowledge Corpus

This directory is the durable machine-readable layer of the research system.

- invariants.yaml: security properties that can be tested or reasoned about.
- counterexamples.yaml: sanitized boundary cases that demonstrate a property failure.
- patterns.yaml: candidate generalized failure patterns.
- protocols.yaml: protocol/component identities referenced by cases.
- lineage.yaml: explicit research-graph relationships.
- experiments.yaml: executable experiment catalog.
- event history lives separately in ledger/events.jsonl.

The YAML corpus is authoritative research metadata. Generated summaries must never
replace the source records.

Node identifiers use the form kind:id, for example
case:near-neap-658 or invariant:invariant.replay.nonce-monotonicity.
