# Knowledge Corpus

This directory is the durable machine-readable layer of the research system.

- invariants.yaml: security properties that can be tested or reasoned about.
- evidence.yaml: source-backed evidence records.
- hypotheses.yaml: explicit candidate explanations that can be confirmed, rejected or superseded.
- counterexamples.yaml: sanitized boundary cases that demonstrate a property failure.
- patterns.yaml: candidate generalized failure patterns.
- protocols.yaml: protocol/component identities referenced by cases.
- lineage.yaml: explicit research-graph relationships.
- experiments.yaml: executable experiment catalog.
- sources.yaml: federation registry for the related research repositories.
- regressions.yaml: explicit acceptance contracts for future regressed stage promotion.
- protocol_versions.yaml: temporal protocol/version context, with unresolved values preserved as unknown.
- negative_results.yaml: durable negative knowledge; an empty registry is valid until a result is actually evidenced.
- sources.yaml: federation registry for the related research repositories.
- event history lives separately in ledger/events.jsonl.

The YAML corpus is authoritative research metadata. Generated summaries must never
replace the source records.

Node identifiers use the form kind:id, for example
case:near-neap-658 or invariant:invariant.replay.nonce-monotonicity.
