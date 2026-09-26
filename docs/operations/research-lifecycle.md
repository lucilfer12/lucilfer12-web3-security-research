# Research Lifecycle

## Intake

Create a case with a stable ID, explicit security property, disclosure class and
provenance. Do not place secrets or private triage material in public records.

## Modeling

Name actors, entry points, privilege boundaries, state mutations and invariants.
Separate an observation from a hypothesis and from a generalized pattern.

## Reproduction

Create a bounded experiment manifest. Record the exact command, expected result,
protocol context and reproducibility status. Capture failures as counterexamples.

## Hardening

Record the mitigation at the same semantic boundary as the violated property.
A fix should not be treated as proof until the relevant regression is executable or
otherwise independently evidenced.

## Regression

Rerun the experiment after changes and preserve both the historical observation and
the new result. Do not delete the old counterexample.

## Generalization

Only promote a pattern to a stronger status when multiple independent cases or strong
reasoning support it. Candidate patterns remain explicitly marked as such.

## Review gates

w3sec validate must pass before merging structured records. w3sec inventory --json is
the canonical machine-readable summary. w3sec ledger verify checks historical event
integrity. w3sec experiment run ... is always explicit; the system never silently
executes arbitrary research commands.
