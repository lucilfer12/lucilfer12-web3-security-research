# Research Intelligence Operations

## Standard run

Run these commands from the repository root:

    python -m w3sec validate
    python -m w3sec audit --json
    python -m w3sec federate --write --candidates --network
    python -m w3sec history --json --write
    python -m w3sec versions --json --write
    python -m w3sec promotion --json --write
    python -m w3sec research --json --write

The commands are deterministic with respect to the checked-out repository and the
available federation roots. Missing optional roots do not invalidate the canonical
repository; they simply produce a smaller external candidate set.

## Reading promotion output

promotion-decisions.json is a decision record, not a status mutator. "hold" means
the next gate still lacks one or more machine-checkable requirements. The output names
the exact missing requirement, so a researcher can target the next experiment or source.
A current pattern can be fully reproduced and still remain unvalidated. Reproduction
establishes behavior for the represented case; corroboration and generalization require
independent scope, protocol diversity, and boundary analysis; validation additionally
requires an independent reproduction, a green regression, and negative-evidence review.

## Reading federation output

Federation records have source-specific statuses and provenance. They are useful for
finding repeated themes, possible corroboration, and executable regression candidates.
They are not canonical evidence until a researcher attaches them to a case, verifies
the relevant source, and records the research action in the ledger.

## Reading version output

A zero-diff report does not mean that two protocol versions are identical. It may mean
there are not yet two source-backed version contexts. The unresolved section is the
research queue for obtaining explicit protocol-version evidence.

## Reading temporal output

temporal-history.json separates ledger events from git commits. Ledger events are
explicit research actions; git commits establish repository chronology. Neither source
is silently upgraded into a security conclusion.
## CI gate

CI must compile the package, run all unit tests, validate records and references, verify
the ledger hash chain, run the longitudinal engines, inspect federation health, and execute
the bounded research manifests. Generated reports are inspection artifacts; CI does not
change canonical knowledge.

## Safe mutation rule

Changing a hypothesis, pattern, invariant, case classification, protocol version, or
promotion status requires an explicit source-backed edit. When the change represents a
research action, append a corresponding ledger event. Never backfill a historical timestamp
from memory or infer it from a filename.
