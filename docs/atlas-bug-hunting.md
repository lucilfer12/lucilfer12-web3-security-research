# ATLAS bug-hunting mode

ATLAS treats source scope as evidence tiers, not a binary include/exclude switch.

## Scope model

**Production** is code reachable from a `neard` binary through Cargo workspace dependencies. It is the primary attack surface.

**Supporting** is workspace Rust that lives in tests, fuzzers, benchmarks, estimators, examples, build scripts, test harnesses, or other non-production paths. Supporting code is still parsed and analyzed. It can supply fixtures, invariants, protocol assumptions, regression evidence, and examples of unsafe edge cases, but its findings are explicitly marked as supporting evidence instead of being silently mixed with production attack surface.

This distinction prevents the old failure mode where useful security knowledge was discarded merely because a file lived under `fuzz/` or `tests/`.

## Analysis pipeline

1. Intake all recognized source languages and preserve source hashes and provenance.
2. Parse language-aware code with comments and strings masked before matching.
3. Build a Cargo production graph for Rust using `cargo metadata --no-deps`.
4. Build an entry-point inventory from host functions, validation/processing functions, network/RPC handlers, state-sync/chunk handlers, and boundary-shaped APIs.
5. Perform function-local taint propagation from input-like parameters and values.
6. Run semantic detectors:
   - panic/indexing reachable from tainted input;
   - input-sized allocations and collection growth;
   - unchecked arithmetic and casts on tainted values;
   - deserialization without a visible nearby size/canonicalization guard;
   - host work before gas charging;
   - consensus-validation invariant gaps.
7. Keep deterministic/static signals as review leads. Attach reachability, confidence, guards, taint variables, scope, and triage score.
8. Require a security property, reproduction, impact measurement, and independent verification before treating a candidate as a validated vulnerability.

## Recall corpus

ATLAS keeps small historical recall fixtures under `corpus/recall/`. These are regression tests that encode a known pre-fix shape and a corrected shape.

The nearcore total-supply case records:
- pre-fix commit: `5727fef42`
- fix commit: `16494072cb10d602e299895b0840d123099fe4df`
- property: block total supply must equal previous supply plus epoch minting minus burned balance.

The recall test must flag the pre-fix validation seam and must stay silent after the invariant check is present.

The Rain/USDR shadow-redemption fixture under `corpus/recall/rain-usdr/` exercises the same rule using a real Foundry project, a pinned OpenZeppelin dependency snapshot, and ATLAS's proof-grade differential verifier. It is opt-in because it requires Foundry and is kept as a regression fixture rather than a production finding.

## Windows release

The Windows build is produced from the active repository with no staging clone and no copy-back step. The visible release artifact is `ATLAS-windows-x64.zip`, accompanied by `dist/BUILD-MANIFEST.txt` and SHA-256 files.