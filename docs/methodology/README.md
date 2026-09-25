# Research Methodology
The canonical chain is:
Asset -> Actor -> Trust Boundary -> Privilege -> Entry Point -> State -> Transition -> Invariant -> Adversarial Input -> Failure -> Impact -> Mitigation -> Regression
## Model
Describe assets, actors, privileges, trust boundaries, dependencies and assumptions.
## Formalize
Turn the concern into a security property that can be reasoned about or tested.
## Attack
Search for an input or transition sequence that violates the property.
## Reproduce
Prefer a minimal deterministic proof with before/after state.
## Measure
Separate direct technical impact from economic impact. Record privilege, capital, timing and environmental assumptions.
## Harden
Restore the intended property rather than merely blocking one observed input.
## Regress
Encode the failure as a test.
## Generalize
Extract reusable patterns only after the original claim is supported.