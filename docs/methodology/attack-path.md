# Attack-Path Method

The canonical graph is:

Actor -> Entry Point -> Authorization -> State Mutation -> Invariant Violation -> Impact

For each edge ask:

1. What enables the transition?
2. Which state changes?
3. Which assumption is relied upon?
4. Which invariant is supposed to prevent failure?
5. What evidence proves the edge exists?

An attack path is complete only when the required privilege and preconditions are explicit.
