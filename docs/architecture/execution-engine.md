# Execution Engine

The execution layer stays deterministic and local.

## State-space exploration

The module src/w3sec/state_space.py provides bounded breadth-first exploration over an
arbitrary state type. A caller supplies named transitions and an invariant predicate.
The engine records a concrete counterexample trace when the invariant fails and limits
search by depth and node count.

## Counterexample minimization

minimize_trace removes actions while preserving the failing predicate. The result is a
smaller reproducible trace, never a replacement for the original evidence.

## Differential testing

src/w3sec/differential.py runs the same action sequence through two implementations and
reports the first divergent step. This supports model-vs-model or fixed-vs-regressed
checks without binding the research OS to one runtime.

## Experiments

src/w3sec/experiments.py executes only explicit manifests. Every manifest declares an
ID, hypothesis, bounded timeout, command and expected exit code. The CLI never discovers
or runs arbitrary scripts implicitly.

## Design boundary

The research OS provides deterministic orchestration and evidence contracts. Chain-
specific execution environments such as Foundry, Rust harnesses, RPC sandboxes or other
local runtimes remain adapters owned by their respective research repositories.
