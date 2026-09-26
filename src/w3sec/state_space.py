from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from typing import Callable, Generic, Hashable, TypeVar

State = TypeVar("State")
TransitionFn = Callable[[State], State]
InvariantFn = Callable[[State], bool]


@dataclass(frozen=True, slots=True)
class Transition(Generic[State]):
    name: str
    apply: TransitionFn[State]


@dataclass(frozen=True, slots=True)
class Counterexample(Generic[State]):
    state: State
    actions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExplorationResult(Generic[State]):
    visited_states: int
    explored_traces: int
    counterexample: Counterexample[State] | None = None


def default_state_key(state: State) -> Hashable:
    try:
        return json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except TypeError:
        return repr(state)


def explore(
    initial: State,
    transitions: list[Transition[State]],
    invariant: InvariantFn[State],
    *,
    max_depth: int = 5,
    max_nodes: int = 1000,
    state_key: Callable[[State], Hashable] = default_state_key,
) -> ExplorationResult[State]:
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")
    if max_nodes < 1:
        raise ValueError("max_nodes must be >= 1")
    visited = {state_key(initial)}
    queue: deque[tuple[State, tuple[str, ...], int]] = deque([(initial, (), 0)])
    traces = 0
    while queue and len(visited) <= max_nodes:
        state, actions, depth = queue.popleft()
        traces += 1
        if not invariant(state):
            return ExplorationResult(len(visited), traces, Counterexample(state, actions))
        if depth >= max_depth:
            continue
        for transition in transitions:
            next_state = transition.apply(state)
            key = state_key(next_state)
            if key in visited:
                continue
            visited.add(key)
            queue.append((next_state, actions + (transition.name,), depth + 1))
    return ExplorationResult(len(visited), traces, None)


def minimize_trace(
    initial: State,
    transitions: dict[str, TransitionFn[State]],
    actions: list[str],
    invariant: InvariantFn[State],
    *,
    max_rounds: int = 100,
) -> list[str]:
    current = list(actions)
    if invariant(_replay(initial, transitions, current)):
        return []
    rounds = 0
    changed = True
    while changed and rounds < max_rounds:
        changed = False
        rounds += 1
        for index in range(len(current)):
            candidate = current[:index] + current[index + 1:]
            if not invariant(_replay(initial, transitions, candidate)):
                current = candidate
                changed = True
                break
    return current


def _replay(
    initial: State,
    transitions: dict[str, TransitionFn[State]],
    actions: list[str],
) -> State:
    state = initial
    for action in actions:
        if action not in transitions:
            raise ValueError(f"unknown transition {action!r}")
        state = transitions[action](state)
    return state
