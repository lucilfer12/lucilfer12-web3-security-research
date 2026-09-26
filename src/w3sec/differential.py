from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Generic, Hashable, TypeVar

State = TypeVar("State")


@dataclass(frozen=True, slots=True)
class Divergence(Generic[State]):
    step: int
    action: str
    left: State
    right: State


@dataclass(frozen=True, slots=True)
class DifferentialResult(Generic[State]):
    actions: tuple[str, ...]
    divergence: Divergence[State] | None


def run_differential(
    initial: State,
    actions: list[str],
    left_step: Callable[[State, str], State],
    right_step: Callable[[State, str], State],
    state_key: Callable[[State], Hashable] | None = None,
) -> DifferentialResult[State]:
    left = right = initial
    compare = state_key or (lambda value: value)
    for index, action in enumerate(actions, 1):
        left = left_step(left, action)
        right = right_step(right, action)
        if compare(left) != compare(right):
            return DifferentialResult(tuple(actions), Divergence(index, action, left, right))
    return DifferentialResult(tuple(actions), None)
