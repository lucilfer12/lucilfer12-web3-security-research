from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AttackPath:
    actor: str
    entry_point: str
    authorization: str
    state_mutation: str
    invariant: str
    impact: str
    edges: list[tuple[str, str]] = field(default_factory=list)

    def nodes(self) -> list[str]:
        return [
            self.actor,
            self.entry_point,
            self.authorization,
            self.state_mutation,
            self.invariant,
            self.impact,
        ]

    def as_edges(self) -> list[tuple[str, str]]:
        if self.edges:
            return list(self.edges)
        nodes = self.nodes()
        return list(zip(nodes, nodes[1:]))
