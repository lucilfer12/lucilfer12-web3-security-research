from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import LineageEdge, NodeRef
from .records import discover_case_records, discover_knowledge_files, load_yaml_mapping


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
        return [self.actor, self.entry_point, self.authorization,
                self.state_mutation, self.invariant, self.impact]

    def as_edges(self) -> list[tuple[str, str]]:
        if self.edges:
            return list(self.edges)
        nodes = self.nodes()
        return list(zip(nodes, nodes[1:]))


class ResearchGraph:
    """Deterministic knowledge graph built from versioned repository records."""
    def __init__(self) -> None:
        self.nodes: dict[str, NodeRef] = {}
        self.edges: list[LineageEdge] = []
        self._edge_keys: set[tuple[str, str, str]] = set()
    def add_node(self, node: NodeRef) -> None:
        self.nodes[node.key] = node

    def add_edge(self, edge: LineageEdge) -> None:
        key = (edge.source.key, edge.relation, edge.target.key)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.add_node(edge.source)
        self.add_node(edge.target)
        self.edges.append(edge)

    def neighbors(self, node: NodeRef, relation: str | None = None) -> list[NodeRef]:
        return [e.target for e in self.edges
                if e.source.key == node.key and (relation is None or e.relation == relation)]

    def reverse_neighbors(self, node: NodeRef) -> list[NodeRef]:
        return [e.source for e in self.edges if e.target.key == node.key]
    def walk(self, start: NodeRef, depth: int = 2, reverse: bool = False) -> list[NodeRef]:
        if depth < 0:
            raise ValueError("depth must be >= 0")
        seen = {start.key}
        queue: deque[tuple[NodeRef, int]] = deque([(start, 0)])
        result: list[NodeRef] = []
        while queue:
            current, level = queue.popleft()
            if level >= depth:
                continue
            candidates = self.reverse_neighbors(current) if reverse else self.neighbors(current)
            for candidate in candidates:
                if candidate.key in seen:
                    continue
                seen.add(candidate.key)
                result.append(candidate)
                queue.append((candidate, level + 1))
        return result

    def shortest_path(self, start: NodeRef, target: NodeRef) -> list[NodeRef]:
        if start.key == target.key:
            return [start]
        queue: deque[NodeRef] = deque([start])
        previous: dict[str, str | None] = {start.key: None}
        refs: dict[str, NodeRef] = {start.key: start}
        while queue:
            current = queue.popleft()
            for neighbor in self.neighbors(current):
                if neighbor.key in previous:
                    continue
                refs[neighbor.key] = neighbor
                previous[neighbor.key] = current.key
                if neighbor.key == target.key:
                    path = [neighbor]
                    cursor: str | None = current.key
                    while cursor is not None:
                        path.append(refs[cursor])
                        cursor = previous[cursor]
                    return list(reversed(path))
                queue.append(neighbor)
        return []
    @classmethod
    def from_repo(cls, root: Path) -> "ResearchGraph":
        graph = cls()
        for _, record in discover_case_records(root):
            case_id = str(record.get("id", ""))
            if not case_id:
                continue
            case = NodeRef("case", case_id)
            graph.add_node(case)
            for field, kind in (
                ("invariants", "invariant"),
                ("patterns", "pattern"),
                ("counterexamples", "counterexample"),
                ("protocols", "protocol"),
                ("evidence", "evidence"),
                ("hypotheses", "hypothesis"),
                ("sources", "source"),
                ("regressions", "regression"),
            ):
                for target_id in _strings(record.get(field)):
                    graph.add_edge(LineageEdge(case, f"references-{kind}",
                                               NodeRef(kind, target_id)))
            for relation in record.get("relationships", []) or []:
                if isinstance(relation, dict) and relation.get("target"):
                    graph.add_edge(LineageEdge(
                        case,
                        str(relation.get("relation", "related-to")),
                        NodeRef.parse(str(relation["target"])),
                    ))

        for path in discover_knowledge_files(root):
            data = load_yaml_mapping(path)
            stem_map = {
                "invariants": ("invariant", "invariants"),
                "patterns": ("pattern", "patterns"),
                "counterexamples": ("counterexample", "counterexamples"),
                "protocols": ("protocol", "protocols"),
                "evidence": ("evidence", "evidence"),
                "hypotheses": ("hypothesis", "hypotheses"),
                "sources": ("source", "source_repos"),
                "regressions": ("regression", "regressions"),
                "protocol_versions": ("protocol-version", "protocol_versions"),
                "negative_results": ("negative_result", "negative_results"),
            }
            mapping = stem_map.get(path.stem)
            if mapping:
                kind, field = mapping
                for item in data.get(field, []) or []:
                    if isinstance(item, dict) and item.get("id"):
                        graph.add_node(NodeRef(kind, str(item["id"])))

        lineage = root / "corpus" / "knowledge" / "lineage.yaml"
        if lineage.exists():
            data = load_yaml_mapping(lineage)
            for raw in data.get("edges", []) or []:
                if not isinstance(raw, dict):
                    continue
                try:
                    source = NodeRef.parse(str(raw["source"]))
                    target = NodeRef.parse(str(raw["target"]))
                except (KeyError, ValueError):
                    continue
                graph.add_edge(LineageEdge(
                    source=source,
                    relation=str(raw.get("relation", "related-to")),
                    target=target,
                    evidence=tuple(_strings(raw.get("evidence"))),
                    valid_from=raw.get("valid_from"),
                    valid_to=raw.get("valid_to"),
                ))
        return graph


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int))]
    return []
