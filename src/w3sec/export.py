from __future__ import annotations

from pathlib import Path
from typing import Any

from .graph import ResearchGraph


def graph_document(root: Path) -> dict[str, Any]:
    graph = ResearchGraph.from_repo(root)
    return {
        "schema_version": 1,
        "nodes": [
            {"id": node.id, "kind": node.kind, "key": node.key}
            for node in sorted(graph.nodes.values(), key=lambda item: item.key)
        ],
        "edges": [
            {
                "source": edge.source.key,
                "relation": edge.relation,
                "target": edge.target.key,
                "evidence": list(edge.evidence),
                "valid_from": edge.valid_from,
                "valid_to": edge.valid_to,
            }
            for edge in sorted(
                graph.edges,
                key=lambda item: (item.source.key, item.relation, item.target.key),
            )
        ],
    }
