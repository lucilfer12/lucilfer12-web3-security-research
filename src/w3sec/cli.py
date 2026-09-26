from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .audit import audit_repo
from .coverage import build_coverage
from .experiments import load_experiment, result_to_json, run_experiment
from .export import graph_document
from .graph import ResearchGraph
from .inventory import build_inventory
from .ledger import append_event, verify_chain
from .model import NodeRef, ResearchStage
from .query import CaseQuery, query_cases, summarize_cases
from .validator import validate_repo


def _root(value: str) -> Path:
    return Path(value).resolve()


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser(prog="w3sec", description="Web3 security research OS")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("path", nargs="?", default=".")
    inv = sub.add_parser("inventory")
    inv.add_argument("path", nargs="?", default=".")
    inv.add_argument("--json", action="store_true")

    coverage = sub.add_parser("coverage")
    coverage.add_argument("path", nargs="?", default=".")
    coverage.add_argument("--json", action="store_true")

    graph_cmd = sub.add_parser("graph")
    graph_cmd.add_argument("path", nargs="?", default=".")
    graph_cmd.add_argument("--json", action="store_true")

    audit = sub.add_parser("audit")
    audit.add_argument("path", nargs="?", default=".")
    audit.add_argument("--json", action="store_true")

    query = sub.add_parser("query")
    query.add_argument("path", nargs="?", default=".")
    query.add_argument("--category")
    query.add_argument("--status")
    query.add_argument("--type", dest="record_type")
    query.add_argument("--tag")
    query.add_argument("--text")
    query.add_argument("--stage")
    query.add_argument("--invariant")
    query.add_argument("--pattern")
    query.add_argument("--protocol")
    query.add_argument("--evidence")
    query.add_argument("--hypothesis")
    query.add_argument("--source")
    query.add_argument("--regression")
    query.add_argument("--json", action="store_true")
    lineage = sub.add_parser("lineage")
    lineage.add_argument("node")
    lineage.add_argument("path", nargs="?", default=".")
    lineage.add_argument("--depth", type=int, default=2)
    lineage.add_argument("--reverse", action="store_true")

    ledger = sub.add_parser("ledger")
    ledger_sub = ledger.add_subparsers(dest="ledger_command", required=True)
    lv = ledger_sub.add_parser("verify")
    lv.add_argument("path", nargs="?", default="ledger/events.jsonl")
    la = ledger_sub.add_parser("append")
    la.add_argument("node")
    la.add_argument("event_type")
    la.add_argument("--actor", default="researcher")
    la.add_argument("--stage", choices=[x.value for x in ResearchStage])
    la.add_argument("--timestamp")
    la.add_argument("--payload", default="{}")
    la.add_argument("--path", default="ledger/events.jsonl")
    exp = sub.add_parser("experiment")
    exp_sub = exp.add_subparsers(dest="experiment_command", required=True)
    ec = exp_sub.add_parser("check")
    ec.add_argument("path")
    er = exp_sub.add_parser("run")
    er.add_argument("path")
    er.add_argument("--root", default=".")

    args = parser.parse_args()
    if args.command == "validate":
        errors = validate_repo(_root(args.path))
        if errors:
            print("\n".join(f"ERROR: {error}" for error in errors))
            return 1
        print("Research validation: OK")
        return 0
    if args.command == "inventory":
        value = build_inventory(_root(args.path))
        if args.json:
            _print_json(value)
        else:
            print(
                f"cases={value['case_count']} "
                f"reproducible={value['reproducible_cases']} "
                f"knowledge={sum(value['knowledge_registry_counts'].values())}"
            )
        return 0

    if args.command == "coverage":
        value = build_coverage(_root(args.path))
        _print_json(value) if args.json else print(
            f"cases={value['case_count']} "
            f"evidence={value['evidence_count']} "
            f"hypotheses={value['hypothesis_count']} "
            f"regression_plans={value['regression_plan_count']}"
        )
        return 0

    if args.command == "graph":
        value = graph_document(_root(args.path))
        if args.json:
            _print_json(value)
        else:
            print(f"nodes={len(value['nodes'])} edges={len(value['edges'])}")
        return 0

    if args.command == "audit":
        value = audit_repo(_root(args.path))
        if args.json:
            _print_json(value)
        else:
            print(
                f"ok={value['ok']} "
                f"nodes={value['graph']['node_count']} "
                f"edges={value['graph']['edge_count']}"
            )
        return 0 if value["ok"] else 1

    if args.command == "query":
        query = CaseQuery(
            category=args.category, status=args.status, record_type=args.record_type,
            tag=args.tag, text=args.text, stage=args.stage, invariant=args.invariant,
            pattern=args.pattern, protocol=args.protocol, evidence=args.evidence,
            hypothesis=args.hypothesis, source=args.source,
            regression=args.regression,
        )
        value = summarize_cases(query_cases(_root(args.path), query))
        if args.json:
            _print_json(value)
        else:
            print("\n".join(
                f"{item['id']} [{item['status']}] {item['title']}" for item in value
            ) or "No matching cases.")
        return 0

    if args.command == "lineage":
        try:
            node = NodeRef.parse(args.node)
        except ValueError as exc:
            print(f"ERROR: {exc}")
            return 2
        graph = ResearchGraph.from_repo(_root(args.path))
        if node.key not in graph.nodes:
            print(f"ERROR: unknown node {node.key}")
            return 1
        for item in graph.walk(node, args.depth, args.reverse):
            print(item.key)
        return 0
    if args.command == "ledger":
        if args.ledger_command == "verify":
            errors = verify_chain(_root(args.path))
            if errors:
                print("\n".join(errors))
            else:
                print("Ledger verification: OK")
            return 0 if not errors else 1

        try:
            node = NodeRef.parse(args.node)
            payload = json.loads(args.payload)
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"ERROR: {exc}")
            return 2
        stage = ResearchStage(args.stage) if args.stage else None
        event = append_event(
            _root(args.path), event_type=args.event_type, subject=node,
            timestamp=args.timestamp or datetime.now(timezone.utc).isoformat(),
            actor=args.actor, stage=stage, payload=payload,
        )
        print(event.event_hash)
        return 0

    if args.command == "experiment":
        spec = load_experiment(_root(args.path))
        if args.experiment_command == "check":
            print(f"Experiment specification OK: {spec.id}")
            return 0
        result = run_experiment(spec, _root(args.root))
        print(result_to_json(result))
        return 0 if result.passed else 1

    return 2
