from __future__ import annotations
import argparse
import json
from importlib.metadata import PackageNotFoundError, version as package_version
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .audit import audit_repo
from .contract_audit import build_contract_audit, write_contract_audit
from .chronicle import build_chronicle, write_chronicle, write_event_backfill_plan
from .coverage import build_coverage
from .experiments import load_experiment, result_to_json, run_experiment
from .export import graph_document
from .federation import (
    build_candidate_network, build_federation_snapshot, write_candidate_snapshot,
    write_federation_snapshot,
)
from .graph import ResearchGraph
from .history import build_domain_evolution, build_temporal_timeline, write_domain_evolution, write_temporal_history
from .inventory import build_inventory
from .intake import build_intake, write_intake_report
from .ledger import append_event, verify_chain
from .model import NodeRef, ResearchStage
from .promotion import build_promotion_engine, write_promotion_report
from .query import CaseQuery, query_cases, summarize_cases
from .research_intelligence import (
    build_research_metrics, write_longitudinal_report,
)
from .validator import validate_repo
from .versions import build_version_diff_report, write_version_diff_report


def _root(value: str) -> Path:
    return Path(value).resolve()


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def main() -> int:
    try:
        app_version = __version__
    except Exception:
        try:
            app_version = package_version("web3-security-research")
        except PackageNotFoundError:
            app_version = "development"
    parser = argparse.ArgumentParser(prog="atlas", description="ATLAS Web3 security research OS")
    parser.add_argument("--version", action="version", version="ATLAS — perpetual development build")
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

    contract_audit = sub.add_parser("audit-contract", help="audit a contract file, archive, or repository")
    contract_audit.add_argument("target")
    contract_audit.add_argument("--os-root", default=".")
    contract_audit.add_argument("--json", action="store_true")
    federate = sub.add_parser("federate")
    federate.add_argument("path", nargs="?", default=".")
    federate.add_argument("--write", action="store_true")
    federate.add_argument("--candidates", action="store_true")
    federate.add_argument("--network", action="store_true")

    research = sub.add_parser("research")
    research.add_argument("path", nargs="?", default=".")
    research.add_argument("--json", action="store_true")
    research.add_argument("--write", action="store_true")

    chronicle = sub.add_parser("chronicle")
    chronicle.add_argument("path", nargs="?", default=".")
    chronicle.add_argument("--json", action="store_true")
    chronicle.add_argument("--write", action="store_true")
    chronicle.add_argument("--backfill-plan", action="store_true")

    history = sub.add_parser("history")
    history.add_argument("path", nargs="?", default=".")
    history.add_argument("--json", action="store_true")
    history.add_argument("--write", action="store_true")
    history.add_argument("--domain", action="store_true")

    versions = sub.add_parser("versions")
    versions.add_argument("path", nargs="?", default=".")
    versions.add_argument("--json", action="store_true")
    versions.add_argument("--write", action="store_true")

    promotion = sub.add_parser("promotion")
    promotion.add_argument("path", nargs="?", default=".")
    promotion.add_argument("--json", action="store_true")
    promotion.add_argument("--write", action="store_true")

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

    intake = sub.add_parser("intake", help="register and structurally analyze a contract file or repository")
    intake.add_argument("target")
    intake.add_argument("--os-root", default=".")
    intake.add_argument("--json", action="store_true")
    intake.add_argument("--write", action="store_true")

    exp = sub.add_parser("experiment")
    exp_sub = exp.add_subparsers(dest="experiment_command", required=True)
    ec = exp_sub.add_parser("check")
    ec.add_argument("path")
    er = exp_sub.add_parser("run")
    er.add_argument("path")
    er.add_argument("--root", default=".")

    args = parser.parse_args()
    root = _root(getattr(args, "path", "."))

    if args.command == "validate":
        errors = validate_repo(root)
        if errors:
            print("\n".join(f"ERROR: {error}" for error in errors))
            return 1
        print("Research validation: OK")
        return 0

    if args.command == "inventory":
        value = build_inventory(root)
        if args.json:
            _print_json(value)
        else:
            print(f"cases={value['case_count']} reproducible={value['reproducible_cases']} knowledge={sum(value['knowledge_registry_counts'].values())}")
        return 0
    if args.command == "coverage":
        value = build_coverage(root)
        _print_json(value) if args.json else print(
            f"cases={value['case_count']} evidence={value['evidence_count']} "
            f"hypotheses={value['hypothesis_count']} regression_plans={value['regression_plan_count']}"
        )
        return 0

    if args.command == "graph":
        value = graph_document(root)
        _print_json(value) if args.json else print(f"nodes={len(value['nodes'])} edges={len(value['edges'])}")
        return 0

    if args.command == "audit":
        value = audit_repo(root)
        _print_json(value) if args.json else print(
            f"ok={value['ok']} nodes={value['graph']['node_count']} edges={value['graph']['edge_count']}"
        )
        return 0 if value["ok"] else 1

    if args.command == "federate":
        value = build_federation_snapshot(root)
        if args.write:
            write_federation_snapshot(root)
        if args.candidates:
            path = write_candidate_snapshot(root)
            print(f"candidate_snapshot={path}")
        if args.network:
            _print_json(build_candidate_network(root))
        else:
            _print_json(value)
        return 0 if value["federation_health"] == "ok" else 1
    if args.command == "research":
        value = build_research_metrics(root)
        if args.write:
            write_longitudinal_report(root)
        _print_json(value) if args.json else print(json.dumps(value, indent=2, ensure_ascii=False))
        return 0

    if args.command == "chronicle":
        value = build_chronicle(root)
        if args.write:
            write_chronicle(root)
        if args.backfill_plan:
            write_event_backfill_plan(root)
        _print_json(value) if args.json else print(json.dumps(value, indent=2, ensure_ascii=False))
        return 0

    if args.command == "history":
        value = build_domain_evolution(root) if args.domain else build_temporal_timeline(root)
        if args.write:
            if args.domain:
                write_domain_evolution(root)
            else:
                write_temporal_history(root)
        _print_json(value) if args.json else print(json.dumps(value, indent=2, ensure_ascii=False))
        return 0

    if args.command == "versions":
        value = build_version_diff_report(root)
        if args.write:
            write_version_diff_report(root)
        _print_json(value) if args.json else print(json.dumps(value, indent=2, ensure_ascii=False))
        return 0

    if args.command == "promotion":
        value = build_promotion_engine(root)
        if args.write:
            write_promotion_report(root)
        if args.json:
            _print_json(value)
        else:
            for item in value["decisions"]:
                print(f"{item['pattern']} stage={item['computed_stage']} decision={item['decision']} missing={','.join(item['missing_requirements'])}")
        return 0
    if args.command == "query":
        query = CaseQuery(
            category=args.category, status=args.status, record_type=args.record_type,
            tag=args.tag, text=args.text, stage=args.stage, invariant=args.invariant,
            pattern=args.pattern, protocol=args.protocol, evidence=args.evidence,
            hypothesis=args.hypothesis, source=args.source, regression=args.regression,
        )
        value = summarize_cases(query_cases(root, query))
        _print_json(value) if args.json else print(
            "\n".join(f"{item['id']} [{item['status']}] {item['title']}" for item in value)
            or "No matching cases."
        )
        return 0

    if args.command == "lineage":
        try:
            node = NodeRef.parse(args.node)
        except ValueError as exc:
            print(f"ERROR: {exc}")
            return 2
        graph = ResearchGraph.from_repo(root)
        if node.key not in graph.nodes:
            print(f"ERROR: unknown node {node.key}")
            return 1
        for item in graph.walk(node, args.depth, args.reverse):
            print(item.key)
        return 0
    if args.command == "ledger":
        if args.ledger_command == "verify":
            errors = verify_chain(root)
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
            root, event_type=args.event_type, subject=node,
            timestamp=args.timestamp or datetime.now(timezone.utc).isoformat(),
            actor=args.actor, stage=stage, payload=payload,
        )
        print(event.event_hash)
        return 0

    if args.command == "audit-contract":
        report = build_contract_audit(_root(args.target), _root(args.os_root))
        write_contract_audit(_root(args.os_root), report)
        if args.json:
            _print_json(report)
        else:
            s = report["summary"]
            print(f"findings={s['finding_count']} critical={s['critical']} high={s['high']} medium={s['medium']} low={s['low']}")
        return 0

    if args.command == "intake":
        target = _root(args.target)
        os_root = _root(args.os_root)
        value = build_intake(target)
        if args.write:
            path = write_intake_report(os_root, value)
            print(f"intake_report={path}")
        _print_json(value) if args.json else print(
            f"intake={value['id']} kind={value['target']['kind']} "
            f"files={value['summary']['source_file_count']} contracts={value['summary']['contract_count']} "
            f"functions={value['summary']['function_count']} hash={value['target']['source_hash']}"
        )
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


if __name__ == "__main__":
    raise SystemExit(main())
