from datetime import datetime, timezone
from pathlib import Path

from w3sec.ledger import append_event, iter_events
from w3sec.model import NodeRef

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "ledger" / "events.jsonl"
STAMP = datetime.now(timezone.utc).isoformat()
EVENTS = [
    ("source:source.repo.forensics", "source_verified", {"records": 226, "git_head": "131d043d65017396f9389e35527e76401bc4c130", "role": "secondary-candidate"}),
    ("source:source.repo.zeroday", "source_verified", {"cases": 20, "git_head": "f2dd4e4f2c282bc65d0e5e6556ed53087651ecba", "role": "curated-external-lead"}),
    ("source:source.repo.invariants", "source_verified", {"findings": 6, "properties": 2, "git_head": "b5daf44cb2623ff68a3257223f9fe9d81567007b", "role": "execution-evidence"}),
    ("source:source.repo.smart-contract-lab", "source_verified", {"finding_families": 4, "regression_tests": 4, "git_head": "b6f7a0d8724715a07588bafcb76ccce999f8dae1", "role": "executable-pattern-lead"}),
    ("report:federation-snapshot", "federation_snapshot_built", {"candidate_records": 262, "source_count": 4, "health": "ok"}),
    ("report:promotion-decisions", "promotion_evaluated", {"patterns": 4, "promotable": 0, "blocked": 4}),
    ("report:protocol-version-diffs", "protocol_diff_evaluated", {"contexts": 3, "diffs": 0, "unresolved": 3}),
]
existing = {(e.get("subject", {}).get("id"), e.get("event_type")) for e in iter_events(LEDGER)}
for subject, event_type, payload in EVENTS:
    if (subject, event_type) in existing:
        continue
    append_event(
        LEDGER,
        event_type=event_type,
        subject=NodeRef.parse(subject),
        timestamp=STAMP,
        actor="longitudinal-engine",
        payload=payload,
    )

print(f"ledger={LEDGER}")
print(f"events_written={sum((subject, event_type) not in existing for subject, event_type, _ in EVENTS)}")
