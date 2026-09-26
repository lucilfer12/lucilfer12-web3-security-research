# Research Ledger

events.jsonl is an append-only, hash-chained event stream.

No historical events are fabricated during migrations. The empty ledger is intentional
until research events are explicitly recorded.

Append:
python -m w3sec ledger append case:near-neap-658 observation --stage reproduced

Verify:
python -m w3sec ledger verify
