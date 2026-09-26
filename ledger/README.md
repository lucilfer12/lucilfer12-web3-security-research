# Research Ledger

events.jsonl is an append-only, hash-chained event stream.

No historical events are fabricated during initialization. The current ledger contains one explicit
genesis/initialization event anchoring the chain; it does not represent historical research activity.

Append:
python -m w3sec ledger append case:near-neap-658 observation --stage reproduced

Verify:
python -m w3sec ledger verify
