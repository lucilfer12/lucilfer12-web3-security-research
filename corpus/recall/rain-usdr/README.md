# ATLAS recall fixture: Rain/USDR shadow redemption

This is a permanent ATLAS recall fixture, not a production finding or submission.

It preserves a real Solidity target that was used to exercise ATLAS proof verification.

## Contents

- rain-usdr-source.zip: original target archive, SHA-256 pinned in manifest.yaml.
- vault-engine-fix.patch: local fixed-state change used by the recall test.
- DifferentialShadowPath.t.sol: the focused differential reproducer.
- vendor/@openzeppelin/contracts: pinned OpenZeppelin 5.4.0 dependency snapshot.

## Expected behavior

The vulnerable state permits a stable-PSM shadow redemption during an active solvency breach.
The fixed state blocks the same withdrawal through VaultEngine.frob() with SolvencyGateActive.

The reproducer also checks that the official PSM buyStable() path is blocked.

## Recall execution

The fixture is opt-in because it requires Foundry and is intentionally heavier than normal unit tests:

    ATLAS_RECALL_RAIN_USDR=1 python -m pytest -q tests/test_recall_rain_usdr.py

The test calls ATLAS's own proof_verifier against both source states and records the effect witness.
