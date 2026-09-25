# ZEROMARK-145  Silent Payout Shortfall

## Security property

A withdrawal path should not report a payout as sufficient when its accounting logic permits a shortfall without making that condition explicit.

## Root cause

The reported logic used a tolerance check around available child liquidity while the result was still marked sufficient=true unconditionally. The supplied triage outcome clarified that the relevant USDC amount was base-unit dust rather than a 10-USDC loss.

## Evidence classification

The supplied triage outcome recorded the finding as accepted, Low severity, fixed, unique, with a bounty of $48.65.

## Generalized pattern

Separate economic magnitude from semantic correctness. A tiny numerical discrepancy can still reveal an API/state-contract mismatch, but impact must be measured using token decimals and the complete execution path.

## Disclosure

This record is intentionally sanitized.
