# ZEROMARK-146  Unbounded Penalty in executeForceExit()

## Security property

A privileged administrative exit must enforce the vault-level maximum penalty intended by the protocol.

## Root cause

The parent executeForceExit(address owner, uint256 penaltyBps) accepted penaltyBps after the role check without an analogous upper-bound guardrail.

The payout calculation was effectively:

    payout -= (payout * penaltyBps) / BASIS_POINTS

With penaltyBps = 10000, the payout can reach zero.

## Threat model

The relevant actor is a holder of the FORCE_EXITER role. This is a privileged-path failure, not a permissionless user exploit.

## Evidence classification

The supplied triage outcome recorded the finding as valid, Medium severity, fixed, with a bounty of $28.14.

## Generalized pattern

When a privileged function accepts a parameter that directly controls an economic deduction, validate the parameter at every security boundary where the invariant is expected to hold. A role check is not a substitute for semantic range validation.

## Disclosure

This public record excludes private platform comments and sensitive operational details.
