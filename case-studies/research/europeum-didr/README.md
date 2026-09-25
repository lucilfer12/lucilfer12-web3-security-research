# Europeum DIDR  Capability Invocation Reachability

## Research status

Under review in the supplied research record.

## Security property

A lifecycle operation should not irreversibly strand the DID by removing the final active key needed to satisfy the controller authorization path.

## Observation

The reported code path allowed revokeVerificationMethod / expireVerificationMethod to remove a last active resolvable capabilityInvocation key without an equivalent guard to the one used for controller removal. The reported _checkController path could then become permanently unsatisfied.

A conditional second path was identified through policy-registry behavior; that path depends on the actual authorization model and should not be treated as universally exploitable without evidence.

## Disclosure discipline

Because the supplied status was still under review, this repository records the research question and technical model without presenting a final severity or bounty outcome.
