# Security Invariants
An invariant is a property intended to remain true across all allowed system transitions.
Examples:
    invariant_onlyAuthorizedCanModifyCriticalState();
    invariant_assetsCoverShares();
    invariant_userCannotWithdrawMoreThanEntitlement();
    invariant_nonceCannotMoveBackward();
    invariant_controllerRemainsReachable();
Each invariant documents its definition, protected property, threat model, relevant state, violation condition, test strategy, mitigation and regression strategy.