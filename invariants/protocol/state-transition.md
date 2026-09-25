# State Transition Integrity
Every externally influenced transition should preserve protocol safety properties across:
    State_n -> Action -> Validation -> State_n+1
Research should identify validation assumptions invalidated by lifecycle, upgrade, serialization or replay transitions.