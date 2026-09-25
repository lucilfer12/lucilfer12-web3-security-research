# Replay Lab
Models authorization keys and consumed nonces across lifecycle transitions.
Core sequence:
    Create -> Authorize -> Consume -> Remove -> Re-add -> Reuse
A replay result is meaningful only after validity windows and production applicability are established.