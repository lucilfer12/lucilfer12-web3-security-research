# Replay Protection
Property: Consumed authorization state must not become valid again through a key lifecycle transition.
Minimal model:
    nonce_after >= nonce_before
Real coverage should include deletion/re-addition, key identity, validity windows and cross-domain replay semantics.