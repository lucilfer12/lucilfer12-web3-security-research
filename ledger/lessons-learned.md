# Lessons Learned
## Impact must be unit-aware
A raw integer difference is not an economic amount until token decimals and execution semantics are known.
## Privilege changes impact
A privileged-role prerequisite must be recorded explicitly.
## Applicability is separate from technical behavior
A replay-sensitive transition can exist while the affected feature is not active in the relevant production population.
## Lifecycle invariants deserve explicit tests
Every mutation that can remove the final authorization path should be covered by a reachability invariant.