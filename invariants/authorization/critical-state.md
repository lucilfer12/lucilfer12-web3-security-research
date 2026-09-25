# Critical-State Authorization
Property: Only explicitly authorized actors may mutate security-critical state.
Questions:
- Is authorization checked at every externally reachable boundary?
- Can delegated calls bypass the check?
- Can a privileged parameter violate a semantic range after authorization succeeds?