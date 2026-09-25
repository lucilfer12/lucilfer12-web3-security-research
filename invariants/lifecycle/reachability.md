# Controller Reachability
Property: A lifecycle operation must not permanently remove the final state needed to satisfy the authorization path.
Generic model:
    reachable(controller_state) == true
Every operation capable of removing a controller or key should be tested against the final-key boundary.