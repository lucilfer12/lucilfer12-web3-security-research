# NEAP-658  Gas-Key Nonce Reset and Replay Window

## Research question

Can a key lifecycle transition invalidate the monotonicity assumption relied upon by DelegateAction replay protection?

## Model

    existing gas key
        -> executed DelegateAction
        -> delete key
        -> re-add key
        -> nonce reset
        -> previously executed action may become acceptable within its remaining validity window

## Evidence classification

The supplied triage outcome classified the report as Informative and duplicate of NEAP-344, with production applicability considered Not Applicable under the protocol-version context described at the time.

## Research lesson

Protocol security requires distinguishing technical behavior from production applicability. Both belong in the research record.
