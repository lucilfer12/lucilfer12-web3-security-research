# Web3 Security Research
**A reproducible research environment for adversarial analysis of decentralized systems.**
This repository is a long-lived research record rather than a collection of claims. It connects threat modeling, security invariants, state-transition analysis, adversarial testing, reproducible proof-of-concepts, remediation, regression evidence, incident forensics, and generalized security patterns.
## Research loop
Observe -> Model -> Hypothesize -> Formalize -> Attack -> Reproduce -> Measure -> Harden -> Regress -> Generalize
## Research domains
- Smart-contract and EVM security
- DeFi accounting, solvency, liquidation and economic invariants
- Authorization and privilege boundaries
- Lifecycle and state-machine failures
- Replay protection and nonce semantics
- Bridges and cross-domain message security
- Oracle and pricing assumptions
- Protocol-runtime security
- Public incident reconstruction and forensic analysis
## Repository map
| Area | Purpose |
|---|---|
| docs/ | Research doctrine, methodology and operating standards |
| atlas/ | Security-domain map and terminology |
| invariants/ | Security properties and testable invariants |
| labs/ | Small adversarial models and regression experiments |
| case-studies/ | Carefully classified research records |
| corpus/ | Structured research corpus and provenance |
| schemas/ | Validation contracts |
| src/w3sec/ | Lightweight CLI and validation utilities |
| templates/ | Reusable research templates |
| experiments/ | Hypotheses and experimental records |
| ledger/ | Research provenance and lessons |
## Evidence standard
A security claim should be traceable through:
Claim -> Source/Code -> Security Property -> Reproduction -> Observed Failure -> Impact -> Mitigation -> Regression
Status is explicit. A validated/fixed finding is not presented as equivalent to an informative, duplicate, experimental, or still-private report.
## Existing research
This hub is additive. It does not replace existing repositories or history.
- lucilfer12/web3-smart-contract-forensics
- lucilfer12/security-invariant-lab
- lucilfer12/smart-contract-security-lab
- lucilfer12/web3-zeroday-forensics
- lucilfer12/private-security-research
## Responsible disclosure
Do not publish private reports, client information, credentials, KYC data, unreleased exploit details, or confidential triage material.
## Reproducibility
Run:
    python -m w3sec validate
    python -m unittest discover -s tests -v
The project grows through evidence-backed research, not artificial volume.