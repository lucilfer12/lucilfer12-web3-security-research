# Federated Research Sources

The central repository is the canonical knowledge and evidence layer, while related
repositories are registered as sources.

## Registered sources

- web3-smart-contract-forensics: public smart-contract finding corpus.
- security-invariant-lab: executable invariant and state-exploration lab.
- smart-contract-security-lab: Solidity/Foundry educational and regression lab.
- web3-zeroday-forensics: public incident and zero-day forensic corpus.
- private-security-research: restricted authorized-assessment workspace; its contents
  are not copied into the public corpus.
- Boot-trading: currently empty auxiliary repository.
- porsche-customer.github.io: separate public research surface, explicitly not canonical evidence.

Each source has a stable source ID in corpus/knowledge/sources.yaml. Cases can point to
source IDs, while the source registry preserves role and trust-boundary semantics.

## Federation rule

The central OS imports structure and provenance, not confidential material. Public or
external data remains attributed to its originating repository. A source reference does
not upgrade the evidentiary status of a case automatically.
