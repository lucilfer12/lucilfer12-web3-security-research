# ATLAS Windows Release — 2026-09-30

Source: active repository checkout on branch `research-os/longitudinal-expansion-2026-09-27`.

Build:
- source commit: `c074fa6c823da90d520978d37185aeb795aa41b5`
- built_at_utc: 2026-09-30T19:09:57.6332690Z
- platform: windows-x64
- python: 3.12.8
- pyinstaller: 6.22.3
- GUI SHA-256: F43E8B2B4EEE84A05A40FA3434E3CF73F4F3863D20C39775EB87BD37B80C61DA
- CLI SHA-256: 272A1BFBE08212397C94D8576A025FAB20E22E97416A7D7FA19D7E20102A1965
- bundle SHA-256: a2a813a552834a83e77832231c92cf94838b7e16bc1e5fa09424c5264785af72
- source mode: active-repository

Quality gates:
- 57 unit/integration tests: OK
- packaged CLI smoke: OK
- target-binding regression: OK
- Rust supporting-code retention regression: OK
- nearcore total-supply recall regression: OK

Security-analysis changes:
- Rust is no longer silently excluded from audit coverage.
- fuzz/tests/benchmarks are analyzed as supporting evidence instead of being treated as production attack surface.
- Cargo metadata defines the Rust production graph reachable from `neard`.
- semantic Rust analysis adds taint-aware panic, resource, arithmetic, deserialization, and gas-ordering checks.
- historical nearcore total-supply validation is represented as a recall regression.
- findings expose scope, reachability, confidence, guards, entry-point context, and triage score.
- static/semantic findings remain review leads until security property, reproduction, impact, and independent verification exist.

Nearcore EXE verification:
- archive: `nearcore-master.zip`
- source files: 1323
- production findings: 335
- supporting findings: 1053
- semantic findings in primary report: 506
- invalid production-scope test/benchmark paths: 0
- automatic high/critical claims: 0

The current Windows artifact is `ATLAS-windows-x64-v2026.09.30.zip`.
