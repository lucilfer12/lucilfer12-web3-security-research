# ATLAS Windows Release — 2026-09-30

Source: active repository checkout on branch `research-os/longitudinal-expansion-2026-09-27`.

Build:
- built_at_utc: 2026-09-30T18:35:53.1281311Z
- platform: windows-x64
- python: 3.12.8
- pyinstaller: 6.22.3
- GUI SHA-256: 39259359139DB40F6D179B75C2A4A3A5EAA74258934DC3F248FFDF30B3516E1B
- CLI SHA-256: 43DF36875B8CF20942AAB5D1760E0338CD202E038030C7B06C425E73D5C9F2E9
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