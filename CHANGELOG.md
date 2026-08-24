# Changelog

Notable changes to crit. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

Consolidated the project onto a single `main` branch and prepared it for
handover to the owning organization.

### Added

- Cross-file taint analysis via cached function summaries, with
  identity-resolved sources/sinks and `crit explain` for per-sink verdicts
  (including *why not*).
- Per-rule evidence harness: `crit rules verify` checks each rule against
  fixtures in `rules/<lang>/tests/<rule-id>/` (`crit:expect` /
  `crit:expect-not`), recorded in `rules/evidence.yaml` and driving SARIF
  precision.
- ObjectScript and Delphi security/quality rule packs — path traversal, SSRF,
  weak crypto, hardcoded keys/credentials, privileged calls, sensitive-data
  logging, format-string injection, insecure TLS, weak cipher modes, DLL
  hijacking, unsafe deserialization, and quality rules.
- `crit coverage` — taxonomy coverage against OWASP Top 10 (2021) and MITRE
  CWE Top 25 (2023).
- Juliet C# benchmark harness (`benchmarks/juliet/`) for an externally-anchored
  precision/recall figure.
- Project governance and hygiene for handover: `LICENSE` (MIT), `SECURITY.md`,
  `CONTRIBUTING.md`, `CHANGELOG.md`, `THIRD-PARTY-NOTICES.md`, `.github/CODEOWNERS`,
  and an `azure-pipelines.yml` mirroring the GitHub Actions CI.

### Changed

- **Renamed the project from `asti` to `crit`** — binary, crates (`crit`,
  `crit-core`), config file (`crit.toml`), state directory (`.crit/`), custom
  ignore file (`.critignore`), and fixture annotation markers (`crit:expect`).
- SARIF `informationUri`/`helpUri` now derive from the crate `repository` field
  (set it in the workspace `Cargo.toml`) instead of a hard-coded URL.
