# Contributing to crit

## Prerequisites

- A Rust toolchain (stable) and a C compiler — the tree-sitter grammars build
  via `cc`.
- Python 3 (only for the Juliet benchmark harness).

## Build & test

```sh
cargo build --release        # binary at target/release/crit
cargo test --release         # unit + integration tests
cargo fmt --all -- --check   # formatting gate
cargo clippy --all-targets -- -D warnings
```

All four must pass; CI enforces them (`.github/workflows/ci.yml`, and
`azure-pipelines.yml` for the internal ADO mirror).

## Writing rules

Rules are YAML in `rules/<lang>/`. Two kinds: **pattern** rules (one
tree-sitter query with a `@finding` capture) and **taint** rules
(`sources`/`sinks`/`sanitizers`). See the [README](README.md#rules) for the
schema and `crit parse <file> -q '<query>'` for exploring a grammar's nodes.

Every rule **must** ship with fixtures that prove it. Fixtures live in a
per-rule directory, `rules/<lang>/tests/<rule-id>/`, and use inline
annotations:

- `crit:expect <rule-id>` — the annotated line must produce that finding.
- `crit:expect-not <rule-id>` — a deliberately-safe line that must not.

Aim for at least 2 of each (that earns `high` SARIF precision). Verify with:

```sh
crit rules verify                    # every rule against its fixtures
crit rules verify --write-evidence   # regenerate rules/evidence.yaml after changes
```

`crit rules verify` is strict — an expected finding that doesn't fire, a safe
line that does, or a finding on an unannotated line all fail. A change that
adds or edits a rule should keep `crit rules verify` green and update
`rules/evidence.yaml`.

## Adding a language

Grammars can be compiled in (a workspace dependency + a builtin registration)
or loaded at runtime from a shared library via `[[grammars]]` in `crit.toml`.
Taint support needs a profile in `profiles/<lang>.yaml`. See the README's
"Adding a language" section.

## Pull requests

- Keep the CI gates green (fmt, clippy, tests, `crit rules verify`).
- New security rules should carry CWE / OWASP / NIST metadata so
  `crit coverage` stays meaningful.
- Update `COVERAGE.md` when you add or close a coverage class.
