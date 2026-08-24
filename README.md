# crit

A fast, multi-language SAST and code-quality scanner built on
[tree-sitter](https://tree-sitter.github.io/).

crit parses source with real tree-sitter grammars and matches YAML rule packs
against the syntax tree. Rules come in two flavours: **pattern rules** (match a
shape in one file) and **taint rules** (track untrusted data from a *source*,
through assignments and function calls within a file, to a dangerous *sink*).
Findings are mapped to common frameworks — OWASP Top 10, CWE, and NIST
SP 800-53 — and rendered as readable terminal output or **SARIF 2.1.0** for CI
and GitHub code scanning.

## Highlights

- **Many languages, one engine.** Built-in grammars for InterSystems
  **ObjectScript**, **Pascal/Delphi**, **JavaScript**, **TypeScript/TSX**,
  **C#**, **Go**, and **Rust** — plus a runtime loader for *any* compiled
  tree-sitter grammar, no rebuild required.
- **Security frameworks built in.** Every security rule carries CWE, OWASP
  Top 10, and NIST control mappings, surfaced in both human and SARIF output.
- **Taint analysis, within and across files.** Field-sensitive, flow-aware
  data-flow tracking across assignments, sanitizers, and function calls (both
  directions), continuing **across module boundaries** via cached function
  summaries — with full source-to-sink traces that span files.
- **Identity-aware rules.** Sinks and sources can match by resolved identity
  (an imported `child_process.exec` reached through `import {exec as run}`),
  not just by spelling — driven entirely by declarative profile sections.
- **Explainable.** `crit explain <file>` shows scopes, how each call resolved,
  and why every sink did or didn't fire. Per-rule fixtures feed a *measured*
  SARIF precision instead of a guess.
- **Fast and parallel.** Files are parsed and analysed across all cores; a
  medium repo scans in milliseconds warm.
- **Differential scans.** `--diff-base <ref>` scans only what changed since a
  git ref (merge-base aware, includes uncommitted/untracked files).
- **Persistent state.** A content-hashed cache reuses results for unchanged
  files between runs; a baseline lets CI fail only on *new* findings.
- **SARIF 2.1.0** with `codeFlows` (taint traces) and stable
  `partialFingerprints`.

## Install

```sh
cargo build --release
# binary at target/release/crit
```

Requires a Rust toolchain and a C compiler (grammars build via `cc`).

## Quick start

```sh
# Scan the current repository
crit scan

# Scan specific paths, only security-critical severities gate CI
crit scan src/ --fail-on critical

# Only files changed since main, reusing cache for the rest
crit scan --diff-base origin/main

# Emit SARIF for GitHub code scanning
crit scan --format sarif -o crit.sarif

# What languages and rules are active?
crit languages
crit rules --verbose
```

Exit codes: `0` clean (or only findings below the `--fail-on` threshold),
`1` findings at/above the threshold, `2` a usage or internal error.

## Commands

| Command | Purpose |
|---------|---------|
| `crit scan [paths…]` | Scan for findings. Core flags below. |
| `crit rules` | List active rules (`--verbose` for metadata). |
| `crit languages` | List built-in and runtime-loaded languages. |
| `crit parse <file>` | Dump a file's syntax tree, or run a query with `-q` — the rule-authoring aid. |
| `crit explain <file>` | Show how the taint engine sees a file: scopes, call resolution, per-sink verdicts (incl. *why not*). `--rule <id>`, `--json`. |
| `crit rules verify` | Verify each rule against its per-rule fixtures (`--write-evidence` regenerates `rules/evidence.yaml`). |
| `crit coverage` | Report taxonomy coverage vs OWASP Top 10 and CWE Top 25. |
| `crit baseline update` | Record current findings as the accepted baseline. |
| `crit baseline info` | Show baseline stats. |
| `crit cache info` / `crit cache clear` | Inspect or drop the incremental cache and summaries. |

### Key `scan` flags

| Flag | Meaning |
|------|---------|
| `--diff-base <ref>` | Only scan files changed since a git ref. |
| `-f, --format <human\|json\|sarif>` | Output format (default `human`). |
| `-o, --output <file>` | Write output to a file. |
| `--sarif-out <file>` | Additionally write SARIF (any format). |
| `--rules <path>` | Load extra rule files/dirs (repeatable). |
| `--rule <id>` | Only run specific rule ids (repeatable). |
| `--lang <id>` | Restrict to languages (repeatable). |
| `--include`/`--exclude <glob>` | Narrow or widen the file set. |
| `--baseline` | Suppress findings recorded in the baseline. |
| `--fail-on <sev>` | Severity gating CI exit (`never` disables). Default `high`. |
| `--no-cache` | Disable the persistent cache for this run. |
| `-j, --jobs <n>` | Parallel scan threads. |

## Differential scans, caching & baselines

These three features cover distinct CI needs:

- **Scope** — `--diff-base origin/main` analyses only changed files. Untouched
  files are served from the cache, so the report still reflects the whole repo
  while doing minimal work.
- **Persistence** — results live in `.crit/cache.json`, keyed by file content
  hash **and** the compiled rule-set hash. Edit a rule and the cache
  invalidates automatically. Commit `.crit/cache.json` or not, as you prefer
  (it is git-ignored by default).
- **Baselines** — `crit baseline update` snapshots current findings by stable
  fingerprint into `.crit/baseline.json`. Then `crit scan --baseline` reports
  only findings *not* in the baseline, letting you adopt crit on a legacy
  codebase and gate CI on newly introduced issues only.

Fingerprints are independent of line numbers, so unrelated edits above a
finding don't churn the baseline.

## Rules

Rules are YAML. A **pattern rule** carries a tree-sitter query; the reported
node is the `@finding` capture (or the first capture). `${capture}`
placeholders in `message` are filled from query captures, and optional
`filters` add regex/equality checks on capture text.

```yaml
rules:
  - id: js.code-injection.eval
    severity: high
    category: security
    languages: [javascript, typescript, tsx]
    message: "`${callee}` executes dynamically constructed code"
    metadata:
      cwe: [CWE-95]
      owasp: ["A03:2021"]
      nist: [SI-10]
    query: |
      (call_expression
        function: (identifier) @callee
        (#any-of? @callee "eval" "Function")) @finding
```

A **taint rule** declares `sources`, `sinks`, and optional `sanitizers`,
each a tree-sitter query with a marker capture (`@source` / `@sink` /
`@sanitizer`). A finding is raised when tainted data reaches a sink without
passing through a sanitizer:

```yaml
  - id: js.sql-injection
    kind: taint
    severity: critical
    category: security
    languages: [javascript, typescript, tsx]
    message: "User-controlled data flows into a SQL query"
    metadata: { cwe: [CWE-89], owasp: ["A03:2021"], nist: [SI-10] }
    sources:
      - label: HTTP request data
        query: |
          ((member_expression) @source
            (#match? @source "^req\\.(query|body|params)"))
    sinks:
      - label: SQL query execution
        query: |
          (call_expression
            function: (member_expression property: (property_identifier) @m)
            arguments: (arguments . (_) @sink)
            (#any-of? @m "query" "execute"))
    sanitizers:
      - query: '((call_expression function: (identifier) @f) @sanitizer (#eq? @f "parseInt"))'
```

Taint semantics are flow- and field-aware: within a scope a use is tainted
only by assignments that **textually precede** it (so a value tainted *after* a
sink use is not reported), and taint is tracked per access path — tainting `o`
reaches `o.v`, a tainted `o.v` reaches a read of `o`, but `o.a` and `o.b` stay
distinct. Cross-scope reads (closures) stay position-insensitive.

**Identity matchers.** Instead of a `query`, a source/sink/sanitizer may use a
`resolved` matcher that matches by *what a name refers to* — so an imported
function reached under an alias is still caught:

```yaml
    sinks:
      - label: child_process execution
        resolved: { module: child_process, name: exec, arg_index: 0 }
    sources:
      - label: request data
        resolved: { member_of: req, path: [query] }
```

A sink matcher takes `module?`, `name`, `arg_index?` (default: all args), and
`match_unresolved` (default false — identity rules never silently fall back to
matching by bare text). This catches `import {exec as run} from 'child_process';
run(x)` that a name query cannot. Identity matching needs the language's
binding profile sections (below); where they are absent the `query` form still
works. `crit explain <file>` shows exactly how each call resolved and why each
sink did or didn't fire.

**Evidence & precision.** A rule may carry fixtures under
`rules/<lang>/tests/<rule-id>/`, annotated inline with `// crit:expect <id>`
and `// crit:expect-not <id>`. `crit rules verify` checks them; `--write-evidence`
records verified counts in `rules/evidence.yaml`, from which SARIF `precision`
is derived (≥2 positive + ≥2 negative → `high`, ≥1 each → `medium`, none →
`low`). Precision is measured, never asserted.

Load your own rules with `--rules <path>` or the `[scan] rules` config key.
Use `crit parse <file>` (optionally `-q '<query>'`) to explore a grammar's
node kinds while authoring, and `crit explain <file>` to see the resolved view.

Built-in packs live in [`rules/`](rules/); taint profiles that map each
grammar's node kinds to the engine's concepts live in
[`profiles/`](profiles/).

### Validating rules

Every rule ships with fixtures that prove it fires where it must and stays
quiet where it must not. Fixtures live in a per-rule directory,
`rules/<lang>/tests/<rule-id>/`, and carry inline expectation annotations:

```objectscript
    // crit:expect os.sql-injection
    set rc = stmt.%Prepare("SELECT ..." _ id)          // must produce this finding
    // crit:expect-not os.sql-injection
    set rc = stmt.%Prepare("SELECT ... WHERE id=?")    // must NOT (false-positive guard)
```

`crit:expect <id>` means the annotated line must yield that finding (for taint
rules, the **sink** line); `crit:expect-not <id>` marks a deliberately-safe
variant that must stay silent. Verification is strict: every `expect` must
fire, every `expect-not` must stay clean, and no finding may land on an
unannotated line.

```sh
crit rules verify                    # verify every rule against its fixtures
crit rules verify --write-evidence   # regenerate rules/evidence.yaml
```

Verified counts land in [`rules/evidence.yaml`](rules/evidence.yaml) and drive
each rule's SARIF `precision` (≥2 positives and ≥2 negatives → `high`). The
command exits non-zero on any unmet expectation, so it is the CI gate and the
inner loop for rule authoring.

### Measuring comprehensiveness

Two objective views of how complete the rules are, documented in
[`COVERAGE.md`](COVERAGE.md):

- **Taxonomy coverage** — `crit coverage` maps the CWE/OWASP tags every rule
  carries against the OWASP Top 10 (2021) and MITRE CWE Top 25 (2023), turning
  "comprehensive" into a tracked fraction per language.
- **External benchmark** — for C# (which the same engine analyses), the
  [`benchmarks/juliet/`](benchmarks/juliet/) harness scores crit against the
  NIST Juliet corpus with OWASP-Benchmark-style precision/recall/Youden's J,
  giving an externally-anchored measure of the engine and rule methodology.
  No comparable labelled corpus exists for ObjectScript or Delphi.

## Adding a language without rebuilding

Compile any tree-sitter grammar to a shared library and register it in
`crit.toml`:

```toml
[[grammars]]
name = "sql"
library = "grammars/libtree-sitter-sql.so"
extensions = ["sql"]
profile = "profiles/sql.yaml"   # optional; enables taint rules
```

`profile` points to a YAML file mapping the grammar's node kinds to crit's
taint concepts (assignments, functions, params, calls, returns, identifier
kinds). Without a profile the language still supports pattern rules. See
[`crit.toml.example`](crit.toml.example) and the built-in
[`profiles/`](profiles/) for the format.

A profile may also declare optional **binding sections** that power identity
matching and cross-file taint — all are safe to omit (a profile without them
behaves exactly as before):

- `member_access` — a field read (`@object`, `@field`, `@access`).
- `method_calls` — a call on a receiver (`@receiver`, `@method`, `@args`, `@call`).
- `imports` — `@module`, `@name`, optional `@alias`.
- `exports` — `@name`.
- `module_resolution` — `{ strategy: path | symbol, extensions, index_files }`;
  `path` resolves relative import specifiers to files (JS/TS), `symbol` matches
  a declared module/namespace name (Go/C#/Rust).

## Configuration

Drop an `crit.toml` at your repo root (see
[`crit.toml.example`](crit.toml.example)) for rule directories, ignore globs,
extension overrides (e.g. treat `.inc` as Pascal), external grammars, and the
default `fail_on` threshold. CLI flags always win.

## CI example (GitHub Actions)

```yaml
- name: crit scan
  run: crit scan --diff-base origin/${{ github.base_ref }} --format sarif -o crit.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: crit.sarif
```

## Cross-file taint

Taint tracking follows flows **across files**: a source in one module that
reaches a sink in another is reported, with a trace that spans both files
(rendered as `otherfile:line` steps and SARIF `codeFlow` locations in the
dependency). Two patterns are covered — a dependency that returns
request-derived data to a caller which sinks it, and a caller that passes
tainted data into a dependency function that sinks it.

Analysis runs in three phases: each file is **summarised** (intra-file
function facts, cached content-addressed under `.crit/summaries/`), summaries
are **linked** through the import graph, then each file is **evaluated** with
its dependencies' summaries. The findings cache is keyed by file content *and*
a link fingerprint over the summaries a file depends on, so editing a
dependency correctly re-evaluates its dependents on the next scan.

Two limitations in this release: cross-file chains deeper than a direct
call/return (a summary built from another cross-file summary) are not tracked;
and `--diff-base` scans do not yet surface cross-file findings in files outside
the changed set (run a full scan for complete cross-file results).

## Design

```
crit (CLI)
└── crit-core
    ├── languages/   grammar registry (builtin + runtime .so) + taint profiles
    ├── rules/       YAML model, loader, per-language query compilation
    ├── engine/      per-file: pattern matching + intra-file taint propagation
    ├── scanner      discovery, git-diff scoping, parallelism, cache, baseline
    ├── state/       .crit/ cache + baseline persistence
    └── output/      human, JSON, SARIF 2.1.0
```

Taint analysis is intra-file by design in this release: it tracks flows within
a file, including across functions in that file, via lightweight function
summaries. The IR is structured so cross-file, whole-program propagation can be
layered on without reworking the engine.

## License

Released under the MIT License — see [LICENSE](LICENSE). Third-party
components are inventoried in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
