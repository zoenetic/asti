# Rule coverage & validation

This document is the coverage map and the definition of "done" for crit's
security and quality rules, focused on the two priority languages —
**InterSystems ObjectScript** and **Pascal/Delphi**. It is meant to stay
honest: every rule listed here ships with per-rule fixtures and is verified by
`crit rules verify` (see below). Coverage that does not yet exist is listed
under *Gaps & roadmap* rather than implied.

## How rules are validated

Each rule has a fixture directory, `rules/<lang>/tests/<rule-id>/`, whose files
mark expectations inline:

- `crit:expect <id>` — the annotated line **must** produce that finding (for a
  taint rule, that line is the *sink*).
- `crit:expect-not <id>` — a deliberately-safe variant that **must not** fire;
  this is how false positives are caught.

`crit rules verify` scans each rule's directory with only that rule enabled and
checks strictly: every `expect` fires, every `expect-not` stays clean, and no
finding lands on an unannotated line. Verified counts are recorded in
[`rules/evidence.yaml`](rules/evidence.yaml) and drive each rule's SARIF
`precision` (≥2 positives and ≥2 negatives → `high`). It is the CI gate
(`.github/workflows/ci.yml`) and the inner loop for authoring rules.

## Objective comprehensiveness measures

Two complementary, objective views — because "comprehensiveness" splits into
*taxonomy completeness* (is there a rule per class?) and *recall* (do we catch
real instances?), and only the first has an external anchor for these languages.

- **Taxonomy coverage** — `crit coverage` scores the CWE/OWASP tags every rule
  carries against the OWASP Top 10 (2021) and MITRE CWE Top 25 (2023). Current:

  | Language | OWASP Top 10 | CWE Top 25 | distinct CWEs |
  |----------|:---:|:---:|:---:|
  | ObjectScript | 7/10 | 8/25 | 17 |
  | Delphi/Pascal | 6/10 | 5/25 | 14 |
  | All languages | 9/10 | 9/25 | 25 |

  The CWE Top 25 fraction is deliberately un-massaged: several of its entries
  are memory-safety weaknesses (out-of-bounds, use-after-free, NULL deref) that
  do not apply to managed ObjectScript and are rare in typical Delphi
  DB/business code. Read the per-item list from `crit coverage`, not the bare
  fraction.

- **External benchmark (engine)** — no labelled corpus exists for ObjectScript
  or Delphi, so recall cannot be measured against an external oracle for them.
  It *can* for **C#**, which the same engine analyses: the
  [`benchmarks/juliet/`](benchmarks/juliet/) harness scores crit against the
  NIST Juliet C# suite (precision, recall, FPR, Youden's J), with a
  baseline-vs-flow-variant split that isolates where cross-file taint does not
  yet reach.
  A strong score there is transferable evidence the engine and rule methodology
  are sound; the language packs are then a matter of breadth, tracked below.

## ObjectScript — 24 rules

| Class | Rules | CWE | Kind | Status |
|-------|-------|-----|------|--------|
| SQL injection | `os.sql-injection` | CWE-89 | taint | ✅ |
| Code injection (XECUTE) | `os.code-injection.xecute-taint`, `os.code-injection.xecute` | CWE-95 | taint + pattern | ✅ |
| Code injection (indirection `@`) | `os.code-injection.indirection` | CWE-95 | pattern | ✅ |
| OS command injection (`$ZF`) | `os.cmd-injection.zf`, `os.cmd-injection.zf-usage` | CWE-78 | taint + pattern | ✅ |
| Reflected XSS (CSP `write`) | `os.xss.csp-write` | CWE-79 | taint | ✅ |
| Path traversal / unsafe file access | `os.path-traversal`, `os.path-traversal.usage` | CWE-22 | taint + pattern | ✅ |
| SSRF (`%Net.HttpRequest`) | `os.ssrf`, `os.ssrf.usage` | CWE-918 | taint + pattern | ✅ |
| Weak cryptography | `os.weak-crypto` | CWE-327/328 | pattern | ✅ |
| Hardcoded encryption key/IV | `os.hardcoded-crypto-key` | CWE-321 | pattern | ✅ |
| Hardcoded credentials | `os.hardcoded-secret`, `os.hardcoded-credential`, `os.hardcoded-credential.sysfunc` | CWE-798 | pattern | ✅ |
| Sensitive data in logs | `os.sensitive-data-log` | CWE-532 | pattern | ✅ |
| Privileged / system calls (`$ZU`, `%SYSTEM.*`) | `os.privileged-call` | CWE-250/272 | pattern | ✅ |
| Quality | `os.quality.goto`, `os.quality.empty-catch`, `os.quality.deprecated-ztrap`, `os.quality.deprecated-zutil`, `os.quality.debug-zwrite`, `os.quality.debug-break` | — | pattern | ✅ |

## Pascal / Delphi — 18 rules

| Class | Rules | CWE | Kind | Status |
|-------|-------|-----|------|--------|
| SQL injection | `pas.sql-injection` | CWE-89 | taint | ✅ |
| OS command injection | `pas.cmd-injection`, `pas.cmd-injection.usage` | CWE-78 | taint + pattern | ✅ |
| Format-string injection | `pas.format-string`, `pas.format-string.usage` | CWE-134 | taint + pattern | ✅ |
| Path traversal | `pas.path-traversal`, `pas.path-traversal.usage` | CWE-22 | taint + pattern | ✅ |
| Insecure randomness | `pas.insecure-random` | CWE-330 | pattern | ✅ |
| Insecure TLS / cert validation | `pas.insecure-tls` | CWE-295 | pattern | ✅ |
| Weak cryptography (hash) | `pas.weak-crypto.hash` | CWE-327/328 | pattern | ✅ |
| Weak cipher mode (DES/RC4/ECB) | `pas.weak-cipher-mode` | CWE-327 | pattern | ✅ |
| Hardcoded key/secret | `pas.hardcoded-secret`, `pas.hardcoded-crypto-key` | CWE-321/798 | pattern | ✅ |
| DLL hijacking | `pas.dll-hijack` | CWE-427 | pattern | ✅ |
| Unsafe deserialization | `pas.unsafe-deserialization` | CWE-502 | pattern | ✅ |
| Quality | `pas.quality.with-statement`, `pas.quality.empty-except`, `pas.quality.catch-all-except` | — | pattern | ✅ |

Every security rule carries CWE, OWASP Top 10, and NIST SP 800-53 mappings,
surfaced in human output and in SARIF (`security-severity`, `external/cwe/*`
tags) for GitHub code scanning.

## Gaps & roadmap

Known limits, in the order they most affect real-world results:

1. **Cross-file taint exists but has coverage gaps.** The engine tracks taint
   across module boundaries via cached function summaries, but not every
   inter-file/inter-procedural shape resolves yet — e.g. a value passed into an
   instance method on a freshly constructed object in another file is currently
   missed (the Juliet `_81` variant in `benchmarks/juliet/sample`). Widening
   call resolution so more of these connect is the priority engine item; the
   Juliet flow-variant recall split is the metric that tracks it.

2. **Parser robustness is unmeasured on real corpora.** Rules can only fire on
   code tree-sitter parses cleanly. A known example surfaced while authoring:
   the Pascal grammar emits `ERROR` nodes for `goto`/`label`, so a `goto`
   quality rule was intentionally dropped rather than shipped broken. Next
   step: a real-world corpus harness that measures the `ERROR`-node rate per
   file and gates regressions (InterSystems Open Exchange / IRIS samples for
   ObjectScript; the Lazarus/FreePascal ecosystem for Delphi). Danger zones to
   expect: ObjectScript macros (`$$$macro`, `#define`), embedded `&sql`/CSP;
   Delphi conditional compilation (`{$IFDEF}`), include files, inline `asm`.

3. **Coverage still has whitespace.** Not yet covered, roughly by value:
   ObjectScript — missing CSP-page authentication (class-parameter check),
   unvalidated redirect, insecure global/subscript access. Delphi — integer
   overflow/range, unsafe `Move`/`PChar` buffer operations, XXE
   (`TXMLDocument`), insecure temp-file creation.

4. **Ground truth is synthetic.** Precision/recall today is measured against
   fixtures we authored. A held-out corpus labelled by an ObjectScript/Delphi
   SME — and positives seeded from public advisories — would give an honest
   recall number that rule authors cannot inadvertently teach to.

The bar for calling a class "done": a green row above **and** survival on the
real-world corpus once that harness lands.
