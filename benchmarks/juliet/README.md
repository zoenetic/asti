# Juliet C# benchmark

An **objective, externally-anchored** measurement of crit's engine and rule
methodology, using the NIST Juliet C# test suite — a large, CWE-labelled corpus
that crit's authors did not write.

This does **not** measure the ObjectScript or Delphi rules (no comparable
labelled corpus exists for those languages — see [`../../COVERAGE.md`](../../COVERAGE.md)).
It measures the *engine* and the *rule-authoring methodology* on ground truth
nobody here authored, which is the closest thing to an objective SAST benchmark
available for a language crit supports.

## Why this is the right anchor

The standard SAST benchmarks (OWASP Benchmark, NIST SARD/Juliet) cover only
mainstream languages. crit supports one of them — **C#** — via the same engine,
rule model, and taint analysis used for ObjectScript and Delphi. So a strong
score here is evidence the machinery is sound; the language-specific packs are
then a question of rule breadth, tracked separately in `COVERAGE.md`.

## Getting the corpus

The corpus is **not** vendored here (it is large and separately licensed, and
this repo's CI network policy blocks the NIST host). Download the **Juliet C#
1.3** test suite from the NIST SARD test-suites page
(<https://samate.nist.gov/SARD/test-suites>) and unpack it. You want the tree of
`.cs` testcase files, conventionally under `src/testcases/CWE*/`.

## Running

```sh
cargo build --release
python3 benchmarks/juliet/score.py /path/to/juliet-csharp/src/testcases
```

Options: `--crit <path>` (default `./target/release/crit`), `--mapping <file>`
(default [`mapping.json`](mapping.json)), `--json` for machine-readable output.

A tiny **Juliet-shaped sample** lives in [`sample/`](sample/) so you can see the
harness work without the full download (and so CI can smoke-test the scorer):

```sh
python3 benchmarks/juliet/score.py benchmarks/juliet/sample
```

## What it scores, and how

Only the CWEs crit has C# rules for are scored; [`mapping.json`](mapping.json)
maps each Juliet CWE folder to the crit rule id(s) that target it. CWEs present
in the corpus with no mapped rule are listed as *unmapped* and **not** counted
against crit (crit makes no claim to cover them).

Scoring is the standard robust Juliet convention:

- **Bad paths, per testcase** — one expected detection per testcase (files that
  differ only by a trailing variant letter, e.g. `_81a`/`_81b`, are one
  testcase). A testcase is a **true positive** if a matching-CWE finding lands
  in any `Bad`-named method or class; a **false negative** otherwise. Per-testcase
  scoring avoids penalising multi-file variants whose `Bad()` source method
  holds no sink.
- **Good constructs, per region** — every `Good`-named method/class is an
  independent negative: a matching finding there is a **false positive**,
  silence is a **true negative**. Bad/good is read from the method name first,
  then the enclosing class name (Juliet's inter-file variants discriminate on
  the class, e.g. `..._81_bad`).

Reported per CWE and overall: precision, recall, false-positive rate, and
**Youden's J** (`recall − FPR`), the OWASP Benchmark score. A dominant strategy
scores J → 1.0; random guessing scores 0.

## The variant breakdown matters

The report splits recall into **baseline** (variant `01`, single-file,
intra-procedural) and **flow-variant** (everything else, including the
inter-file `_5x`/`_8x` families). crit tracks taint **across files** via cached
function summaries, but not every inter-file/inter-procedural shape resolves
yet, so baseline is expected to score well while some flow variants still miss.
That split turns the benchmark into a precise diagnostic — it attributes misses
to specific unresolved call shapes rather than to rule gaps, and it is exactly
the signal that tracks the cross-file coverage work in `COVERAGE.md`.
