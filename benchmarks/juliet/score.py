#!/usr/bin/env python3
"""Score crit against the NIST Juliet C# test suite (or any Juliet-shaped tree).

Juliet is an externally-authored, CWE-labelled corpus, so running crit's C#
rules against it yields an *objective* precision/recall figure on ground truth
we did not write. That number does not validate the ObjectScript/Delphi rules,
but it validates the engine and the rule methodology on a standard benchmark.

Scoring follows the standard robust convention for Juliet:

* Each testcase names its methods/classes `Bad*` (vulnerable) and `Good*`
  (fixed). Files that share a base name differing only by a trailing variant
  letter (e.g. `_81a`/`_81b`) are one testcase.
* Bad paths are scored per-testcase — one expected detection per testcase — so
  a multi-file variant whose `Bad()` "source" method holds no sink does not
  create a spurious miss.
* Good constructs are scored per-region — each is an independent chance to
  raise a false positive.

We report per-CWE precision, recall, false-positive rate and Youden's J
(recall - FPR, the OWASP Benchmark score), plus a baseline-vs-flow-variant
recall split that isolates where crit's cross-file taint does not yet reach
(some inter-file Juliet variants are still expected to miss).

Usage:
    python3 benchmarks/juliet/score.py <testcases_dir> \
        [--crit ./target/release/crit] [--mapping benchmarks/juliet/mapping.json] [--json]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

CWE_IN_NAME = re.compile(r"CWE(\d+)")
VARIANT = re.compile(r"_(\d+)([a-z])?\.cs$", re.IGNORECASE)
IDENT = re.compile(r"[A-Za-z_]\w*")
KEYWORDS = {
    "if", "for", "while", "switch", "catch", "using", "lock", "fixed",
    "foreach", "return", "sizeof", "typeof", "nameof", "new",
}


def strip_code(text: str) -> str:
    """Replace comments and string/char literals with spaces, preserving
    newlines and offsets, so brace scanning is not fooled by braces inside
    strings or comments."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        two = text[i : i + 2]
        if two == "//":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if two == "/*":
            while i < n and text[i : i + 2] != "*/":
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            out.append("  ")
            i += 2
            continue
        if c == '"' and text[i - 1 : i] == "@":
            out.append(" ")
            i += 1
            while i < n:
                if text[i : i + 2] == '""':
                    out.append("  ")
                    i += 2
                    continue
                if text[i] == '"':
                    break
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            out.append(" ")
            i += 1
            continue
        if c == '"':
            out.append(" ")
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    out.append("  ")
                    i += 2
                    continue
                out.append(" ")
                i += 1
            out.append(" ")
            i += 1
            continue
        if c == "'":
            out.append(" ")
            i += 1
            while i < n and text[i] != "'":
                if text[i] == "\\":
                    out.append("  ")
                    i += 2
                    continue
                out.append(" ")
                i += 1
            out.append(" ")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def method_regions(text: str):
    """Return [(name, class_name, start_line, end_line)] for methods declared
    directly in a class/struct/interface body, via a comment/string-stripped
    brace scan that also tracks the enclosing type name."""
    s = strip_code(text)
    regions = []
    depth = 0
    line = 1
    class_body_depths = set()
    class_stack = []          # (class_name, body_depth)
    method_stack = []         # (name, start_line, depth_before_open, class_name)
    saw_type_kw = False
    expect_class_name = False
    pending_class_name = None
    pending_method_name = None
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        m = IDENT.match(s, i)
        if m:
            word = m.group(0)
            i = m.end()
            if word in ("class", "struct", "interface"):
                saw_type_kw = True
                expect_class_name = True
                continue
            if expect_class_name:
                pending_class_name = word
                expect_class_name = False
                continue
            # identifier immediately followed by '(' at class-body depth,
            # whose ')' is followed by '{', is a method declaration.
            j = i
            while j < n and s[j] in " \t":
                j += 1
            if j < n and s[j] == "(" and word not in KEYWORDS:
                pd, k = 0, j
                while k < n:
                    if s[k] == "(":
                        pd += 1
                    elif s[k] == ")":
                        pd -= 1
                        if pd == 0:
                            break
                    k += 1
                k += 1
                while k < n and s[k] in " \t\r\n":
                    k += 1
                if k < n and s[k] == "{" and depth in class_body_depths:
                    pending_method_name = word
            continue
        if c == "{":
            if saw_type_kw:
                class_body_depths.add(depth + 1)
                class_stack.append((pending_class_name, depth + 1))
                pending_class_name = None
                saw_type_kw = False
            elif pending_method_name is not None:
                cls = class_stack[-1][0] if class_stack else None
                method_stack.append((pending_method_name, line, depth, cls))
                pending_method_name = None
            depth += 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            class_body_depths.discard(depth + 1)
            if class_stack and class_stack[-1][1] == depth + 1:
                class_stack.pop()
            if method_stack and method_stack[-1][2] == depth:
                name, start, _, cls = method_stack.pop()
                regions.append((name, cls, start, line))
            i += 1
            continue
        if c == ";":
            saw_type_kw = False
            expect_class_name = False
            pending_method_name = None
        i += 1
    return regions


def classify(name: str, cls: str | None):
    """bad/good for a region, preferring the method name, then the class name
    (Juliet's inter-file variants discriminate on the class, e.g. `_81_bad`)."""
    for token in (name or "", cls or ""):
        low = token.lower()
        if "good" in low:
            return "good"
        if "bad" in low:
            return "bad"
    return None


def innermost_region(regions, ln):
    best = None
    for r in regions:
        _name, _cls, start, end = r
        if start <= ln <= end and classify(_name, _cls):
            if best is None or (end - start) < (best[3] - best[2]):
                best = r
    return best


def run_crit(crit: str, target: str):
    proc = subprocess.run(
        [crit, "scan", target, "--format", "json", "--fail-on", "never", "--no-cache"],
        capture_output=True,
        text=True,
    )
    if not proc.stdout.strip():
        sys.exit(f"crit produced no output (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)["findings"]


def variant_bucket(fname: str) -> str:
    m = VARIANT.search(fname)
    if m and m.group(1).lstrip("0") in ("", "1") and not m.group(2):
        return "baseline"
    return "flow-variant"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("testcases", help="Juliet testcases directory")
    ap.add_argument("--crit", default="./target/release/crit")
    ap.add_argument("--mapping", default=str(Path(__file__).parent / "mapping.json"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    mapping = json.loads(Path(args.mapping).read_text())
    findings = run_crit(args.crit, args.testcases)

    by_file: dict[str, list] = {}
    for f in findings:
        by_file.setdefault(Path(f["file"]).name, []).append(
            (f["span"]["start"]["line"], f["rule_id"])
        )

    # Group files into testcases (shared base name modulo trailing variant letter).
    testcases: dict[tuple, list] = {}
    unmapped = set()
    for path in sorted(Path(args.testcases).rglob("*.cs")):
        m = CWE_IN_NAME.search(path.name)
        if not m:
            continue
        cwe = f"CWE-{m.group(1)}"
        if not mapping.get(cwe):
            unmapped.add(cwe)
            continue
        key = re.sub(r"_(\d+)[a-z]?\.cs$", r"_\1", path.name)
        testcases.setdefault((cwe, key), []).append(path)

    tallies: dict[str, dict] = {}
    variants: dict[str, dict] = {}

    for (cwe, key), paths in sorted(testcases.items()):
        ruleids = set(mapping[cwe])
        t = tallies.setdefault(cwe, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        vb = variants.setdefault(cwe, {}).setdefault(
            variant_bucket(key + ".cs"), {"tp": 0, "fn": 0}
        )
        has_bad = False
        bad_hit = False
        for path in paths:
            regions = method_regions(path.read_text(errors="replace"))
            matched = [ln for (ln, rid) in by_file.get(path.name, []) if rid in ruleids]
            for r in regions:
                kind = classify(r[0], r[1])
                if not kind:
                    continue
                region_hit = any(innermost_region(regions, ln) == r for ln in matched)
                if kind == "bad":
                    has_bad = True
                    bad_hit = bad_hit or region_hit
                elif region_hit:
                    t["fp"] += 1
                else:
                    t["tn"] += 1
        if has_bad:
            if bad_hit:
                t["tp"] += 1
                vb["tp"] += 1
            else:
                t["fn"] += 1
                vb["fn"] += 1

    report(tallies, variants, unmapped, args.json)


def metrics(t):
    tp, fp, fn, tn = t["tp"], t["fp"], t["fn"], t["tn"]
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return prec, rec, fpr, f1, rec - fpr


def report(tallies, variants, unmapped, as_json):
    if as_json:
        doc = {
            "cwes": {
                cwe: {
                    **t,
                    "precision": metrics(t)[0],
                    "recall": metrics(t)[1],
                    "fpr": metrics(t)[2],
                    "f1": metrics(t)[3],
                    "youden_j": metrics(t)[4],
                    "variants": variants.get(cwe, {}),
                }
                for cwe, t in sorted(tallies.items())
            },
            "unmapped_cwes": sorted(unmapped),
        }
        print(json.dumps(doc, indent=2))
        return

    print("crit vs Juliet C# — objective benchmark\n")
    print(f"  {'CWE':<10} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} "
          f"{'prec':>6} {'recall':>7} {'FPR':>6} {'Youden J':>9}")
    print("  " + "-" * 68)
    agg = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for cwe, t in sorted(tallies.items()):
        for k in agg:
            agg[k] += t[k]
        p, r, fpr, _f1, j = metrics(t)
        print(f"  {cwe:<10} {t['tp']:>4} {t['fp']:>4} {t['fn']:>4} {t['tn']:>4} "
              f"{p*100:>5.0f}% {r*100:>6.0f}% {fpr*100:>5.0f}% {j:>9.2f}")
    print("  " + "-" * 68)
    p, r, fpr, _f1, j = metrics(agg)
    print(f"  {'ALL':<10} {agg['tp']:>4} {agg['fp']:>4} {agg['fn']:>4} {agg['tn']:>4} "
          f"{p*100:>5.0f}% {r*100:>6.0f}% {fpr*100:>5.0f}% {j:>9.2f}")

    print("\n  Recall by variant (isolates where cross-file taint doesn't reach):")
    for cwe, vb in sorted(variants.items()):
        for bucket, c in sorted(vb.items()):
            tot = c["tp"] + c["fn"]
            rec = c["tp"] / tot if tot else 1.0
            print(f"    {cwe:<10} {bucket:<12} recall {rec*100:>4.0f}%  ({c['tp']}/{tot})")

    if unmapped:
        print("\n  CWEs present but not mapped to any crit rule (not scored): "
              + ", ".join(sorted(unmapped)))


if __name__ == "__main__":
    main()
