# Third-party notices

crit is distributed under the MIT License (see [LICENSE](LICENSE)). It builds
on third-party open-source components, listed here for license awareness. The
exact set and versions are pinned in [`Cargo.lock`](Cargo.lock).

## Summary

At the time of writing, **all** dependencies are permissive open-source
licenses — **no copyleft (GPL/LGPL/AGPL/MPL) is present**. Approximate
breakdown of the 99 transitive crates:

| License | Crates |
|---|---|
| MIT OR Apache-2.0 | 54 |
| MIT | 17 |
| Unlicense OR MIT / Unlicense/MIT | 6 |
| Apache-2.0 OR MIT | 4 |
| ISC | 2 |
| Apache-2.0 (incl. WITH LLVM-exception variants) | 4 |
| BSD-2-Clause | 1 |
| CC0-1.0 / MIT-0 variants | 2 |
| Apache-2.0 OR BSL-1.0 | 1 |
| (MIT OR Apache-2.0) AND Unicode-3.0 | 1 |
| Platform crates not resolved locally* | 7 |

\* Windows/target-specific crates (`windows-sys`, `winapi-util`, `hermit-abi`,
`r-efi`, `anstyle-wincon`, `windows-link`, `once_cell_polyfill`) were not in the
local build cache to read; all are well-known permissive (MIT OR Apache-2.0).
Regenerate a definitive report with the commands below.

## Bundled tree-sitter grammars

These parsers are compiled into the binary and are the components most worth
naming explicitly. All are MIT-licensed:

| Grammar | Version | License |
|---|---|---|
| tree-sitter (runtime) | 0.26.x | MIT |
| tree-sitter-objectscript | 1.9.x | MIT |
| tree-sitter-pascal | 0.10.x | MIT |
| tree-sitter-c-sharp | 0.23.x | MIT |
| tree-sitter-go | 0.25.x | MIT |
| tree-sitter-javascript | 0.25.x | MIT |
| tree-sitter-typescript | 0.23.x | MIT |
| tree-sitter-rust | 0.24.x | MIT |
| tree-sitter-language | 0.1.x | MIT |

## Regenerating a definitive report

This file is a point-in-time summary. For a machine-generated, per-crate
license report (recommended as a release step, run where the registry is
reachable):

```sh
cargo install cargo-about   # or cargo-license / cargo-deny
cargo about generate about.hbs > THIRD-PARTY-LICENSES.html
# license policy gate (fails the build on a disallowed license):
cargo install cargo-deny && cargo deny check licenses
```

Adding a `deny.toml` license allow-list and wiring `cargo deny check` into CI is
the recommended way to keep this guarantee enforced over time.
