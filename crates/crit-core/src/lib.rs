//! crit-core: the engine behind `crit`, a tree-sitter based multi-language
//! SAST and code-quality scanner.
//!
//! The crate is organised around a few central concepts:
//!
//! * [`languages::Registry`] — the set of languages the scanner understands.
//!   Built-in grammars are compiled into the binary; additional grammars can
//!   be loaded at runtime from shared libraries.
//! * [`rules`] — YAML rule packs (pattern rules and taint rules) compiled
//!   into tree-sitter queries per language.
//! * [`engine`] — per-file execution: pattern matching and intra-file taint
//!   propagation.
//! * [`scanner`] — orchestration: file discovery, git-diff scoping, caching,
//!   parallel execution and baseline comparison.
//! * [`output`] — human, JSON and SARIF 2.1.0 renderers.

pub mod binder;
pub mod config;
pub mod diff;
pub mod engine;
pub mod evidence;
pub mod findings;
pub mod languages;
pub mod linker;
pub mod output;
pub mod rules;
pub mod scanner;
pub mod state;

/// Engine version stamped into caches and SARIF output.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Canonical project URL, surfaced in SARIF (`informationUri` and the default
/// rule `helpUri`). Derived from the crate's `repository` field so there is a
/// single place to set it — update `repository` in the workspace `Cargo.toml`.
pub const PROJECT_URL: &str = env!("CARGO_PKG_REPOSITORY");

/// Cache/analysis schema revision, mixed into the rules hash. Bump whenever
/// analysis semantics change in a way that should invalidate caches even if
/// rule content is identical.
pub const ANALYSIS_REVISION: u32 = 4;
