//! Ensure the crate recompiles when the embedded rule/profile trees change.
//!
//! `rules/` and `profiles/` are baked into the binary via `include_dir!`,
//! which does not by itself register the directory contents with Cargo's
//! change detection. Without these directives an incremental build keeps the
//! previously embedded rules even after a pack is added or edited.

fn main() {
    println!("cargo:rerun-if-changed=../../rules");
    println!("cargo:rerun-if-changed=../../profiles");
}
