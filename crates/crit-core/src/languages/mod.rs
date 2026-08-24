//! Language registry: built-in grammars compiled into the binary plus
//! dynamically loaded grammars from shared libraries.

pub mod profile;

use crate::config::GrammarConfig;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tree_sitter::Language;

pub use profile::TaintProfileSpec;

/// A language known to the scanner.
pub struct LanguageDef {
    /// Stable identifier used in rules and CLI flags, e.g. `objectscript`.
    pub id: String,
    pub display_name: String,
    /// File extensions (lowercase, without dot) that map to this language.
    pub extensions: Vec<String>,
    pub language: Language,
    pub builtin: bool,
    /// Taint profile (syntax concept mapping) for this language, if any.
    /// Languages without a profile still support pattern rules.
    pub taint_profile: Option<TaintProfileSpec>,
}

/// Registry of all available languages with extension-based detection.
pub struct Registry {
    langs: Vec<Arc<LanguageDef>>,
    by_id: HashMap<String, usize>,
    by_ext: HashMap<String, usize>,
}

struct Builtin {
    id: &'static str,
    display: &'static str,
    extensions: &'static [&'static str],
    lang: fn() -> Language,
}

const BUILTINS: &[Builtin] = &[
    Builtin {
        id: "objectscript",
        display: "InterSystems ObjectScript (UDL)",
        // .cls class definitions; .mac/.int routines and .inc include files
        // parse with error recovery under the UDL grammar, which is good
        // enough for rule matching. `.inc` can be remapped to pascal via the
        // `[extensions]` table in crit.toml for Delphi codebases.
        extensions: &["cls", "mac", "int", "inc"],
        lang: || tree_sitter_objectscript::LANGUAGE_OBJECTSCRIPT_UDL.into(),
    },
    Builtin {
        id: "pascal",
        display: "Pascal / Delphi",
        extensions: &["pas", "pp", "dpr", "dpk", "lpr"],
        lang: || tree_sitter_pascal::LANGUAGE.into(),
    },
    Builtin {
        id: "javascript",
        display: "JavaScript",
        extensions: &["js", "mjs", "cjs", "jsx"],
        lang: || tree_sitter_javascript::LANGUAGE.into(),
    },
    Builtin {
        id: "typescript",
        display: "TypeScript",
        extensions: &["ts", "mts", "cts"],
        lang: || tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    },
    Builtin {
        id: "tsx",
        display: "TypeScript (TSX)",
        extensions: &["tsx"],
        lang: || tree_sitter_typescript::LANGUAGE_TSX.into(),
    },
    Builtin {
        id: "csharp",
        display: "C#",
        extensions: &["cs"],
        lang: || tree_sitter_c_sharp::LANGUAGE.into(),
    },
    Builtin {
        id: "go",
        display: "Go",
        extensions: &["go"],
        lang: || tree_sitter_go::LANGUAGE.into(),
    },
    Builtin {
        id: "rust",
        display: "Rust",
        extensions: &["rs"],
        lang: || tree_sitter_rust::LANGUAGE.into(),
    },
];

impl Registry {
    /// Build the registry with all built-in languages and their embedded
    /// taint profiles.
    pub fn with_builtins() -> Result<Self> {
        let mut reg = Registry {
            langs: Vec::new(),
            by_id: HashMap::new(),
            by_ext: HashMap::new(),
        };
        for b in BUILTINS {
            let profile = profile::builtin_profile(b.id)?;
            reg.insert(LanguageDef {
                id: b.id.to_string(),
                display_name: b.display.to_string(),
                extensions: b.extensions.iter().map(|e| e.to_string()).collect(),
                language: (b.lang)(),
                builtin: true,
                taint_profile: profile,
            })?;
        }
        Ok(reg)
    }

    fn insert(&mut self, def: LanguageDef) -> Result<()> {
        if self.by_id.contains_key(&def.id) {
            bail!("duplicate language id `{}`", def.id);
        }
        let idx = self.langs.len();
        self.by_id.insert(def.id.clone(), idx);
        for ext in &def.extensions {
            // First registration wins; overrides are applied separately.
            self.by_ext.entry(ext.to_ascii_lowercase()).or_insert(idx);
        }
        self.langs.push(Arc::new(def));
        Ok(())
    }

    /// Load an external grammar from a shared library, as configured in
    /// crit.toml. The library handle is intentionally leaked: the Language
    /// points into it and must stay valid for the process lifetime.
    pub fn add_dynamic(&mut self, cfg: &GrammarConfig, base_dir: &Path) -> Result<()> {
        let path = if Path::new(&cfg.library).is_absolute() {
            std::path::PathBuf::from(&cfg.library)
        } else {
            base_dir.join(&cfg.library)
        };
        let symbol = cfg
            .symbol
            .clone()
            .unwrap_or_else(|| format!("tree_sitter_{}", cfg.name.replace('-', "_")));

        let language = unsafe {
            let lib = libloading::Library::new(&path)
                .with_context(|| format!("failed to load grammar library {}", path.display()))?;
            let func: libloading::Symbol<unsafe extern "C" fn() -> *const ()> = lib
                .get(symbol.as_bytes())
                .with_context(|| format!("symbol `{symbol}` not found in {}", path.display()))?;
            let raw = *func;
            // Keep the library mapped forever; Language borrows from it.
            std::mem::forget(lib);
            Language::new(tree_sitter_language::LanguageFn::from_raw(raw))
        };

        let abi = language.abi_version();
        let (min, max) = (
            tree_sitter::MIN_COMPATIBLE_LANGUAGE_VERSION,
            tree_sitter::LANGUAGE_VERSION,
        );
        if abi < min || abi > max {
            bail!(
                "grammar `{}` has incompatible ABI version {abi} (supported: {min}..={max})",
                cfg.name
            );
        }

        let profile = match &cfg.profile {
            Some(p) => {
                let ppath = if Path::new(p).is_absolute() {
                    std::path::PathBuf::from(p)
                } else {
                    base_dir.join(p)
                };
                let text = std::fs::read_to_string(&ppath)
                    .with_context(|| format!("failed to read taint profile {}", ppath.display()))?;
                Some(profile::parse_profile(&text)?)
            }
            None => None,
        };

        self.insert(LanguageDef {
            id: cfg.name.clone(),
            display_name: cfg.display_name.clone().unwrap_or_else(|| cfg.name.clone()),
            extensions: cfg
                .extensions
                .iter()
                .map(|e| e.to_ascii_lowercase())
                .collect(),
            language,
            builtin: false,
            taint_profile: profile,
        })
    }

    /// Force an extension to resolve to a given language id (config
    /// `[extensions]` table).
    pub fn override_extension(&mut self, ext: &str, lang_id: &str) -> Result<()> {
        let idx = *self
            .by_id
            .get(lang_id)
            .with_context(|| format!("unknown language `{lang_id}` in [extensions] override"))?;
        self.by_ext
            .insert(ext.trim_start_matches('.').to_ascii_lowercase(), idx);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<Arc<LanguageDef>> {
        self.by_id.get(id).map(|&i| self.langs[i].clone())
    }

    /// Detect the language for a path from its extension.
    pub fn detect(&self, path: &Path) -> Option<Arc<LanguageDef>> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        self.by_ext.get(&ext).map(|&i| self.langs[i].clone())
    }

    pub fn all(&self) -> impl Iterator<Item = &Arc<LanguageDef>> {
        self.langs.iter()
    }
}
