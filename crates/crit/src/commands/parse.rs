//! `crit parse` — dump a file's syntax tree and test queries against it.
//! This is the primary rule-authoring aid.

use super::Context;
use anyhow::{bail, Context as _, Result};
use clap::Args;
use std::path::PathBuf;
use streaming_iterator::StreamingIterator;

#[derive(Args)]
pub struct ParseArgs {
    /// File to parse.
    pub file: PathBuf,

    /// Language id (default: detected from the file extension).
    #[arg(long = "lang", value_name = "LANG")]
    pub language: Option<String>,

    /// Run this tree-sitter query and print its captures instead of the tree.
    #[arg(long, short = 'q', value_name = "QUERY")]
    pub query: Option<String>,

    /// Print anonymous (unnamed) nodes too.
    #[arg(long)]
    pub anonymous: bool,
}

pub fn run(ctx: &Context, args: ParseArgs) -> Result<i32> {
    let lang = match &args.language {
        Some(id) => ctx
            .registry
            .get(id)
            .with_context(|| format!("unknown language `{id}`"))?,
        None => ctx
            .registry
            .detect(&args.file)
            .with_context(|| format!("cannot detect language for {}", args.file.display()))?,
    };
    let source = std::fs::read_to_string(&args.file)
        .with_context(|| format!("failed to read {}", args.file.display()))?;

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&lang.language)?;
    let Some(tree) = parser.parse(&source, None) else {
        bail!("parser produced no tree");
    };
    if tree.root_node().has_error() {
        eprintln!("note: tree contains ERROR nodes (grammar could not parse everything)");
    }

    match &args.query {
        Some(q) => {
            let query = tree_sitter::Query::new(&lang.language, q)
                .map_err(|e| anyhow::anyhow!("query error: {e}"))?;
            let names = query.capture_names();
            let mut cursor = tree_sitter::QueryCursor::new();
            let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
            let mut n = 0;
            while let Some(m) = matches.next() {
                n += 1;
                println!("match #{n}");
                for cap in m.captures {
                    let node = cap.node;
                    let text = node.utf8_text(source.as_bytes()).unwrap_or("<non-utf8>");
                    let text: String = text.chars().take(80).collect();
                    println!(
                        "  @{:<12} {}:{} {} {:?}",
                        names[cap.index as usize],
                        node.start_position().row + 1,
                        node.start_position().column + 1,
                        node.kind(),
                        text
                    );
                }
            }
            println!("{n} matches");
        }
        None => {
            print_tree(&tree, &source, args.anonymous);
        }
    }
    Ok(0)
}

fn print_tree(tree: &tree_sitter::Tree, source: &str, anonymous: bool) {
    let mut cursor = tree.walk();
    let mut depth: usize = 0;
    loop {
        let node = cursor.node();
        if node.is_named() || anonymous {
            let text = if node.child_count() == 0 {
                let t = node.utf8_text(source.as_bytes()).unwrap_or("");
                let t: String = t.chars().take(60).collect();
                format!("  {t:?}")
            } else {
                String::new()
            };
            let field = cursor
                .field_name()
                .map(|f| format!("{f}: "))
                .unwrap_or_default();
            println!(
                "{}{}{} [{},{}]-[{},{}]{}",
                "  ".repeat(depth),
                field,
                node.kind(),
                node.start_position().row + 1,
                node.start_position().column + 1,
                node.end_position().row + 1,
                node.end_position().column + 1,
                text
            );
        }
        // Depth-first traversal with a TreeCursor.
        if cursor.goto_first_child() {
            depth += 1;
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
            depth -= 1;
        }
    }
}
