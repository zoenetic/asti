//! `crit cache` — inspect or clear the incremental scan cache.

use super::Context;
use anyhow::Result;
use clap::{Args, Subcommand};
use crit_core::state::cache::Cache;

#[derive(Args)]
pub struct CacheArgs {
    #[command(subcommand)]
    pub command: CacheCommand,
}

#[derive(Subcommand)]
pub enum CacheCommand {
    /// Show cache statistics.
    Info,
    /// Delete the cache.
    Clear,
}

pub fn run(ctx: &Context, args: CacheArgs) -> Result<i32> {
    match args.command {
        CacheCommand::Info => match Cache::stats(&ctx.root) {
            Some((files, bytes)) => {
                println!(
                    "cache at {}: {files} files, {:.1} KiB",
                    crit_core::state::state_dir(&ctx.root)
                        .join("cache.json")
                        .display(),
                    bytes as f64 / 1024.0
                );
            }
            None => println!("no cache"),
        },
        CacheCommand::Clear => {
            let cache = Cache::clear(&ctx.root)?;
            let summaries = crit_core::state::summary_store::clear(&ctx.root)?;
            if cache || summaries {
                println!("cache cleared");
            } else {
                println!("no cache to clear");
            }
        }
    }
    Ok(0)
}
