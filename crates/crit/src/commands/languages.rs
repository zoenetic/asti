//! `crit languages` — list registered languages.

use super::Context;
use anyhow::Result;

pub fn run(ctx: &Context) -> Result<i32> {
    for lang in ctx.registry.all() {
        println!(
            "{:<14} {:<34} .{}{}{}",
            lang.id,
            lang.display_name,
            lang.extensions.join(" ."),
            if lang.builtin { "" } else { "  (external)" },
            if lang.taint_profile.is_some() {
                "  [taint]"
            } else {
                ""
            }
        );
    }
    Ok(0)
}
