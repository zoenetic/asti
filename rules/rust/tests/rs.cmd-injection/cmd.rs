use std::process::Command;

fn direct() {
    Command::new(std::env::args().nth(1).unwrap()); // crit:expect rs.cmd-injection
}

fn via_var() {
    let prog = std::env::var("PROG").unwrap();
    // crit:expect rs.cmd-injection
    Command::new(prog);
}

fn fixed() {
    Command::new("ls"); // crit:expect-not rs.cmd-injection
}

fn internal(prog: String) {
    Command::new(prog); // crit:expect-not rs.cmd-injection
}
