fn calls() {
    let a = compute().unwrap(); // crit:expect rs.quality.unwrap
    let b = parse_input().unwrap(); // crit:expect rs.quality.unwrap
    let c = compute().expect("must compute"); // crit:expect-not rs.quality.unwrap
    let d = fallible().unwrap_or_default(); // crit:expect-not rs.quality.unwrap
}
