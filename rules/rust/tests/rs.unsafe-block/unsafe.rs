fn writes(ptr: *mut u8) {
    unsafe { *ptr = 1; } // crit:expect rs.unsafe-block
}

fn reads() -> u8 {
    let v = unsafe { read_raw() }; // crit:expect rs.unsafe-block
    v
}

fn safe() {
    let x = compute(); // crit:expect-not rs.unsafe-block
}

fn also_safe() {
    let y = 2 + 2; // crit:expect-not rs.unsafe-block
}
