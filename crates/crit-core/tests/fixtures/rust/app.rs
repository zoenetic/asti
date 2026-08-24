fn main() {
    let name = std::env::args().nth(1).unwrap();
    let out = std::process::Command::new("sh").arg("-c").arg(format!("ping {name}")).output();
    let q = sqlx::query(&format!("SELECT * FROM u WHERE id={name}"));
}
