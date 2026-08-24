fn queries(conn: &Conn, id: i64) {
    sqlx::query(&format!("SELECT * FROM u WHERE id = {}", id)); // crit:expect rs.sql-injection.format
    conn.execute(format!("DELETE FROM u WHERE id = {}", id)); // crit:expect rs.sql-injection.format
    sqlx::query("SELECT * FROM u WHERE id = $1"); // crit:expect-not rs.sql-injection.format
    conn.execute("DELETE FROM u WHERE active = 0"); // crit:expect-not rs.sql-injection.format
}
