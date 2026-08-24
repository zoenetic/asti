class SqlTests {
  void Direct() {
    var id = Request.QueryString["id"];
    var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + id); // crit:expect cs.sql-injection
  }
  void CommandText(SqlCommand c) {
    var id = Request.Form["id"];
    c.CommandText = "SELECT * FROM u WHERE id=" + id; // crit:expect cs.sql-injection
  }
  void Constant() {
    var cmd = new SqlCommand("SELECT * FROM u WHERE active=1"); // crit:expect-not cs.sql-injection
  }
  void Internal(string id) {
    var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + id); // crit:expect-not cs.sql-injection
  }
}
