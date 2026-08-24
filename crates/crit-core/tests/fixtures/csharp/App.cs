class T {
  void M() {
    var id = Request.QueryString["id"];
    var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + id);
    cmd.CommandText = "x" + id;
    Process.Start("cmd", "/c " + id);
    var h = MD5.Create();
  }
}
