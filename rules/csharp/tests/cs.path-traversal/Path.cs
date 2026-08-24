class PathTests {
  void Read() {
    var name = Request.QueryString["name"];
    File.ReadAllText("/data/" + name); // crit:expect cs.path-traversal
  }
  void Write() {
    File.WriteAllText(Request.Form["path"], "x"); // crit:expect cs.path-traversal
  }
  void Safe() {
    var name = Request.QueryString["name"];
    File.ReadAllText(Path.GetFileName(name)); // crit:expect-not cs.path-traversal
  }
  void Fixed() {
    File.ReadAllText("/etc/app.config"); // crit:expect-not cs.path-traversal
  }
}
