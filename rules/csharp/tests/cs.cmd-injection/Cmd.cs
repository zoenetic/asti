class CmdTests {
  void Direct() {
    var id = Request.QueryString["id"];
    Process.Start("cmd", "/c " + id); // crit:expect cs.cmd-injection
  }
  void ViaForm() {
    var host = Request.Form["host"];
    Process.Start("ping " + host); // crit:expect cs.cmd-injection
  }
  void Fixed() {
    Process.Start("notepad.exe"); // crit:expect-not cs.cmd-injection
  }
  void Internal(string arg) {
    Process.Start("cmd", arg); // crit:expect-not cs.cmd-injection
  }
}
