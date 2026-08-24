program CmdTests;
var s: String;
begin
  s := ParamStr(1);
  WinExec(PChar('cmd /c ' + s), 0); // crit:expect pas.cmd-injection
  ShellExecute(0, 'open', PChar(ParamStr(2)), nil, nil, 0); // crit:expect pas.cmd-injection
  WinExec(PChar('cmd /c dir'), 0); // crit:expect-not pas.cmd-injection
  ShellExecute(0, 'open', 'notepad.exe', nil, nil, 0); // crit:expect-not pas.cmd-injection
end.
