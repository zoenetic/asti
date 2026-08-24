program UsageTests;
begin
  WinExec(PChar(cmd), 0); // crit:expect pas.cmd-injection.usage
  FpSystem(cmd); // crit:expect pas.cmd-injection.usage
  ShellExecute(0, 'open', app, nil, nil, 0); // crit:expect-not pas.cmd-injection.usage
  CreateProcess(nil, cmd, nil, nil, False, 0, nil, nil, si, pi); // crit:expect-not pas.cmd-injection.usage
end.
