program DllTest;
begin
  LoadLibrary('kernel32.dll'); // crit:expect pas.dll-hijack
  LoadPackage('myplugin.bpl'); // crit:expect pas.dll-hijack
  LoadLibrary('C:\Windows\System32\kernel32.dll'); // crit:expect-not pas.dll-hijack
  LoadPackage('/opt/app/lib/myplugin.bpl'); // crit:expect-not pas.dll-hijack
end.
