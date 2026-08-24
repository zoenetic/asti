program FormatStringTest;

uses SysUtils;

// Positive: user-controlled command-line arg used as the format string.
procedure FormatVuln;
var s: String;
begin
  s := ParamStr(1);
  Format(s, [42]); // crit:expect pas.format-string
end;

// Positive: environment value used as the format string of WideFormat.
procedure FormatVulnEnv;
var fmt: String;
begin
  fmt := GetEnvironmentVariable('TEMPLATE');
  WideFormat(fmt, [1, 2]); // crit:expect pas.format-string
end;

// Negative: constant literal format string; user data only in the args array.
procedure FormatSafeLiteral;
var name: String;
begin
  name := ParamStr(1);
  Format('%s: %d', [name, 42]); // crit:expect-not pas.format-string
end;

// Negative: literal format string; tainted value sits in the args array, not
// the format-string argument, so the sink is not reached.
procedure FormatSafeArgs;
begin
  Format('%s', [ParamStr(3)]); // crit:expect-not pas.format-string
end;

begin
  FormatVuln;
  FormatVulnEnv;
  FormatSafeLiteral;
  FormatSafeArgs;
end.
