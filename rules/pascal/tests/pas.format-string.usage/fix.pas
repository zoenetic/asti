program FormatUsageTest;

uses SysUtils;

// Positive: first argument of Format is a bare identifier, not a literal.
procedure UsageVuln;
var s: String;
begin
  s := ParamStr(1);
  Format(s, [42]); // crit:expect pas.format-string.usage
end;

// Positive: non-literal format string passed to WideFormat (even a local var
// that is not externally tainted still trips the coarse usage rule).
procedure UsageVulnLocal;
var fmt: String;
begin
  fmt := '%d';
  WideFormat(fmt, [1, 2]); // crit:expect pas.format-string.usage
end;

// Negative: constant literal format string as the first argument.
procedure UsageSafeLiteral;
var name: String;
begin
  name := ParamStr(1);
  Format('%s: %d', [name, 42]); // crit:expect-not pas.format-string.usage
end;

// Negative: constant literal format string, no dynamic first argument.
procedure UsageSafeConst;
begin
  Format('%d', [42]); // crit:expect-not pas.format-string.usage
end;

begin
  UsageVuln;
  UsageVulnLocal;
  UsageSafeLiteral;
  UsageSafeConst;
end.
