program PathUsageTest;

uses SysUtils, Classes;

// Positive: TFileStream.Create with a caller-supplied path.
procedure UsageVulnStream;
var path: String;
    fs: TFileStream;
begin
  path := ParamStr(1);
  fs := TFileStream.Create(path, fmOpenRead); // crit:expect pas.path-traversal.usage
  fs.Free;
end;

// Positive: LoadFromFile is a file-path API; the coarse usage rule flags it
// even with a constant literal path.
procedure UsageConstLoad;
var sl: TStringList;
begin
  sl := TStringList.Create;
  sl.LoadFromFile('/etc/app/settings.ini'); // crit:expect pas.path-traversal.usage
  sl.LoadFromStream(nil); // crit:expect-not pas.path-traversal.usage
  sl.Free;
end;

// Negative: stream-only APIs are not file-path sinks.
procedure UsageSafeStream;
var sl: TStringList;
    ms: TMemoryStream;
begin
  sl := TStringList.Create;
  ms := TMemoryStream.Create;
  sl.SaveToStream(ms); // crit:expect-not pas.path-traversal.usage
  ms.Free;
  sl.Free;
end;

begin
  UsageVulnStream;
  UsageConstLoad;
  UsageSafeStream;
end.
