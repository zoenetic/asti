program PathTraversalTest;

uses SysUtils, Classes;

// Positive: command-line arg flows straight into TFileStream.Create.
procedure PathVulnStream;
var path: String;
    fs: TFileStream;
begin
  path := ParamStr(1);
  fs := TFileStream.Create(path, fmOpenRead); // crit:expect pas.path-traversal
  fs.Free;
end;

// Positive: environment value flows into LoadFromFile.
procedure PathVulnLoad;
var cfg: String;
    sl: TStringList;
begin
  cfg := GetEnvironmentVariable('CONFIG');
  sl := TStringList.Create;
  sl.LoadFromFile(cfg); // crit:expect pas.path-traversal
  sl.Free;
end;

// Negative: ExtractFileName strips directory components, defeating traversal,
// so the taint rule stays quiet.
procedure PathSafeSanitized;
var raw, safe: String;
    fs: TFileStream;
begin
  raw := ParamStr(1);
  safe := ExtractFileName(raw);
  fs := TFileStream.Create('/var/app/data/' + safe, fmOpenRead); // crit:expect-not pas.path-traversal
  fs.Free;
end;

// Negative: constant literal path; no external input reaches the sink.
procedure PathSafeConst;
var sl: TStringList;
begin
  sl := TStringList.Create;
  sl.LoadFromFile('/etc/app/settings.ini'); // crit:expect-not pas.path-traversal
  sl.Free;
end;

begin
  PathVulnStream;
  PathVulnLoad;
  PathSafeSanitized;
  PathSafeConst;
end.
