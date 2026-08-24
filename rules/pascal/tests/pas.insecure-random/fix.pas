program InsecureRandomTest;

uses SysUtils;

// Positive: seeding the non-cryptographic PRNG.
procedure TokenVulnSeed;
begin
  Randomize; // crit:expect pas.insecure-random
end;

// Positive: token derived from the predictable Random generator.
procedure TokenVulnValue;
var token: String;
begin
  token := IntToStr(Random(999999)); // crit:expect pas.insecure-random
end;

// Negative: cryptographically-backed unique id; not the Random PRNG.
procedure TokenSafeGuid;
var guid: TGUID;
begin
  CreateGUID(guid); // crit:expect-not pas.insecure-random
end;

// Negative: plain integer formatting, no PRNG involved.
procedure TokenSafeCounter;
var s: String;
begin
  s := IntToStr(GetTickCount); // crit:expect-not pas.insecure-random
end;

begin
  TokenVulnSeed;
  TokenVulnValue;
  TokenSafeGuid;
  TokenSafeCounter;
end.
