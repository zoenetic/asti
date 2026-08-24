program CryptoTests;
var h: String;
begin
  h := MD5String(data); // crit:expect pas.weak-crypto.hash
  h := SHA1(data); // crit:expect pas.weak-crypto.hash
  h := SHA256String(data); // crit:expect-not pas.weak-crypto.hash
  h := ComputeHash(data); // crit:expect-not pas.weak-crypto.hash
end.
