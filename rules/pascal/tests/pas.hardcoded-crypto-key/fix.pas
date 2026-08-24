program KeyTest;
begin
  Cipher.Key := 'S3cr3tKeyMaterial'; // crit:expect pas.hardcoded-crypto-key
  DES.Password := 'p@ssw0rd!'; // crit:expect pas.hardcoded-crypto-key
  Cipher.Key := DeriveKeyFromConfig('kek'); // crit:expect-not pas.hardcoded-crypto-key
  Cipher.IV := RandomBytes(16); // crit:expect-not pas.hardcoded-crypto-key
end.
