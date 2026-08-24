program CipherTest;
begin
  DESEncrypt(Data); // crit:expect pas.weak-cipher-mode
  Crypt.CipherMode := cmECB; // crit:expect pas.weak-cipher-mode
  AESEncrypt(Data); // crit:expect-not pas.weak-cipher-mode
  Crypt.CipherMode := cmCBC; // crit:expect-not pas.weak-cipher-mode
end.
