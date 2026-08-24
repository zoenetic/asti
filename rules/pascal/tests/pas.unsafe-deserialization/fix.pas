program DeserTest;
begin
  Reader.ReadComponent(nil); // crit:expect pas.unsafe-deserialization
  Stream.ReadComponentRes(Comp); // crit:expect pas.unsafe-deserialization
  Stream.ReadBuffer(Buf, Len); // crit:expect-not pas.unsafe-deserialization
  Config.LoadFromFile('trusted.ini'); // crit:expect-not pas.unsafe-deserialization
end.
