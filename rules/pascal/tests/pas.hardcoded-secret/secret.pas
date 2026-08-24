program SecretTests;
begin
  password := 'supersecret123'; // crit:expect pas.hardcoded-secret
  apiKey := 'abcdef0123456789'; // crit:expect pas.hardcoded-secret
  username := 'administrator'; // crit:expect-not pas.hardcoded-secret
  secret := 'short'; // crit:expect-not pas.hardcoded-secret
end.
