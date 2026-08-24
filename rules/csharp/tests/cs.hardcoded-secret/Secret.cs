class SecretTests {
  string password = "supersecret123";  // crit:expect cs.hardcoded-secret
  string apiKey = "abcdef0123456789";  // crit:expect cs.hardcoded-secret
  string username = "administrator";   // crit:expect-not cs.hardcoded-secret
  string secret = "short";             // crit:expect-not cs.hardcoded-secret
}
