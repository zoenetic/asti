class CryptoTests {
  void Weak() {
    var a = MD5.Create();  // crit:expect cs.weak-crypto
    var b = SHA1.Create(); // crit:expect cs.weak-crypto
  }
  void Strong() {
    var c = SHA256.Create(); // crit:expect-not cs.weak-crypto
    var d = Aes.Create();    // crit:expect-not cs.weak-crypto
  }
}
