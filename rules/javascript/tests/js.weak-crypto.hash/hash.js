const crypto = require('crypto');

function md5(data) {
  return crypto.createHash("md5").update(data).digest("hex"); // crit:expect js.weak-crypto.hash
}

function sha1(data) {
  return crypto.createHash("sha1").update(data); // crit:expect js.weak-crypto.hash
}

function sha256(data) {
  return crypto.createHash("sha256").update(data); // crit:expect-not js.weak-crypto.hash
}

function hmac(data) {
  return crypto.createHmac("sha256", key); // crit:expect-not js.weak-crypto.hash
}
