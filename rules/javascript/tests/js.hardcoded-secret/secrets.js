const apiKey = "sk-live-9f8e7d6c5b4a"; // crit:expect js.hardcoded-secret
const password = "hunter42secret"; // crit:expect js.hardcoded-secret

const passwordHint = "changeme-see-vault"; // crit:expect-not js.hardcoded-secret
const username = "alice-admin"; // crit:expect-not js.hardcoded-secret
const secretKey = "abc"; // crit:expect-not js.hardcoded-secret
const authToken = process.env.AUTH_TOKEN; // crit:expect-not js.hardcoded-secret
