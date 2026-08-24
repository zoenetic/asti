fn secrets() {
    let password = "supersecret123"; // crit:expect rs.hardcoded-secret
    let api_key = "abcdef0123456789"; // crit:expect rs.hardcoded-secret
    let username = "administrator"; // crit:expect-not rs.hardcoded-secret
    let secret = "short"; // crit:expect-not rs.hardcoded-secret
}
