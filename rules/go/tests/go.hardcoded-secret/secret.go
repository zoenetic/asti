package main

func secrets() {
	password := "supersecretvalue" // crit:expect go.hardcoded-secret
	apiKey := "abcdef0123456789"   // crit:expect go.hardcoded-secret
	username := "administrator"    // crit:expect-not go.hardcoded-secret
	secret := "short"              // crit:expect-not go.hardcoded-secret
	_, _, _, _ = password, apiKey, username, secret
}
