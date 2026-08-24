package main

import (
	"net/http"
	ex "os/exec"
)

// Aliased package import: the text query keyed on "exec.Command" cannot match
// `ex.Command`; identity resolution does.
func viaAlias(r *http.Request) {
	ex.Command("sh", "-c", "ping "+r.FormValue("host")) // crit:expect go.cmd-injection
}

func viaAliasContext(r *http.Request, ctx interface{}) {
	ex.CommandContext(ctx, "sh", "-c", r.URL.Query().Get("q")) // crit:expect go.cmd-injection
}

func fixedAlias() {
	ex.Command("ls", "-la") // crit:expect-not go.cmd-injection
}

func internalAlias(host string) {
	ex.Command("ping", host) // crit:expect-not go.cmd-injection
}
