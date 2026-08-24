package main

import (
	"net/http"
	"os/exec"
)

func direct(r *http.Request) {
	exec.Command("sh", "-c", "ping "+r.FormValue("host")) // crit:expect go.cmd-injection
}

func viaVar(r *http.Request) {
	host := r.URL.Query().Get("host")
	// crit:expect go.cmd-injection
	exec.Command("sh", "-c", "ping "+host)
}

func fixed() {
	exec.Command("ls", "-la") // crit:expect-not go.cmd-injection
}

func internal(host string) {
	exec.Command("ping", host) // crit:expect-not go.cmd-injection
}
