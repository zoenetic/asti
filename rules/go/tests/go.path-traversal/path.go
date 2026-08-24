package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func read(r *http.Request) {
	os.ReadFile("/data/" + r.FormValue("name")) // crit:expect go.path-traversal
}

func viaVar(r *http.Request) {
	name := r.URL.Query().Get("name")
	// crit:expect go.path-traversal
	os.Open("/data/" + name)
}

func safe(r *http.Request) {
	os.ReadFile(filepath.Base(r.FormValue("name"))) // crit:expect-not go.path-traversal
}

func fixed() {
	os.ReadFile("/etc/app.conf") // crit:expect-not go.path-traversal
}
