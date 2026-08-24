package main

import (
	"fmt"
	"net/http"
	"text/template"
)

func direct(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(r.FormValue("q"))) // crit:expect go.xss.direct-write
}

func fprintf(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<p>%s</p>", r.URL.Query().Get("q")) // crit:expect go.xss.direct-write
}

func escaped(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(template.HTMLEscapeString(r.FormValue("q")))) // crit:expect-not go.xss.direct-write
}

func static(w http.ResponseWriter) {
	w.Write([]byte("<p>hello</p>")) // crit:expect-not go.xss.direct-write
}
