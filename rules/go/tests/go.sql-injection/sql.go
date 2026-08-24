package main

import "net/http"

func direct(r *http.Request, db DB) {
	db.Query("SELECT * FROM u WHERE id = " + r.FormValue("id")) // crit:expect go.sql-injection
}

func viaVar(r *http.Request, db DB) {
	id := r.URL.Query().Get("id")
	// crit:expect go.sql-injection
	db.Query("SELECT * FROM u WHERE id = " + id)
}

func constant(db DB) {
	db.Query("SELECT * FROM u WHERE active = 1") // crit:expect-not go.sql-injection
}

func internal(db DB, id string) {
	db.Query("SELECT * FROM u WHERE id = " + id) // crit:expect-not go.sql-injection
}
