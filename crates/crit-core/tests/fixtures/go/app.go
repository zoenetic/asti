package main
func h(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, _ := db.Query("SELECT * FROM u WHERE id=" + id)
	out, _ := exec.Command("sh", "-c", "ping "+id).Output()
	_ = md5.New()
	_, _ = rows, out
}
