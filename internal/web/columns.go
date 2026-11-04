package web

import (
	"net/http"
	"strings"

	"github.com/amit/47certificates/internal/store"
)

// columnChoice is one column with the state of its checkbox.
type columnChoice struct {
	Key     string
	Label   string
	Title   string
	Checked bool
}

// handleCertColumns shows the column chooser.
func (s *Server) handleCertColumns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, _ := UserFrom(ctx)
	chosen, err := s.deps.Store.GetCertColumns(ctx, u.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	set := map[string]bool{}
	for _, c := range chosen {
		set[c] = true
	}
	choices := make([]columnChoice, 0, len(store.CertColumns))
	for _, c := range store.CertColumns {
		choices = append(choices, columnChoice{
			Key:     c.Key,
			Label:   c.Label,
			Title:   c.Title,
			Checked: set[c.Key],
		})
	}
	data := struct {
		pageData
		AllColumns []columnChoice
	}{
		pageData:  s.base(r, "Choose columns"),
		AllColumns: choices,
	}
	s.render(w, "columns", data)
}

// handleCertColumnsPost saves the column choice.
func (s *Server) handleCertColumnsPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	u, _ := UserFrom(ctx)
	cols := r.PostForm["columns"]
	if len(cols) == 0 {
		http.Error(w, "choose at least one column", http.StatusBadRequest)
		return
	}
	if err := s.deps.Store.SetCertColumns(ctx, u.ID, cols); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = s.deps.Store.Audit(ctx, &u.ID, "columns.set", "certs",
		[]byte(`{"columns":"`+strings.Join(cols, ",")+`"}`), clientIP(r))
	http.Redirect(w, r, "/certs", http.StatusSeeOther)
}

// columnsFor renders the chosen columns as the column definitions the
// template uses.
func columnsFor(chosen []string) []store.CertColumn {
	set := map[string]bool{}
	for _, c := range chosen {
		set[c] = true
	}
	var out []store.CertColumn
	for _, c := range store.CertColumns {
		if set[c.Key] {
			out = append(out, c)
		}
	}
	return out
}
