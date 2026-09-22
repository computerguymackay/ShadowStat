package web

import (
	"net/http"

	"ShadowStat/internal/store"
)

type pageHandlers struct {
	db *store.DB
}

// pageVars is passed to every authenticated page template so the shared "nav"
// partial has a consistent shape to read from regardless of which page included it.
type pageVars struct {
	Breadcrumb string // non-empty on drill-down pages, e.g. a host's IP
	HostID     int64
	HostIP     string
}

func (h *pageHandlers) login(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "login.html", nil)
}

func (h *pageHandlers) dashboard(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "dashboard.html", &pageVars{})
}

func (h *pageHandlers) hostDetail(w http.ResponseWriter, r *http.Request) {
	hostID, ok := parseHostID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	host, err := h.db.HostByID(hostID)
	if err != nil {
		if err == store.ErrNotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "host_detail.html", &pageVars{
		Breadcrumb: host.IP,
		HostID:     host.ID,
		HostIP:     host.IP,
	})
}

func renderTemplate(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
