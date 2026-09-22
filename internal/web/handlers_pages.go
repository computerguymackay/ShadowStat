package web

import (
	"net/http"

	"ShadowStat/internal/store"
)

type pageHandlers struct {
	db *store.DB
}

func (h *pageHandlers) login(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "login.html", nil)
}

func (h *pageHandlers) dashboard(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "dashboard.html", nil)
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

	renderTemplate(w, "host_detail.html", map[string]any{
		"HostID": host.ID,
		"HostIP": host.IP,
	})
}

func renderTemplate(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
