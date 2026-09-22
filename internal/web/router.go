package web

import (
	"net/http"

	"ShadowStat/internal/auth"
	"ShadowStat/internal/store"
)

func newRouter(db *store.DB, sessions *auth.Manager) http.Handler {
	pages := &pageHandlers{db: db}
	api := &apiHandlers{db: db, sessions: sessions}

	mux := http.NewServeMux()

	// Static assets (no auth required — CSS/JS have no sensitive content).
	mux.Handle("GET /static/", http.FileServerFS(staticFS))

	// Pages.
	mux.HandleFunc("GET /login", pages.login)
	mux.HandleFunc("GET /{$}", requireSession(sessions, false, pages.dashboard))
	mux.HandleFunc("GET /hosts/{id}", requireSession(sessions, false, pages.hostDetail))
	mux.HandleFunc("GET /alerts", requireSession(sessions, false, pages.alerts))

	// Auth API.
	mux.HandleFunc("POST /api/login", api.login)
	mux.HandleFunc("POST /api/logout", api.logout)
	mux.HandleFunc("POST /api/reauth", requireSession(sessions, true, api.reauth))

	// Data API.
	mux.HandleFunc("GET /api/hosts", requireSession(sessions, true, api.listHosts))
	mux.HandleFunc("GET /api/hosts/{id}/series", requireSession(sessions, true, api.hostSeries))
	mux.HandleFunc("GET /api/hosts/{id}/flows", requireSession(sessions, true, api.hostFlows))
	mux.HandleFunc("GET /api/hosts/{id}/alerts", requireSession(sessions, true, api.hostAlerts))

	// Alerts API.
	mux.HandleFunc("GET /api/alerts", requireSession(sessions, true, api.listAlerts))
	mux.HandleFunc("POST /api/alerts/{id}/ack", requireSession(sessions, true, api.ackAlert))

	// Settings API (read requires a session, write requires a freshly elevated one).
	mux.HandleFunc("GET /api/settings", requireSession(sessions, true, api.getSettings))
	mux.HandleFunc("PUT /api/settings", requireElevated(sessions, api.putSettings))

	return mux
}
