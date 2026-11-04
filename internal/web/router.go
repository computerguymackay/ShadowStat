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
	mux.HandleFunc("GET /settings", requireAdmin(sessions, false, pages.settings))

	// Auth API.
	mux.HandleFunc("POST /api/login", api.login)
	mux.HandleFunc("POST /api/logout", api.logout)
	mux.HandleFunc("POST /api/reauth", requireSession(sessions, true, api.reauth))

	// Data API — viewable by any authenticated user (standard users can view
	// dashboards, just not mutate anything).
	mux.HandleFunc("GET /api/hosts", requireSession(sessions, true, api.listHosts))
	mux.HandleFunc("GET /api/hosts/{id}/series", requireSession(sessions, true, api.hostSeries))
	mux.HandleFunc("GET /api/hosts/{id}/totals", requireSession(sessions, true, api.hostTotals))
	mux.HandleFunc("GET /api/hosts/{id}/breakdown", requireSession(sessions, true, api.hostBreakdown))
	mux.HandleFunc("GET /api/hosts/{id}/flows", requireSession(sessions, true, api.hostFlows))

	// Admin-only mutations and settings/user management.
	mux.HandleFunc("GET /api/settings", requireAdmin(sessions, true, api.getSettings))
	mux.HandleFunc("PUT /api/settings", requireAdminElevated(sessions, api.putSettings))
	mux.HandleFunc("GET /api/interfaces", requireAdmin(sessions, true, api.listInterfaces))
	mux.HandleFunc("GET /api/users", requireAdmin(sessions, true, api.listUsers))
	mux.HandleFunc("POST /api/users", requireAdminElevated(sessions, api.createUser))
	mux.HandleFunc("PUT /api/users/{id}/role", requireAdminElevated(sessions, api.updateUserRole))
	mux.HandleFunc("DELETE /api/users/{id}", requireAdminElevated(sessions, api.deleteUser))

	return mux
}
