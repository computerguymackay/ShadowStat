package web

import (
	"context"
	"net/http"

	"ShadowStat/internal/auth"
	"ShadowStat/internal/store"
)

const sessionCookieName = "shadowstat_session"

type ctxKey int

const sessionCtxKey ctxKey = iota

// requireSession rejects requests without a valid session: redirects to /login
// for page routes, or returns 401 JSON for API routes (distinguished by isAPI).
func requireSession(sessions *auth.Manager, isAPI bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			denyUnauthenticated(w, r, isAPI)
			return
		}
		sess, err := sessions.Validate(cookie.Value)
		if err != nil {
			denyUnauthenticated(w, r, isAPI)
			return
		}
		ctx := context.WithValue(r.Context(), sessionCtxKey, sess)
		next(w, r.WithContext(ctx))
	}
}

func denyUnauthenticated(w http.ResponseWriter, r *http.Request, isAPI bool) {
	if isAPI {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// requireElevated additionally rejects requests whose session hasn't recently
// re-authenticated, used to gate settings-mutating API endpoints.
func requireElevated(sessions *auth.Manager, next http.HandlerFunc) http.HandlerFunc {
	return requireSession(sessions, true, func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFromContext(r.Context())
		if !auth.IsElevated(sess) {
			writeJSONError(w, http.StatusForbidden, "reauth_required")
			return
		}
		next(w, r)
	})
}

func sessionFromContext(ctx context.Context) *store.Session {
	sess, _ := ctx.Value(sessionCtxKey).(*store.Session)
	return sess
}
