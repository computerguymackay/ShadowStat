package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"ShadowStat/internal/auth"
	"ShadowStat/internal/store"
)

type apiHandlers struct {
	db       *store.DB
	sessions *auth.Manager
}

// --- auth ---------------------------------------------------------------

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *apiHandlers) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	token, err := h.sessions.Login(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, store.ErrNotFound) {
			writeJSONError(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	setSessionCookie(w, token, auth.SessionIdleTimeout)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *apiHandlers) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_ = h.sessions.Logout(cookie.Value)
	}
	clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type reauthRequest struct {
	Password string `json:"password"`
}

func (h *apiHandlers) reauth(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	var req reauthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.sessions.Elevate(sess.Token, req.Password); err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeJSONError(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func setSessionCookie(w http.ResponseWriter, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(ttl),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// --- hosts ----------------------------------------------------------------

const sparklineWindow = 60 * time.Minute

type hostSummary struct {
	ID          int64          `json:"id"`
	IP          string         `json:"ip"`
	DisplayName string         `json:"display_name,omitempty"`
	LastSeen    int64          `json:"last_seen"`
	Sparkline   []seriesPointJ `json:"sparkline"`
}

type seriesPointJ struct {
	T    int64 `json:"t"`
	Sent int64 `json:"sent"`
	Recv int64 `json:"recv"`
}

func (h *apiHandlers) listHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.db.ListHosts()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	now := time.Now().Unix()
	from := now - int64(sparklineWindow.Seconds())

	out := make([]hostSummary, 0, len(hosts))
	for _, host := range hosts {
		points, err := h.db.SparklineSeries(host.ID, from, now)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		out = append(out, hostSummary{
			ID:          host.ID,
			IP:          host.IP,
			DisplayName: host.DisplayName.String,
			LastSeen:    host.LastSeen,
			Sparkline:   toSeriesJSON(points),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
}

// --- series (the core zoomable graph endpoint) -----------------------------

// granularity thresholds, in seconds, for picking which table to query based
// on the requested [from,to] range. See plan §6 for rationale.
const (
	rangeFlowsRecentMax = 24 * int64(time.Hour/time.Second)
	range1mMax          = 10 * 24 * int64(time.Hour/time.Second)
	range5mMax          = 90 * 24 * int64(time.Hour/time.Second)
	range1hMax          = 2 * 365 * 24 * int64(time.Hour/time.Second)
)

func (h *apiHandlers) hostSeries(w http.ResponseWriter, r *http.Request) {
	hostID, ok := parseHostID(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_host_id")
		return
	}

	from, to, ok := parseRange(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_range")
		return
	}

	direction := -1
	if dStr := r.URL.Query().Get("direction"); dStr != "" {
		d, err := strconv.Atoi(dStr)
		if err != nil || d < 0 || d > 3 {
			writeJSONError(w, http.StatusBadRequest, "invalid_direction")
			return
		}
		direction = d
	}

	span := to - from
	now := time.Now().Unix()

	var (
		points      []store.SeriesPoint
		err         error
		granularity string
	)

	switch {
	case span <= rangeFlowsRecentMax && to >= now-rangeFlowsRecentMax:
		granularity = "raw"
		points, err = h.db.HostSeriesFromFlowsRecent(hostID, from, to, direction)
	case span <= range1mMax:
		granularity = "1m"
		points, err = h.db.HostSeriesFromRollup("1m", hostID, from, to, direction)
	case span <= range5mMax:
		granularity = "5m"
		points, err = h.db.HostSeriesFromRollup("5m", hostID, from, to, direction)
	case span <= range1hMax:
		granularity = "1h"
		points, err = h.db.HostSeriesFromRollup("1h", hostID, from, to, direction)
	default:
		granularity = "1d"
		points, err = h.db.HostSeriesFromRollup("1d", hostID, from, to, direction)
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"granularity": granularity,
		"series":      toColumnarSeries(points),
	})
}

// --- flows detail -----------------------------------------------------------

func (h *apiHandlers) hostFlows(w http.ResponseWriter, r *http.Request) {
	hostID, ok := parseHostID(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_host_id")
		return
	}
	from, to, ok := parseRange(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_range")
		return
	}
	if time.Now().Unix()-to > rangeFlowsRecentMax {
		writeJSONError(w, http.StatusBadRequest, "range_too_old_for_flow_detail")
		return
	}

	limit := 500
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 && l <= 5000 {
			limit = l
		}
	}

	flows, err := h.db.HostFlows(hostID, from, to, limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"flows": flows})
}

// --- settings -----------------------------------------------------------

func (h *apiHandlers) getSettings(w http.ResponseWriter, r *http.Request) {
	kv, err := h.db.AllSettings()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	delete(kv, store.KeySetupComplete)
	writeJSON(w, http.StatusOK, kv)
}

func (h *apiHandlers) putSettings(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	restartRequired := false
	if _, ok := req[store.KeyCaptureInterface]; ok {
		restartRequired = true
	}
	if _, ok := req[store.KeyLANSubnetCIDR]; ok {
		restartRequired = true
	}

	if err := h.db.SetSettings(req); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "restart_required": restartRequired})
}

// --- shared helpers -----------------------------------------------------

func parseHostID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

func parseRange(r *http.Request) (from, to int64, ok bool) {
	q := r.URL.Query()
	fromStr, toStr := q.Get("from"), q.Get("to")
	if fromStr == "" || toStr == "" {
		return 0, 0, false
	}
	f, err1 := strconv.ParseInt(fromStr, 10, 64)
	t, err2 := strconv.ParseInt(toStr, 10, 64)
	if err1 != nil || err2 != nil || f >= t {
		return 0, 0, false
	}
	return f, t, true
}

func toSeriesJSON(points []store.SeriesPoint) []seriesPointJ {
	out := make([]seriesPointJ, 0, len(points))
	for _, p := range points {
		out = append(out, seriesPointJ{T: p.BucketTS, Sent: p.BytesSent, Recv: p.BytesRecv})
	}
	return out
}

// toColumnarSeries reshapes rows into the parallel-array format uPlot consumes directly.
func toColumnarSeries(points []store.SeriesPoint) map[string]any {
	t := make([]int64, len(points))
	sent := make([]int64, len(points))
	recv := make([]int64, len(points))
	for i, p := range points {
		t[i] = p.BucketTS
		sent[i] = p.BytesSent
		recv[i] = p.BytesRecv
	}
	return map[string]any{"t": t, "sent": sent, "recv": recv}
}
