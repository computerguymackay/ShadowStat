package web

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"

	"ShadowStat/internal/auth"
	"ShadowStat/internal/geoip"
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

const (
	sparklineWindow = 60 * time.Minute
	day             = 24 * 60 * 60 // seconds
	topProtocolsN   = 3
	breakdownLimit  = 100
)

type hostSummary struct {
	ID           int64          `json:"id"`
	IP           string         `json:"ip"`
	DisplayName  string         `json:"display_name,omitempty"`
	FirstSeen    int64          `json:"first_seen"`
	LastSeen     int64          `json:"last_seen"`
	Sent24h      int64          `json:"sent_24h"`
	Recv24h      int64          `json:"recv_24h"`
	TotalSent    int64          `json:"total_sent"`
	TotalRecv    int64          `json:"total_recv"`
	TotalsSince  int64          `json:"totals_since,omitempty"`
	TopProtocols []string       `json:"top_protocols"`
	Sparkline    []seriesPointJ `json:"sparkline"`
}

type seriesPointJ struct {
	T    int64 `json:"t"`
	Sent int64 `json:"sent"`
	Recv int64 `json:"recv"`
}

// listHosts serves the dashboard: every LAN host with its last-24h and
// since-first-seen traffic, busiest first, plus a whole-WAN 24h summary.
func (h *apiHandlers) listHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.db.ListHosts()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	now := time.Now().Unix()
	recent, err := h.db.HostTrafficSince(now - day)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	totals, err := h.db.AllHostTotals()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	// Day buckets that overlap the last 24h: yesterday (UTC) and today.
	top, err := h.db.TopProtocols(((now-day)/day)*day, topProtocolsN)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	var wan store.ByteCounts
	out := make([]hostSummary, 0, len(hosts))
	for _, host := range hosts {
		points, err := h.db.SparklineSeries(host.ID, now-int64(sparklineWindow.Seconds()), now)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		rc, t := recent[host.ID], totals[host.ID]
		wan.Sent += rc.Sent
		wan.Recv += rc.Recv
		protos := top[host.ID]
		if protos == nil {
			protos = []string{}
		}
		out = append(out, hostSummary{
			ID:           host.ID,
			IP:           host.IP,
			DisplayName:  host.DisplayName.String,
			FirstSeen:    host.FirstSeen,
			LastSeen:     host.LastSeen,
			Sent24h:      rc.Sent,
			Recv24h:      rc.Recv,
			TotalSent:    t.BytesSent,
			TotalRecv:    t.BytesRecv,
			TotalsSince:  t.TotalsSince,
			TopProtocols: protos,
			Sparkline:    toSeriesJSON(points),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Sent24h+out[i].Recv24h > out[j].Sent24h+out[j].Recv24h
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"hosts":   out,
		"summary": map[string]int64{"sent_24h": wan.Sent, "recv_24h": wan.Recv},
	})
}

// hostTotals returns a host's cumulative counters since it was first seen.
func (h *apiHandlers) hostTotals(w http.ResponseWriter, r *http.Request) {
	hostID, ok := parseIDParam(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_host_id")
		return
	}
	host, err := h.db.HostByID(hostID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found")
		return
	} else if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	t, _, err := h.db.HostTotalsByID(hostID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	resp := map[string]any{
		"first_seen":   host.FirstSeen,
		"last_seen":    host.LastSeen,
		"bytes_sent":   t.BytesSent,
		"bytes_recv":   t.BytesRecv,
		"packets_sent": t.PacketsSent,
		"packets_recv": t.PacketsRecv,
		"totals_since": t.TotalsSince,
	}
	if t.ExactSince.Valid {
		resp["exact_since"] = t.ExactSince.Int64
	}
	writeJSON(w, http.StatusOK, resp)
}

// hostBreakdown returns who a host talked to, and on which ports and
// protocols, over [from, to].
func (h *apiHandlers) hostBreakdown(w http.ResponseWriter, r *http.Request) {
	hostID, ok := parseIDParam(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_host_id")
		return
	}
	from, to, ok := parseRange(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_range")
		return
	}
	b, err := h.db.HostBreakdown(hostID, from, to, time.Now().Unix()-day, breakdownLimit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	for i := range b.Peers {
		if ip := net.ParseIP(b.Peers[i].RemoteIP); ip != nil {
			b.Peers[i].Country, _ = geoip.CountryForIP(ip)
		}
	}
	writeJSON(w, http.StatusOK, b)
}

// --- series (the core zoomable graph endpoint) -----------------------------

func (h *apiHandlers) hostSeries(w http.ResponseWriter, r *http.Request) {
	hostID, ok := parseIDParam(r)
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
		if err != nil || (d != store.DirOutbound && d != store.DirInbound && d != store.DirUnknown) {
			writeJSONError(w, http.StatusBadRequest, "invalid_direction")
			return
		}
		direction = d
	}

	granularity := store.ChooseSeriesTier(from, to, time.Now().Unix(), h.retentionDays())
	var (
		points []store.SeriesPoint
		err    error
	)
	if granularity == "raw" {
		points, err = h.db.HostSeriesFromFlowsRecent(hostID, from, to, direction)
	} else {
		points, err = h.db.HostSeriesFromRollup(granularity, hostID, from, to, direction)
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

// retentionDays reads the retention setting, falling back to the default.
func (h *apiHandlers) retentionDays() int {
	if v, ok, err := h.db.GetSetting(store.KeyRetentionDays); err == nil && ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 30
}

// --- conversations ------------------------------------------------------

// hostFlows returns a host's individual conversations. Only the last 24h is
// kept at this detail; older ranges are rejected.
func (h *apiHandlers) hostFlows(w http.ResponseWriter, r *http.Request) {
	hostID, ok := parseIDParam(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_host_id")
		return
	}
	from, to, ok := parseRange(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_range")
		return
	}
	now := time.Now().Unix()
	if to < now-day {
		writeJSONError(w, http.StatusBadRequest, "range_too_old_for_flow_detail")
		return
	}
	from = max(from, now-day)

	limit := 200
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 && l <= 5000 {
			limit = l
		}
	}

	convs, err := h.db.HostConversations(hostID, from, to, limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"flows": convs})
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

func parseIDParam(r *http.Request) (int64, bool) {
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
