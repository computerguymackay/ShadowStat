package web

import (
	"net/http"
	"strconv"

	"ShadowStat/internal/store"
)

type alertJSON struct {
	ID           int64  `json:"id"`
	HostID       int64  `json:"host_id"`
	HostIP       string `json:"host_ip"`
	Kind         string `json:"kind"`
	Severity     string `json:"severity"`
	Summary      string `json:"summary"`
	Detail       string `json:"detail,omitempty"`
	DetectedAt   int64  `json:"detected_at"`
	Acknowledged bool   `json:"acknowledged"`
}

func toAlertsJSON(alerts []store.Alert) []alertJSON {
	out := make([]alertJSON, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, alertJSON{
			ID: a.ID, HostID: a.HostID, HostIP: a.HostIP, Kind: a.Kind, Severity: a.Severity,
			Summary: a.Summary, Detail: a.Detail, DetectedAt: a.DetectedAt, Acknowledged: a.Acknowledged,
		})
	}
	return out
}

const defaultAlertLimit = 200

// listAlerts returns the most recent alerts across all hosts.
func (h *apiHandlers) listAlerts(w http.ResponseWriter, r *http.Request) {
	limit := defaultAlertLimit
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 && l <= 2000 {
			limit = l
		}
	}
	unackedOnly := r.URL.Query().Get("unacked_only") == "1"

	alerts, err := h.db.ListAlerts(limit, unackedOnly)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": toAlertsJSON(alerts)})
}

// hostAlerts returns the most recent alerts for a single host.
func (h *apiHandlers) hostAlerts(w http.ResponseWriter, r *http.Request) {
	hostID, ok := parseHostID(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_host_id")
		return
	}
	alerts, err := h.db.ListAlertsForHost(hostID, defaultAlertLimit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": toAlertsJSON(alerts)})
}

// ackAlert marks an alert as acknowledged.
func (h *apiHandlers) ackAlert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_alert_id")
		return
	}
	if err := h.db.AcknowledgeAlert(id); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
