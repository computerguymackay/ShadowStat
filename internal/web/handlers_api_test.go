package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ShadowStat/internal/store"
)

func seededDB(t *testing.T) (*store.DB, int64) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "shadowstat.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	now := time.Now().Unix()
	hostID, err := db.UpsertHost("192.168.1.50", now-3600)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InsertFlows([]store.FlowRecord{{
		HostID: hostID, Direction: store.DirOutbound, Proto: 6,
		LocalIP: "192.168.1.50", LocalPort: 50000, RemoteIP: "1.1.1.1", RemotePort: 443,
		FirstSeen: now - 600, LastSeen: now - 590, BytesSent: 100, BytesRecv: 2000,
		ServicePort: 443, AppProto: "HTTPS", AppConfidence: store.ConfPayload,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RunRollup(); err != nil {
		t.Fatal(err)
	}
	return db, hostID
}

func call(t *testing.T, h http.HandlerFunc, path string, id int64) map[string]any {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.SetPathValue("id", fmt.Sprint(id))
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", path, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: bad JSON: %v", path, err)
	}
	return out
}

func TestHostEndpoints(t *testing.T) {
	db, hostID := seededDB(t)
	api := &apiHandlers{db: db}
	now := time.Now().Unix()
	rng := fmt.Sprintf("?from=%d&to=%d", now-86400, now)

	hosts := call(t, api.listHosts, "/api/hosts", 0)
	list := hosts["hosts"].([]any)
	h := list[0].(map[string]any)
	if h["sent_24h"].(float64) != 100 || h["total_recv"].(float64) != 2000 {
		t.Errorf("host summary = %+v", h)
	}
	if protos := h["top_protocols"].([]any); len(protos) != 1 || protos[0] != "HTTPS" {
		t.Errorf("top_protocols = %v", protos)
	}
	if s := hosts["summary"].(map[string]any); s["recv_24h"].(float64) != 2000 {
		t.Errorf("WAN summary = %+v", s)
	}

	totals := call(t, api.hostTotals, "/api/hosts/1/totals", hostID)
	if totals["bytes_sent"].(float64) != 100 {
		t.Errorf("totals = %+v", totals)
	}

	b := call(t, api.hostBreakdown, "/api/hosts/1/breakdown"+rng, hostID)
	peers := b["peers"].([]any)
	if len(peers) != 1 || peers[0].(map[string]any)["country"] == "" {
		t.Errorf("peers = %+v (want 1.1.1.1 with a country)", peers)
	}

	flows := call(t, api.hostFlows, "/api/hosts/1/flows"+rng, hostID)
	if f := flows["flows"].([]any); len(f) != 1 || f[0].(map[string]any)["app_proto"] != "HTTPS" {
		t.Errorf("flows = %+v", flows)
	}

	series := call(t, api.hostSeries, "/api/hosts/1/series"+rng, hostID)
	if series["granularity"] != "raw" {
		t.Errorf("granularity = %v", series["granularity"])
	}
}

func TestPagesRender(t *testing.T) {
	vars := &pageVars{HostID: 1, HostIP: "192.168.1.50", Breadcrumb: "x", IsAdmin: true}
	for _, page := range []string{"dashboard.html", "host_detail.html", "settings.html", "login.html"} {
		w := httptest.NewRecorder()
		renderTemplate(w, page, vars)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "</html>") {
			t.Errorf("%s failed to render: %d %s", page, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "/alerts") {
			t.Errorf("%s still links to the removed alerts page", page)
		}
	}
}
