(function () {
  "use strict";

  async function api(path, opts) {
    const res = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, opts));
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      const err = new Error(body.error || res.statusText);
      err.status = res.status;
      err.code = body.error;
      throw err;
    }
    return res.json();
  }

  function fmtBytes(n) {
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    n = Number(n) || 0;
    while (n >= 1024 && i < units.length - 1) {
      n /= 1024;
      i++;
    }
    return n.toFixed(i === 0 ? 0 : 1) + " " + units[i];
  }

  function fmtTime(unixSeconds) {
    return new Date(unixSeconds * 1000).toLocaleString();
  }

  // Builds a <td> with a data-label attribute so the narrow-viewport CSS can
  // render it as a "label: value" row inside a card instead of a table cell.
  function td(label, text) {
    const el = document.createElement("td");
    el.dataset.label = label;
    el.textContent = text;
    return el;
  }

  function wireLoginForm() {
    const form = document.getElementById("login-form");
    if (!form) return;
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const errEl = document.getElementById("login-error");
      errEl.hidden = true;
      const fd = new FormData(form);
      try {
        await api("/api/login", {
          method: "POST",
          body: JSON.stringify({ username: fd.get("username"), password: fd.get("password") }),
        });
        window.location.href = "/";
      } catch (err) {
        errEl.textContent = "Invalid username or password.";
        errEl.hidden = false;
      }
    });
  }

  function wireLogoutButton() {
    const btn = document.getElementById("logout-btn");
    if (!btn) return;
    btn.addEventListener("click", async () => {
      await api("/api/logout", { method: "POST" }).catch(() => {});
      window.location.href = "/login";
    });
  }

  // Debounces window resize so uPlot instances aren't re-laid-out on every
  // single resize event (e.g. while a mobile browser's chrome is animating
  // in/out, or a desktop window is being dragged).
  function onResize(fn, delay) {
    let t;
    window.addEventListener("resize", () => {
      clearTimeout(t);
      t = setTimeout(fn, delay || 150);
    });
  }

  function makeSparkline(container, points) {
    const t = points.map((p) => p.t);
    const sent = points.map((p) => p.sent);
    const recv = points.map((p) => p.recv);
    const width = container.clientWidth || 140;
    new uPlot(
      {
        width,
        height: 36,
        cursor: { show: false },
        legend: { show: false },
        axes: [{ show: false }, { show: false }],
        series: [{}, { stroke: "#4f8cff" }, { stroke: "#ff8c4f" }],
      },
      [t, sent, recv],
      container
    );
  }

  const alertKindLabels = {
    new_destination: "New destination",
    beaconing: "Beaconing",
    exfil_ratio: "Upload/download ratio",
    dns_anomaly: "DNS anomaly",
    port_scan: "Port scan",
  };

  // detailRow appends a "label: value" row to a detail <dl>.
  function detailRow(dl, label, value) {
    const row = document.createElement("div");
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    row.appendChild(dt);
    row.appendChild(dd);
    dl.appendChild(row);
  }

  // buildAlertDetail parses an alert's JSON detail blob into a human-readable
  // panel, tailored per detector kind since each has a different shape.
  // Falls back to raw key/value pairs for anything it doesn't recognize, so
  // this never hides information even if a field is missing/unexpected.
  function buildAlertDetail(kind, direction, detailStr) {
    const dl = document.createElement("dl");
    dl.className = "alert-detail-fields";

    let d = {};
    try {
      d = JSON.parse(detailStr || "{}");
    } catch (e) {
      const pre = document.createElement("pre");
      pre.textContent = detailStr || "(no detail)";
      return pre;
    }

    const directionLabels = {
      outbound: "Outbound — this device initiated the traffic",
      inbound: "Inbound — a remote host contacted this device (no request from this device seen)",
      bidirectional: "Bidirectional — this device initiated it, and the peer also responded/reached back",
      unknown: "Unknown",
    };
    detailRow(dl, "Direction", directionLabels[direction] || directionLabels.outbound);

    switch (kind) {
      case "port_scan": {
        detailRow(dl, "Target", d.remote_ip);
        detailRow(dl, "Distinct ports probed", String(d.port_count));
        if (Array.isArray(d.ports)) {
          const list = d.ports.join(", ") + (d.ports_truncated ? ", …" : "");
          detailRow(dl, "Ports", list);
        }
        detailRow(dl, "Window", `${d.window_seconds}s`);
        break;
      }
      case "new_destination": {
        detailRow(dl, "Peer", `${d.remote_ip}:${d.remote_port}`);
        detailRow(dl, "Why it's flagged", "Not contacted by this host in the last 30 days");
        break;
      }
      case "beaconing": {
        detailRow(dl, "Peer", `${d.remote_ip}:${d.remote_port}`);
        detailRow(dl, "Mean interval", `${Math.round(d.mean_interval_s)}s`);
        detailRow(dl, "Observations", String(d.observations));
        break;
      }
      case "exfil_ratio": {
        detailRow(dl, "Sent", fmtBytes(d.bytes_sent));
        detailRow(dl, "Received", fmtBytes(d.bytes_recv));
        detailRow(dl, "Ratio", `${Number(d.ratio).toFixed(1)}x`);
        break;
      }
      case "dns_anomaly": {
        if (d.qname) {
          detailRow(dl, "Domain", d.qname);
          detailRow(dl, "Why it's flagged", "High-entropy name, suggestive of a DGA (domain generation algorithm)");
        } else {
          detailRow(dl, "Query count", String(d.query_count));
          detailRow(dl, "Window", `${d.window_seconds}s`);
        }
        break;
      }
      default: {
        for (const [k, v] of Object.entries(d)) {
          detailRow(dl, k, String(v));
        }
      }
    }
    return dl;
  }

  // Renders a list of alerts into listEl (a <ul>), showing emptyEl instead if
  // there are none. showHostLink includes a link to the host's detail page
  // (used on the global alerts page; omitted on a host's own alerts section).
  function renderAlertList(listEl, emptyEl, alerts, showHostLink) {
    listEl.innerHTML = "";
    if (!alerts || alerts.length === 0) {
      listEl.hidden = true;
      emptyEl.hidden = false;
      return;
    }
    listEl.hidden = false;
    emptyEl.hidden = true;

    for (const a of alerts) {
      const li = document.createElement("li");
      li.className = "alert-item severity-" + a.severity + (a.acknowledged ? " acknowledged" : "");

      const main = document.createElement("div");
      main.className = "alert-main";

      const body = document.createElement("button");
      body.type = "button";
      body.className = "alert-body";
      body.setAttribute("aria-expanded", "false");

      const summary = document.createElement("div");
      summary.className = "alert-summary";
      summary.textContent = a.summary;
      body.appendChild(summary);

      const meta = document.createElement("div");
      meta.className = "alert-meta";
      const kindSpan = document.createElement("span");
      kindSpan.textContent = alertKindLabels[a.kind] || a.kind;
      meta.appendChild(kindSpan);
      const timeSpan = document.createElement("span");
      timeSpan.textContent = fmtTime(a.detected_at);
      meta.appendChild(timeSpan);
      if (showHostLink) {
        const hostLink = document.createElement("a");
        hostLink.href = "/hosts/" + a.host_id;
        hostLink.textContent = a.host_ip;
        hostLink.addEventListener("click", (e) => e.stopPropagation());
        meta.appendChild(hostLink);
      }
      const chevron = document.createElement("span");
      chevron.className = "alert-chevron";
      chevron.textContent = "Details ▾";
      meta.appendChild(chevron);
      body.appendChild(meta);
      main.appendChild(body);

      const detailPanel = document.createElement("div");
      detailPanel.className = "alert-detail";
      detailPanel.hidden = true;
      let built = false;
      body.addEventListener("click", () => {
        if (!built) {
          detailPanel.appendChild(buildAlertDetail(a.kind, JSON.parse(a.detail || "{}").direction, a.detail));
          built = true;
        }
        const expanded = !detailPanel.hidden;
        detailPanel.hidden = expanded;
        body.setAttribute("aria-expanded", String(!expanded));
        chevron.textContent = expanded ? "Details ▾" : "Details ▴";
      });
      main.appendChild(detailPanel);
      li.appendChild(main);

      if (!a.acknowledged) {
        const btn = document.createElement("button");
        btn.className = "alert-ack-btn";
        btn.type = "button";
        btn.textContent = "Acknowledge";
        btn.addEventListener("click", async () => {
          btn.disabled = true;
          try {
            await api(`/api/alerts/${a.id}/ack`, { method: "POST" });
            li.classList.add("acknowledged");
            btn.remove();
          } catch (err) {
            btn.disabled = false;
          }
        });
        li.appendChild(btn);
      }

      listEl.appendChild(li);
    }
  }

  async function initAlerts() {
    wireLogoutButton();
    const listEl = document.getElementById("alert-list");
    const emptyEl = document.getElementById("alert-list-empty");
    const toggle = document.getElementById("unacked-toggle");

    async function load() {
      let data;
      try {
        data = await api(`/api/alerts?unacked_only=${toggle.checked ? "1" : "0"}`);
      } catch (err) {
        if (err.status === 401) {
          window.location.href = "/login";
          return;
        }
        throw err;
      }
      renderAlertList(listEl, emptyEl, data.alerts, true);
    }

    toggle.addEventListener("change", load);
    await load();
  }

  async function initDashboard() {
    wireLogoutButton();
    const tbody = document.getElementById("host-table-body");
    const emptyEl = document.getElementById("host-table-empty");
    let data;
    try {
      data = await api("/api/hosts");
    } catch (err) {
      if (err.status === 401) {
        window.location.href = "/login";
        return;
      }
      throw err;
    }

    if (!data.hosts || data.hosts.length === 0) {
      document.getElementById("host-table").hidden = true;
      emptyEl.hidden = false;
      return;
    }

    for (const host of data.hosts) {
      const tr = document.createElement("tr");
      tr.tabIndex = 0;
      tr.addEventListener("click", () => {
        window.location.href = "/hosts/" + host.id;
      });
      tr.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          window.location.href = "/hosts/" + host.id;
        }
      });

      tr.appendChild(td("Host", host.display_name || host.ip));
      tr.appendChild(td("Last seen", fmtTime(host.last_seen)));

      const sparkTd = td("Activity (last hour)", "");
      sparkTd.className = "sparkline";
      tr.appendChild(sparkTd);

      tbody.appendChild(tr);
      if (host.sparkline && host.sparkline.length > 1) {
        makeSparkline(sparkTd, host.sparkline);
      }
    }
  }

  async function initHostDetail() {
    wireLogoutButton();
    const main = document.querySelector("main[data-host-id]");
    const hostID = main.dataset.hostId;

    const now = Math.floor(Date.now() / 1000);
    let from = now - 24 * 3600;

    const graphEl = document.getElementById("host-graph");
    let plot;

    function resizePlot() {
      if (!plot) return;
      plot.setSize({ width: graphEl.clientWidth, height: plot.height });
    }
    onResize(resizePlot);

    async function loadSeries(from, to) {
      const data = await api(`/api/hosts/${hostID}/series?from=${from}&to=${to}`);
      const t = data.series.t,
        sent = data.series.sent,
        recv = data.series.recv;

      if (plot) {
        plot.setData([t, sent, recv]);
        return;
      }
      plot = new uPlot(
        {
          width: graphEl.clientWidth || 800,
          height: 300,
          series: [
            {},
            { label: "Sent", stroke: "#4f8cff" },
            { label: "Received", stroke: "#ff8c4f" },
          ],
          hooks: {
            setSelect: [
              (u) => {
                if (u.select.width <= 0) return;
                const newFrom = Math.round(u.posToVal(u.select.left, "x"));
                const newTo = Math.round(u.posToVal(u.select.left + u.select.width, "x"));
                loadSeries(newFrom, newTo);
              },
            ],
          },
        },
        [t, sent, recv],
        graphEl
      );
    }

    async function loadFlows(from, to) {
      const tbody = document.getElementById("flow-table-body");
      const table = document.getElementById("flow-table");
      const emptyEl = document.getElementById("flow-table-empty");
      tbody.innerHTML = "";

      let data;
      try {
        data = await api(`/api/hosts/${hostID}/flows?from=${from}&to=${to}&limit=200`);
      } catch (err) {
        table.hidden = true;
        emptyEl.hidden = false;
        return; // range too old for flow detail, or other error
      }

      if (!data.flows || data.flows.length === 0) {
        table.hidden = true;
        emptyEl.hidden = false;
        return;
      }
      table.hidden = false;
      emptyEl.hidden = true;

      const dirLabels = ["LAN→WAN", "WAN→LAN", "inter-VLAN"];
      for (const f of data.flows) {
        const tr = document.createElement("tr");
        tr.appendChild(td("Peer", f.RemoteIP));
        tr.appendChild(td("Port", f.RemotePort));
        tr.appendChild(td("Proto", f.Proto));
        tr.appendChild(td("Direction", dirLabels[f.Direction] || f.Direction));
        tr.appendChild(td("Sent", fmtBytes(f.BytesSent)));
        tr.appendChild(td("Received", fmtBytes(f.BytesRecv)));
        tr.appendChild(td("Last seen", fmtTime(f.LastSeen)));
        tbody.appendChild(tr);
      }
    }

    async function loadAlerts() {
      const listEl = document.getElementById("host-alert-list");
      const emptyEl = document.getElementById("host-alert-list-empty");
      try {
        const data = await api(`/api/hosts/${hostID}/alerts`);
        renderAlertList(listEl, emptyEl, data.alerts, false);
      } catch (err) {
        // non-fatal: leave the section empty rather than breaking the page
      }
    }

    try {
      await loadSeries(from, now);
      await loadFlows(from, now);
      await loadAlerts();
    } catch (err) {
      if (err.status === 401) {
        window.location.href = "/login";
      }
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    wireLoginForm();
  });

  window.ShadowStat = { initDashboard, initHostDetail, initAlerts };
})();
