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

  function makeSparkline(container, points) {
    const t = points.map((p) => p.t);
    const sent = points.map((p) => p.sent);
    const recv = points.map((p) => p.recv);
    const width = container.clientWidth || 160;
    new uPlot(
      {
        width,
        height: 40,
        cursor: { show: false },
        legend: { show: false },
        axes: [{ show: false }, { show: false }],
        series: [{}, { stroke: "#4f8cff" }, { stroke: "#ff8c4f" }],
      },
      [t, sent, recv],
      container
    );
  }

  async function initDashboard() {
    wireLogoutButton();
    const tbody = document.getElementById("host-table-body");
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

    for (const host of data.hosts) {
      const tr = document.createElement("tr");
      tr.addEventListener("click", () => {
        window.location.href = "/hosts/" + host.id;
      });

      const nameTd = document.createElement("td");
      nameTd.textContent = host.display_name || host.ip;
      tr.appendChild(nameTd);

      const seenTd = document.createElement("td");
      seenTd.textContent = fmtTime(host.last_seen);
      tr.appendChild(seenTd);

      const sparkTd = document.createElement("td");
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
      tbody.innerHTML = "";
      let data;
      try {
        data = await api(`/api/hosts/${hostID}/flows?from=${from}&to=${to}&limit=200`);
      } catch (err) {
        return; // range too old for flow detail, or other error — leave table empty
      }
      const dirLabels = ["LAN→WAN", "WAN→LAN", "inter-VLAN"];
      for (const f of data.flows || []) {
        const tr = document.createElement("tr");
        [
          f.RemoteIP,
          f.RemotePort,
          f.Proto,
          dirLabels[f.Direction] || f.Direction,
          fmtBytes(f.BytesSent),
          fmtBytes(f.BytesRecv),
          fmtTime(f.LastSeen),
        ].forEach((val) => {
          const td = document.createElement("td");
          td.textContent = val;
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      }
    }

    try {
      await loadSeries(from, now);
      await loadFlows(from, now);
    } catch (err) {
      if (err.status === 401) {
        window.location.href = "/login";
      }
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    wireLoginForm();
  });

  window.ShadowStat = { initDashboard, initHostDetail };
})();
