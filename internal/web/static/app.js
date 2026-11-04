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

  const l4Names = { 1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6" };
  function l4Name(n) {
    return l4Names[n] || "IP proto " + n;
  }

  function el(tag, className, text) {
    const e = document.createElement(tag);
    if (className) e.className = className;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  // appLabel renders an application-protocol name with its confidence:
  // payload-confirmed names show plainly, port-only guesses get a "?", and
  // unknown stays "Unknown" rather than pretending.
  function appLabel(name, confidence, proto) {
    if (!name) {
      const l4 = l4Name(proto);
      const span = el("span", "muted", proto === 1 || proto === 58 ? l4 : "Unknown");
      span.title = "Not identified";
      return span;
    }
    const span = el("span", "", confidence >= 2 ? name : name + "?");
    span.title = confidence >= 2 ? "Identified from the traffic itself" : "Guessed from the port number only";
    return span;
  }

  function protoListLabel(names) {
    if (!names || names.length === 0) return "—";
    return names.map((n) => n || "Unknown").join(", ");
  }

  const directionLabels = {
    0: ["Outbound", "This host started the connection"],
    1: ["Inbound", "Someone on the internet started the connection to this host"],
    4: ["Unknown", "Couldn't tell who started it (e.g. it was already running when first seen)"],
  };
  function directionLabel(d) {
    const [text, title] = directionLabels[d] || directionLabels[4];
    const span = el("span", "dir dir-" + text.toLowerCase(), text);
    span.title = title;
    return span;
  }

  const startedByLabels = {
    host: ["This host", "Every connection was started by this host"],
    remote: ["Remote peer", "Every connection was started from the internet side"],
    both: ["Both", "Some connections were started by each side"],
    unknown: ["Unknown", "Couldn't tell who started the connections"],
  };
  function startedByLabel(s) {
    const [text, title] = startedByLabels[s] || startedByLabels.unknown;
    const span = el("span", "dir", text);
    span.title = title;
    return span;
  }

  function fmtDate(unixSeconds) {
    return new Date(unixSeconds * 1000).toLocaleDateString();
  }

  // tdNode is td() for cells whose content is an element rather than text.
  function tdNode(label, node) {
    const cell = td(label, "");
    cell.appendChild(node);
    return cell;
  }

  function showTable(table, emptyEl, hasRows) {
    table.hidden = !hasRows;
    emptyEl.hidden = hasRows;
  }

  function redirectIfLoggedOut(err) {
    if (err.status === 401) {
      window.location.href = "/login";
      return true;
    }
    return false;
  }

  async function initDashboard() {
    wireLogoutButton();
    const tbody = document.getElementById("host-table-body");
    const emptyEl = document.getElementById("host-table-empty");
    const summaryEl = document.getElementById("wan-summary");
    let data;
    try {
      data = await api("/api/hosts");
    } catch (err) {
      if (redirectIfLoggedOut(err)) return;
      throw err;
    }

    summaryEl.textContent =
      "WAN, last 24 hours: ↑ " + fmtBytes(data.summary.sent_24h) + " sent · ↓ " + fmtBytes(data.summary.recv_24h) + " received";

    if (!data.hosts || data.hosts.length === 0) {
      document.getElementById("host-table").hidden = true;
      emptyEl.hidden = false;
      return;
    }

    for (const host of data.hosts) {
      const tr = document.createElement("tr");
      tr.tabIndex = 0;
      const open = () => (window.location.href = "/hosts/" + host.id);
      tr.addEventListener("click", open);
      tr.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          open();
        }
      });

      const nameCell = el("div", "", host.display_name || host.ip);
      if (host.display_name) nameCell.appendChild(el("div", "sub", host.ip));
      tr.appendChild(tdNode("Host", nameCell));
      tr.appendChild(td("Sent (24h)", fmtBytes(host.sent_24h)));
      tr.appendChild(td("Received (24h)", fmtBytes(host.recv_24h)));
      const totals = td("Since first seen", "↑ " + fmtBytes(host.total_sent) + "  ↓ " + fmtBytes(host.total_recv));
      totals.title = "Counted since " + fmtDate(host.totals_since || host.first_seen);
      tr.appendChild(totals);
      tr.appendChild(td("Top protocols", protoListLabel(host.top_protocols)));
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
    const firstSeen = Number(main.dataset.firstSeen) || 0;
    const DAY = 24 * 3600;

    const graphEl = document.getElementById("host-graph");
    const rangeLabel = document.getElementById("range-label");
    const rangeButtons = document.querySelectorAll(".range-picker button");
    let plot;

    function resizePlot() {
      if (!plot) return;
      plot.setSize({ width: graphEl.clientWidth, height: plot.height });
    }
    onResize(resizePlot);

    async function loadTotals() {
      const t = await api(`/api/hosts/${hostID}/totals`);
      document.getElementById("total-sent").textContent = fmtBytes(t.bytes_sent);
      document.getElementById("total-recv").textContent = fmtBytes(t.bytes_recv);
      const note = document.getElementById("totals-note");
      if (t.totals_since) {
        let text = "Totals count from " + fmtDate(t.totals_since) + ".";
        if (t.exact_since) {
          text +=
            " Traffic before " + fmtDate(t.exact_since) + " was rebuilt from older summaries when ShadowStat was upgraded, and may be incomplete.";
        }
        note.textContent = text;
      } else {
        note.textContent = "No traffic counted yet.";
      }
    }

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
            { label: "Sent ↑", stroke: "#4f8cff", value: (u, v) => (v == null ? "—" : fmtBytes(v)) },
            { label: "Received ↓", stroke: "#ff8c4f", value: (u, v) => (v == null ? "—" : fmtBytes(v)) },
          ],
          axes: [{}, { values: (u, vals) => vals.map((v) => fmtBytes(v)), size: 70 }],
          hooks: {
            setSelect: [
              (u) => {
                if (u.select.width <= 0) return;
                const newFrom = Math.round(u.posToVal(u.select.left, "x"));
                const newTo = Math.round(u.posToVal(u.select.left + u.select.width, "x"));
                u.setSelect({ left: 0, top: 0, width: 0, height: 0 }, false);
                setRange(newFrom, newTo, null);
              },
            ],
          },
        },
        [t, sent, recv],
        graphEl
      );
    }

    async function loadBreakdown(from, to) {
      const data = await api(`/api/hosts/${hostID}/breakdown?from=${from}&to=${to}`);
      document.getElementById("day-resolution-note").hidden = !data.day_resolution;

      const peerBody = document.getElementById("peer-table-body");
      peerBody.innerHTML = "";
      for (const p of data.peers) {
        const tr = document.createElement("tr");
        const who = el("div", "", p.name || p.remote_ip);
        if (p.name) {
          const sub = el("div", "sub", p.remote_ip);
          sub.title = "Name taken from the most recent DNS answer that pointed at this address";
          who.appendChild(sub);
        }
        tr.appendChild(tdNode("Peer", who));
        tr.appendChild(td("Country", p.country || "—"));
        tr.appendChild(td("Protocols", protoListLabel(p.protocols)));
        tr.appendChild(td("Ports", p.ports.filter((n) => n > 0).join(", ") || "—"));
        tr.appendChild(tdNode("Started by", startedByLabel(p.started_by)));
        tr.appendChild(td("Sent", fmtBytes(p.bytes_sent)));
        tr.appendChild(td("Received", fmtBytes(p.bytes_recv)));
        peerBody.appendChild(tr);
      }
      showTable(document.getElementById("peer-table"), document.getElementById("peer-table-empty"), data.peers.length > 0);

      const svcBody = document.getElementById("service-table-body");
      svcBody.innerHTML = "";
      for (const s of data.services) {
        const tr = document.createElement("tr");
        tr.appendChild(tdNode("Protocol", appLabel(s.app_proto, s.app_confidence, s.proto)));
        tr.appendChild(td("Port", s.service_port > 0 ? `${s.service_port}/${l4Name(s.proto)}` : l4Name(s.proto)));
        tr.appendChild(tdNode("Started by", startedByLabel(s.started_by)));
        tr.appendChild(td("Peers", String(s.peers)));
        tr.appendChild(td("Sent", fmtBytes(s.bytes_sent)));
        tr.appendChild(td("Received", fmtBytes(s.bytes_recv)));
        svcBody.appendChild(tr);
      }
      showTable(document.getElementById("service-table"), document.getElementById("service-table-empty"), data.services.length > 0);
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
        emptyEl.textContent = "Individual connections are only kept for the last 24 hours.";
        showTable(table, emptyEl, false);
        return;
      }
      emptyEl.textContent = "No connections in this range.";
      showTable(table, emptyEl, data.flows.length > 0);

      for (const f of data.flows) {
        const tr = document.createElement("tr");
        tr.appendChild(td("Peer", f.remote_ip));
        tr.appendChild(tdNode("Protocol", appLabel(f.app_proto, f.app_confidence, f.proto)));
        tr.appendChild(td("Ports", f.proto === 6 || f.proto === 17 ? `${f.local_port} → ${f.remote_port}/${l4Name(f.proto)}` : l4Name(f.proto)));
        tr.appendChild(tdNode("Started by", directionLabel(f.direction)));
        tr.appendChild(td("Sent", fmtBytes(f.bytes_sent)));
        tr.appendChild(td("Received", fmtBytes(f.bytes_recv)));
        tr.appendChild(td("Last seen", fmtTime(f.last_seen)));
        tbody.appendChild(tr);
      }
    }

    async function setRange(from, to, presetName) {
      for (const b of rangeButtons) b.classList.toggle("active", b.dataset.range === presetName);
      rangeLabel.textContent = "Showing " + fmtTime(from) + " – " + fmtTime(to);
      try {
        await Promise.all([loadSeries(from, to), loadBreakdown(from, to), loadFlows(from, to)]);
      } catch (err) {
        redirectIfLoggedOut(err);
      }
    }

    function presetRange(name) {
      const now = Math.floor(Date.now() / 1000);
      const spans = { "24h": DAY, "7d": 7 * DAY, "30d": 30 * DAY };
      const from = name === "all" ? Math.min(firstSeen || now - DAY, now - 60) : now - spans[name];
      setRange(from, now, name);
    }

    for (const b of rangeButtons) {
      b.addEventListener("click", () => presetRange(b.dataset.range));
    }

    try {
      await loadTotals();
    } catch (err) {
      if (redirectIfLoggedOut(err)) return;
    }
    presetRange("24h");
  }

  // withElevation runs actionFn(); if the server says the session needs a
  // fresh re-auth (settings-mutating endpoints require this), it prompts for
  // the password via the shared modal, elevates the session, then retries
  // actionFn() exactly once more. Any other error propagates normally.
  async function withElevation(actionFn) {
    try {
      return await actionFn();
    } catch (err) {
      if (err.code !== "reauth_required") throw err;
      await promptForReauth();
      return actionFn();
    }
  }

  function promptForReauth() {
    return new Promise((resolve, reject) => {
      const modal = document.getElementById("reauth-modal");
      const form = document.getElementById("reauth-form");
      const note = document.getElementById("reauth-note");
      const cancelBtn = document.getElementById("reauth-cancel-btn");
      note.textContent = "";
      modal.hidden = false;
      form.password.focus();

      function cleanup() {
        modal.hidden = true;
        form.removeEventListener("submit", onSubmit);
        cancelBtn.removeEventListener("click", onCancel);
        modal.removeEventListener("click", onBackdropClick);
        document.removeEventListener("keydown", onKeydown);
      }
      function onCancel() {
        cleanup();
        reject(new Error("reauth cancelled"));
      }
      // Clicking the dark backdrop (not the box itself) or pressing Escape
      // are the standard ways people expect to back out of a modal — without
      // these, the only way out was the easy-to-miss "Cancel" button.
      function onBackdropClick(e) {
        if (e.target === modal) onCancel();
      }
      function onKeydown(e) {
        if (e.key === "Escape") onCancel();
      }
      async function onSubmit(e) {
        e.preventDefault();
        try {
          await api("/api/reauth", { method: "POST", body: JSON.stringify({ password: form.password.value }) });
          form.reset();
          cleanup();
          resolve();
        } catch (err) {
          if (err.code === "unauthenticated") {
            // The session itself expired (not a wrong password) — every
            // retry would fail identically, so send them to log in again
            // instead of leaving them stuck re-typing a password that was
            // never the problem.
            cleanup();
            window.location.href = "/login";
            return;
          }
          form.password.value = "";
          form.password.focus();
          note.textContent = err.code === "invalid_credentials" ? "Incorrect password." : "Something went wrong — try again.";
        }
      }
      form.addEventListener("submit", onSubmit);
      cancelBtn.addEventListener("click", onCancel);
      modal.addEventListener("click", onBackdropClick);
      document.addEventListener("keydown", onKeydown);
    });
  }

  async function initSettings() {
    wireLogoutButton();

    const ifaceSelect = document.getElementById("capture-interface-select");
    const subnetInput = document.getElementById("lan-subnet-input");
    const retentionSelect = document.getElementById("retention-select");
    const generalNote = document.getElementById("general-settings-note");
    const generalForm = document.getElementById("general-settings-form");

    async function loadGeneralSettings() {
      const [ifaceData, settings] = await Promise.all([api("/api/interfaces"), api("/api/settings")]);

      ifaceSelect.innerHTML = "";
      for (const name of ifaceData.interfaces || []) {
        const opt = document.createElement("option");
        opt.value = name;
        opt.textContent = name;
        ifaceSelect.appendChild(opt);
      }
      if (settings.capture_interface) ifaceSelect.value = settings.capture_interface;
      if (settings.lan_subnet_cidr) subnetInput.value = settings.lan_subnet_cidr;
      if (settings.retention_days) retentionSelect.value = settings.retention_days;
    }

    generalForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      generalNote.textContent = "";
      try {
        const data = await withElevation(() =>
          api("/api/settings", {
            method: "PUT",
            body: JSON.stringify({
              capture_interface: ifaceSelect.value,
              lan_subnet_cidr: subnetInput.value,
              retention_days: retentionSelect.value,
            }),
          })
        );
        generalNote.textContent = data.restart_required
          ? "Saved. Restart shadowstat for the capture interface/subnet change to take effect."
          : "Saved.";
      } catch (err) {
        generalNote.textContent = "Could not save: " + (err.code || err.message);
      }
    });

    const userTableBody = document.getElementById("user-table-body");
    const addUserForm = document.getElementById("add-user-form");
    const addUserNote = document.getElementById("add-user-note");

    async function loadUsers() {
      const data = await api("/api/users");
      userTableBody.innerHTML = "";
      for (const u of data.users || []) {
        const tr = document.createElement("tr");
        tr.appendChild(td("Username", u.username));

        const roleTd = td("Role", "");
        const roleSelect = document.createElement("select");
        for (const r of ["standard", "admin"]) {
          const opt = document.createElement("option");
          opt.value = r;
          opt.textContent = r === "admin" ? "Admin" : "Standard";
          if (r === u.role) opt.selected = true;
          roleSelect.appendChild(opt);
        }
        roleSelect.addEventListener("change", async () => {
          try {
            await withElevation(() =>
              api(`/api/users/${u.id}/role`, { method: "PUT", body: JSON.stringify({ role: roleSelect.value }) })
            );
            await loadUsers();
          } catch (err) {
            alert("Could not change role: " + (err.code || err.message));
            roleSelect.value = u.role;
          }
        });
        roleTd.appendChild(roleSelect);
        tr.appendChild(roleTd);

        tr.appendChild(td("Created", fmtTime(u.created_at)));

        const actionsTd = td("", "");
        const delBtn = document.createElement("button");
        delBtn.type = "button";
        delBtn.className = "small-btn";
        delBtn.textContent = "Delete";
        delBtn.addEventListener("click", async () => {
          if (!confirm(`Delete user "${u.username}"?`)) return;
          try {
            await withElevation(() => api(`/api/users/${u.id}`, { method: "DELETE" }));
            await loadUsers();
          } catch (err) {
            alert("Could not delete user: " + (err.code || err.message));
          }
        });
        actionsTd.appendChild(delBtn);
        tr.appendChild(actionsTd);

        userTableBody.appendChild(tr);
      }
    }

    addUserForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      addUserNote.textContent = "";
      const fd = new FormData(addUserForm);
      try {
        await withElevation(() =>
          api("/api/users", {
            method: "POST",
            body: JSON.stringify({ username: fd.get("username"), password: fd.get("password"), role: fd.get("role") }),
          })
        );
        addUserForm.reset();
        addUserNote.textContent = "User added.";
        await loadUsers();
      } catch (err) {
        addUserNote.textContent = "Could not add user: " + (err.code || err.message);
      }
    });

    try {
      await loadGeneralSettings();
      await loadUsers();
    } catch (err) {
      if (err.status === 401) window.location.href = "/login";
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    wireLoginForm();
  });

  window.ShadowStat = { initDashboard, initHostDetail, initSettings };
})();
