# ShadowStat

A self-contained, single-binary Linux WAN traffic monitor. Captures traffic
off a mirrored switch port and shows, per LAN host, what crosses the WAN link:
who it talks to, on which ports and protocols, and how much data goes each
way — with history from the moment each host was first seen. It is not an
IDS and doesn't try to be one.

## Status

Live capture → in-memory aggregation → durable two-tier SQLite storage →
authenticated, mobile-friendly HTTPS UI:

- **Dashboard:** every LAN host (named from DHCP when known) with bytes sent
  and received in the last 24h, totals since first seen, top protocols, and
  a whole-WAN 24h summary.
- **Host page:** totals since first seen, a zoomable graph (24h / 7d / 30d /
  since first seen, or drag to zoom), and three tables for the chosen range —
  *who it talks to* (peer name from DNS answers, IP, country, protocols,
  ports, who started it, bytes each way), *ports & protocols*, and
  individual *connections* (last 24h).
- **Direction is explicit everywhere:** "Sent" is LAN host → internet,
  "Received" is internet → LAN host, and each conversation is labeled
  *outbound* (the host started it), *inbound* (the internet side started it)
  or *unknown*.
- **Protocol identification** from port numbers plus small, in-tree payload
  signatures (TLS/HTTPS, HTTP, SSH, SMTP, IMAP, POP3, FTP, RDP, BitTorrent,
  DNS, NTP, QUIC, STUN, WireGuard). Port-only guesses are marked with "?",
  and "unknown" is shown as unknown.
- **Settings** for capture interface, LAN subnet and history retention, plus
  user management — admins get full control, standard users get read-only
  access.

## Roadmap

- **IPv6** — the decoder already parses it, but the capture filter drops it
  and the LAN side is defined by one IPv4 subnet. Needs a LAN IPv6 prefix
  setting.
- **Cert replacement UI** — swap the self-signed cert for a real one (or
  ACME) via the settings page, hot-swapped without a restart.
- **Pluggable sFlow/NetFlow sources** — `capture.Source` already has the
  seam; only the AF_PACKET implementation exists today.

## Requirements

- Linux (uses AF_PACKET for capture)
- Go 1.26+ to build
- A network interface that can see WAN-crossing traffic — normally a NIC
  connected to a mirrored switch port that mirrors the router's uplink.
  ShadowStat puts this interface into promiscuous mode itself on every start
  (via `SetPromiscuous(true)`) — nothing to configure manually there, but the
  switch port it's plugged into does need to actually be configured as a
  mirror/SPAN port of the router's uplink, or there's nothing to capture.
- **A second network interface (wired or Wi-Fi) for the machine's own
  connectivity.** A mirror/SPAN port only ever sends the box a *copy* of
  traffic — it's not a normal switched port, so it generally can't be relied
  on for the box's own default route, DNS, SSH/WireGuard access, or the
  HTTPS UI being reachable. Run the OS, remote access, and the web UI over a
  separate NIC; dedicate the mirrored one to capture only.

No other runtime dependencies: the binary is a fully static, CGO_ENABLED=0
build (pure-Go SQLite via `modernc.org/sqlite`, pure-Go packet capture via
`gopacket/pcapgo`'s AF_PACKET support — no libpcap, no cgo). `install-service`
additionally shells out to `useradd` and `systemctl`/`rc-update` (both
standard on any systemd or OpenRC distro), but only if you use it.

## Installation (fresh machine)

### Option A: download a pre-built binary

Every [release](https://github.com/computerguymackay/ShadowStat/releases)
publishes static binaries for `linux/amd64`, `linux/arm64` (64-bit Pi
OS/most modern ARM boards), `linux/armv7` (32-bit Pi OS, Pi 2/3/4), and
`linux/armv6` (Pi Zero/1). No Go toolchain needed on the target machine —
useful on a Raspberry Pi, where building from source can be slow.

```sh
curl -LO https://github.com/computerguymackay/ShadowStat/releases/latest/download/shadowstat-linux-arm64.tar.gz
tar xzf shadowstat-linux-arm64.tar.gz
sudo mv shadowstat-linux-arm64 /usr/local/bin/shadowstat
```

(swap `arm64` for `armv7`/`armv6`/`amd64` to match your device — `uname -m`
tells you which: `aarch64` → arm64, `armv7l` → armv7, `armv6l` → armv6,
`x86_64` → amd64). `SHA256SUMS.txt` in the same release verifies the download.

### Option B: build from source

```sh
git clone git@github.com:computerguymackay/ShadowStat.git
cd ShadowStat
make build              # -> bin/shadowstat, a single static binary
```

### Either way, then

```sh
./bin/shadowstat run    # (or just `shadowstat run` if installed to PATH)
                         # interactive first-run setup (see below), Ctrl+C once it's serving

sudo ./bin/shadowstat install-service   # optional: run it as a proper system service
```

That's the whole install — no package manager, no separate config step, no
dependencies to install beyond Go itself if building from source. The
interactive `run` step is required at least once (it's what creates the
database and prompts for capture interface/LAN subnet/retention/admin
credentials); skipping straight to `install-service` on a machine that's
never been set up will
refuse with a clear message telling you to do that first.

## Build

```sh
make build       # -> bin/shadowstat
make setcap      # grant the dev binary CAP_NET_RAW/CAP_NET_ADMIN so it can
                  # capture without running the whole process as root
make run         # build + run
make test        # go test ./...
```

## Running

```sh
./bin/shadowstat run
```

On first run (no database found), if stdin is a terminal you'll be walked
through setup: choose a capture interface, enter your LAN subnet in CIDR
form, pick a retention window, and set an admin username/password (this
first account is always an admin — additional users, of either role, are
added afterward from the Settings page). A self-signed TLS certificate is
generated automatically. Everything — capture interface, LAN subnet,
retention window, admin credentials — is stored in the SQLite database;
there are no config files or environment variables.

### Settings & user management

Once logged in as an admin, `/settings` lets you change the capture
interface/LAN subnet/history retention and add/remove/reassign user
accounts — all
settings-mutating actions require re-entering your password first
(prompted automatically), even within an already-logged-in session.
Standard users can view the dashboard and host pages but have no access to
`/settings` or any mutating action. The system won't let you delete or demote your own
account, or remove the last remaining admin — both would risk locking
everyone out of settings with no way back in through the UI.

On subsequent runs, setup is skipped and configuration is read straight from
the database.

If launched with no database and no interactive terminal available (e.g. by
a process supervisor before setup has ever completed), the binary exits
immediately with a clear error rather than hanging on a prompt.

### Running as a service

```sh
sudo ./bin/shadowstat install-service
```

This installs and starts ShadowStat as a systemd service (best-effort OpenRC
support too — see below), running as a dedicated unprivileged `shadowstat`
system user with `CAP_NET_RAW`/`CAP_NET_ADMIN` granted via the unit's
`AmbientCapabilities`, not file capabilities on the binary — so, unlike
`make setcap`, it survives a rebuild.

- **Refuses to run** if setup hasn't completed yet — do an interactive `run`
  first — or if another `shadowstat run` process is already active (it would
  conflict on the capture interface and HTTPS port).
- **Migrates automatically**: if `/var/lib/shadowstat` has no database yet
  but one exists from an earlier interactive run (checked via `$SUDO_USER`'s
  own data dir), it's *moved* there and ownership handed to the service user
  — your existing history is preserved, not discarded.
- `--user <name>` to use a different service account, `--root` to run as
  root instead of a dedicated user, `--data-dir <path>` to point at a
  database elsewhere without migrating anything.

Manage it afterward with `shadowstat status` (or `systemctl status
shadowstat`) and `journalctl -u shadowstat -f` for logs. `sudo shadowstat
uninstall-service` stops and removes the service — the database, cert, and
service user are left in place.

### Data directory

Everything (`shadowstat.db` + its WAL sidecar files, `cert.pem`, `key.pem`)
lives in one directory, resolved in this order:

1. `--data-dir <path>` flag, if given
2. `/var/lib/shadowstat`, if running as root or that path is writable
3. `$XDG_DATA_HOME/shadowstat`, or `~/.local/share/shadowstat` otherwise

### Upgrading from an earlier version (database schema v2)

The first start of this version upgrades the database in place, in one
transaction, and only ever adds things (columns, tables):

- Flow rows from the last 24h are relabeled "unknown" direction, because the
  old format recorded packet direction rather than who started the
  conversation. New rows are labeled properly.
- Each host's since-first-seen totals are rebuilt from the existing graph
  rollups. The host page says from which date the totals count and notes
  that pre-upgrade history may be incomplete (the old rollup job could miss
  minutes, and restarts left gaps).
- The old `alerts`, `known_peers` and `dns_queries` tables are left
  untouched but are no longer used.

Back up `shadowstat.db` before upgrading. To roll back to the previous
binary, stop ShadowStat and run (with the `sqlite3` CLI):

```sh
sqlite3 shadowstat.db "UPDATE schema_meta SET version = 1;"
```

The old binary then runs normally and ignores the new tables and columns.
Resetting the version makes the next upgrade re-run the migration, so
traffic recorded while rolled back isn't double-counted. (Totals are then
rebuilt from the rollups again; up to a minute or so of traffic around the
original upgrade can drop out.) To remove the v2
additions completely (optional, not needed for the old binary):

```sql
DROP TABLE rollup_state; DROP TABLE host_totals;
DROP TABLE host_peer_daily; DROP TABLE peer_names;
ALTER TABLE flows_recent DROP COLUMN service_port;
ALTER TABLE flows_recent DROP COLUMN app_proto;
ALTER TABLE flows_recent DROP COLUMN app_confidence;
```

If you're staying on this version, the old detector data can be removed with
`DROP TABLE alerts; DROP TABLE known_peers; DROP TABLE dns_queries;`.

## Command-line reference

`shadowstat` with no subcommand is equivalent to `shadowstat run`.

| Subcommand | Flags | What it does |
|---|---|---|
| `run` | `--data-dir <path>` — see [Data directory](#data-directory) above<br>`--promiscuous` (default `true`) — set `false` to limit capture to this host's own traffic, useful for testing on a regular workstation without needing `CAP_NET_ADMIN` | Starts capture + web UI. Runs the interactive first-time setup wizard first if no completed setup exists (requires a terminal; exits with code `10` if none is attached). |
| `install-service` | `--user <name>` (default `shadowstat`) — system account to run as<br>`--root` — run as root instead of a dedicated user<br>`--data-dir <path>` — use this exact directory, skipping auto-migration | Installs and starts ShadowStat as a systemd/OpenRC service. Requires root. See [Running as a service](#running-as-a-service). |
| `uninstall-service` | none | Stops and removes the service. Requires root. Database/cert/service user are left in place. |
| `status` | none | Prints service status (`systemctl status` / `rc-service status` under the hood), or says it isn't installed. No root required. |
| `version` | none | Prints the build version. |

## Architecture

See the implementation plan for full detail on the data model, capture
pipeline, rollup/retention design, and web API. Short version:

- `internal/capture` — pulls packets off an AF_PACKET socket (via
  `gopacket/pcapgo`), decodes them, and aggregates in memory before flushing
  batches to SQLite on a timer (never per-packet writes). Handles both
  untagged and single-802.1Q-tagged (VLAN) traffic — useful when the
  mirrored port is a trunk carrying multiple VLANs rather than a single flat
  subnet. The kernel-level BPF filter only cuts non-IPv4 noise (ARP, STP,
  IPv6 for now); LAN-subnet address matching happens entirely in Go
  (`Decoder`) once a packet is fully parsed, rather than by hand-computing
  fixed byte offsets in BPF — a VLAN tag shifts every offset after it, which
  is exactly what broke address matching at the BPF level for a tagged trunk
  in practice. Also opportunistically learns each host's MAC (from the
  Ethernet header of its own traffic) and hostname (from DHCP option 12,
  decoded off broadcast DISCOVER/REQUEST packets), so hosts can show up as
  names instead of bare IPs.
- `internal/capture` (continued) — each conversation is aggregated under
  one key (protocol + both endpoints, no direction), so a row carries both
  sent and received bytes. The hot path only notes TCP SYN/SYN-ACK and ICMP
  echo flags and copies the first ≤256 payload bytes per side; *who started
  it*, the *service port* and the *application protocol* (`classify.go`) are
  worked out at flush time and remembered per conversation across flushes.
  DNS answers seen on the wire map remote IPs to the names hosts looked up.
- `internal/store` — the only package touching `database/sql`. Two-tier
  storage: `flows_recent` (one row per conversation per flush, last 24h)
  plus `rollup_1m/5m/1h/1d` for graphs, `host_totals` (cumulative per-host
  counters, never pruned), `host_peer_daily` (per host/day/peer/service
  breakdown, kept for the retention setting) and `peer_names`.
- `internal/rollupjob` — once a minute (and at startup), folds every
  `flows_recent` row newer than a saved watermark into all rollup tiers,
  `host_totals` and `host_peer_daily` in one transaction, so each row is
  counted exactly once regardless of timing or restarts; then prunes.
- `internal/geoip` — a self-contained IPv4→country table built by
  `tools/geoip-gen` (run via `make geoip-data`) from the five RIRs' public
  allocation statistics and embedded in the binary, used to show each remote
  peer's country. No account or license key needed.
- `internal/web` — HTTPS-only (`net/http` + `crypto/tls`), session auth via
  argon2id-hashed credentials, JSON API driving a vendored uPlot frontend for
  zoomable graphs, and a settings page for capture config and user
  management — gated by two middleware layers (`requireAdmin` for the admin
  role, `requireElevated`/`requireAdminElevated` for a freshly
  re-authenticated session) on top of the base `requireSession` check.
- `internal/service` — systemd/OpenRC unit generation, system user creation,
  and dev-to-system data dir migration behind `install-service` /
  `uninstall-service` / `status`.

## Testing without a mirrored switch port

There's no mirror port in a typical dev environment, so verification layers
from fastest to most realistic:

1. **Unit tests** (`go test ./...`) — synthesize packets in-memory and run
   them through the real decode/aggregate/flush path against a tempfile
   SQLite DB. No privileges or hardware needed.
2. **pcap replay** — `internal/capture.ReplaySource` feeds a `.pcap` file
   through the exact same channel the live AF_PACKET source uses, exercising
   the full pipeline end-to-end, through the rollup job (see
   `pipeline_test.go`: HTTPS, QUIC, inbound SSH, ping, DNS naming, unknown
   UDP, LAN-to-LAN filtering).
3. **Live smoke test** — `make setcap && ./bin/shadowstat run` against a real
   interface (even just your dev machine's own NIC, non-promiscuous, own
   traffic) exercises the live AF_PACKET + hand-built BPF filter path, the
   TLS handshake, and the UI rendering real data end-to-end.
