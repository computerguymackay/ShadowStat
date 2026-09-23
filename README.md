# ShadowStat

A self-contained Linux network monitoring tool. Captures WAN traffic off a
mirrored switch port and serves per-host bandwidth statistics, interactive
historical graphs, and behavioral suspicious-activity detection — all with
persistent history that survives restarts.

## Status

MVP core plus detection engine, device naming, and service install: live
capture → aggregation → durable two-tier SQLite storage → authenticated,
mobile-friendly HTTPS UI with per-host stats (shown by name when known,
learned from DHCP), zoomable graphs, and an alerts view fed by five
behavioral detectors (new destinations, beaconing, upload/download ratio,
DNS volume/entropy, port scanning). See Roadmap below for what's next.

## Roadmap

- **Cert replacement UI** — swap the self-signed cert for a real one (or
  ACME) via the settings page, hot-swapped without a restart.
- **Pluggable sFlow/NetFlow sources** — `capture.Source` already has the
  seam; only the AF_PACKET implementation exists today.
- **Blocked-but-trying detector** — needs firewall log integration, not yet
  scoped.

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
form, pick a retention window, and set an admin username/password. A
self-signed TLS certificate is generated automatically. Everything — capture
interface, LAN subnet, retention window, admin credentials — is stored in the
SQLite database; there are no config files or environment variables.

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
- `internal/store` — the only package touching `database/sql`. Two-tier
  storage: `flows_recent` (full 5-tuple, last 24h) plus `rollup_1m/5m/1h/1d`
  tables for zoomed-out, long-retention graphing.
- `internal/rollupjob` — rolls `flows_recent` up into the rollup tables and
  prunes old data on independent tickers per granularity.
- `internal/detect` — five periodic detectors reading the same
  `flows_recent`/`dns_queries` data, writing deduplicated `alerts` rows:
  **new destinations** (a peer/port not contacted by a host in 30 days —
  labeled outbound/inbound/bidirectional depending on who actually initiated
  contact), **beaconing** (suspiciously regular contact intervals with one
  peer — works on encrypted traffic since it only looks at timing), **exfil
  ratio** (upload far exceeding download to WAN), **DNS anomaly** (abnormal
  query volume, or a high-entropy queried domain suggestive of a DGA), and
  **port scan** (many distinct ports involving one peer in a short window —
  checked in both directions: this host scanning out, *and* another LAN
  device scanning this host, which needed LAN-to-LAN traffic to be recorded
  from both hosts' perspectives, not just the packet's source — see
  `capture.DecodeResult.Flow2`).
- `internal/web` — HTTPS-only (`net/http` + `crypto/tls`), session auth via
  argon2id-hashed credentials, JSON API driving a vendored uPlot frontend for
  zoomable graphs from year view down to single-minute detail, plus an
  alerts page/API with acknowledge.
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
   the full pipeline end-to-end (see `pipeline_test.go`).
3. **Live smoke test** — `make setcap && ./bin/shadowstat run` against a real
   interface (even just your dev machine's own NIC, non-promiscuous, own
   traffic) exercises the live AF_PACKET + hand-built BPF filter path, the
   TLS handshake, and the UI rendering real data end-to-end.
