# ShadowStat

A self-contained Linux network monitoring tool. Captures WAN traffic off a
mirrored switch port and serves per-host bandwidth statistics, interactive
historical graphs, and behavioral suspicious-activity detection — all with
persistent history that survives restarts.

## Status

MVP core plus detection engine and device naming: live capture →
aggregation → durable two-tier SQLite storage → authenticated,
mobile-friendly HTTPS UI with per-host stats (shown by name when known,
learned from DHCP), zoomable graphs, and an alerts view fed by five
behavioral detectors (new destinations, beaconing, upload/download ratio,
DNS volume/entropy, port scanning). See Roadmap below for what's next.

## Roadmap

- **Service install** — `install-service`/`uninstall-service`/`status`
  subcommands, systemd (+ openrc/sysvinit where practical) unit generation,
  a dedicated unprivileged service user with `AmbientCapabilities=CAP_NET_RAW
  CAP_NET_ADMIN` so capture works without running as root or depending on
  file capabilities surviving a rebuild.
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
  connected to a mirrored switch port that mirrors the router's uplink

No other runtime dependencies: the binary is a fully static, CGO_ENABLED=0
build (pure-Go SQLite via `modernc.org/sqlite`, pure-Go packet capture via
`gopacket/pcapgo`'s AF_PACKET support — no libpcap, no cgo).

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

### Data directory

Everything (`shadowstat.db` + its WAL sidecar files, `cert.pem`, `key.pem`)
lives in one directory, resolved in this order:

1. `--data-dir <path>` flag, if given
2. `/var/lib/shadowstat`, if running as root or that path is writable
3. `$XDG_DATA_HOME/shadowstat`, or `~/.local/share/shadowstat` otherwise

## Architecture

See the implementation plan for full detail on the data model, capture
pipeline, rollup/retention design, and web API. Short version:

- `internal/capture` — pulls packets off an AF_PACKET socket (via
  `gopacket/pcapgo`), decodes them, and aggregates in memory before flushing
  batches to SQLite on a timer (never per-packet writes). Also opportunistically
  learns each host's MAC (from the Ethernet header of its own traffic) and
  hostname (from DHCP option 12, decoded off broadcast DISCOVER/REQUEST
  packets — the BPF filter has a dedicated branch admitting broadcast traffic
  for exactly this), so hosts can show up as names instead of bare IPs.
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
