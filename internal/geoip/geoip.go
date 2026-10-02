// Package geoip provides a minimal IPv4-to-country lookup, backed by an
// embedded table built from the five Regional Internet Registries' public
// allocation data (see tools/geoip-gen) rather than a third-party database
// like MaxMind's GeoLite2 — this data has no account/license-key requirement
// and no redistribution restriction, so it can be embedded directly in the
// binaries ShadowStat publishes.
package geoip

import (
	"embed"
	"encoding/binary"
	"net"
	"sort"
)

//go:embed data/ipv4_country.bin
var tableFile embed.FS

const recordSize = 10 // 4 bytes start + 4 bytes end (both big-endian, inclusive) + 2 bytes ASCII country code

type record struct {
	start uint32
	end   uint32
	cc    string
}

var table []record

func init() {
	data, err := tableFile.ReadFile("data/ipv4_country.bin")
	if err != nil {
		// The embedded file is part of the build; a failure here means the
		// binary itself is broken, not a runtime condition to recover from.
		panic("geoip: embedded table missing: " + err.Error())
	}
	table = parseTable(data)
}

func parseTable(data []byte) []record {
	n := len(data) / recordSize
	out := make([]record, n)
	for i := 0; i < n; i++ {
		off := i * recordSize
		out[i] = record{
			start: binary.BigEndian.Uint32(data[off : off+4]),
			end:   binary.BigEndian.Uint32(data[off+4 : off+8]),
			cc:    string(data[off+8 : off+10]),
		}
	}
	return out
}

// CountryForIP returns the ISO 3166-1 alpha-2 country code allocated to ip,
// if known. Returns ok=false for IPv6 (not yet supported, matching the rest
// of the capture pipeline), and for addresses with no allocation record —
// which includes all private/reserved ranges (10.0.0.0/8, 192.168.0.0/16,
// etc.), since those were never allocated to any country. That's the
// correct behavior for a detector that should never flag LAN-local traffic.
func CountryForIP(ip net.IP) (string, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return "", false
	}
	target := binary.BigEndian.Uint32(ip4)

	i := sort.Search(len(table), func(i int) bool { return table[i].end >= target })
	if i < len(table) && table[i].start <= target {
		return table[i].cc, true
	}
	return "", false
}
