package geoip

import (
	"net"
	"testing"
)

func TestCountryForIPKnownAllocations(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want string
	}{
		// BBC (RIPE NCC, GB) — a long-standing, stable allocation.
		{"BBC", "212.58.224.1", "GB"},
		// China Telecom / major CN allocation block.
		{"China Telecom", "61.135.169.1", "CN"},
		// Yandex (RIPE NCC, RU).
		{"Yandex", "77.88.55.1", "RU"},
		// Google Public DNS — ARIN, US.
		{"Google DNS", "8.8.8.8", "US"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cc, ok := CountryForIP(net.ParseIP(tc.ip))
			if !ok {
				t.Fatalf("expected a country for %s, got none", tc.ip)
			}
			if cc != tc.want {
				t.Errorf("CountryForIP(%s) = %q, want %q", tc.ip, cc, tc.want)
			}
		})
	}
}

func TestCountryForIPPrivateRangesUnknown(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"} {
		if cc, ok := CountryForIP(net.ParseIP(ip)); ok {
			t.Errorf("expected no country for private/reserved %s, got %q", ip, cc)
		}
	}
}

func TestCountryForIPv6Unsupported(t *testing.T) {
	if _, ok := CountryForIP(net.ParseIP("2001:4860:4860::8888")); ok {
		t.Error("expected IPv6 lookups to report not-ok (not yet supported)")
	}
}

func TestTableIsSortedAndNonOverlapping(t *testing.T) {
	if len(table) < 1000 {
		t.Fatalf("suspiciously small table: %d records", len(table))
	}
	for i := 1; i < len(table); i++ {
		if table[i].start <= table[i-1].end {
			t.Fatalf("records %d and %d overlap or are out of order: [%d,%d] then [%d,%d]",
				i-1, i, table[i-1].start, table[i-1].end, table[i].start, table[i].end)
		}
	}
}
