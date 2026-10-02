// Command geoip-gen builds ShadowStat's embedded IPv4-to-country lookup table
// from the five Regional Internet Registries' public "delegated-extended"
// allocation statistics — freely redistributable public data (no account,
// no license key, no EULA restrictions, unlike MaxMind's GeoLite2), which is
// why this generates the table from scratch rather than embedding a
// third-party database.
//
// This is a manual maintenance tool, not part of ShadowStat's normal build —
// IP allocations change slowly, so the embedded table only needs regenerating
// occasionally (`make geoip-data`), not on every compile. Requires network
// access to fetch the source files; the normal `go build`/`make build` does
// not.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Source URLs for each RIR's delegated-extended statistics file. Format
// (pipe-delimited, documented at https://www.nro.net/about/rirs/statistics/):
//
//	registry|cc|type|start|value|date|status[|extensions...]
//
// Only type=ipv4 rows with status allocated/assigned carry a meaningful
// country code; everything else (summary lines, comments, ipv6/asn rows,
// available/reserved blocks) is skipped.
var sources = []string{
	"https://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest",
	"https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
	"https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
	"https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
	"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

type record struct {
	start uint32
	end   uint32 // inclusive
	cc    [2]byte
}

func main() {
	outPath := flag.String("out", "internal/geoip/data/ipv4_country.bin", "output binary table path")
	flag.Parse()

	var all []record
	client := &http.Client{Timeout: 60 * time.Second}

	for _, url := range sources {
		log.Printf("fetching %s", url)
		recs, err := fetchAndParse(client, url)
		if err != nil {
			log.Fatalf("fetch %s: %v", url, err)
		}
		log.Printf("  %d usable records", len(recs))
		all = append(all, recs...)
	}

	// Stable sort so that, for the handful of exact-duplicate ranges two
	// registries occasionally both publish (a legacy allocation re-registered
	// after an inter-RIR transfer, without the old registry's record being
	// removed — observed 3 times across ~260k records as of this writing),
	// whichever source was listed first in `sources` consistently wins,
	// rather than depending on sort's internal tie-breaking.
	sort.SliceStable(all, func(i, j int) bool { return all[i].start < all[j].start })

	merged := resolveOverlapsAndMergeAdjacent(all)
	log.Printf("total %d records, %d after resolving overlaps and merging adjacent same-country ranges", len(all), len(merged))

	if err := writeTable(*outPath, merged); err != nil {
		log.Fatalf("write table: %v", err)
	}
	log.Printf("wrote %s", *outPath)
}

func fetchAndParse(client *http.Client, url string) ([]record, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	return parseDelegatedExtended(resp.Body)
}

func parseDelegatedExtended(r io.Reader) ([]record, error) {
	var out []record
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 7 {
			continue // version/summary line
		}
		cc, typ, startStr, countStr, status := fields[1], fields[2], fields[3], fields[4], fields[6]
		if typ != "ipv4" {
			continue
		}
		if status != "allocated" && status != "assigned" {
			continue
		}
		if len(cc) != 2 {
			continue // defensive; the current data has no such rows
		}

		ip := net.ParseIP(startStr).To4()
		if ip == nil {
			continue
		}
		count, err := strconv.ParseUint(countStr, 10, 32)
		if err != nil || count == 0 {
			continue
		}

		start := binary.BigEndian.Uint32(ip)
		end := start + uint32(count) - 1

		out = append(out, record{start: start, end: end, cc: [2]byte{cc[0], cc[1]}})
	}
	return out, scanner.Err()
}

// resolveOverlapsAndMergeAdjacent collapses consecutive same-country ranges
// (common: the same organization often holds several contiguous
// allocations) to shrink the table, and resolves the rare case of two
// registries claiming overlapping ranges under different country codes —
// keeping whichever appeared first (see the stable-sort comment above) and
// truncating or dropping the later, conflicting one so the output table is
// always strictly sorted and non-overlapping (required for binary-search
// lookups to be correct). Input must already be sorted by start.
func resolveOverlapsAndMergeAdjacent(sorted []record) []record {
	if len(sorted) == 0 {
		return nil
	}
	out := make([]record, 0, len(sorted))
	cur := sorted[0]
	for _, r := range sorted[1:] {
		trueOverlap := r.start <= cur.end // shares at least one address with cur — NOT just touching

		switch {
		case r.cc == cur.cc && r.start <= cur.end+1:
			// Same country, touching or overlapping: extend the run.
			if r.end > cur.end {
				cur.end = r.end
			}
		case !trueOverlap:
			// Different country, but no shared address — whether directly
			// adjacent (the overwhelmingly common case: one allocation
			// ending exactly where the next begins) or separated by a gap,
			// this is just the next distinct allocation, not a conflict.
			out = append(out, cur)
			cur = r
		default:
			// Genuinely overlapping with a DIFFERENT country — an actual
			// conflicting claim (rare: ~3 cases across the whole dataset as
			// of this writing, all exact-duplicate ranges from an inter-RIR
			// transfer leaving a stale record behind). Keep `cur` (it won
			// the stable sort's tie-break) and drop whatever portion of `r`
			// overlaps it; if r extends past cur, keep the non-overlapping
			// remainder as a new run.
			log.Printf("resolving conflicting claim: keeping %s for [%d,%d], dropping %s's overlapping claim for [%d,%d]",
				cur.cc, cur.start, cur.end, r.cc, r.start, r.end)
			if r.end > cur.end {
				out = append(out, cur)
				cur = record{start: cur.end + 1, end: r.end, cc: r.cc}
			}
			// Else r is fully contained within cur: nothing to do, cur
			// already covers it and r is entirely discarded.
		}
	}
	out = append(out, cur)
	return out
}

// writeTable serializes records as a sorted, fixed-width binary table: for
// each record, 4 bytes start (big-endian), 4 bytes end (big-endian), 2 bytes
// ASCII country code — 10 bytes/record, no header needed since the format
// never changes and the record count is simply file-size/10.
func writeTable(path string, records []record) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	buf := make([]byte, 10)
	for _, r := range records {
		binary.BigEndian.PutUint32(buf[0:4], r.start)
		binary.BigEndian.PutUint32(buf[4:8], r.end)
		buf[8], buf[9] = r.cc[0], r.cc[1]
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}
	return w.Flush()
}
