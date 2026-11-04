package capture

import (
	"bytes"
	"encoding/binary"

	"ShadowStat/internal/store"
)

// Protocol identification. Runs at flush time (never per packet) on the
// payload snippets the Aggregator kept, plus the conversation's ports.
//
// Two levels of confidence, plus "unknown":
//   - store.ConfPayload: a payload signature matched (a TLS record header,
//     an SSH banner, an HTTP request line, a QUIC long header, ...).
//   - store.ConfPort: only the service port matched a well-known service.
//     Easily wrong: anything can run on port 443.
//   - store.ConfUnknown with an empty name: neither matched. This is an
//     expected answer, not an error.

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

type portKey struct{ proto, port int }

// wellKnownPorts names services by (L4 protocol, server port). It is also
// what roles.go uses to guess which side is the server.
var wellKnownPorts = map[portKey]string{
	{protoTCP, 20}: "FTP", {protoTCP, 21}: "FTP", {protoTCP, 22}: "SSH", {protoTCP, 23}: "Telnet",
	{protoTCP, 25}: "SMTP", {protoTCP, 53}: "DNS", {protoTCP, 80}: "HTTP", {protoTCP, 110}: "POP3",
	{protoTCP, 143}: "IMAP", {protoTCP, 389}: "LDAP", {protoTCP, 443}: "HTTPS", {protoTCP, 445}: "SMB",
	{protoTCP, 465}: "SMTPS", {protoTCP, 587}: "SMTP", {protoTCP, 636}: "LDAPS", {protoTCP, 853}: "DNS-over-TLS",
	{protoTCP, 993}: "IMAPS", {protoTCP, 995}: "POP3S", {protoTCP, 1194}: "OpenVPN", {protoTCP, 1883}: "MQTT",
	{protoTCP, 3306}: "MySQL", {protoTCP, 3389}: "RDP", {protoTCP, 5222}: "XMPP", {protoTCP, 5432}: "PostgreSQL",
	{protoTCP, 8080}: "HTTP", {protoTCP, 8443}: "HTTPS", {protoTCP, 8883}: "MQTTS",

	{protoUDP, 53}: "DNS", {protoUDP, 67}: "DHCP", {protoUDP, 68}: "DHCP", {protoUDP, 123}: "NTP",
	{protoUDP, 443}: "QUIC", {protoUDP, 500}: "IPsec", {protoUDP, 1194}: "OpenVPN", {protoUDP, 1900}: "SSDP",
	{protoUDP, 3478}: "STUN", {protoUDP, 4500}: "IPsec", {protoUDP, 5353}: "mDNS", {protoUDP, 51820}: "WireGuard",
}

// tlsPortNames names TLS traffic by its port. TLS anywhere else is just "TLS".
var tlsPortNames = map[int]string{
	443: "HTTPS", 8443: "HTTPS", 465: "SMTPS", 636: "LDAPS", 853: "DNS-over-TLS",
	993: "IMAPS", 995: "POP3S", 8883: "MQTTS",
}

// classify names a conversation's application protocol. client and server
// are the payload snippets from each side, if the roles are known; when the
// direction is unknown, both orderings are tried.
func classify(proto, servicePort, direction int, localPayload, remotePayload []byte) (string, int) {
	switch proto {
	case protoICMP, protoICMPv6:
		return "", store.ConfUnknown // the L4 protocol says it all
	}

	tries := [][2][]byte{{localPayload, remotePayload}}
	switch direction {
	case store.DirInbound:
		tries = [][2][]byte{{remotePayload, localPayload}}
	case store.DirUnknown:
		tries = append(tries, [2][]byte{remotePayload, localPayload})
	}
	for _, t := range tries {
		if name := matchPayload(proto, servicePort, t[0], t[1]); name != "" {
			return name, store.ConfPayload
		}
	}

	if name, ok := wellKnownPorts[portKey{proto, servicePort}]; ok {
		return name, store.ConfPort
	}
	return "", store.ConfUnknown
}

// matchPayload checks the client's and server's first bytes against known
// signatures. Either may be nil.
func matchPayload(proto, port int, client, server []byte) string {
	if proto == protoTCP {
		return matchTCP(port, client, server)
	}
	if proto == protoUDP {
		return matchUDP(port, client, server)
	}
	return ""
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
}

func matchTCP(port int, client, server []byte) string {
	for _, b := range [][]byte{client, server} {
		if isTLSRecord(b) {
			if name, ok := tlsPortNames[port]; ok {
				return name
			}
			return "TLS"
		}
		if bytes.HasPrefix(b, []byte("SSH-")) {
			return "SSH"
		}
		if bytes.HasPrefix(b, []byte("\x13BitTorrent protocol")) {
			return "BitTorrent"
		}
	}
	for _, m := range httpMethods {
		if bytes.HasPrefix(client, m) {
			return "HTTP"
		}
	}
	if bytes.HasPrefix(server, []byte("HTTP/1.")) {
		return "HTTP"
	}

	switch {
	case bytes.HasPrefix(server, []byte("220")):
		head := server[:min(len(server), 128)]
		switch {
		case port == 21:
			return "FTP"
		case bytes.Contains(head, []byte("SMTP")), port == 25, port == 587, port == 2525:
			return "SMTP"
		}
	case bytes.HasPrefix(client, []byte("EHLO ")), bytes.HasPrefix(client, []byte("HELO ")):
		return "SMTP"
	case bytes.HasPrefix(server, []byte("* OK")):
		return "IMAP"
	case bytes.HasPrefix(server, []byte("+OK")):
		return "POP3"
	case port == 3389 && len(client) >= 4 && client[0] == 0x03 && client[1] == 0x00:
		return "RDP" // TPKT header on the RDP port
	}
	return ""
}

// isTLSRecord reports whether b starts with a TLS record header: a content
// type (change_cipher_spec, alert, handshake or application_data), a 3.x
// version, and a length no bigger than TLS allows.
func isTLSRecord(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	return b[0] >= 0x14 && b[0] <= 0x17 && b[1] == 0x03 && b[2] <= 0x04 &&
		binary.BigEndian.Uint16(b[3:5]) <= 16384+2048
}

func matchUDP(port int, client, server []byte) string {
	for _, b := range [][]byte{client, server} {
		switch {
		case (port == 53 || port == 5353) && looksLikeDNS(b):
			if port == 5353 {
				return "mDNS"
			}
			return "DNS"
		case port == 123 && looksLikeNTP(b):
			return "NTP"
		case looksLikeQUICLongHeader(b):
			return "QUIC"
		case looksLikeSTUN(b):
			return "STUN"
		case looksLikeWireGuardHandshake(b):
			return "WireGuard"
		}
	}
	return ""
}

// looksLikeDNS checks a DNS header: standard query opcode and 1–4 questions.
func looksLikeDNS(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	opcode := (b[2] >> 3) & 0x0f
	qd := binary.BigEndian.Uint16(b[4:6])
	return opcode == 0 && qd >= 1 && qd <= 4
}

// looksLikeNTP checks for a full NTP header with a valid version and mode.
func looksLikeNTP(b []byte) bool {
	if len(b) < 48 {
		return false
	}
	version := (b[0] >> 3) & 0x07
	mode := b[0] & 0x07
	return version >= 1 && version <= 4 && mode >= 1 && mode <= 5
}

// looksLikeQUICLongHeader matches a QUIC long-header packet (used for the
// handshake) carrying a known version: v1, v2, a draft, or version
// negotiation. Short-header packets carry no signature, so a QUIC
// conversation first seen mid-stream falls back to the port guess.
func looksLikeQUICLongHeader(b []byte) bool {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return false
	}
	v := binary.BigEndian.Uint32(b[1:5])
	return v == 0x00000001 || v == 0x6b3343cf || v == 0 || v&0xffffff00 == 0xff000000
}

// looksLikeSTUN matches a STUN message header with the RFC 5389 magic cookie.
func looksLikeSTUN(b []byte) bool {
	return len(b) >= 20 && b[0]&0xc0 == 0 && binary.BigEndian.Uint32(b[4:8]) == 0x2112a442
}

// looksLikeWireGuardHandshake matches WireGuard's fixed-size handshake
// messages (initiation, response, cookie reply). Data packets are left to
// the port guess, since their header alone is too generic.
func looksLikeWireGuardHandshake(b []byte) bool {
	if len(b) < 4 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return false
	}
	switch b[0] {
	case 1:
		return len(b) == 148
	case 2:
		return len(b) == 92
	case 3:
		return len(b) == 64
	}
	return false
}

// inferRoles works out who started a conversation and which port is the
// service port. A TCP handshake or ping seen in this window settles it.
// Otherwise it falls back to ports: if exactly one side uses a well-known
// service port, that side is the server. If neither or both do, the
// direction is unknown and the lower port is reported as the service port.
func inferRoles(proto, localPort, remotePort int, localStarted, remoteStarted bool) (direction, servicePort int) {
	switch {
	case localStarted && !remoteStarted:
		return store.DirOutbound, remotePort
	case remoteStarted && !localStarted:
		return store.DirInbound, localPort
	}
	if proto != protoTCP && proto != protoUDP {
		return store.DirUnknown, 0
	}

	localServer := isServerPort(proto, localPort)
	remoteServer := isServerPort(proto, remotePort)
	switch {
	case remoteServer && !localServer:
		return store.DirOutbound, remotePort
	case localServer && !remoteServer:
		return store.DirInbound, localPort
	}
	return store.DirUnknown, min(localPort, remotePort)
}

func isServerPort(proto, port int) bool {
	if port <= 0 {
		return false
	}
	if port < 1024 {
		return true
	}
	_, ok := wellKnownPorts[portKey{proto, port}]
	return ok
}
