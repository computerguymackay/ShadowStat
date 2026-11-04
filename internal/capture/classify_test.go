package capture

import (
	"testing"

	"ShadowStat/internal/store"
)

func pad(prefix []byte, n int) []byte {
	if len(prefix) >= n {
		return prefix
	}
	return append(append([]byte(nil), prefix...), make([]byte, n-len(prefix))...)
}

var (
	tlsClientHello = []byte{0x16, 0x03, 0x01, 0x00, 0xc8, 0x01, 0x00, 0x00, 0xc4}
	tlsAppData     = []byte{0x17, 0x03, 0x03, 0x01, 0x00, 0xaa, 0xbb}
	dnsQuery       = []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 3, 'f', 'o', 'o', 0}
	ntpClient      = pad([]byte{0x23}, 48) // version 4, mode 3 (client)
	quicInitial    = pad([]byte{0xc3, 0x00, 0x00, 0x00, 0x01, 0x08}, 1200)
	quicShort      = pad([]byte{0x40, 0x12, 0x34}, 50)
	stunBinding    = pad([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, 20)
	wgInitiation   = pad([]byte{0x01, 0x00, 0x00, 0x00}, 148)
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name           string
		proto, port    int
		direction      int
		local, remote  []byte
		wantName       string
		wantConfidence int
	}{
		// Payload signatures.
		{"TLS handshake on 443", protoTCP, 443, store.DirOutbound, tlsClientHello, nil, "HTTPS", store.ConfPayload},
		{"TLS mid-stream on 443", protoTCP, 443, store.DirUnknown, tlsAppData, nil, "HTTPS", store.ConfPayload},
		{"TLS on an odd port", protoTCP, 5000, store.DirOutbound, tlsClientHello, nil, "TLS", store.ConfPayload},
		{"TLS on IMAPS port", protoTCP, 993, store.DirOutbound, nil, tlsAppData, "IMAPS", store.ConfPayload},
		{"HTTP request", protoTCP, 8000, store.DirOutbound, []byte("GET /index.html HTTP/1.1\r\n"), nil, "HTTP", store.ConfPayload},
		{"HTTP response only", protoTCP, 8000, store.DirOutbound, nil, []byte("HTTP/1.1 200 OK\r\n"), "HTTP", store.ConfPayload},
		{"SSH outbound", protoTCP, 22, store.DirOutbound, []byte("SSH-2.0-OpenSSH_9.6\r\n"), nil, "SSH", store.ConfPayload},
		{"SSH server on the LAN host", protoTCP, 2222, store.DirInbound, []byte("SSH-2.0-OpenSSH_9.6\r\n"), nil, "SSH", store.ConfPayload},
		{"SMTP banner", protoTCP, 2526, store.DirOutbound, nil, []byte("220 mx.example.com ESMTP Postfix\r\n"), "SMTP", store.ConfPayload},
		{"FTP banner", protoTCP, 21, store.DirOutbound, nil, []byte("220 Welcome\r\n"), "FTP", store.ConfPayload},
		{"IMAP banner", protoTCP, 143, store.DirOutbound, nil, []byte("* OK IMAP4rev1 ready\r\n"), "IMAP", store.ConfPayload},
		{"POP3 banner", protoTCP, 110, store.DirOutbound, nil, []byte("+OK POP3 ready\r\n"), "POP3", store.ConfPayload},
		{"BitTorrent handshake", protoTCP, 51413, store.DirOutbound, []byte("\x13BitTorrent protocol"), nil, "BitTorrent", store.ConfPayload},
		{"DNS query", protoUDP, 53, store.DirOutbound, dnsQuery, nil, "DNS", store.ConfPayload},
		{"NTP client", protoUDP, 123, store.DirOutbound, ntpClient, nil, "NTP", store.ConfPayload},
		{"QUIC initial", protoUDP, 443, store.DirOutbound, quicInitial, nil, "QUIC", store.ConfPayload},
		{"QUIC on another port", protoUDP, 8443, store.DirOutbound, quicInitial, nil, "QUIC", store.ConfPayload},
		{"STUN", protoUDP, 19302, store.DirOutbound, stunBinding, nil, "STUN", store.ConfPayload},
		{"WireGuard handshake", protoUDP, 40000, store.DirUnknown, nil, wgInitiation, "WireGuard", store.ConfPayload},

		// Port-only guesses.
		{"443 with no payload yet", protoTCP, 443, store.DirOutbound, nil, nil, "HTTPS", store.ConfPort},
		{"QUIC mid-stream (short header)", protoUDP, 443, store.DirOutbound, quicShort, nil, "QUIC", store.ConfPort},
		{"220 banner on SMTP port, no SMTP text", protoTCP, 25, store.DirOutbound, nil, []byte("220 hello\r\n"), "SMTP", store.ConfPayload},

		// Unknown is a valid answer.
		{"random UDP", protoUDP, 40000, store.DirUnknown, []byte{0xde, 0xad, 0xbe, 0xef}, nil, "", store.ConfUnknown},
		{"TLS-looking header with impossible length", protoTCP, 5000, store.DirOutbound, []byte{0x16, 0x03, 0x03, 0xff, 0xff}, nil, "", store.ConfUnknown},
		{"DNS port but not DNS", protoUDP, 53, store.DirOutbound, []byte{1, 2, 3}, nil, "DNS", store.ConfPort},
		{"ICMP", protoICMP, 0, store.DirOutbound, nil, nil, "", store.ConfUnknown},
	}
	for _, c := range cases {
		name, conf := classify(c.proto, c.port, c.direction, c.local, c.remote)
		if name != c.wantName || conf != c.wantConfidence {
			t.Errorf("%s: got (%q, %d), want (%q, %d)", c.name, name, conf, c.wantName, c.wantConfidence)
		}
	}
}

func TestInferRoles(t *testing.T) {
	cases := []struct {
		name                       string
		proto, local, remote       int
		localStarted, remoteStart  bool
		wantDirection, wantService int
	}{
		{"SYN from the LAN host", protoTCP, 50000, 443, true, false, store.DirOutbound, 443},
		{"SYN from the internet", protoTCP, 8080, 40000, false, true, store.DirInbound, 8080},
		{"no handshake, remote well-known", protoTCP, 50000, 443, false, false, store.DirOutbound, 443},
		{"no handshake, local well-known", protoTCP, 22, 40000, false, false, store.DirInbound, 22},
		{"both high and unknown", protoUDP, 40000, 50000, false, false, store.DirUnknown, 40000},
		{"both well-known", protoUDP, 123, 53, false, false, store.DirUnknown, 53},
		{"conflicting evidence falls back to ports", protoTCP, 50000, 443, true, true, store.DirOutbound, 443},
		{"ping from the LAN host", protoICMP, 0, 0, true, false, store.DirOutbound, 0},
		{"ICMP with no echo request", protoICMP, 0, 0, false, false, store.DirUnknown, 0},
	}
	for _, c := range cases {
		dir, svc := inferRoles(c.proto, c.local, c.remote, c.localStarted, c.remoteStart)
		if dir != c.wantDirection || svc != c.wantService {
			t.Errorf("%s: got (%d, %d), want (%d, %d)", c.name, dir, svc, c.wantDirection, c.wantService)
		}
	}
}
