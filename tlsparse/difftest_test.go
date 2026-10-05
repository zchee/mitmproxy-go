// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest

package tlsparse_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/internal/difftest"
	"github.com/zchee/mitmproxy-go/tlsparse"
)

// pythonParseScript reads one hex-encoded wire capture per stdin line, runs
// upstream's parse_client_hello on it, and prints one tab-separated line per
// capture: "error", "incomplete", or "ok", the SNI (empty for None), the
// ALPN protocols as comma-joined hex, the cipher suites comma-joined, and
// the extensions as comma-joined type:hex pairs.
const pythonParseScript = `
import sys
from mitmproxy.proxy.layers import tls

for line in sys.stdin:
    data = bytes.fromhex(line.strip())
    try:
        ch = tls.parse_client_hello(data)
    except ValueError:
        print("error")
        continue
    if ch is None:
        print("incomplete")
        continue
    print("\t".join([
        "ok",
        ch.sni or "",
        ",".join(p.hex() for p in ch.alpn_protocols),
        ",".join(str(c) for c in ch.cipher_suites),
        ",".join("%d:%s" % (t, b.hex()) for t, b in ch.extensions),
    ]))
`

// captureClientHello returns the first TLS record flight a crypto/tls client
// with cfg writes, read record by record until it holds the whole
// ClientHello.
func captureClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	go func() {
		// The handshake can only fail: the server side never answers. It
		// ends when the test closes the pipe.
		conn := tls.Client(client, cfg)
		_ = conn.HandshakeContext(t.Context())
	}()

	// A hang detector only, not a bound under test.
	if err := server.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var data []byte
	buf := make([]byte, 4096)
	for {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("reading the ClientHello flight: %v (have %d bytes)", err, len(data))
		}
		data = append(data, buf[:n]...)
		msg, err := tlsparse.GetClientHello(data)
		if err != nil {
			t.Fatalf("GetClientHello on the flight: %v", err)
		}
		if msg != nil {
			return data
		}
	}
}

// goResult formats what ParseClientHello reports for data as a
// pythonParseScript line.
func goResult(data []byte) (string, error) {
	ch, err := tlsparse.ParseClientHello(data)
	if err != nil {
		if !errors.Is(err, tlsparse.ErrMalformed) {
			return "", fmt.Errorf("error does not wrap ErrMalformed: %w", err)
		}
		return "error", nil
	}
	if ch == nil {
		return "incomplete", nil
	}
	alpn := make([]string, 0, 4)
	for _, p := range ch.ALPNProtocols() {
		alpn = append(alpn, hex.EncodeToString(p))
	}
	ciphers := make([]string, 0, 32)
	for _, c := range ch.CipherSuites() {
		ciphers = append(ciphers, fmt.Sprint(c))
	}
	exts := make([]string, 0, 16)
	for _, ext := range ch.Extensions() {
		exts = append(exts, fmt.Sprintf("%d:%s", ext.Type, hex.EncodeToString(ext.Body)))
	}
	return strings.Join([]string{
		"ok", ch.SNI(), strings.Join(alpn, ","), strings.Join(ciphers, ","), strings.Join(exts, ","),
	}, "\t"), nil
}

// TestDifferentialClientHello feeds the same wire captures to upstream's
// parse_client_hello and to ParseClientHello: multi-record and 512-byte
// record reassembly, the permissive-length quirks, truncations, and hellos
// produced by crypto/tls clients under different configurations.
func TestDifferentialClientHello(t *testing.T) {
	quirkPrefix := slices.Concat([]byte{0x03, 0x03}, make([]byte, 32), []byte{0})
	quirkBody := func(rest ...[]byte) []byte {
		return slices.Concat(quirkPrefix, slices.Concat(rest...))
	}

	vectors := map[string][]byte{
		"upstream single record": cat(mustHex(t, "1603010065"), handshakeNoExtensions(t)),
		"upstream split records": cat(mustHex(t, "1603010020"), handshakeNoExtensions(t)[:32],
			mustHex(t, "1603010045"), handshakeNoExtensions(t)[32:]),
		"upstream with extensions":        recordWithExtensions(t),
		"incomplete split":                cat(mustHex(t, "1603010020"), handshakeNoExtensions(t)[:32])[:42],
		"4 KiB hello in three records":    inRecords(handshake(buildHello(t, 4800)), 1700),
		"4 KiB hello in 512-byte records": inRecords(handshake(buildHello(t, 4800)), 512),
		"length low byte 0xff":            inRecords(handshake(buildHello(t, 511)), 600),
		"garbage after complete message":  append(inRecords(handshake(buildHello(t, 300)), 100), []byte("GET /")...),
		"message declares less than records hold": inRecords(
			append(handshake(buildHello(t, 300)), 0xaa, 0xbb), 16384,
		),
		"odd cipher suite length": inRecords(handshake(
			quirkBody([]byte{0x00, 0x03, 0x13, 0x01, 0x02, 0xaa, 0xbb}),
		), 16384),
		"extensions read past declared length": inRecords(handshake(
			quirkBody([]byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x00},
				[]byte("\x00\x10\x00\x0e\x00\x0c\x02h2\x08http/1.1")),
		), 16384),
		"second server_name carries the SNI": inRecords(handshake(
			quirkBody([]byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x1e},
				[]byte("\x00\x00\x00\x08\x00\x06\x01\x00\x03foo"),
				[]byte("\x00\x00\x00\x0e\x00\x0c\x00\x00\x09mitm.test")),
		), 16384),
		"name_type 1 gives no SNI": inRecords(handshake(
			quirkBody([]byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x0c},
				[]byte("\x00\x00\x00\x08\x00\x06\x01\x00\x03foo")),
		), 16384),
		"two names give no SNI": inRecords(handshake(
			quirkBody([]byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x12},
				[]byte("\x00\x00\x00\x0e\x00\x0c\x00\x00\x03foo\x00\x00\x03bar")),
		), 16384),
		"empty server_name body": inRecords(handshake(
			quirkBody([]byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}),
		), 16384),
		"server_name with one trailing byte": inRecords(handshake(
			quirkBody([]byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x10},
				[]byte("\x00\x00\x00\x0c\x00\x09\x00\x00\x06ok.one\xff")),
		), 16384),
		"server_name with two trailing bytes": inRecords(handshake(
			quirkBody([]byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x11},
				[]byte("\x00\x00\x00\x0d\x00\x09\x00\x00\x06ok.one\xff\xff")),
		), 16384),
		"alpn with trailing bytes": inRecords(handshake(
			quirkBody([]byte{0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x0a},
				[]byte("\x00\x10\x00\x06\x00\x05\x02h2\xff\xff")),
		), 16384),
		"empty message": inRecords([]byte{0x01, 0x00, 0x00, 0x00}, 16384),
	}

	configs := map[string]*tls.Config{
		"default with sni and alpn": {
			ServerName: "example.test",
			NextProtos: []string{"h2", "http/1.1"},
		},
		"no sni": {
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		},
		"no alpn": {
			ServerName: "example.test",
		},
		"tls12 only": {
			ServerName: "example.test",
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
		},
		"tls10 to tls12 with restricted ciphers": {
			ServerName: "legacy.example.test",
			MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
		},
		"tls13 only": {
			ServerName: "h3.example.test",
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"h2"},
		},
	}
	for name, cfg := range configs {
		vectors["crypto/tls "+name] = captureClientHello(t, cfg)
	}

	names := slices.Sorted(maps.Keys(vectors))
	var stdin bytes.Buffer
	for _, name := range names {
		fmt.Fprintf(&stdin, "%s\n", hex.EncodeToString(vectors[name]))
	}

	out := difftest.Python(t, pythonParseScript, stdin.Bytes())
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(nil, 1<<20)
	for _, name := range names {
		if !sc.Scan() {
			t.Fatalf("Python output ended before %q: %v", name, sc.Err())
		}
		want := sc.Text()
		got, err := goResult(vectors[name])
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("%s:\n   Go %s\nwants %s", name, got, want)
		}
	}
	if sc.Scan() {
		t.Fatalf("unexpected extra Python output %q", sc.Text())
	}
	t.Logf("compared %d captures", len(names))
}
