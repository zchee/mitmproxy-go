// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse_test

import (
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/tlsparse"
)

// The upstream tests ported here, one Go case each:
//
//	test/mitmproxy/test_tls.py
//	  TestClientHello.test_no_extensions        TestClientHelloUpstream "no extensions"
//	  TestClientHello.test_extensions           TestClientHelloUpstream "extensions"
//	  TestDTLSClientHello.*                     not applicable: DTLS is not parsed yet
//	test/mitmproxy/net/test_tls.py
//	  test_is_record_magic                      TestStartsLikeTLSRecord
//	  test_is_dtls_record_magic                 not applicable: DTLS is not parsed yet
//	  test_supported, test_make_master_secret_logger, test_sslkeylogfile,
//	  test_get_curve                            not applicable: TLS configuration, not parsing
//	test/mitmproxy/proxy/layers/test_tls.py
//	  test_record_contents                      TestHandshakeRecordContents
//	  test_record_contents_err                  TestHandshakeRecordContentsErrors
//	  test_get_client_hello                     TestGetClientHelloUpstream
//	  test_parse_client_hello                   TestParseClientHelloUpstream
//	  test_dtls_*                               not applicable: DTLS is not parsed yet
//	  TestServerTLS.*, TestClientTLS.*          the TLS layer's tests, not the parser's

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func cat(parts ...[]byte) []byte { return slices.Concat(parts...) }

// clientHelloNoExtensions is CLIENT_HELLO_NO_EXTENSIONS of test_tls.py: a
// ClientHello body without its handshake header.
const clientHelloNoExtensions = "03015658a756ab2c2bff55f636814deac086b7ca56b65058c7893ffc6074f5245f70205658a75475103a152637" +
	"78e1bb6d22e8bbd5b6b0a3a59760ad354e91ba20d353001a0035002f000a000500040009000300060008006000" +
	"61006200640100"

// clientHelloExtensions is the body of TestClientHello.test_extensions and,
// after its record and handshake headers, of client_hello_with_extensions in
// the layer tests.
const clientHelloExtensions = "03033b70638d2523e1cba15f8364868295305e9c52aceabda4b5147210abc783e6e1000022c02bc02fc02cc030" +
	"cca9cca8cc14cc13c009c013c00ac014009c009d002f0035000a0100006cff0100010000000010000e00000b65" +
	"78616d706c652e636f6d0017000000230000000d00120010060106030501050304010403020102030005000501" +
	"00000000001200000010000e000c02683208687474702f312e3175500000000b00020100000a00080006001d00" +
	"170018"

type helloView struct {
	SNI          string
	CipherSuites []uint16
	ALPN         [][]byte
	Extensions   []tlsparse.Extension
}

func view(ch *tlsparse.ClientHello) helloView {
	return helloView{SNI: ch.SNI(), CipherSuites: ch.CipherSuites(), ALPN: ch.ALPNProtocols(), Extensions: ch.Extensions()}
}

func TestClientHelloUpstream(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		raw  string
		want helloView
	}{
		"no extensions": {
			raw: clientHelloNoExtensions,
			want: helloView{
				CipherSuites: []uint16{53, 47, 10, 5, 4, 9, 3, 6, 8, 96, 97, 98, 100},
			},
		},
		"extensions": {
			raw: clientHelloExtensions,
			want: helloView{
				SNI: "example.com",
				CipherSuites: []uint16{
					49195, 49199, 49196, 49200, 52393, 52392, 52244, 52243,
					49161, 49171, 49162, 49172, 156, 157, 47, 53, 10,
				},
				ALPN: [][]byte{[]byte("h2"), []byte("http/1.1")},
				Extensions: []tlsparse.Extension{
					{Type: 65281, Body: []byte("\x00")},
					{Type: 0, Body: []byte("\x00\x0e\x00\x00\x0bexample.com")},
					{Type: 23, Body: []byte{}},
					{Type: 35, Body: []byte{}},
					{Type: 13, Body: []byte("\x00\x10\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x02\x01\x02\x03")},
					{Type: 5, Body: []byte("\x01\x00\x00\x00\x00")},
					{Type: 18, Body: []byte{}},
					{Type: 16, Body: []byte("\x00\x0c\x02h2\x08http/1.1")},
					{Type: 30032, Body: []byte{}},
					{Type: 11, Body: []byte("\x01\x00")},
					{Type: 10, Body: []byte("\x00\x06\x00\x1d\x00\x17\x00\x18")},
				},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw := mustHex(t, tt.raw)
			ch, err := tlsparse.NewClientHello(raw)
			if err != nil {
				t.Fatalf("NewClientHello: %v", err)
			}
			if diff := gocmp.Diff(tt.want, view(ch)); diff != "" {
				t.Errorf("ClientHello mismatch (-want +got):\n%s", diff)
			}
			if ch.String() == "" {
				t.Error("String() is empty")
			}
			if got := ch.RawBytes(false); !slices.Equal(got, raw) {
				t.Errorf("RawBytes(false) = %x, want %x", got, raw)
			}
		})
	}
}

// TestRawBytesWrapped is the raw_bytes(True) assertion of test_no_extensions:
// the record header always says TLS 1.2, whatever the client sent.
func TestRawBytesWrapped(t *testing.T) {
	t.Parallel()

	raw := mustHex(t, clientHelloNoExtensions)
	want := cat([]byte("\x16\x03\x03\x00\x65"), []byte("\x01\x00\x00\x61"), raw)
	ch, err := tlsparse.NewClientHello(raw)
	if err != nil {
		t.Fatalf("NewClientHello: %v", err)
	}
	if got := ch.RawBytes(true); !slices.Equal(got, want) {
		t.Errorf("RawBytes(true) = %x, want %x", got, want)
	}
}

func TestClientHelloString(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		raw  string
		want string
	}{
		"no extensions": {raw: clientHelloNoExtensions, want: "ClientHello(sni: None, alpn_protocols: [])"},
		"extensions":    {raw: clientHelloExtensions, want: "ClientHello(sni: example.com, alpn_protocols: [b'h2', b'http/1.1'])"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ch, err := tlsparse.NewClientHello(mustHex(t, tt.raw))
			if err != nil {
				t.Fatalf("NewClientHello: %v", err)
			}
			if got := ch.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStartsLikeTLSRecord(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in   []byte
		want bool
	}{
		"http":           {in: []byte("POST /"), want: false},
		"version 3.4":    {in: []byte("\x16\x03\x04"), want: false},
		"empty":          {in: []byte(""), want: false},
		"one byte":       {in: []byte("\x16"), want: false},
		"two bytes":      {in: []byte("\x16\x03"), want: false},
		"SSL 3.0":        {in: []byte("\x16\x03\x00"), want: true},
		"TLS 1.0":        {in: []byte("\x16\x03\x01"), want: true},
		"TLS 1.1":        {in: []byte("\x16\x03\x02"), want: true},
		"TLS 1.2":        {in: []byte("\x16\x03\x03"), want: true},
		"DTLS 1.0":       {in: mustHex(t, "16fefe"), want: false},
		"alert record":   {in: []byte("\x15\x03\x01"), want: false},
		"longer TLS 1.2": {in: []byte("\x16\x03\x03\x00\x05hello"), want: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := tlsparse.StartsLikeTLSRecord(tt.in); got != tt.want {
				t.Errorf("StartsLikeTLSRecord(%x) = %t, want %t", tt.in, got, tt.want)
			}
		})
	}
}

// records collects what HandshakeRecordContents yields until its first
// error.
func records(data []byte) ([][]byte, error) {
	var got [][]byte
	for body, err := range tlsparse.HandshakeRecordContents(data) {
		if err != nil {
			return got, err
		}
		got = append(got, body)
	}
	return got, nil
}

func TestHandshakeRecordContents(t *testing.T) {
	t.Parallel()

	data := mustHex(t, "1603010002beef1603010001ff")
	got, err := records(data)
	if err != nil {
		t.Fatalf("HandshakeRecordContents: %v", err)
	}
	if diff := gocmp.Diff([][]byte{[]byte("\xbe\xef"), []byte("\xff")}, got); diff != "" {
		t.Errorf("records mismatch (-want +got):\n%s", diff)
	}
	for i := range 6 {
		got, err := records(data[:i])
		if err != nil || len(got) != 0 {
			t.Errorf("HandshakeRecordContents(data[:%d]) = %x, %v; want nothing", i, got, err)
		}
	}
}

func TestHandshakeRecordContentsErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in      []byte
		wantErr string
	}{
		"not a TLS record": {in: []byte("GET /error"), wantErr: `tlsparse: malformed ClientHello: expected TLS record, got b'GET /' instead`},
		"empty record":     {in: mustHex(t, "1603010000"), wantErr: "tlsparse: malformed ClientHello: record must not be empty"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := records(tt.in)
			if len(got) != 0 {
				t.Errorf("yielded %x before the error", got)
			}
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			if !errors.Is(err, tlsparse.ErrMalformed) {
				t.Errorf("error %v does not wrap ErrMalformed", err)
			}
		})
	}
}

// handshakeNoExtensions is client_hello_no_extensions of the layer tests:
// the no-extensions body with its handshake header.
func handshakeNoExtensions(t testing.TB) []byte {
	return cat(mustHex(t, "01000061"), mustHex(t, clientHelloNoExtensions))
}

// recordWithExtensions is client_hello_with_extensions of the layer tests:
// one record holding the whole handshake message.
func recordWithExtensions(t testing.TB) []byte {
	return cat(mustHex(t, "16030300bb010000b7"), mustHex(t, clientHelloExtensions))
}

func TestGetClientHelloUpstream(t *testing.T) {
	t.Parallel()

	hs := handshakeNoExtensions(t)
	split := cat(mustHex(t, "1603010020"), hs[:32], mustHex(t, "1603010045"), hs[32:])
	tests := map[string]struct {
		in   []byte
		want []byte
	}{
		"single record":          {in: cat(mustHex(t, "1603010065"), hs), want: hs},
		"split over two records": {in: split, want: hs},
		"incomplete":             {in: split[:42], want: nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := tlsparse.GetClientHello(tt.in)
			if err != nil {
				t.Fatalf("GetClientHello: %v", err)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("GetClientHello mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseClientHelloUpstream(t *testing.T) {
	t.Parallel()

	data := recordWithExtensions(t)

	ch, err := tlsparse.ParseClientHello(data)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if got := ch.SNI(); got != "example.com" {
		t.Errorf("SNI() = %q, want %q", got, "example.com")
	}

	ch, err = tlsparse.ParseClientHello(data[:50])
	if ch != nil || err != nil {
		t.Errorf("ParseClientHello(data[:50]) = %v, %v; want nil, nil", ch, err)
	}

	bad := cat(data[:183], make([]byte, 9))
	ch, err = tlsparse.ParseClientHello(bad)
	if ch != nil || !errors.Is(err, tlsparse.ErrMalformed) {
		t.Errorf("ParseClientHello(bad) = %v, %v; want nil, ErrMalformed", ch, err)
	}
}
