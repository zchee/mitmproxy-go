// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/quic-go/quic-go/quicvarint"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/tcp"
)

func http3Vectors(t testing.TB) map[string]struct {
	data []byte
	uni  bool
} {
	t.Helper()
	literals := map[string]struct {
		hex string
		uni bool
	}{
		"test_view_http3/headers":                             {hex: "011d0000d1c1d7508a089d5c0b8170dc780f035f508825b650c3abbcdae0dd"},
		"test_view_http3/broken_headers":                      {hex: "011d0000d1c1d7508a089d5c0b8170dc780f035f508825b650c3abffffffff"},
		"test_view_http3/headers_and_data":                    {hex: "0140490000db5f2793497ca589d34d1f6a1271d882a60b50b0d0431b5f4d90d06258741e54ad8f7efd70ebc8c097075696d07abe940894dc5ad410042502e5c6deb81714c5a37f540333313500413b3c21444f43545950452048544d4c205055424c494320222d2f2f5733432f2f4454442048544d4c20342e30312f2f454e2222687474703a2f2f7777772e77332e6f72672f54522f68746d6c342f7374726963742e647464223e0d0a3c48544d4c3e3c484541443e3c5449544c453e4e6f7420466f756e643c2f5449544c453e0d0a3c4d45544120485454502d45515549563d22436f6e74656e742d547970652220436f6e74656e743d22746578742f68746d6c3b20636861727365743d75732d6173636969223e3c2f484541443e0d0a3c424f44593e3c68323e4e6f7420466f756e643c2f68323e0d0a3c68723e3c703e48545450204572726f72203430342e2054686520726571756573746564207265736f75726365206973206e6f7420666f756e642e3c2f703e0d0a3c2f424f44593e3c2f48544d4c3e0d0a"},
		"test_view_http3/empty":                               {},
		"test_view_http3_unidirectional/settings":             {hex: "00040d06ffffffffffffffff01000700", uni: true},
		"test_view_http3_unidirectional/unknown_setting":      {hex: "00040d3fffffffffffffffff01000700", uni: true},
		"test_view_http3_unidirectional/out_of_bounds":        {hex: "00040d06ffffffffffffffff01004200", uni: true},
		"test_view_http3_unidirectional/incomplete":           {hex: "00040d06ffffff", uni: true},
		"test_view_http3_unidirectional/qpack_encoder_stream": {hex: "02", uni: true},
	}
	tests := make(map[string]struct {
		data []byte
		uni  bool
	}, len(literals))
	for name, literal := range literals {
		data, err := hex.DecodeString(literal.hex)
		if err != nil {
			t.Fatal(err)
		}
		tests[name] = struct {
			data []byte
			uni  bool
		}{data, literal.uni}
	}
	return tests
}

func http3Metadata(data []byte, unidirectional bool) Metadata {
	f := flow.NewTCPFlow(nil, nil, false)
	message := &tcp.Message{FromClient: len(data) > 16, Content: data}
	f.Messages = []*tcp.Message{message}
	f.Metadata.Set("quic_is_unidirectional", unidirectional)
	return Metadata{Flow: f, TCPMessage: message}
}

func TestHTTP3Frames(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		for name, tt := range http3Vectors(t) {
			t.Run(name, func(t *testing.T) {
				text, err := (HTTP3Frames{}).Prettify(nil, http3Metadata(tt.data, tt.uni))
				if err != nil {
					t.Fatal(err)
				}
				if text == "" && (tt.uni || len(tt.data) != 0) {
					t.Fatal("expected a rendered frame or stream type")
				}
			})
		}
		t.Run("test_render_priority", func(t *testing.T) {
			if (HTTP3Frames{}).RenderPriority([]byte("random stuff"), Metadata{}) != 0 {
				t.Fatal("flowless bytes selected")
			}
		})
	})
}

func TestHTTP3Replay(t *testing.T) {
	first := &tcp.Message{FromClient: true, Content: []byte{0, 3, 'a'}}
	server := &tcp.Message{Content: []byte{0, 1, 'z'}}
	last := &tcp.Message{FromClient: true, Content: []byte{'b', 'c'}}
	f := flow.NewTCPFlow(nil, nil, false)
	f.Messages = []*tcp.Message{first, server, last}
	f.Metadata.Set("quic_is_unidirectional", false)
	view := HTTP3Frames{}
	for _, message := range []*tcp.Message{first, server, last, first, last} {
		text, err := view.Prettify(nil, Metadata{Flow: f, TCPMessage: message})
		if err != nil {
			t.Fatal(err)
		}
		switch message {
		case first:
			if text != "" {
				t.Fatalf("incomplete frame attributed early: %q", text)
			}
		case server:
			if !strings.Contains(text, "z") || strings.Contains(text, "abc") {
				t.Fatalf("directions were mixed: %q", text)
			}
		case last:
			if !strings.Contains(text, "abc") {
				t.Fatalf("completed frame missing: %q", text)
			}
		}
	}
	if !bytes.Equal(first.Content, []byte{0, 3, 'a'}) || !bytes.Equal(last.Content, []byte{'b', 'c'}) {
		t.Fatal("replay mutated message bytes")
	}
	client := &connection.Client{}
	client.ALPN = []byte("h3-29")
	f.ClientConn = client
	if view.RenderPriority(nil, Metadata{Flow: f}) != 2 {
		t.Fatal("HTTP/3 ALPN was not selected")
	}
}

func TestHTTP3Limits(t *testing.T) {
	data := quicvarint.Append(nil, 0)
	data = quicvarint.Append(data, newViewBudget("HTTP/3").limits.InputBytes+1)
	if _, err := (HTTP3Frames{}).Prettify(nil, http3Metadata(data, false)); err == nil {
		t.Fatal("oversized frame accepted")
	} else if _, ok := errors.AsType[*LimitError](err); !ok {
		t.Fatalf("expected typed limit, got %v", err)
	}
	full := newViewBudget("HTTP/3")
	full.output = full.limits.OutputBytes - 1
	if _, err := renderHTTP3Frame(0, []byte{1}, full); err == nil {
		t.Fatal("hex dump bypassed output budget")
	}
}

func FuzzHTTP3Frames(f *testing.F) {
	for _, tt := range http3Vectors(f) {
		f.Add(tt.data, tt.uni)
	}
	f.Fuzz(func(t *testing.T, data []byte, uni bool) {
		text, err := (HTTP3Frames{}).Prettify(nil, http3Metadata(data, uni))
		if err == nil && uint64(len(text)) > newViewBudget("HTTP/3").limits.OutputBytes {
			t.Fatal("output exceeds bound")
		}
	})
}
