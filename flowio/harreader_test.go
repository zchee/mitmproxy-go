// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowio

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestHARReaderTimestampRejections(t *testing.T) {
	tests := map[string]struct{ stamp string }{
		"error: date only": {"2023-03-29"},
		"error: ISO week":  {"2023-W13-3T17:37:42"},
		"error: compact":   {"20230329T173742"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			data := `{"log":{"entries":[{"startedDateTime":"` + tt.stamp + `","time":0,"request":{"method":"GET","url":"http://example.com/","httpVersion":"HTTP/1.1","headers":[]},"response":{"status":200,"httpVersion":"HTTP/1.1","headers":[],"content":{}}}]}}`
			_, err := NewReader(strings.NewReader(data)).Next()
			if err == nil || err.Error() != "Unable to read HAR file. Please provide a valid HAR file" {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestHARReader(t *testing.T) {
	tests := map[string]struct {
		data    string
		wantErr string
	}{
		"success: empty HAR":            {data: `{"log":{"entries":[]}}`},
		"success: BOM before empty HAR": {data: utf8BOM + `{"log":{"entries":[]}}`},
		"error: corrupt HAR":            {data: `{"log":`, wantErr: "Unable to read HAR file. Please provide a valid HAR file"},
		"error: corrupt entry":          {data: `{"log":{"entries":[{}]}}`, wantErr: "Unable to read HAR file. Please provide a valid HAR file"},
		"error: trailing JSON":          {data: `{"log":{"entries":[]}}{}`, wantErr: "Unable to read HAR file. Please provide a valid HAR file"},
		"error: BOM before whitespace":  {data: utf8BOM + ` {"log":{"entries":[]}}`, wantErr: "not a tnetstring: missing or invalid length prefix"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := NewReader(iotest.OneByteReader(strings.NewReader(tt.data)))
			_, err := r.Next()
			if tt.wantErr == "" {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("empty HAR error = %v, want EOF", err)
				}
			} else {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				if strings.HasPrefix(tt.data, "{") && errors.Unwrap(err) == nil {
					t.Fatal("HAR cause was discarded")
				}
			}
			if _, again := r.Next(); again != err {
				t.Fatalf("cached error = %v, want identical %v", again, err)
			}
		})
	}
}
