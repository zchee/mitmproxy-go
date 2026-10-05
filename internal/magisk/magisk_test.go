// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Upstream test mapping (mitmproxy/test/mitmproxy/utils/test_magisk.py):
//
//	test_get_ca          -> not applicable here: loading the CA from the
//	                        configuration directory belongs to the onboarding
//	                        app (certs.FromStore); this package takes the
//	                        parsed certificate as a parameter.
//	test_subject_hash_old -> TestSubjectHashOld/"success: fixture CA equals openssl -subject_hash_old"
//	test_magisk_write     -> TestWriteModule/"success: entries equal the upstream fixture zip"
package magisk

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

// fixtureCA parses the CA certificate of the upstream-generated configuration
// directory fixture.
func fixtureCA(t *testing.T) *x509.Certificate {
	t.Helper()
	data := testutil.Fixture(t, "mitmproxy/confdir/mitmproxy-ca.pem")
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			t.Fatal("no CERTIFICATE block in mitmproxy/confdir/mitmproxy-ca.pem")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return ca
	}
}

func TestSubjectHashOld(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		ca   func(t *testing.T) *x509.Certificate
		want string
	}{
		// The expected value is upstream's: openssl x509 -subject_hash_old
		// over the fixture CA prints efb15d7d (test_subject_hash_old).
		"success: fixture CA equals openssl -subject_hash_old": {
			ca:   fixtureCA,
			want: "efb15d7d",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diff := gocmp.Diff(tt.want, SubjectHashOld(tt.ca(t))); diff != "" {
				t.Error(diff)
			}
		})
	}
}

// zipEntry is one archive member: its name and decompressed contents.
type zipEntry struct {
	Name    string
	Content []byte
}

// readZip returns every entry of the archive in order.
func readZip(t *testing.T, data []byte) []zipEntry {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]zipEntry, 0, len(r.File))
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		if err := rc.Close(); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, zipEntry{Name: f.Name, Content: content})
	}
	return entries
}

func TestWriteModule(t *testing.T) {
	t.Parallel()

	t.Run("success: entries equal the upstream fixture zip", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		if err := WriteModule(&buf, fixtureCA(t)); err != nil {
			t.Fatal(err)
		}
		got := readZip(t, buf.Bytes())
		want := readZip(t, testutil.Fixture(t, "mitmproxy/confdir/mitmproxy-magisk-module.zip"))
		if diff := gocmp.Diff(want, got); diff != "" {
			t.Errorf("archive entries (-want +got):\n%s", diff)
		}
	})

	t.Run("error: failing writer", func(t *testing.T) {
		t.Parallel()
		if err := WriteModule(failWriter{}, fixtureCA(t)); !errors.Is(err, errFailWriter) {
			t.Errorf("WriteModule = %v, want %v", err, errFailWriter)
		}
	})
}

var errFailWriter = errors.New("write refused")

// failWriter refuses every write.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errFailWriter }
