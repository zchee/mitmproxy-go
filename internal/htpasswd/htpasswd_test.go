// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package htpasswd

import (
	"errors"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	gocmp "github.com/google/go-cmp/cmp"
)

// TestCheck ports test_sha1 and test_bcrypt from mitmproxy/utils/test_htpasswd.py.
func TestCheck(t *testing.T) {
	const content = "user1:{SHA}8FePHnF0saQcTqjG4X96ijuIySo=\nuser2:{SHA}i+UhJqb95FCnFio2UdWJu1HpV50=\nuser3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=:extra\nuser_bcrypt:$2b$05$opH8g9/PUhK6HVSnhdX7P.oB6MTMOlIlXgb4THm1Adh12t4IuqMsK\n"
	file, err := New(iotest.OneByteReader(strings.NewReader(content)))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		user, password string
		want           bool
	}{
		"success: first SHA":           {"user1", "pass1", true},
		"success: second SHA":          {"user2", "pass2", true},
		"success: trailing fields":     {"user3", "pass3", true},
		"error: wrong SHA password":    {"user1", "pass2", false},
		"error: unknown user":          {"wronguser", "testpassword", false},
		"success: bcrypt":              {"user_bcrypt", "pass", true},
		"error: wrong bcrypt password": {"user_bcrypt", "wrong", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diff := gocmp.Diff(tt.want, file.Check(tt.user, tt.password)); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	tests := map[string]struct{ content, message string }{
		"error: malformed":      {"malformed", "Malformed htpasswd line"},
		"error: empty username": {":malformed", "Malformed htpasswd line"},
		"error: apr1":           {"user_md5:$apr1$....", "Unsupported htpasswd format"},
		"error: ssha":           {"user_ssha:{SSHA}...", "Unsupported htpasswd format"},
		"error: plain":          {"user_plain:pass", "Unsupported htpasswd format"},
		"error: crypt":          {"user_crypt:..j8N8I28nVM", "Unsupported htpasswd format"},
		"error: empty hash":     {"user_empty_pw:", "Unsupported htpasswd format"},
		"error: invalid UTF8":   {"\xff:{SHA}...", "UTF-8"},
		"error: file bound":     {strings.Repeat("#", 8<<20+1), "exceeds"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := New(strings.NewReader(tt.content))
			if err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("got %v, want %q", err, tt.message)
			}
		})
	}
	_, err := New(iotest.ErrReader(os.ErrPermission))
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("read failure: %v", err)
	}
}

func TestFromFile(t *testing.T) {
	file, err := FromFile("../../testdata/mitmproxy/htpasswd")
	if err != nil || len(file.users) == 0 {
		t.Fatalf("file=%v, err=%v", file, err)
	}
	_, err = FromFile(t.TempDir() + "/nonexistent")
	if err == nil || !strings.Contains(err.Error(), "Htpasswd file not found") {
		t.Fatalf("missing file: %v", err)
	}
}

func TestEmptyAndComments(t *testing.T) {
	file, err := New(strings.NewReader("\n# comment\n \n\t# another comment\n"))
	if err != nil || len(file.users) != 0 {
		t.Fatalf("file=%v, err=%v", file, err)
	}
}

func TestVariants(t *testing.T) {
	tests := map[string]struct{ hash string }{
		"success: bcrypt a":                    {"$2a$05$opH8g9/PUhK6HVSnhdX7P.oB6MTMOlIlXgb4THm1Adh12t4IuqMsK"},
		"success: bcrypt y":                    {"$2y$05$opH8g9/PUhK6HVSnhdX7P.oB6MTMOlIlXgb4THm1Adh12t4IuqMsK"},
		"success: duplicate and unicode lines": {"{SHA}wrong\r\nx:{SHA}wrong\vx:{SHA}wrong\fx:{SHA}wrong\x1cx:{SHA}wrong\x1dx:{SHA}wrong\x1ex:{SHA}wrong\u0085x:{SHA}wrong x:{SHA}wrong x:$2b$05$opH8g9/PUhK6HVSnhdX7P.oB6MTMOlIlXgb4THm1Adh12t4IuqMsK"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			file, err := New(strings.NewReader("x:" + tt.hash))
			if err != nil {
				t.Fatal(err)
			}
			if !file.Check("x", "pass") {
				t.Fatal("password refused")
			}
		})
	}
	file, err := New(strings.NewReader("x:$2b$bad"))
	if err != nil {
		t.Fatal(err)
	}
	if file.Check("x", "pass") {
		t.Fatal("malformed bcrypt accepted")
	}
}
