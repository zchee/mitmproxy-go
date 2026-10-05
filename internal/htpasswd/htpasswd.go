// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package htpasswd reads Apache password files supporting bcrypt and SHA-1.
package htpasswd

import (
	"crypto/sha1" //nolint:gosec // Apache {SHA} files require the legacy SHA-1 digest.
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

// ErrFormat reports a malformed or unsupported password file.
var ErrFormat = errors.New("htpasswd: invalid file")

// File is an immutable password database safe for concurrent checks.
type File struct{ users map[string]string }

// New reads a UTF-8 password file from r, capped at 8 MiB. Unsupported hash
// prefixes and malformed lines return ErrFormat. Later entries replace earlier
// entries for the same user, and comments and empty lines are ignored.
func New(r io.Reader) (*File, error) {
	const maxSize = 8 << 20
	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("%w: content exceeds 8 MiB", ErrFormat)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: content is not UTF-8", ErrFormat)
	}
	file := &File{users: make(map[string]string)}
	// Python splitlines includes these separators, not just LF and CRLF.
	for line := range strings.FieldsFuncSeq(string(data), func(r rune) bool {
		return strings.ContainsRune("\n\r\v\f\x1c\x1d\x1e\u0085  ", r)
	}) {
		line = strings.TrimFunc(line, func(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f })
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, hash, ok := strings.Cut(line, ":")
		if !ok || user == "" {
			return nil, fmt.Errorf("%w: Malformed htpasswd line: %s", ErrFormat, pyrepr.Str(line))
		}
		if !strings.HasPrefix(hash, "{SHA}") && !strings.HasPrefix(hash, "$2y$") && !strings.HasPrefix(hash, "$2b$") && !strings.HasPrefix(hash, "$2a$") {
			return nil, fmt.Errorf("%w: Unsupported htpasswd format for user %s", ErrFormat, pyrepr.Str(user))
		}
		file.users[user] = hash
	}
	return file, nil
}

// FromFile opens path and reads it with New. Missing files retain os.ErrNotExist.
func FromFile(path string) (*File, error) {
	f, err := os.Open(path) //nolint:gosec // The caller explicitly selects its password file.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("Htpasswd file not found: %s: %w", path, err) //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return New(f)
}

// Check reports whether username's hash matches the UTF-8 password. Missing
// users, invalid hashes and mismatched passwords return false.
func (f *File) Check(username, password string) bool {
	hash, ok := f.users[username]
	if !ok {
		return false
	}
	hash, _, _ = strings.Cut(hash, ":")
	if expected, ok := strings.CutPrefix(hash, "{SHA}"); ok {
		digest := sha1.Sum([]byte(password)) //nolint:gosec // Match Apache's existing {SHA} hashes; do not generate new hashes.
		actual := base64.StdEncoding.EncodeToString(digest[:])
		return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
