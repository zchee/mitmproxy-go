// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package proxyauth authenticates requests with a password, htpasswd file or LDAP.
package proxyauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"unicode"
	"weak"

	textunicode "golang.org/x/text/encoding/unicode"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/htpasswd"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/options"
)

// ProxyAuth requires authentication and remembers successful CONNECT clients.
// Credentials live as long as the client connection object remains reachable.
// LDAP servers are trusted configuration; authentication has a 10-second deadline
// and allows 1 MiB received per connection, using at most two connections.
// Hook methods must run through an addon.Manager's dispatch domain.
type ProxyAuth struct {
	opts     *options.Manager
	validate func(string, string) bool
	ldap     *ldapConfig
	// Cleanup runs outside dispatch. Weak keys preserve the lifetime of Python's
	// WeakKeyDictionary without retaining a closed client's flow graph.
	authenticated sync.Map
}

// New returns an authentication addon using opts.
func New(opts *options.Manager) *ProxyAuth { return &ProxyAuth{opts: opts} }

// Load registers the upstream authentication option.
func (p *ProxyAuth) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "proxyauth", options.TypeOptStr, (*string)(nil), `Require proxy authentication. Format: "username:pass", "any" to accept any user/pass combination, "@path" to use an Apache htpasswd file, or "ldap[s]:url_server_ldap[:port]:dn_auth:password:dn_subtree[?search_filter_key=...]" for LDAP authentication.`)
}

// Configure validates a new authentication specification before publishing it.
// LDAP is connected lazily so configuration never waits on network I/O.
func (p *ProxyAuth) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated["proxyauth"]; !ok {
		return nil
	}
	spec := p.opts.OptStr("proxyauth")
	var validate func(string, string) bool
	var directory *ldapConfig
	if spec != nil && *spec != "" {
		switch {
		case *spec == "any":
			validate = func(string, string) bool { return true }
		case strings.HasPrefix(*spec, "@"):
			path := strings.TrimPrefix(*spec, "@")
			if strings.HasPrefix(path, "~") {
				end := strings.IndexFunc(path, func(r rune) bool { return r < 128 && os.IsPathSeparator(byte(r)) })
				if end < 0 {
					end = len(path)
				}
				var home string
				var err error
				if end == 1 {
					home, err = os.UserHomeDir()
				} else {
					var account *user.User
					account, err = user.Lookup(path[1:end])
					if err == nil {
						home = account.HomeDir
					}
				}
				if err != nil {
					return &options.OptionsError{Msg: "Could not open htpasswd file: " + path, Err: err}
				}
				path = strings.TrimRightFunc(home, func(r rune) bool { return r < 128 && os.IsPathSeparator(byte(r)) }) + path[end:]
			}
			file, err := htpasswd.FromFile(path)
			if err != nil {
				return &options.OptionsError{Msg: "Could not open htpasswd file: " + path, Err: err}
			}
			validate = file.Check
		case strings.HasPrefix(*spec, "ldap"):
			var err error
			directory, err = parseLDAPSpec(*spec)
			if err != nil {
				return err
			}
		case strings.Contains(*spec, ":"):
			user, password, _ := strings.Cut(*spec, ":")
			if strings.Contains(password, ":") {
				return options.Errorf("Invalid single-user auth specification.")
			}
			validate = func(u, pw string) bool { return u == user && pw == password }
		default:
			return options.Errorf("Invalid proxyauth specification.")
		}
	}
	p.validate, p.ldap = validate, directory
	return nil
}

// HTTPConnect authenticates CONNECT and remembers its credentials for the client.
func (p *ProxyAuth) HTTPConnect(ctx context.Context, f *flow.HTTPFlow) error {
	if p.validate == nil && p.ldap == nil {
		return nil
	}
	valid, err := p.authenticate(ctx, f)
	if valid {
		value, _ := f.Metadata.Get("proxyauth")
		pair := value.([]any)
		key := weak.Make(f.ClientConn)
		if _, loaded := p.authenticated.Swap(key, [2]string{pair[0].(string), pair[1].(string)}); !loaded {
			runtime.AddCleanup(f.ClientConn, p.authenticated.Delete, any(key))
		}
	}
	return err
}

// RequestHeaders authenticates a request unless its CONNECT or replay exempts it.
func (p *ProxyAuth) RequestHeaders(ctx context.Context, f *flow.HTTPFlow) error {
	if p.validate == nil && p.ldap == nil {
		return nil
	}
	if value, ok := p.authenticated.Load(weak.Make(f.ClientConn)); ok {
		pair := value.([2]string)
		f.Metadata.Set("proxyauth", []any{pair[0], pair[1]})
		return nil
	}
	if f.IsReplay != nil && *f.IsReplay != "" {
		return nil
	}
	_, err := p.authenticate(ctx, f)
	return err
}

func (p *ProxyAuth) authenticate(ctx context.Context, f *flow.HTTPFlow) (bool, error) {
	mode, err := modespec.Parse(f.ClientConn.ProxyMode)
	proxy := err == nil && (mode.Name() == "regular" || mode.Name() == "upstream")
	header := "Authorization"
	if proxy {
		header = "Proxy-Authorization"
	}
	_, user, password, err := ParseHTTPBasicAuth(f.Request.Headers.Get(header))
	valid := false
	if err == nil {
		if directory := p.ldap; directory != nil {
			// The immutable configuration and credentials are captured before the
			// lock is released; configure may replace p.ldap during this exchange.
			ctx, err = addon.Concurrent(ctx, func(ctx context.Context) error {
				var err error
				valid, err = directory.check(ctx, user, password)
				return err
			})
			if err != nil {
				slog.WarnContext(ctx, "LDAP authentication failed", "error_type", fmt.Sprintf("%T", err))
			}
		} else {
			valid = p.validate(user, password)
		}
	}
	if valid {
		f.Metadata.Set("proxyauth", []any{user, password})
		f.Request.Headers.Del(header)
		return true, nil
	}
	status, challenge := 401, "WWW-Authenticate"
	if proxy {
		status, challenge = 407, "Proxy-Authenticate"
	}
	var headers httpmsg.Headers
	headers.Set(challenge, `Basic realm="mitmproxy"`)
	reason := httpmsg.StatusText(status)
	body := fmt.Sprintf("<html><head><title>%d %s</title></head><body><h1>%d %s</h1></body></html>", status, reason, status, reason)
	f.Response, err = httpmsg.MakeResponse(status, []byte(body), headers)
	return false, err
}

// MakeAuth returns upstream's base64 basic-auth value, including its trailing LF.
// The caller supplies the scheme, conventionally "basic".
func MakeAuth(username, password, scheme string) string {
	return scheme + " " + base64.StdEncoding.EncodeToString([]byte(username+":"+password)) + "\n"
}

// ParseHTTPBasicAuth returns the scheme and UTF-8 credentials in a basic header.
// Malformed headers and headers larger than 64 KiB return an error. As upstream
// does, it ignores non-alphabet base64 bytes and replaces invalid UTF-8.
func ParseHTTPBasicAuth(header string) (scheme, username, password string, err error) {
	if len(header) > 64<<10 {
		return "", "", "", errors.New("authentication header exceeds 64 KiB")
	}
	fields := strings.FieldsFunc(header, func(r rune) bool { return unicode.IsSpace(r) || r >= '\x1c' && r <= '\x1f' })
	if len(fields) != 2 {
		return "", "", "", errors.New("invalid authentication header")
	}
	scheme = fields[0]
	if strings.ToLower(scheme) != "basic" {
		return "", "", "", errors.New("unknown authentication scheme")
	}
	// Python ignores embedded and excess padding, but still requires enough
	// trailing padding for an incomplete quartet (RFC 4648 section 3.3).
	encoded := make([]byte, 0, len(fields[1]))
	padding := 0
	for i := range len(fields[1]) {
		c := fields[1][i]
		if c == '=' {
			padding++
		} else if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' {
			encoded = append(encoded, c)
			padding = 0
		}
	}
	if remainder := len(encoded) % 4; remainder != 0 {
		if remainder == 1 || padding < 4-remainder {
			return "", "", "", errors.New("invalid base64 padding")
		}
		for range 4 - remainder {
			encoded = append(encoded, '=')
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return "", "", "", err
	}
	text, err := textunicode.UTF8.NewDecoder().String(string(decoded))
	if err != nil {
		return "", "", "", err
	}
	username, password, ok := strings.Cut(text, ":")
	if !ok {
		return "", "", "", errors.New("authentication credentials have no colon")
	}
	return scheme, username, password, nil
}
