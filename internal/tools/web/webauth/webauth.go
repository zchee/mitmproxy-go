// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package webauth implements mitmweb password, session and XSRF policy.
package webauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/options"
)

type configuration struct {
	password    string
	hash        *passwordHash
	host        string
	port        int
	randomToken bool
}

// WebAuth registers web_password and publishes immutable authentication policy.
// Load and Configure run under addon dispatch; HTTP checks never enter dispatch.
// Construct it with New and load it through addon.Manager before serving HTTP.
type WebAuth struct {
	opts   *options.Manager
	config atomic.Pointer[configuration]
	secret [32]byte
	clock  func() time.Time
}

// New returns an addon using opts. Load initializes its per-process secrets.
func New(opts *options.Manager) *WebAuth {
	return &WebAuth{opts: opts, clock: time.Now}
}

// Name preserves the upstream addon lookup name.
func (*WebAuth) Name() string { return "webauth" }

// Load registers only web_password and initializes authentication policy.
func (auth *WebAuth) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "web_password", options.TypeStr, "", "Password to protect the mitmweb user interface. Values starting with `$` are interpreted as an argon2 hash, everything else is considered a plaintext password. If no password is provided, a random token is generated on startup.For automated calls, you can pass the password as token query parameteror as `Authorization: Bearer ...` header."); err != nil {
		return err
	}
	if _, err := rand.Read(auth.secret[:]); err != nil {
		return err
	}
	return auth.Configure(ctx, map[string]struct{}{"web_password": {}})
}

// Configure validates password changes before publishing a new configuration.
// Invalid PHC values return OptionsError without replacing the previous policy.
func (auth *WebAuth) Configure(ctx context.Context, updated map[string]struct{}) error {
	_, passwordChanged := updated["web_password"]
	_, hostChanged := updated["web_host"]
	_, portChanged := updated["web_port"]
	if !passwordChanged && !hostChanged && !portChanged {
		return nil
	}
	previous := auth.config.Load()
	next := configuration{host: "127.0.0.1", port: 8081}
	if previous != nil {
		next = *previous
	}
	if auth.opts.Has("web_host") {
		next.host = auth.opts.Str("web_host")
	}
	if auth.opts.Has("web_port") {
		next.port = auth.opts.Int("web_port")
	}
	if passwordChanged || previous == nil {
		next.password = auth.opts.Str("web_password")
		next.hash = nil
		next.randomToken = next.password == ""
		switch {
		case strings.HasPrefix(next.password, "$"):
			hash, err := parsePasswordHash(next.password)
			if err != nil {
				return options.Errorf("`web_password` starts with `$`, but it's not a valid argon2 hash.")
			}
			next.hash = hash
		case next.randomToken:
			var token [16]byte
			if _, err := rand.Read(token[:]); err != nil {
				return err
			}
			next.password = hex.EncodeToString(token[:])
		default:
			slog.WarnContext(ctx, "Using a plaintext password to protect the mitmweb user interface. Consider using an argon2 hash for `web_password`  instead.")
		}
	}
	auth.config.Store(&next)
	return nil
}

// WebURL returns the current URL, including the token only for generated tokens.
func (auth *WebAuth) WebURL() string {
	config := auth.config.Load()
	if config == nil {
		return ""
	}
	address := "http://" + net.JoinHostPort(config.host, strconv.Itoa(config.port)) + "/"
	if config.randomToken {
		address += "?token=" + url.QueryEscape(config.password)
	}
	return address
}

// AuthCookieName returns the current port-scoped session cookie name.
func (auth *WebAuth) AuthCookieName() string {
	config := auth.config.Load()
	if config == nil {
		return ""
	}
	return cookieName(config)
}

func cookieName(config *configuration) string {
	return "mitmproxy-auth-" + strconv.Itoa(config.port)
}

// IsValidPassword checks captured policy outside addon dispatch. It returns
// ErrVerifierBusy when either shared Argon2 limit is full, or a context error
// for a canceled request. Argon2 reservations remain held until derivation ends.
func (auth *WebAuth) IsValidPassword(ctx context.Context, password string) (bool, error) {
	return checkPassword(ctx, auth.config.Load(), password)
}

func checkPassword(ctx context.Context, config *configuration, password string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if config == nil {
		return false, nil
	}
	if config.hash != nil {
		return config.hash.check(ctx, password)
	}
	want := sha256.Sum256([]byte(config.password))
	got := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1, nil
}
