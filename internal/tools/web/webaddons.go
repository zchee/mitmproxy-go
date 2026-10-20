// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/options"
)

var availableWebColumns = []string{"icon", "index", "method", "version", "path", "quickactions", "size", "status", "time", "timestamp", "tls", "comment"}

// AvailableColumns returns an owned copy of the frontend's column vocabulary.
func AvailableColumns() []string { return slices.Clone(availableWebColumns) }

// WebAddon registers the web display options and starts the assembled frontend.
// A standalone value can register options without constructing a Master.
type WebAddon struct{ master *Master } //nolint:revive // Keep upstream's addon name for composed registry consumers.

// Load registers the display and listener options with their upstream metadata.
// Password registration belongs to WebAuth.
func (*WebAddon) Load(ctx context.Context, loader *addon.Loader) error {
	for _, spec := range []struct {
		name    string
		typ     options.Type
		def     any
		help    string
		choices []string
	}{
		{"web_open_browser", options.TypeBool, true, "Start a browser.", nil},
		{"web_debug", options.TypeBool, false, "Enable mitmweb debugging.", nil},
		{"web_port", options.TypeInt, 8081, "Web UI port.", nil},
		{"web_host", options.TypeStr, "127.0.0.1", "Web UI host.", nil},
		{"web_columns", options.TypeSeq, []string{"tls", "icon", "path", "method", "status", "size", "time"}, "Columns to show in the flow list. Can be one of the following: " + strings.Join(availableWebColumns, ", "), nil},
		{"web_theme", options.TypeStr, "system", "Preferred color theme for the mitmweb user interface.", []string{"system", "dark", "light"}},
	} {
		if err := loader.AddOption(ctx, spec.name, spec.typ, spec.def, spec.help, spec.choices...); err != nil {
			return err
		}
	}
	return nil
}

// Running binds the web listener and starts browser work outside dispatch.
func (a *WebAddon) Running(ctx context.Context) error {
	if a.master == nil {
		return errors.New("web addon requires an assembled master to run")
	}
	m := a.master
	if m.stopping.Load() {
		return nil
	}
	host, port := m.Options.Str("web_host"), m.Options.Int("web_port")
	open, password := m.Options.Bool("web_open_browser"), m.Options.Str("web_password") != ""
	_, err := addon.Concurrent(ctx, func(clean context.Context) error {
		if err := m.startHTTP(clean, host, port); err != nil {
			if m.stopping.Load() && errors.Is(err, context.Canceled) {
				return nil
			}
			return &options.OptionsError{Msg: err.Error(), Err: err}
		}
		address := m.WebURL()
		m.logger.InfoContext(clean, "Web server listening at "+address)
		if open {
			m.mu.Lock()
			if m.closed {
				m.mu.Unlock()
				return nil
			}
			life := m.lifetime
			m.browser.Go(func() {
				if !openBrowser(life, address) && life.Err() == nil {
					m.logger.InfoContext(life, "No web browser found. Please open a browser and point it to "+address)
					if !password {
						m.logger.InfoContext(life, "You can configure a fixed authentication token by setting the `web_password` option (https://docs.mitmproxy.org/stable/concepts-options/#web_password).")
					}
				}
			})
			m.mu.Unlock()
		}
		return nil
	})
	if err == nil && !m.stopping.Load() {
		close(m.ready)
	}
	return err
}

// Done signals request and launcher cancellation without joining under dispatch.
func (a *WebAddon) Done(ctx context.Context) error {
	if a.master != nil {
		a.master.mu.Lock()
		if a.master.cancel != nil {
			a.master.cancel()
		}
		a.master.mu.Unlock()
		if a.master.hub != nil {
			return a.master.hub.Done(ctx)
		}
	}
	return nil
}

func (m *Master) startHTTP(ctx context.Context, host string, port int) error {
	m.mu.Lock()
	life := m.lifetime
	m.mu.Unlock()
	if life == nil {
		return errors.New("web master must be started with Run")
	}
	if err := life.Err(); err != nil {
		return err
	}
	listener, err := new(net.ListenConfig).Listen(life, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		displayHost := host
		if displayHost == "" {
			displayHost = "*"
		}
		failure := fmt.Errorf("Web server failed to listen on %s:%d with %w", displayHost, port, err) //nolint:staticcheck // Preserve upstream's user-facing listener failure.
		if errors.Is(err, syscall.EADDRINUSE) {
			return fmt.Errorf("%w\nTry specifying a different port by using `--set web_port=%d`.", failure, port+2) //nolint:staticcheck // Preserve upstream's complete port-conflict hint.
		}
		return failure
	}
	if port == 0 {
		actual := listener.Addr().(*net.TCPAddr).Port
		if err := m.Do(ctx, func(ctx context.Context) error { return m.Options.Update(ctx, map[string]any{"web_port": actual}) }); err != nil {
			return errors.Join(err, listener.Close())
		}
	}
	server := &http.Server{Handler: m.Handler(), BaseContext: func(net.Listener) context.Context { return life }}
	served := make(chan struct{})
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.Join(context.Canceled, listener.Close())
	}
	m.server, m.addr, m.served = server, listener.Addr(), served
	m.mu.Unlock()
	go func() {
		defer close(served)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.logger.ErrorContext(life, "Web server failed", "error", err)
			m.ShutdownWithError(err)
		}
	}()
	return nil
}
