// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/term"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/anticache"
	"github.com/zchee/mitmproxy-go/addons/anticomp"
	"github.com/zchee/mitmproxy-go/addons/block"
	"github.com/zchee/mitmproxy-go/addons/blocklist"
	"github.com/zchee/mitmproxy-go/addons/browser"
	"github.com/zchee/mitmproxy-go/addons/clientplayback"
	"github.com/zchee/mitmproxy-go/addons/commandhistory"
	"github.com/zchee/mitmproxy-go/addons/comment"
	"github.com/zchee/mitmproxy-go/addons/core"
	"github.com/zchee/mitmproxy-go/addons/cut"
	"github.com/zchee/mitmproxy-go/addons/disableh2c"
	"github.com/zchee/mitmproxy-go/addons/dnsresolver"
	"github.com/zchee/mitmproxy-go/addons/errorcheck"
	"github.com/zchee/mitmproxy-go/addons/eventstore"
	"github.com/zchee/mitmproxy-go/addons/export"
	"github.com/zchee/mitmproxy-go/addons/intercept"
	"github.com/zchee/mitmproxy-go/addons/maplocal"
	"github.com/zchee/mitmproxy-go/addons/mapremote"
	"github.com/zchee/mitmproxy-go/addons/modifybody"
	"github.com/zchee/mitmproxy-go/addons/modifyheaders"
	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/addons/onboarding"
	"github.com/zchee/mitmproxy-go/addons/proxyauth"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/addons/readfile"
	"github.com/zchee/mitmproxy-go/addons/save"
	"github.com/zchee/mitmproxy-go/addons/savehar"
	"github.com/zchee/mitmproxy-go/addons/serverplayback"
	"github.com/zchee/mitmproxy-go/addons/stickyauth"
	"github.com/zchee/mitmproxy-go/addons/stickycookie"
	"github.com/zchee/mitmproxy-go/addons/stripdnshttpsrecords"
	"github.com/zchee/mitmproxy-go/addons/tlsconfig"
	"github.com/zchee/mitmproxy-go/addons/updatealtsvc"
	"github.com/zchee/mitmproxy-go/addons/upstreamauth"
	"github.com/zchee/mitmproxy-go/addons/view"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/internal/tools/console/commander"
	"github.com/zchee/mitmproxy-go/internal/tools/console/eventlog"
	"github.com/zchee/mitmproxy-go/internal/tools/console/flowlist"
	"github.com/zchee/mitmproxy-go/internal/tools/console/flowview"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/internal/tools/console/keymap"
	"github.com/zchee/mitmproxy-go/internal/tools/console/settings"
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
	"github.com/zchee/mitmproxy-go/script"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/httplayer"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/modes"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tcplayer"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tlslayer"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/udplayer"
)

// Config configures the console without starting listeners or terminal work.
type Config struct {
	Options        *options.Manager
	Stdin          io.ReadCloser
	Stdout, Stderr io.Writer
}

type presentationOwner uint8

const (
	unselectedPresentation presentationOwner = iota
	terminalPresentation
	harnessPresentation
)

// Master assembles the interactive frontend and the ported default addons.
// View and Events require Do; Model and Program belong to the UI goroutine.
type Master struct {
	*master.Master
	View                   *view.View
	Events                 *eventstore.EventStore
	ProxyServer            *proxyserver.ProxyServer
	Bridge                 *Bridge
	Model                  *Model
	Program                *tea.Program
	logger                 *slog.Logger
	stdout, stderr         io.Writer
	eventLogs              *addon.LogHandler
	ready, runDone, uiDone chan struct{}
	running, uiStarted     atomic.Bool
	readyOnce              sync.Once
	mu, closeMu            sync.Mutex
	stdin                  io.Reader
	owner                  presentationOwner
	closed, logsClosed     bool
	scripts                *script.Loader
}

type consoleLogHandler struct{ slog.Handler }

// New registers addons in upstream order without opening the terminal or sockets.
// The caller must Close a constructed master it does not Run.
func New(ctx context.Context, cfg Config) (*Master, error) {
	opts := cfg.Options
	if opts == nil {
		opts = options.New()
	}
	if cfg.Stdin == nil {
		cfg.Stdin = os.Stdin
	}
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	handler := new(consoleLogHandler)
	logger := slog.New(handler)
	var m *Master
	base := master.New(master.Config{Options: opts, Logger: logger, BeforeClose: func(ctx context.Context) error { return m.closeFrontend(ctx) }})
	m = &Master{Master: base, logger: logger, stdin: cfg.Stdin, stdout: cfg.Stdout, stderr: cfg.Stderr, ready: make(chan struct{}), runDone: make(chan struct{}), uiDone: make(chan struct{})}
	var err error
	m.Events, err = eventstore.New()
	if err != nil {
		return nil, errors.Join(err, m.Close(context.WithoutCancel(ctx)))
	}
	m.eventLogs = m.Events.LogHandler(base.Addons)
	ec := errorcheck.New(errorcheck.Config{Stderr: cfg.Stderr, RepeatErrorsOnStderr: true})
	handler.Handler = slog.NewMultiHandler(base.LogHandler(), m.eventLogs, ec.LogHandler())
	ps, err := proxyserver.New(proxy.Config{Manager: base.Addons, Options: opts, Connections: new(proxy.Connections), HTTPFidelity: new(http1.FidelityCounter), Logger: logger})
	if err != nil {
		return nil, errors.Join(err, m.Close(context.WithoutCancel(ctx)))
	}
	m.ProxyServer, m.View = ps, view.New(base.Addons)
	m.scripts = script.New(base, script.Config{Logger: logger, ListenAddrs: ps.ListenAddrs})
	m.Bridge, err = NewBridge(context.WithoutCancel(ctx), BridgeConfig{Master: base, View: m.View, Events: m.Events, Project: flowlist.Project, Listeners: func() []string {
		var listeners []string
		for _, address := range ps.ListenAddrs() {
			listeners = append(listeners, fmt.Sprint(address))
		}
		return listeners
	}})
	if err != nil {
		return nil, errors.Join(err, m.Close(context.WithoutCancel(ctx)))
	}
	frontend := &ConsoleAddon{bridge: m.Bridge, master: m}
	keys := &keymap.Config{Submit: func(ctx context.Context, path string) error {
		return m.Bridge.Dispatch(ctx, contract.Action{Kind: "keymap_load", Value: path})
	}}
	if err := base.Addons.Add(ctx,
		core.New(base.Addons), browser.New(opts, base.Addons), block.New(opts),
		stripdnshttpsrecords.New(opts), blocklist.New(opts), anticache.New(opts), anticomp.New(opts),
		clientplayback.New(base), commandhistory.New(opts), comment.New(base.Addons), cut.New(),
		disableh2c.New(), export.New(opts), onboarding.New(opts), proxyauth.New(opts), ps, m.scripts,
		dnsresolver.New(opts, logger), nextlayer.New(opts), serverplayback.New(base),
		mapremote.New(opts), maplocal.New(opts), modifybody.New(opts), modifyheaders.New(opts),
		stickyauth.New(opts), stickycookie.New(opts), save.New(opts, m.ShutdownWithError),
		savehar.New(opts, version.Version), tlsconfig.New(opts), upstreamauth.New(opts), updatealtsvc.New(opts),
		intercept.New(opts), m.View, m.Events, readfile.New(base, readfile.Config{Stdin: cfg.Stdin, Logger: logger}), frontend, keys, ec,
	); err != nil {
		return nil, errors.Join(err, m.Close(context.WithoutCancel(ctx)))
	}
	if err := base.Do(ctx, func(context.Context) error {
		m.Bridge.unsubscribe = append(m.Bridge.unsubscribe, ps.SubscribeServerState(func(context.Context, proxyserver.ServerSnapshot) { m.Bridge.Invalidate() }))
		return nil
	}); err != nil {
		return nil, errors.Join(err, m.Close(context.WithoutCancel(ctx)))
	}
	return m, nil
}

// NewProgram selects terminal ownership and binds the assembled presentation model.
// It must be called before Run; any second presentation selection is refused.
func (m *Master) NewProgram() (*tea.Program, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.running.Load() || m.owner != unselectedPresentation {
		return nil, errors.New("console presentation is already selected or closed")
	}
	model := m.makeModel()
	program, err := NewProgram(model, tea.WithContext(context.WithoutCancel(m.Bridge.Context())), tea.WithInput(m.stdin), tea.WithOutput(m.stdout), tea.WithoutSignalHandler())
	if err != nil {
		return nil, err
	}
	m.Model, m.Program, m.owner = model, program, terminalPresentation
	return program, nil
}

// NewModel selects harness ownership and returns an unbound assembled model.
// The harness uses the bridge context and its own program sender with DrainTo
// and DeliverEffectsTo. Any second presentation selection is refused.
func (m *Master) NewModel() (*Model, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.running.Load() || m.owner != unselectedPresentation {
		return nil, errors.New("console presentation is already selected or closed")
	}
	m.Model, m.owner = m.makeModel(), harnessPresentation
	return m.Model, nil
}

func (m *Master) makeModel() *Model {
	lifetime := m.Bridge.Context()
	model := NewModel(m.Bridge, map[string]WidgetFactory{
		"flowlist":    func(host contract.Host) contract.Widget { return flowlist.New(lifetime, host) },
		"eventlog":    func(host contract.Host) contract.Widget { return eventlog.New(lifetime, host) },
		"flowview":    func(host contract.Host) contract.Widget { return flowview.New(lifetime, host) },
		"commands":    func(host contract.Host) contract.Widget { return commander.NewReference(lifetime, host) },
		"commander":   func(host contract.Host) contract.Widget { return commander.New(lifetime, host) },
		"options":     func(host contract.Host) contract.Widget { return settings.NewOptions(lifetime, host) },
		"keybindings": func(host contract.Host) contract.Widget { return settings.NewBindings(lifetime, host) },
	})
	model.ready = func() { m.readyOnce.Do(func() { close(m.ready) }) }
	return model
}

// Logger returns this master's per-instance frontend and addon logger.
func (m *Master) Logger() *slog.Logger { return m.logger }

// Ready closes when the selected presentation model reaches Init.
// It stays open on a startup failure; callers must also observe Run's result.
func (m *Master) Ready() <-chan struct{} { return m.ready }

// Run starts the proxy lifecycle with the selected presentation owner, at most once.
// Terminal ownership requires a TTY; a harness drives its own program and sender.
// Both paths join the same owned bridge and frontend work before returning.
func (m *Master) Run(ctx context.Context) (err error) {
	if !m.running.CompareAndSwap(false, true) {
		return errors.New("console master already run")
	}
	defer close(m.runDone)
	defer func() {
		err = errors.Join(err, m.closeFrontend(context.WithoutCancel(ctx)), m.Master.Close(context.WithoutCancel(ctx)))
	}()
	m.mu.Lock()
	closed, owner := m.closed, m.owner
	m.mu.Unlock()
	if closed {
		return errors.New("console master is closed")
	}
	if owner == unselectedPresentation {
		return errors.New("console presentation is not selected")
	}
	if owner == terminalPresentation {
		file, ok := m.stdout.(interface{ Fd() uintptr })
		if !ok || !term.IsTerminal(file.Fd()) {
			return errors.New("Error: mitmproxy's console interface requires a tty. Please run mitmproxy in an interactive shell environment.") //nolint:staticcheck // Preserve upstream's interactive-shell diagnostic.
		}
		if runtime.GOOS != "windows" {
			locale := os.Getenv("LC_ALL")
			if locale == "" {
				locale = os.Getenv("LC_CTYPE")
			}
			if locale == "" {
				locale = os.Getenv("LANG")
			}
			if locale != "" && !strings.Contains(strings.ToLower(locale), "utf") {
				if _, err := fmt.Fprintf(m.stderr, "mitmproxy expects a UTF-8 console environment, not %s. Set your LANG environment variable to something like en_US.UTF-8.\n", pyrepr.Value(locale)); err != nil {
					return err
				}
			}
		}
	}
	bindings, present, err := keymap.ReadPath(keymap.DefaultPath(m.Options.Str("confdir")))
	if err != nil {
		return err
	}
	if present {
		if err := m.Do(ctx, func(context.Context) error { return m.Bridge.Keys.Install(bindings) }); err != nil {
			return err
		}
	}
	if owner == terminalPresentation {
		signals := make(chan os.Signal, 1)
		stop, joined := make(chan struct{}), make(chan struct{})
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		defer func() {
			signal.Stop(signals)
			close(stop)
			<-joined
			for {
				select {
				case <-signals:
				default:
					return
				}
			}
		}()
		go func() {
			defer close(joined)
			// Send only after Init, so startup failures cannot strand a sender.
			var ready <-chan struct{}
			for {
				select {
				case <-stop:
					return
				case <-ctx.Done():
					return
				case <-m.Bridge.Context().Done():
					return
				case received := <-signals:
					if received == syscall.SIGTERM {
						m.Shutdown()
					} else {
						ready = m.ready
					}
				case <-ready:
					select {
					case <-stop:
						return
					case <-ctx.Done():
						return
					case <-m.Bridge.Context().Done():
						return
					default:
					}
					// Send also selects on the program's own shutdown context.
					m.Program.Send(quitPromptMsg{})
					ready = nil
				}
			}
		}()
	}
	return m.Master.Run(ctx)
}

func (m *Master) startProgram() {
	m.mu.Lock()
	if m.closed || m.owner != terminalPresentation || !m.uiStarted.CompareAndSwap(false, true) {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	go func() {
		defer close(m.uiDone)
		_, err := m.Program.Run()
		if err != nil && m.Bridge.Context().Err() == nil {
			m.Master.ShutdownWithError(err)
		} else {
			m.Master.Shutdown()
		}
	}()
}

// Shutdown requests lifecycle shutdown without waiting for the terminal join.
func (m *Master) Shutdown() { m.Master.Shutdown() }

// ShutdownWithError retains the first fatal error and stops the frontend.
func (m *Master) ShutdownWithError(err error) { m.Master.ShutdownWithError(err); m.Shutdown() }

// Close stops and joins the terminal, commands and log consumers outside dispatch.
// It is safe before Run, on failed construction, and on repeated calls.
func (m *Master) Close(ctx context.Context) error {
	m.Shutdown()
	if m.running.Load() {
		select {
		case <-m.runDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return errors.Join(m.closeFrontend(ctx), m.Master.Close(ctx))
}

func (m *Master) closeFrontend(ctx context.Context) error {
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	m.Shutdown()
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	drain, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var err error
	if m.scripts != nil {
		err = m.scripts.Close()
	}
	if m.uiStarted.Load() {
		quitDone := make(chan struct{})
		go func() {
			m.Program.Quit()
			close(quitDone)
		}()
		select {
		case <-m.uiDone:
		case <-drain.Done():
			err = drain.Err()
			// Bubble Tea's kill path can race its input reader. Use it only if
			// an orderly Quit has not completed within the five-second drain bound.
			m.Program.Kill()
			<-m.uiDone
		}
		<-quitDone
	}
	if m.Bridge != nil {
		err = errors.Join(err, m.Bridge.Close(drain))
	}
	if m.Model != nil {
		err = errors.Join(err, m.Model.closeProcesses())
	}
	if m.ProxyServer != nil {
		err = errors.Join(err, m.ProxyServer.Close(drain))
	}
	if m.eventLogs != nil {
		if !m.logsClosed {
			err = errors.Join(err, m.Master.LogHandler().Flush(drain), m.eventLogs.Flush(drain))
			m.logsClosed = true
		}
		err = errors.Join(err, m.eventLogs.Close(drain))
	}
	return err
}
