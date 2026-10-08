// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package browser starts isolated browsers configured to use the proxy.
package browser

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/options"
)

// browserCleanupTimeout bounds detached reaper diagnostics, not process or filesystem I/O.
const browserCleanupTimeout = 5 * time.Second

// removeProfile is captured before reaping starts so tests can inject a real
// removal followed by a failure without changing a running worker's operation.
var removeProfile = os.RemoveAll

// Browser owns the browsers and temporary profiles started by browser.start.
// Its methods run under the addon's dispatch lock; reapers run outside it.
type Browser struct {
	opts     *options.Manager
	manager  *addon.Manager
	lookPath func(string) (string, error)
	browser  []browserProcess
	lifetime context.Context
	cancel   context.CancelFunc
	workers  sync.WaitGroup
}

type browserProcess struct {
	cmd    *exec.Cmd
	dir    string
	exited <-chan struct{}
}

// New returns a browser addon using opts and manager's dispatch domain.
func New(opts *options.Manager, manager *addon.Manager) *Browser {
	return &Browser{opts: opts, manager: manager, lookPath: exec.LookPath}
}

// Load registers the browser.start command.
func (b *Browser) Load(_ context.Context, loader *addon.Loader) error {
	return loader.AddCommand("browser.start", b.Start)
}

// Start launches an isolated browser. With no name it selects Chrome; at most
// one name may be given. It returns profile creation and process launch errors.
func (b *Browser) Start(ctx context.Context, names ...string) error {
	if len(names) > 1 {
		return errors.New("browser.start accepts at most one browser name")
	}
	if len(b.browser) > 0 {
		slog.Log(ctx, addon.LevelAlert, "Starting additional browser")
	}
	name := "chrome"
	if len(names) == 1 {
		name = names[0]
	}
	var executables, flatpaks []string
	switch name {
	case "chrome", "chromium":
		executables = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Application\chrome.exe`,
			"google-chrome", "google-chrome-stable", "chrome", "chromium", "chromium-browser", "google-chrome-unstable",
		}
		flatpaks = []string{"com.google.Chrome", "org.chromium.Chromium", "com.github.Eloston.UngoogledChromium", "com.google.ChromeDev"}
	case "edge":
		executables = []string{
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
			"microsoft-edge", "microsoft-edge-stable", "microsoft-edge-dev", "microsoft-edge-beta",
		}
		flatpaks = []string{"com.microsoft.Edge"}
	case "firefox":
		executables = []string{
			"/Applications/Firefox.app/Contents/MacOS/firefox",
			`C:\Program Files\Mozilla Firefox\firefox.exe`,
			"firefox", "mozilla-firefox", "mozilla",
		}
		flatpaks = []string{"org.mozilla.firefox"}
	default:
		slog.Log(ctx, addon.LevelAlert, "Invalid browser name.")
		return nil
	}
	if b.cancel == nil {
		// A command's context carries a dispatch frame. Background work must
		// instead enter Manager.Do with a context that never had that frame.
		b.lifetime, b.cancel = context.WithCancel(context.Background())
	}
	for _, candidate := range executables {
		if path, err := b.lookPath(candidate); err == nil {
			return b.launch(name, []string{path})
		}
	}
	flatpak, err := b.lookPath("flatpak")
	if err != nil {
		slog.Log(ctx, addon.LevelAlert, "Your platform is not supported yet - please submit a patch.")
		return nil
	}
	lifetime := b.lifetime
	b.workers.Go(func() {
		var command []string
		for _, id := range flatpaks {
			if lifetime.Err() != nil {
				return
			}
			if exec.CommandContext(lifetime, flatpak, "info", id).Run() == nil { //nolint:gosec // Fixed executable and app candidates resolved through the user's PATH; no shell.
				command = []string{flatpak, "run", "-p", id}
				break
			}
		}
		_ = b.manager.Do(lifetime, func(ctx context.Context) error {
			if lifetime.Err() != nil {
				return nil
			}
			if command == nil {
				slog.Log(ctx, addon.LevelAlert, "Your platform is not supported yet - please submit a patch.")
			} else if err := b.launch(name, command); err != nil {
				slog.ErrorContext(ctx, "Starting browser", "error", err)
			}
			return nil
		})
	})
	return nil
}

func (b *Browser) launch(name string, command []string) error {
	dir, err := os.MkdirTemp("", "mitmproxy-browser-")
	if err != nil {
		return err
	}
	host := b.opts.Str("listen_host")
	if host == "" {
		host = "127.0.0.1"
	}
	port := 8080
	if configured := b.opts.OptInt("listen_port"); configured != nil && *configured != 0 {
		port = *configured
	}
	args := command[1:]
	if name == "firefox" {
		prefs := firefoxPrefs + fmt.Sprintf(`user_pref("network.proxy.http", "%s");user_pref("network.proxy.http_port", %d);user_pref("network.proxy.ssl", "%s");user_pref("network.proxy.ssl_port", %d);`, host, port, host, port)
		if err := os.WriteFile(filepath.Join(dir, "prefs.js"), []byte(prefs), 0o600); err != nil {
			return errors.Join(err, os.RemoveAll(dir))
		}
		args = append(args, "--profile", dir, "--new-window", "about:blank")
	} else {
		args = append(args, "--user-data-dir="+dir, fmt.Sprintf("--proxy-server=%s:%d", host, port), "--disable-fre", "--no-default-browser-check", "--no-first-run", "--disable-extensions", "about:blank")
	}
	cmd := exec.Command(command[0], args...) //nolint:gosec // Only known browser executables are searched; options are separate arguments, never shell input.
	if err := cmd.Start(); err != nil {
		return errors.Join(err, os.RemoveAll(dir))
	}
	lifetime := b.lifetime
	remove := removeProfile
	exited := make(chan struct{})
	b.browser = append(b.browser, browserProcess{cmd: cmd, dir: dir, exited: exited})
	b.workers.Go(func() {
		// Exit status is immaterial, including the expected kill on shutdown.
		_ = cmd.Wait()
		close(exited)
		<-lifetime.Done()
		if err := remove(dir); err != nil {
			cleanupCtx, stopCleanup := context.WithTimeout(context.WithoutCancel(lifetime), browserCleanupTimeout)
			defer stopCleanup()
			_ = b.manager.Do(cleanupCtx, func(ctx context.Context) error {
				slog.ErrorContext(ctx, "Removing browser profile", "error", err)
				return nil
			})
		}
	})
	return nil
}

const firefoxPrefs = `user_pref("datareporting.policy.firstRunURL", "");` +
	`user_pref("network.proxy.type", 1);` +
	`user_pref("network.proxy.share_proxy_settings", true);` +
	`user_pref("datareporting.healthreport.uploadEnabled", false);` +
	`user_pref("app.normandy.enabled", false);` +
	`user_pref("app.update.auto", false);` +
	`user_pref("app.update.enabled", false);` +
	`user_pref("app.update.autoInstallEnabled", false);` +
	`user_pref("app.shield.optoutstudies.enabled", false);` +
	`user_pref("extensions.blocklist.enabled", false);` +
	`user_pref("browser.safebrowsing.downloads.remote.enabled", false);` +
	`user_pref("browser.region.network.url", "");` +
	`user_pref("browser.region.update.enabled", false);` +
	`user_pref("browser.region.local-geocoding", false);` +
	`user_pref("extensions.pocket.enabled", false);` +
	`user_pref("network.captive-portal-service.enabled", false);` +
	`user_pref("network.connectivity-service.enabled", false);` +
	`user_pref("toolkit.telemetry.server", "");` +
	`user_pref("dom.push.serverURL", "");` +
	`user_pref("services.settings.enabled", false);` +
	`user_pref("browser.newtab.preload", false);` +
	`user_pref("browser.safebrowsing.provider.google4.updateURL", "");` +
	`user_pref("browser.safebrowsing.provider.mozilla.updateURL", "");` +
	`user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);` +
	`user_pref("browser.newtabpage.activity-stream.default.sites", "");` +
	`user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);` +
	`user_pref("browser.bookmarks.restore_default_bookmarks", false);` +
	`user_pref("browser.bookmarks.file", "");`

// Done kills launched browsers and cancels pending work. Windows permits a
// one-second exit confirmation after a raced access-denied termination error.
// Reapers remove profiles after the children have exited.
func (b *Browser) Done(_ context.Context) error {
	if b.cancel != nil {
		b.cancel()
		b.cancel = nil
	}
	var errs []error
	for _, browser := range b.browser {
		if err := killProcess(browser.cmd.Process); err != nil && !errors.Is(err, os.ErrProcessDone) {
			errs = append(errs, err)
		}
	}
	b.browser = nil
	return errors.Join(errs...)
}
