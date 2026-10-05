// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package browser

import (
	"bufio"
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/options"
)

type logRecorder struct {
	slog.Handler
	records chan slog.Record
}

func (r *logRecorder) Handle(_ context.Context, record slog.Record) error {
	r.records <- record.Clone()
	return nil
}

type launchRecord struct {
	Args  []string
	Prefs string
}

func buildRecorder(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "recorder.exe")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", path, "./testdata/recorder")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build recorder: %v\n%s", err, output)
	}
	binary, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return binary
}

func setupBrowser(t *testing.T, binary []byte, names ...string) (*Browser, *addon.Manager, *net.TCPListener, <-chan slog.Record) {
	t.Helper()
	path := t.TempDir()
	for _, name := range names {
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		if err := os.WriteFile(filepath.Join(path, name), binary, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", path)
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	t.Setenv("BROWSER_RECORD_ADDR", listener.Addr().String())
	recorder := &logRecorder{Handler: slog.NewTextHandler(io.Discard, nil), records: make(chan slog.Record, 32)}
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(recorder))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })
	opts := options.New()
	manager := addon.NewManager(opts, command.NewManager(), addon.Config{})
	t.Cleanup(manager.Close)
	browser := New(opts, manager)
	browser.lookPath = func(name string) (string, error) {
		// Absolute upstream candidates must never launch an installed user browser.
		if strings.ContainsAny(name, `/\`) {
			return "", exec.ErrNotFound
		}
		return exec.LookPath(name)
	}
	if err := manager.Add(t.Context(), browser); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Clear(t.Context()); err != nil {
			t.Error(err)
		}
		waitWorkers(t, browser)
	})
	return browser, manager, listener, recorder.records
}

func waitWorkers(t *testing.T, browser *Browser) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		browser.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		hang(t, "browser workers did not finish")
	}
}

func nextLog(t *testing.T, logs <-chan slog.Record) slog.Record {
	t.Helper()
	select {
	case record := <-logs:
		return record
	case <-time.After(30 * time.Second):
		hang(t, "missing browser log")
		return slog.Record{}
	}
}

func hang(t *testing.T, message string) {
	t.Helper()
	stack := make([]byte, 1<<20)
	n := runtime.Stack(stack, true)
	t.Fatalf("%s\n%s", message, stack[:n])
}

func acceptRecord(t *testing.T, listener *net.TCPListener) (net.Conn, launchRecord) {
	t.Helper()
	if err := listener.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if err != nil {
		hang(t, err.Error())
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		hang(t, err.Error())
	}
	var record launchRecord
	if err := json.Unmarshal(line, &record); err != nil {
		t.Fatal(err)
	}
	return conn, record
}

// connectionTerminated accepts the EOF or Windows reset caused by killing a child.
func connectionTerminated(err error) bool {
	const wsaECONNRESET = syscall.Errno(10054)
	return errors.Is(err, io.EOF) || runtime.GOOS == "windows" && errors.Is(err, wsaECONNRESET)
}

func TestConnectionTerminated(t *testing.T) {
	tests := map[string]struct {
		err  error
		want bool
	}{
		"success: EOF":           {err: io.EOF, want: true},
		"success: wrapped EOF":   {err: fmt.Errorf("read: %w", io.EOF), want: true},
		"platform: killed child": {err: &net.OpError{Op: "read", Err: syscall.Errno(10054)}, want: runtime.GOOS == "windows"},
		"error: open connection": {},
		"error: deadline":        {err: os.ErrDeadlineExceeded},
		"error: other socket":    {err: &net.OpError{Op: "read", Err: syscall.Errno(10053)}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, connectionTerminated(tt.err)); diff != "" {
				t.Fatalf("connectionTerminated(%v) (-want +got):\n%s", tt.err, diff)
			}
		})
	}
}

// TestBrowser ports upstream test_browser with a real recording executable.
func TestBrowser(t *testing.T) {
	binary := buildRecorder(t)
	browser, manager, listener, logs := setupBrowser(t, binary, "google-chrome")
	var children []browserProcess
	var conns []net.Conn
	for range 2 {
		if _, err := manager.Call(t.Context(), "browser.start"); err != nil {
			t.Fatal(err)
		}
		conn, record := acceptRecord(t, listener)
		if len(record.Args) != 7 {
			t.Fatalf("unexpected arguments: %q", record.Args)
		}
		dir, ok := strings.CutPrefix(record.Args[0], "--user-data-dir=")
		if !ok || dir == "" {
			t.Fatalf("missing isolated profile: %q", record.Args)
		}
		want := []string{"--user-data-dir=" + dir, "--proxy-server=127.0.0.1:8080", "--disable-fre", "--no-default-browser-check", "--no-first-run", "--disable-extensions", "about:blank"}
		if diff := gocmp.Diff(want, record.Args); diff != "" {
			t.Fatal(diff)
		}
		conns = append(conns, conn)
	}
	if _, err := manager.Call(t.Context(), "browser.start", "unsupported-browser"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Starting additional browser", "Starting additional browser", "Invalid browser name."} {
		record := nextLog(t, logs)
		if record.Message != want || record.Level != addon.LevelAlert {
			t.Fatalf("log = %s %q, want alert %q", record.Level, record.Message, want)
		}
	}
	if err := manager.Do(t.Context(), func(ctx context.Context) error {
		children = append(children, browser.browser...)
		if len(children) != 2 {
			t.Fatalf("children = %d, want 2", len(children))
		}
		return browser.Done(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	waitWorkers(t, browser)
	for _, conn := range conns {
		if _, err := conn.Read(make([]byte, 1)); !connectionTerminated(err) {
			hang(t, fmt.Sprintf("browser connection after done: %v", err))
		}
	}
	for _, child := range children {
		if child.cmd.ProcessState == nil {
			t.Error("child was not reaped")
		}
		if _, err := os.Stat(child.dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("profile cleanup: %v", err)
		}
	}
	if len(browser.browser) != 0 {
		t.Fatal("browser list not cleared")
	}
}

// TestBrowserKinds ports test_browser_start_firefox and test_browser_start_edge,
// and checks the Chrome alias and the exact flags and prefs from browser.py.
func TestBrowserKinds(t *testing.T) {
	binary := buildRecorder(t)
	tests := map[string]struct {
		name, executable, host string
		port                   *int
		proxy                  string
	}{
		"chrome":               {"chrome", "google-chrome", "proxy.example", new(1234), "proxy.example:1234"},
		"chromium alias":       {"chromium", "chromium", "", new(0), "127.0.0.1:8080"},
		"edge":                 {"edge", "microsoft-edge", "::1", new(8123), "::1:8123"},
		"firefox":              {"firefox", "firefox", "proxy.example", new(1234), ""},
		"firefox defaults":     {"firefox", "mozilla", "", new(0), ""},
		"firefox literal host": {"firefox", "mozilla-firefox", `quote"host`, new(1234), ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, manager, listener, _ := setupBrowser(t, binary, tt.executable)
			if err := manager.Do(t.Context(), func(ctx context.Context) error {
				return manager.Options().Update(ctx, map[string]any{"listen_host": tt.host, "listen_port": tt.port})
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Call(t.Context(), "browser.start", tt.name); err != nil {
				t.Fatal(err)
			}
			_, record := acceptRecord(t, listener)
			if tt.name == "firefox" {
				if len(record.Args) != 4 {
					t.Fatalf("Firefox arguments = %q", record.Args)
				}
				want := []string{"--profile", record.Args[1], "--new-window", "about:blank"}
				if diff := gocmp.Diff(want, record.Args); diff != "" {
					t.Fatal(diff)
				}
				host, port := tt.host, *tt.port
				if host == "" {
					host = "127.0.0.1"
				}
				if port == 0 {
					port = 8080
				}
				prefs := firefoxBasePrefs + fmt.Sprintf(`user_pref("network.proxy.http", "%s");user_pref("network.proxy.http_port", %d);user_pref("network.proxy.ssl", "%s");user_pref("network.proxy.ssl_port", %d);`, host, port, host, port)
				if diff := gocmp.Diff(prefs, record.Prefs); diff != "" {
					t.Fatal(diff)
				}
			} else {
				if len(record.Args) != 7 || !strings.HasPrefix(record.Args[0], "--user-data-dir=") {
					t.Fatalf("Chromium arguments = %q", record.Args)
				}
				want := []string{record.Args[0], "--proxy-server=" + tt.proxy, "--disable-fre", "--no-default-browser-check", "--no-first-run", "--disable-extensions", "about:blank"}
				if diff := gocmp.Diff(want, record.Args); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

// Each string and its order are copied from the pinned upstream's prefs list;
// writelines concatenates them without separators.
const firefoxBasePrefs = `user_pref("datareporting.policy.firstRunURL", "");` +
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

// TestSearchOrder covers test_no_browser, test_find_executable_cmd_no_executable,
// test_browser_start_firefox_not_found and test_browser_start_edge_not_found.
func TestSearchOrder(t *testing.T) {
	tests := map[string]struct{ candidates []string }{
		"chrome":  {[]string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`, `C:\Program Files (x86)\Google\Application\chrome.exe`, "google-chrome", "google-chrome-stable", "chrome", "chromium", "chromium-browser", "google-chrome-unstable", "flatpak"}},
		"edge":    {[]string{"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, `C:\Program Files\Microsoft\Edge\Application\msedge.exe`, "microsoft-edge", "microsoft-edge-stable", "microsoft-edge-dev", "microsoft-edge-beta", "flatpak"}},
		"firefox": {[]string{"/Applications/Firefox.app/Contents/MacOS/firefox", `C:\Program Files\Mozilla Firefox\firefox.exe`, "firefox", "mozilla-firefox", "mozilla", "flatpak"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			browser, manager, _, logs := setupBrowser(t, nil)
			lookup := browser.lookPath
			var got []string
			browser.lookPath = func(candidate string) (string, error) {
				got = append(got, candidate)
				return lookup(candidate)
			}
			if _, err := manager.Call(t.Context(), "browser.start", name); err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(tt.candidates, got); diff != "" {
				t.Fatal(diff)
			}
			if record := nextLog(t, logs); record.Message != "Your platform is not supported yet - please submit a patch." || record.Level != addon.LevelAlert {
				t.Fatalf("unsupported log = %v", record)
			}
		})
	}
}

func TestCommandRegistration(t *testing.T) {
	_, manager, _, logs := setupBrowser(t, nil)
	for name, cmd := range manager.Commands().Commands() {
		if name != "browser.start" || cmd.Help != "" || cmd.Return != nil || len(cmd.Params) != 1 {
			t.Fatalf("unexpected command: %#v", cmd)
		}
	}
	if _, err := manager.Call(t.Context(), "browser.start", "chrome", "edge"); err == nil {
		t.Fatal("extra argument accepted")
	}
	if _, err := manager.Commands().Execute(t.Context(), "browser.start 'unknown browser'"); err != nil {
		t.Fatal(err)
	}
	if record := nextLog(t, logs); record.Message != "Invalid browser name." {
		t.Fatal(record.Message)
	}
}
