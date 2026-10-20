// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build browser && linux

package acceptance_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"

	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/internal/tools/web"
	"github.com/zchee/mitmproxy-go/options"
)

func TestMitmwebBrowser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("browser acceptance must run unprivileged with the sandbox enabled")
	}
	chrome := os.Getenv("MITMPROXY_TEST_CHROME")
	artifacts := os.Getenv("MITMPROXY_TEST_WEB_ARTIFACTS")
	if !filepath.IsAbs(chrome) || !filepath.IsAbs(artifacts) {
		t.Fatal("MITMPROXY_TEST_CHROME and MITMPROXY_TEST_WEB_ARTIFACTS must be absolute paths")
	}
	chromeFile, err := os.Open(chrome)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, chromeFile)
	if err := errors.Join(readErr, chromeFile.Close()); err != nil {
		t.Fatal(err)
	}
	digest := hash.Sum(nil)
	if want := os.Getenv("MITMPROXY_TEST_CHROME_SHA256"); want == "" || hex.EncodeToString(digest) != want {
		t.Fatalf("Chrome executable does not match the frozen provisioning hash: %x", digest)
	}
	version, err := exec.CommandContext(t.Context(), chrome, "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	output, err := os.MkdirTemp(artifacts, "browser-")
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte) {
		if err := os.WriteFile(filepath.Join(output, name), raw, 0o600); err != nil {
			t.Errorf("write browser artifact %s: %v", name, err)
		}
	}
	write("chrome-version.txt", version)
	write("chrome-executable.sha256", fmt.Appendf(nil, "%x  %s\n", digest, chrome))
	head := os.Getenv("MITMPROXY_TEST_WEB_HEAD")
	if raw, err := hex.DecodeString(head); err != nil || len(raw) != 20 {
		t.Fatal("MITMPROXY_TEST_WEB_HEAD must be the exact 40-digit source commit")
	}
	write("server-head.txt", []byte(head+"\n"))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	hash.Reset()
	_, readErr = io.Copy(hash, binary)
	if err := errors.Join(readErr, binary.Close()); err != nil {
		t.Fatal(err)
	}
	write("test-binary.sha256", fmt.Appendf(nil, "%x  %s\n", hash.Sum(nil), executable))

	tests := map[string]struct{ path, editedPath, header string }{
		"edit and replay": {"/browser-original", "/browser-edited", "changed-through-ui"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			type originRequest struct{ Path, Header string }
			requests := make(chan originRequest, 8)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case requests <- originRequest{r.URL.Path, r.Header.Get("X-Acceptance")}:
				default:
					t.Error("origin request evidence overflow")
				}
				_, _ = io.WriteString(w, "browser acceptance response")
			}))
			defer origin.Close()
			tuple := newWebInputTuple(t, "")
			opts := options.New()
			if err := opts.Update(t.Context(), map[string]any{"confdir": tuple.confdir}); err != nil {
				t.Fatal(err)
			}
			log, err := os.OpenFile(filepath.Join(output, "backend.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := log.Close(); err != nil {
					t.Errorf("close backend log: %v", err)
				}
			})
			backend, err := web.New(t.Context(), web.Config{Options: opts, Stdin: io.NopCloser(strings.NewReader("")), Stdout: log, Stderr: log, WithTermlog: false})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var runErr error
			runStarted := false
			t.Cleanup(func() {
				backend.Shutdown()
				ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 15*time.Second)
				defer cancel()
				if err := backend.Close(ctx); err != nil {
					t.Errorf("join browser WebMaster: %v", err)
				}
				if runStarted {
					select {
					case <-done:
						if runErr != nil && !errors.Is(runErr, context.Canceled) {
							t.Errorf("browser WebMaster Run: %v", runErr)
						}
					case <-ctx.Done():
						t.Errorf("WebMaster Run did not join: %v", ctx.Err())
					}
				}
				if address, ok := backend.WebAddr().(*net.TCPAddr); ok && address != nil {
					tuple.webPort = address.Port
					verifyWebPortsReleased(t, tuple)
				}
			})
			if err := backend.Do(t.Context(), func(ctx context.Context) error {
				return opts.Update(ctx, map[string]any{
					"web_host": "127.0.0.1", "web_port": 0, "web_open_browser": false,
					"web_password": webTestPassword, "mode": []string{"regular@127.0.0.1:18080"},
				})
			}); err != nil {
				t.Fatal(err)
			}
			runStarted = true
			go func() {
				runErr = backend.Run(t.Context())
				close(done)
			}()
			readyContext, cancelReady := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancelReady()
			select {
			case <-backend.Ready():
			case <-done:
				t.Fatalf("WebMaster exited before binding: %v", runErr)
			case <-readyContext.Done():
				t.Fatalf("WebMaster never bound: %v", readyContext.Err())
			}
			address, ok := backend.WebAddr().(*net.TCPAddr)
			if !ok || address == nil || address.Port == 0 || !address.IP.Equal(net.IPv4(127, 0, 0, 1)) {
				t.Fatalf("unexpected WebMaster address: %v", backend.WebAddr())
			}
			tuple.webPort = address.Port
			if opts.Int("web_port") != tuple.webPort {
				t.Fatalf("bound port %d was not published before Ready", tuple.webPort)
			}
			client := webClient(t)
			readyTimer := time.NewTicker(50 * time.Millisecond)
			defer readyTimer.Stop()
			for {
				status, _, raw, err := requestWeb(readyContext, client, tuple, http.MethodGet, "/state", nil)
				if err == nil && status == http.StatusOK && expectedWebListener(raw) {
					break
				}
				select {
				case <-done:
					t.Fatalf("WebMaster exited before proxy readiness: %v", runErr)
				case <-readyContext.Done():
					t.Fatalf("proxy listener not ready: status=%d request_error=%v context=%v", status, err, readyContext.Err())
				case <-readyTimer.C:
				}
			}
			recordBrowserAssets(t, tuple, write)

			allocatorOptions := append(slices.Clone(chromedp.DefaultExecAllocatorOptions[:]), chromedp.ExecPath(chrome), chromedp.UserDataDir(t.TempDir()), chromedp.Flag("no-sandbox", false), chromedp.WindowSize(1440, 1000))
			allocator, cancelAllocator := chromedp.NewExecAllocator(t.Context(), allocatorOptions...)
			defer cancelAllocator()
			browser, cancelBrowser := chromedp.NewContext(allocator)
			defer cancelBrowser()
			if err := chromedp.Do(browser, chromedp.Navigate("about:blank")); err != nil {
				t.Fatalf("sandbox-capable Chrome launch: %v", err)
			}
			sandboxContext, cancelSandbox := context.WithTimeout(browser, 30*time.Second)
			defer cancelSandbox()
			if err := chromedp.Do(sandboxContext, chromedp.Navigate("chrome://sandbox")); err != nil {
				t.Fatalf("navigate certifying browser sandbox status: %v", err)
			}
			sandboxStatus, err := chromedp.Run(sandboxContext, chromedp.Evaluate[string](`document.body.innerText`))
			if err != nil {
				t.Fatalf("read certifying browser sandbox status: %v", err)
			}
			write("sandbox-status.txt", []byte(sandboxStatus+"\n"))
			if !strings.Contains(sandboxStatus, "You are adequately sandboxed.") {
				t.Fatalf("certifying browser is not adequately sandboxed: %s", sandboxStatus)
			}
			eventsContext, cancelEvents := context.WithCancel(browser)
			var workers sync.WaitGroup
			var evidenceMu sync.Mutex
			var eventLog []string
			addEvent := func(line string) {
				evidenceMu.Lock()
				defer evidenceMu.Unlock()
				if len(eventLog) >= 4096 {
					t.Error("browser diagnostic event bound exceeded")
					cancelEvents()
					return
				}
				eventLog = append(eventLog, line)
			}
			console := chromedp.Events(eventsContext, runtime.ConsoleAPICalled)
			failures := chromedp.Events(eventsContext, network.LoadingFailed)
			connections := chromedp.Events(eventsContext, network.WebSocketHandshakeResponseReceived)
			frames := chromedp.Events(eventsContext, network.WebSocketFrameReceived)
			connected := make(chan int, 1)
			updates := make(chan string, 256)
			workers.Go(func() {
				for event, err := range connections {
					if err != nil {
						return
					}
					if event.Response != nil {
						select {
						case connected <- int(event.Response.Status):
						default:
							t.Error("unexpected additional WebSocket handshake")
						}
					}
				}
			})
			workers.Go(func() {
				for event, err := range console {
					if err != nil {
						return
					}
					addEvent(fmt.Sprintf("console: %+v", event))
				}
			})
			workers.Go(func() {
				for event, err := range failures {
					if err != nil {
						return
					}
					addEvent(fmt.Sprintf("failed-request: %+v", event))
				}
			})
			workers.Go(func() {
				for event, err := range frames {
					if err != nil {
						return
					}
					if event.Response == nil {
						continue
					}
					var message struct {
						Type string `json:"type"`
					}
					if json.Unmarshal(event.Response.PayloadData, &message) == nil {
						addEvent("websocket: " + message.Type)
						select {
						case updates <- message.Type:
						default:
							t.Error("WS evidence overflow")
						}
					}
				}
			})
			defer func() {
				shotContext, cancel := context.WithTimeout(context.WithoutCancel(browser), 10*time.Second)
				defer cancel()
				screenshot, err := chromedp.Run(shotContext, chromedp.FullScreenshot(100))
				if err != nil {
					t.Errorf("final/failure screenshot: %v", err)
				} else {
					write("final-or-failure.png", screenshot)
				}
				cancelEvents()
				workers.Wait()
				evidenceMu.Lock()
				defer evidenceMu.Unlock()
				raw, err := json.Marshal(eventLog)
				if err != nil {
					t.Error(err)
				} else {
					write("console-network-websocket.json", raw)
				}
			}()
			if err := chromedp.Do(browser, chromedp.Func(func(ctx context.Context, target *chromedp.Target) error {
				if _, err := cdp.Call(ctx, target, network.Enable, network.EnableParams{}); err != nil {
					return err
				}
				_, err := cdp.Call(ctx, target, runtime.Enable, cdp.Empty{})
				return err
			})); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(browser, 90*time.Second)
			defer cancel()
			webURL := backend.WebURL() + "?token=" + url.QueryEscape(webTestPassword)
			if err := chromedp.Do(ctx, chromedp.Navigate(webURL), chromedp.WaitVisible(chromedp.CSS("input[placeholder='Search']"))); err != nil {
				t.Fatal(err)
			}
			select {
			case status := <-connected:
				if status != http.StatusSwitchingProtocols {
					t.Fatalf("UI WebSocket handshake status=%d", status)
				}
			case <-ctx.Done():
				t.Fatal("UI WebSocket never connected")
			}
			proxyURL, err := url.Parse("http://127.0.0.1:18080")
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			proxyClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}
			deliveryContext, cancelDelivery := context.WithTimeout(ctx, 5*time.Second)
			defer cancelDelivery()
			request, err := http.NewRequestWithContext(deliveryContext, http.MethodGet, origin.URL+tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Acceptance", "original")
			response, err := proxyClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, response.Body); err != nil {
				t.Fatal(err)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case original := <-requests:
				if original.Path != tt.path || original.Header != "original" {
					t.Fatalf("original origin request=%+v", original)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			seenAdd := false
			for !seenAdd {
				select {
				case kind := <-updates:
					seenAdd = kind == "flows/add"
				case <-deliveryContext.Done():
					t.Fatal("hooked flow did not reach the browser WebSocket before five seconds")
				}
			}
			row := chromedp.Search(`//tr[contains(.,'browser-original')]`)
			if err := chromedp.Do(ctx, chromedp.WaitVisible(row), chromedp.Click(row), chromedp.WaitVisible(chromedp.CSS("section.request"))); err != nil {
				t.Fatal(err)
			}
			pathEditor := chromedp.CSS(".request-line .inline-input:nth-of-type(2)")
			if err := chromedp.Do(ctx, chromedp.Click(pathEditor), chromedp.WaitVisible(chromedp.CSS(".request-line [contenteditable='plaintext-only']"))); err != nil {
				t.Fatal(err)
			}
			if _, err := chromedp.Run(ctx, chromedp.Poll[bool](`document.activeElement === document.querySelector('.request-line .inline-input:nth-of-type(2)')`, chromedp.WithPollingTimeout(30*time.Second))); err != nil {
				t.Fatal(err)
			}
			if err := chromedp.Do(ctx, chromedp.KeyEvent("a", chromedp.KeyModifiers(chromedp.ModifierCtrl)), chromedp.KeyEvent(origin.URL+tt.editedPath+kb.Enter)); err != nil {
				t.Fatal(err)
			}
			header := chromedp.Search(`//section[contains(@class,'request')]//*[contains(@class,'kv-row')][.//*[contains(@class,'kv-key') and text()='X-Acceptance']]//*[contains(@class,'kv-value')]`)
			if err := chromedp.Do(ctx, chromedp.Click(header), chromedp.WaitVisible(chromedp.CSS(".headers [contenteditable='plaintext-only']"))); err != nil {
				t.Fatal(err)
			}
			if _, err := chromedp.Run(ctx, chromedp.Poll[bool](`document.activeElement.matches('section.request .headers [contenteditable="plaintext-only"]')`, chromedp.WithPollingTimeout(30*time.Second))); err != nil {
				t.Fatal(err)
			}
			if err := chromedp.Do(ctx, chromedp.KeyEvent("a", chromedp.KeyModifiers(chromedp.ModifierCtrl)), chromedp.KeyEvent(tt.header+kb.Enter)); err != nil {
				t.Fatal(err)
			}
			if _, err := chromedp.Run(ctx, chromedp.Poll[bool](`document.querySelector('.request-line').textContent.includes('browser-edited') && [...document.querySelectorAll('.headers .kv-value')].some(n=>n.textContent==='changed-through-ui')`, chromedp.WithPollingMutation(), chromedp.WithPollingTimeout(30*time.Second))); err != nil {
				t.Fatal(err)
			}
			if err := chromedp.Do(ctx, chromedp.Click(chromedp.CSS("[title='[r]eplay flow']"))); err != nil {
				t.Fatal(err)
			}
			select {
			case replay := <-requests:
				if replay.Path != tt.editedPath || replay.Header != tt.header {
					t.Fatalf("UI replay origin request=%+v, want path=%s header=%s", replay, tt.editedPath, tt.header)
				}
				raw, err := json.Marshal(replay)
				if err != nil {
					t.Fatal(err)
				}
				write("edited-origin-request.json", raw)
			case <-ctx.Done():
				t.Fatal("UI replay never reached the real origin")
			}
			seenUpdate := false
			for !seenUpdate {
				select {
				case event := <-updates:
					seenAdd = seenAdd || event == "flows/add"
					seenUpdate = seenUpdate || event == "flows/update"
				case <-ctx.Done():
					t.Fatalf("UI WS evidence missing: add=%v update=%v", seenAdd, seenUpdate)
				}
			}
			if _, err := chromedp.Run(ctx, chromedp.Poll[bool](`document.querySelector('.flow-detail').textContent.includes('browser-edited')`, chromedp.WithPollingMutation(), chromedp.WithPollingTimeout(30*time.Second))); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func recordBrowserAssets(t *testing.T, tuple webInputTuple, write func(string, []byte)) {
	t.Helper()
	client := webClient(t)
	entries, err := os.ReadDir(testutil.FixturePath(t, "mitmproxy/tools/web/static"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 10 {
		t.Fatalf("frontend static count=%d, want 10", len(entries))
	}
	files := map[string]string{"/": "mitmproxy/tools/web/index.html"}
	for _, entry := range entries {
		files["/static/"+entry.Name()] = "mitmproxy/tools/web/static/" + entry.Name()
	}
	var hashes []string
	for route, fixture := range files {
		status, _, raw, err := requestWeb(t.Context(), client, tuple, http.MethodGet, route, nil)
		if err != nil || status != http.StatusOK {
			t.Fatalf("asset %s status=%d err=%v", route, status, err)
		}
		got, want := sha256.Sum256(raw), sha256.Sum256(testutil.Fixture(t, fixture))
		if got != want {
			t.Fatalf("served asset %s SHA256=%x, want %x", route, got, want)
		}
		hashes = append(hashes, fmt.Sprintf("%x  %s", got, route))
	}
	slices.Sort(hashes)
	raw, err := json.Marshal(hashes)
	if err != nil {
		t.Fatal(err)
	}
	write("served-ui-assets.json", raw)
	write("server-input.json", fmt.Appendf(nil, "{\"web_port\":%s,\"proxy_port\":18080}\n", strconv.Itoa(tuple.webPort)))
}
