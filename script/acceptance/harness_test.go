// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package acceptance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

var (
	dumpBinary    string
	repoRoot      string
	listenPattern = regexp.MustCompile(`listening at (127\.0\.0\.1:[0-9]+)`)
)

// TestMain builds the production command, without test-only addon imports.
func TestMain(m *testing.M) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate acceptance sources")
	}
	repoRoot = filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
	dir, err := os.MkdirTemp("", "script-acceptance-")
	if err != nil {
		panic(err)
	}
	dumpBinary = filepath.Join(dir, "mitmdump")
	if runtime.GOOS == "windows" {
		dumpBinary += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	cmd := exec.CommandContext(ctx, "go", "build", "-race", "-o", dumpBinary, "./cmd/mitmdump")
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	cancel()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "build race-enabled mitmdump: %v\n%s", err, output)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	binary, err := os.ReadFile(dumpBinary)
	if err != nil {
		panic(err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "race-enabled mitmdump sha256=%x toolchain=%s host=%s/%s\n", sha256.Sum256(binary), runtime.Version(), runtime.GOOS, runtime.GOARCH)
	code := m.Run()
	if err := os.RemoveAll(dir); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

type observedLog struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	changed chan struct{}
	events  []logObservation
}

type logObservation struct {
	end int
	at  time.Time
}

func newLog() *observedLog { return &observedLog{changed: make(chan struct{})} }

func (l *observedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.buf.Write(p)
	l.events = append(l.events, logObservation{l.buf.Len(), time.Now()})
	close(l.changed)
	l.changed = make(chan struct{})
	return n, err
}

func (l *observedLog) snapshot() (string, <-chan struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String(), l.changed
}

func (l *observedLog) text() string {
	text, _ := l.snapshot()
	return text
}

func (l *observedLog) await(t *testing.T, predicate func(string) bool) string {
	t.Helper()
	watchdog := time.NewTimer(15 * time.Second)
	defer watchdog.Stop()
	for {
		text, changed := l.snapshot()
		if predicate(text) {
			return text
		}
		select {
		case <-changed:
		case <-watchdog.C:
			t.Fatalf("missing log acknowledgement:\n%s", text)
		case <-t.Context().Done():
			t.Fatalf("test canceled awaiting log acknowledgement:\n%s", text)
		}
	}
}

func (l *observedLog) contains(t *testing.T, text string) {
	t.Helper()
	l.await(t, func(output string) bool { return strings.Contains(output, text) })
}

func (l *observedLog) observed(t *testing.T, marker string) time.Time {
	t.Helper()
	l.contains(t, marker)
	l.mu.Lock()
	defer l.mu.Unlock()
	end := strings.Index(l.buf.String(), marker) + len(marker)
	for _, event := range l.events {
		if event.end >= end {
			return event.at
		}
	}
	t.Fatalf("no monotonic observation for %q", marker)
	return time.Time{}
}

type process struct {
	cmd            *exec.Cmd
	logs           *observedLog
	done           chan struct{}
	err            error
	wantExit       int
	wantHookErrors int
	addr           string
	route          *loopbackRoute
}

// loopbackRoute maps every flow destination onto one owned origin. It never
// resolves or dials the requested hostname, including on an assertion failure.
type loopbackRoute struct {
	mu       sync.Mutex
	wantHost string
	seen     []string
}

func (r *loopbackRoute) expect(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.wantHost = host
}

func (r *loopbackRoute) destinations() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.seen)
}

func guardedUpstream(t *testing.T, target string) (string, *loopbackRoute) {
	t.Helper()
	return guardedUpstreamWithReport(t, target, func(err error) { t.Error(err) })
}

func guardedUpstreamWithReport(t *testing.T, target string, report func(error)) (string, *loopbackRoute) {
	t.Helper()
	if target == "" {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("metadata-only process attempted an upstream request to %s", r.Host)
			http.Error(w, "unexpected upstream request", http.StatusBadGateway)
		}))
		t.Cleanup(origin.Close)
		target = origin.URL
	}
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.IsLoopback() || u.Port() == "" {
		t.Fatalf("upstream target must be an owned literal loopback listener: %q", target)
	}
	route := &loopbackRoute{wantHost: u.Host}
	var workers sync.WaitGroup
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requested := req.URL.Host
		if !strings.Contains(requested, ":") {
			requested += ":80"
		}
		route.mu.Lock()
		route.seen = append(route.seen, requested)
		want := route.wantHost
		route.mu.Unlock()
		if req.Host != want {
			report(fmt.Errorf("upstream requested host %q, want %q (mapped to %s)", req.Host, want, u.Host))
			http.Error(w, "unexpected upstream host", http.StatusBadGateway)
			return
		}
		// This is the only dial in the forwarder; the flow cannot supply it.
		conn, err := (&net.Dialer{}).DialContext(req.Context(), "tcp", u.Host)
		if err != nil {
			t.Errorf("dial owned loopback origin: %v", err)
			http.Error(w, "owned origin unavailable", http.StatusBadGateway)
			return
		}
		if err := req.Write(conn); err != nil {
			_ = conn.Close()
			t.Errorf("forward request to owned origin: %v", err)
			http.Error(w, "forwarding failed", http.StatusBadGateway)
			return
		}
		// Hijack removes the connection from httptest's shutdown accounting.
		// Register our join before that ownership transfer.
		workers.Add(1)
		defer workers.Done()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = conn.Close()
			t.Error(err)
			return
		}
		defer func() { _ = client.Close(); _ = conn.Close() }()
		var copies sync.WaitGroup
		copies.Go(func() { _, _ = io.Copy(conn, buffered); _ = conn.Close(); _ = client.Close() })
		_, _ = io.Copy(client, conn)
		_ = client.Close()
		_ = conn.Close()
		copies.Wait()
	}))
	t.Cleanup(func() {
		upstream.Close()
		workers.Wait()
		t.Logf("owned upstream target=%s requested destinations=%v; all forwarders joined", u.Host, route.destinations())
	})
	return upstream.URL, route
}

func startProcess(t *testing.T, target string, args ...string) *process {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 45*time.Second)
	upstream, route := guardedUpstream(t, target)
	if !slices.Contains(args, "--mode") {
		args = append([]string{"--mode", "upstream:" + upstream}, args...)
	}
	args = append([]string{"--set", "confdir=" + t.TempDir(), "--set", "termlog_verbosity=debug", "--set", "connection_strategy=lazy", "--listen-host", "127.0.0.1", "-p", "0"}, args...)
	cmd := exec.CommandContext(ctx, dumpBinary, args...)
	// Only the race runtime's exit delay is removed; reports still fail the child.
	cmd.Env = append(os.Environ(), "GORACE=atexit_sleep_ms=0")
	p := &process{cmd: cmd, logs: newLog(), done: make(chan struct{}), route: route}
	cmd.Stdout, cmd.Stderr = p.logs, p.logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		defer cancel()
		select {
		case <-p.done:
		default:
			if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
				t.Errorf("interrupt mitmdump: %v", err)
			}
			watchdog := time.NewTimer(10 * time.Second)
			defer watchdog.Stop()
			select {
			case <-p.done:
			case <-watchdog.C:
				cancel()
				<-p.done
				t.Error("mitmdump did not join after shutdown")
			}
		}
		if p.cmd.ProcessState.ExitCode() != p.wantExit {
			t.Errorf("mitmdump exit: %v\n%s", p.err, p.logs.text())
		}
		if got := strings.Count(p.logs.text(), "Addon error:"); got != p.wantHookErrors {
			t.Errorf("joined child logged %d hook errors, want %d", got, p.wantHookErrors)
		}
		if strings.Contains(p.logs.text(), "script instance is retired") {
			t.Error("normal teardown dispatched a retired script instance")
		}
		t.Logf("joined mitmdump pid=%d\n%s", p.cmd.Process.Pid, p.logs.text())
	})
	return p
}

func startProxy(t *testing.T, target string, scripts []string, args ...string) *process {
	t.Helper()
	for _, path := range scripts {
		args = append(args, "-s", path)
	}
	p := startProcess(t, target, args...)
	text := p.logs.await(t, func(output string) bool { return listenPattern.MatchString(output) })
	p.addr = listenPattern.FindStringSubmatch(text)[1]
	return p
}

func (p *process) wait(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		if p.cmd.ProcessState.ExitCode() != p.wantExit {
			t.Fatalf("mitmdump exit: %v\n%s", p.err, p.logs.text())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("mitmdump did not exit:\n%s", p.logs.text())
	}
}

func scriptFile(t *testing.T, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "addon.star")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func examplePath(name string) string {
	return filepath.Join(repoRoot, "examples", "addons", name+".star")
}

func proxyClient(t *testing.T, p *process) *http.Client {
	t.Helper()
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: p.addr}), DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}
}

type response struct {
	status   int
	headers  http.Header
	trailers http.Header
	body     string
}

func send(t *testing.T, client *http.Client, method, target, body string, headers http.Header) response {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header = headers.Clone()
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{res.StatusCode, res.Header.Clone(), res.Trailer.Clone(), string(data)}
}

type originRequest struct {
	method, path, host, body string
	headers, trailers        http.Header
}

func ownedOrigin(t *testing.T, body string) (*httptest.Server, <-chan originRequest) {
	t.Helper()
	seen := make(chan originRequest, 32)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read owned origin request: %v", err)
			return
		}
		select {
		case seen <- originRequest{r.Method, r.RequestURI, r.Host, string(data), r.Header.Clone(), r.Trailer.Clone()}:
		default:
			t.Error("unexpected excess origin requests")
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(origin.Close)
	return origin, seen
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(15 * time.Second):
		t.Fatal("missing owned peer acknowledgement")
	case <-t.Context().Done():
		t.Fatal("test canceled awaiting owned peer")
	}
	var zero T
	return zero
}

func equal[T any](t *testing.T, want, got T) {
	t.Helper()
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Fatalf("(-want +got):\n%s", diff)
	}
}

func deadline(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
}
