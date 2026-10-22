// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package acceptance_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

type requestResult struct {
	response response
	err      error
	at       time.Time
}

func requestAsync(t *testing.T, client *http.Client, target string, barrier <-chan struct{}) <-chan requestResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 15*time.Second)
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	result := make(chan requestResult, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		if barrier != nil {
			select {
			case <-barrier:
			case <-ctx.Done():
				result <- requestResult{err: ctx.Err()}
				return
			}
		}
		res, err := client.Do(req)
		got := requestResult{err: err}
		if err == nil {
			body, readErr := io.ReadAll(res.Body)
			closeErr := res.Body.Close()
			got.err = readErr
			if got.err == nil {
				got.err = closeErr
			}
			got.response = response{res.StatusCode, res.Header.Clone(), res.Trailer.Clone(), string(body)}
		}
		got.at = time.Now()
		result <- got
	}()
	t.Cleanup(func() { cancel(); <-joined })
	return result
}

func completed(t *testing.T, result <-chan requestResult) requestResult {
	t.Helper()
	got := receive(t, result)
	if got.err != nil {
		t.Fatal(got.err)
	}
	return got
}

func otherFlow(t *testing.T, worker, timed bool) {
	origin, seen := ownedOrigin(t, "forwarded")
	source := `def _request(f):
    if f.request.path == "/slow":
        ctx.log("slow-entered")
        ctx.sleep(1)
        f.request.headers["x-concurrent"] = "1"
        ctx.log("slow-finished")
def requestheaders(f):
    if f.request.path == "/fast":
        f.request.headers["x-ordinary"] = "1"
`
	if worker {
		source += "request = concurrent(_request)\n"
	} else {
		source += "request = _request\n"
	}
	p := startProxy(t, origin.URL, []string{scriptFile(t, source)})
	client := proxyClient(t, p)
	slow := requestAsync(t, client, origin.URL+"/slow", nil)
	p.logs.contains(t, "slow-entered")
	start := time.Now()
	fast := completed(t, requestAsync(t, client, origin.URL+"/fast", nil))
	elapsed := fast.at.Sub(start)
	if timed && elapsed > 200*time.Millisecond {
		t.Fatalf("second flow took %s, limit 200ms", elapsed)
	}
	select {
	case result := <-slow:
		t.Fatalf("slow flow already completed while second ran: %+v", result)
	default:
	}
	if strings.Contains(p.logs.text(), "slow-finished") {
		t.Fatal("second flow completed only after the sleeping handler")
	}
	r := receive(t, seen)
	equal(t, "/fast", r.path)
	equal(t, "1", r.headers.Get("X-Ordinary"))
	completed(t, slow)
	r = receive(t, seen)
	equal(t, "/slow", r.path)
	equal(t, "1", r.headers.Get("X-Concurrent"))
	t.Logf("sleep=1s worker=%v second-flow completion after entry acknowledgement=%s", worker, elapsed)
}

func fiveParallel(t *testing.T, timed bool) {
	origin, seen := ownedOrigin(t, "five")
	var path string
	var entered <-chan struct{}
	var release func()
	if timed {
		path = scriptFile(t, "def _request(f):\n    ctx.log('parallel-entry')\n    ctx.sleep(1)\n    ctx.log('parallel-complete')\nrequest = concurrent(_request)\n")
	} else {
		url, entries, unblock := barrierOrigin(t)
		entered, release = entries, unblock
		path = scriptFile(t, fmt.Sprintf("def _request(f):\n    ctx.http_get(%q)\n    f.request.headers['x-parallel'] = 'merged'\nrequest = concurrent(_request)\n", url))
	}
	p := startProxy(t, origin.URL, []string{path})
	client := proxyClient(t, p)
	barrier := make(chan struct{})
	results := make([]<-chan requestResult, 5)
	for i := range 5 {
		results[i] = requestAsync(t, client, fmt.Sprintf("%s/%d", origin.URL, i), barrier)
	}
	start := time.Now()
	close(barrier)
	if !timed {
		for range 5 {
			receive(t, entered)
		}
		for _, result := range results {
			select {
			case <-result:
				t.Fatal("handler completed before common release")
			default:
			}
		}
		release()
	} else {
		p.logs.await(t, func(text string) bool { return strings.Count(text, "parallel-entry") == 5 })
		if strings.Contains(p.logs.text(), "parallel-complete") {
			t.Fatal("not all five handlers entered together")
		}
	}
	for _, result := range results {
		got := completed(t, result)
		elapsed := got.at.Sub(start)
		if timed && (elapsed < time.Second || elapsed > 2*time.Second) {
			t.Fatalf("five-flow completion %s outside actual 1s wait / 2s bound", elapsed)
		}
		r := receive(t, seen)
		if !timed {
			equal(t, "merged", r.headers.Get("X-Parallel"))
		}
		t.Logf("one of five complete at %s from shared release", elapsed)
	}
}

func reloadInflight(t *testing.T, timed bool) {
	a := assembledDump(t)
	a.load(t, "def _request(f):\n    ctx.log('old-worker-entered')\n    ctx.sleep(1)\n    f.request.headers['x-retired-worker'] = 'merged'\n    ctx.log('old-worker-finished')\nrequest = concurrent(_request)\n")
	f := testflow.TFlow()
	done := asyncHook(t, a, addon.RequestHook{Flow: f})
	a.logs.contains(t, "old-worker-entered")
	start := time.Now()
	a.load(t, "def request(f):\n    f.request.headers['x-new-instance'] = 'loaded'\n")
	elapsed := time.Since(start)
	if timed && elapsed > 200*time.Millisecond {
		t.Fatalf("reload took %s, limit 200ms", elapsed)
	}
	if strings.Contains(a.logs.text(), "old-worker-finished") {
		t.Fatal("reload waited for the retired worker")
	}
	if err := receive(t, done); err != nil {
		t.Fatal(err)
	}
	a.logs.contains(t, "old-worker-finished")
	equal(t, "merged", f.Request.Headers.Get("X-Retired-Worker"))
	next := testflow.TFlow()
	a.hook(t, addon.RequestHook{Flow: next})
	equal(t, "loaded", next.Request.Headers.Get("X-New-Instance"))
	t.Logf("reload returned in %s before retired worker completed its actual 1s sleep", elapsed)
}

func nonblockingParallel(t *testing.T, timed bool) {
	origin, seen := ownedOrigin(t, "nonblocking")
	p := startProxy(t, origin.URL, []string{examplePath("nonblocking")})
	client := proxyClient(t, p)
	barrier := make(chan struct{})
	one := requestAsync(t, client, origin.URL+"/one", barrier)
	two := requestAsync(t, client, origin.URL+"/two", barrier)
	start := time.Now()
	close(barrier)
	p.logs.await(t, func(text string) bool { return strings.Count(text, "handle request:") == 2 })
	if strings.Contains(p.logs.text(), "start  request:") {
		t.Fatal("a start preceded both handle acknowledgements")
	}
	for _, result := range []<-chan requestResult{one, two} {
		got := completed(t, result)
		elapsed := got.at.Sub(start)
		if timed && elapsed > 6*time.Second {
			t.Fatalf("nonblocking pair completion %s exceeds 6s", elapsed)
		}
		receive(t, seen)
		t.Logf("nonblocking response complete at %s from pair release", elapsed)
	}
	equal(t, 2, strings.Count(p.logs.text(), "start  request:"))
	if timed {
		for _, path := range []string{"/one", "/two"} {
			host := strings.TrimPrefix(origin.URL, "http://")
			host, _, _ = strings.Cut(host, ":")
			begin := p.logs.observed(t, "handle request: "+host+path)
			end := p.logs.observed(t, "start  request: "+host+path)
			elapsed := end.Sub(begin)
			if elapsed < 5*time.Second || elapsed > 6*time.Second {
				t.Fatalf("nonblocking %s start-after-handle=%s, want [5s,6s]", path, elapsed)
			}
			t.Logf("nonblocking %s start-after-own-handle=%s", path, elapsed)
		}
	}
}

func mtimeReload(t *testing.T, timed bool) {
	origin, seen := ownedOrigin(t, "mtime")
	path := scriptFile(t, "def request(f):\n    f.request.headers['x-generation'] = 'old'\n")
	p := startProxy(t, origin.URL, []string{path})
	client := proxyClient(t, p)
	send(t, client, "GET", origin.URL, "", nil)
	equal(t, "old", receive(t, seen).headers.Get("X-Generation"))
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("def running():\n    ctx.log('new-generation-ready')\ndef request(f):\n    f.request.headers['x-generation'] = 'new'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := stat.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	p.logs.contains(t, "new-generation-ready")
	send(t, client, "GET", origin.URL, "", nil)
	equal(t, "new", receive(t, seen).headers.Get("X-Generation"))
	elapsed := time.Since(start)
	if timed && elapsed > 2*time.Second {
		t.Fatalf("new effect after completed edit took %s, limit 2s", elapsed)
	}
	t.Logf("explicit newer-mtime edit to acknowledged new effect=%s", elapsed)
}
