// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addon/hookdata"
	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/addons/proxyserver"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"

	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/modes"
	_ "github.com/zchee/mitmproxy-go/internal/proxy/layers/tcplayer"
)

func testFieldMerge(t *testing.T) {
	f := newFixture(t)
	entered, release := concurrentBarrier(t, f)
	f.load(loadConcurrent(f, "f.request.headers['x-worker'] = 'header'\nf.request.method = 'POST'\nf.request.stream = True\nf.response.reason = 'Worker'\nf.error.msg = 'worker-error'\nf.metadata['worker'] = 'owned'\nf.marked = 'worker'\nf.is_replay = 'request'\nctx.sleep(1)"))
	x := f.request()
	x.Response, _ = httpmsg.MakeResponse(200, []byte("old"), nil)
	x.Error = flow.NewError("old")
	x.Request.StreamFunc = func(b []byte) [][]byte { return [][]byte{b} }
	done := startConcurrent(t, f, t.Context(), addon.RequestHook{Flow: x})
	awaitConcurrent(t, entered)
	if err := f.master.Do(t.Context(), func(context.Context) error {
		x.Comment = "untouched"
		x.Request.Path = "/live"
		x.Request.SetHost("live.test")
		x.Request.SetContent([]byte("live-body"))
		x.Request.Trailers = httpmsg.Headers{{Name: []byte("x-trailer"), Value: []byte("live")}}
		x.Request.Method = "PATCH"
		x.Response.StatusCode = 201
		x.Response.SetContent([]byte("live-response"))
		x.Error.Timestamp = 42
		x.Metadata.Set("live", "retained")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	release()
	if err := awaitConcurrent(t, done); err != nil {
		t.Fatal(err)
	}
	if x.Request.Host != "live.test" || x.Request.Path != "/live" || x.Request.Method != "POST" || string(x.Request.RawContent) != "live-body" || !x.Request.Stream || x.Request.StreamFunc == nil || x.Request.Trailers.Get("x-trailer") != "live" {
		t.Fatalf("request semantic merge lost unrelated fields: %v; %s", x.Request, f.logs.String())
	}
	if x.Response.StatusCode != 201 || x.Response.Reason != "Worker" || string(x.Response.RawContent) != "live-response" || x.Comment != "untouched" || x.Marked != "worker" || x.IsReplay == nil || *x.IsReplay != "request" || x.Error.Msg != "worker-error" || x.Error.Timestamp != 42 {
		t.Fatalf("flow/response/error semantic merge failed: %s", f.logs.String())
	}
	if value, _ := x.Metadata.Get("live"); value != "retained" {
		t.Fatal("untouched metadata key lost")
	}
	if value, _ := x.Metadata.Get("worker"); value != "owned" {
		t.Fatal("worker metadata key missing")
	}
	// DNS fields use their own native state decoder rather than HTTP coercion.
	d := newFixture(t)
	dnsEntered, dnsRelease := concurrentBarrier(t, d)
	d.load(d.file("dns-fields.star", "def _dns(f):\n    f.request.question.name = 'worker.test'\n    f.response.answers[0].ttl = 123\n    ctx.sleep(1)\ndns_request = concurrent(_dns)\n"))
	h := d.request()
	df := flow.NewDNSFlow(h.ClientConn, h.ServerConn, true)
	df.Request = &dns.Message{Query: true, Questions: []dns.Question{{Name: "old.test", Type: dns.TypeA, Class: dns.ClassIN}}}
	df.Response = df.Request.Succeed([]dns.ResourceRecord{dns.TXT("old.test", "old", 60)})
	dnsDone := startConcurrent(t, d, t.Context(), addon.DNSRequestHook{Flow: df})
	awaitConcurrent(t, dnsEntered)
	if err := d.master.Do(t.Context(), func(context.Context) error {
		df.Request.ID = 7
		df.Response.ResponseCode = dns.ResponseCodeNXDOMAIN
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	dnsRelease()
	if err := awaitConcurrent(t, dnsDone); err != nil {
		t.Fatal(err)
	}
	if df.Request.ID != 7 || df.Request.Questions[0].Name != "worker.test" || df.Response.ResponseCode != dns.ResponseCodeNXDOMAIN || df.Response.Answers[0].TTL != 123 {
		t.Fatalf("DNS semantic merge: %s", d.logs.String())
	}
}

func testMessageMerge(t *testing.T, kind string) {
	f := newFixture(t)
	entered, release := concurrentBarrier(t, f)
	h := f.request()
	var model flow.Flow = h
	prefix := "f.messages"
	name := "tcp_message"
	var contents func() []string
	switch kind {
	case "tcp":
		x := flow.NewTCPFlow(h.ClientConn, h.ServerConn, true)
		x.Messages = []*tcp.Message{tcp.NewMessage(true, []byte("zero")), tcp.NewMessage(false, []byte("one"))}
		model = x
		contents = func() []string {
			out := make([]string, len(x.Messages))
			for n, m := range x.Messages {
				out[n] = string(m.Content)
			}
			return out
		}
	case "udp":
		x := flow.NewUDPFlow(h.ClientConn, h.ServerConn, true)
		x.Messages = []*udp.Message{udp.NewMessage(true, []byte("zero")), udp.NewMessage(false, []byte("one"))}
		model = x
		name = "udp_message"
		contents = func() []string {
			out := make([]string, len(x.Messages))
			for n, m := range x.Messages {
				out[n] = string(m.Content)
			}
			return out
		}
	case "websocket":
		h.WebSocket = &websocket.Data{Messages: []*websocket.Message{websocket.NewMessage(websocket.OpText, true, []byte("zero")), websocket.NewMessage(websocket.OpText, false, []byte("one"))}}
		prefix = "f.websocket.messages"
		name = "websocket_message"
		contents = func() []string {
			out := make([]string, len(h.WebSocket.Messages))
			for n, m := range h.WebSocket.Messages {
				out[n] = string(m.Content)
			}
			return out
		}
	}
	body := fmt.Sprintf("%s[0].content = b'worker-zero'\n%s.append(%s[0].copy())\nf.backup()\nctx.sleep(1)\n%s[-1].content = b'worker-added-edited'\n%s.append(%s[0].copy())", prefix, prefix, prefix, prefix, prefix, prefix)
	f.load(f.file("messages.star", "def _message(f):\n"+indentStarlark(body)+"\n"+name+" = concurrent(_message)\n"))
	done := startConcurrent(t, f, t.Context(), concurrentTestHook(name, model))
	awaitConcurrent(t, entered)
	if err := f.master.Do(t.Context(), func(context.Context) error {
		switch x := model.(type) {
		case *flow.TCPFlow:
			x.Messages[0].FromClient = false
			x.Messages[1].Content = []byte("live-one")
			x.Messages = append(x.Messages, tcp.NewMessage(false, []byte("live-suffix")))
		case *flow.UDPFlow:
			x.Messages[0].FromClient = false
			x.Messages[1].Content = []byte("live-one")
			x.Messages = append(x.Messages, udp.NewMessage(false, []byte("live-suffix")))
		case *flow.HTTPFlow:
			x.WebSocket.Messages[0].FromClient = false
			x.WebSocket.Messages[1].Content = []byte("live-one")
			x.WebSocket.Messages = append(x.WebSocket.Messages, websocket.NewMessage(websocket.OpText, false, []byte("live-suffix")))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	release()
	if err := awaitConcurrent(t, done); err != nil {
		t.Fatal(err)
	}
	want := []string{"worker-zero", "live-one", "live-suffix", "worker-added-edited", "worker-zero"}
	if diff := gocmp.Diff(want, contents()); diff != "" {
		t.Fatal(diff)
	}
	var direction bool
	switch x := model.(type) {
	case *flow.TCPFlow:
		direction = x.Messages[0].FromClient
	case *flow.UDPFlow:
		direction = x.Messages[0].FromClient
	case *flow.HTTPFlow:
		direction = x.WebSocket.Messages[0].FromClient
	}
	if direction {
		t.Fatal("unchanged message direction overwrote live edit")
	}
	f.wantLog("Addon error:", 0)
}

func testBackupOrder(t *testing.T) {
	for _, editBefore := range []bool{false, true} {
		f := newFixture(t)
		entered, release := concurrentBarrier(t, f)
		body := "ctx.sleep(1)\nf.backup()\nf.comment = 'worker-edit'\nf.revert()"
		if editBefore {
			body = "f.comment = 'worker-before'\nctx.sleep(1)\nf.backup()\nf.comment = 'worker-after'"
		}
		f.load(loadConcurrent(f, body))
		x := f.request()
		id := x.ID
		done := startConcurrent(t, f, t.Context(), addon.RequestHook{Flow: x})
		awaitConcurrent(t, entered)
		if err := f.master.Do(t.Context(), func(context.Context) error { x.Comment = "live-edit"; x.Request.Path = "/live"; return nil }); err != nil {
			t.Fatal(err)
		}
		release()
		if err := awaitConcurrent(t, done); err != nil {
			t.Fatal(err)
		}
		if x.ID != id || x.Request.Path != "/live" {
			t.Fatal("backup/revert lost live identity or whole state")
		}
		if editBefore {
			if x.Comment != "worker-after" || !x.Modified() {
				t.Fatalf("edit-backup-edit order failed: %s", f.logs.String())
			}
			if err := x.Revert(); err != nil {
				t.Fatal(err)
			}
			if x.Comment != "worker-before" || x.ID != id || x.Modified() {
				t.Fatal("backup captured copy ID or wrong checkpoint")
			}
		} else if x.Comment != "live-edit" || x.Modified() {
			t.Fatalf("backup-edit-revert did not clear backup: %s", f.logs.String())
		}
		f.wantLog("Addon error:", 0)
	}
}

type resumeObservedContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *resumeObservedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

type killedSnapshot struct {
	live, intercepted bool
	message           string
}
type killObserver struct{ snapshots chan killedSnapshot }

func (*killObserver) Name() string { return "script-kill-observer" }
func (o *killObserver) Update(_ context.Context, flows []flow.Flow) error {
	for _, f := range flows {
		if _, ok := f.(*flow.TCPFlow); ok && f.Common().Error != nil && f.Common().Error.Msg == flow.KilledMessage {
			select {
			case o.snapshots <- killedSnapshot{f.Common().Live, f.Common().Intercepted(), f.Common().Error.Msg}:
			default:
			}
		}
	}
	return nil
}

func testKillActions(t *testing.T, ordering bool) {
	cases := []struct {
		body   string
		backup bool
	}{
		{"f.intercept()\nf.kill()", false},
		{"f.kill()", true},
	}
	if ordering {
		cases = []struct {
			body   string
			backup bool
		}{
			{"f.intercept()\nf.backup()\nf.kill()\nf.revert()", false},
			{"f.kill()\nf.revert()", true},
			{"f.kill()\nf.intercept()\nf.backup()\nf.resume()", false},
		}
	}
	for _, test := range cases {
		testKilledTransport(t, test.body, test.backup, false)
	}
}

func testKillPrecedence(t *testing.T) {
	testKilledTransport(t, "f.revert()\nf.intercept()", true, true)
	testKilledTransport(t, "f.kill()\nf.revert()", true, true)
	// A naturally non-live flow is not a protected killed outcome and must not
	// receive the killed-only Resume normalization.
	f := newFixture(t)
	f.load(loadConcurrent(f, "f.intercept()"))
	x := f.request()
	x.Live = false
	f.hook(addon.RequestHook{Flow: x})
	if !x.Intercepted() || x.Error != nil {
		t.Fatal("non-live flow treated as killed")
	}
	x.Resume()
}

func testKilledTransport(t *testing.T, actions string, backup, liveKill bool) {
	t.Helper()
	f := newFixture(t)
	entered, release := concurrentBarrier(t, f)
	connections := new(proxy.Connections)
	cfg := proxy.Config{Manager: f.master.Addons, Options: f.master.Options, Connections: connections, Logger: f.loader.logger()}
	ps, err := proxyserver.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.master.Addons.Add(t.Context(), ps, nextlayer.New(f.master.Options)); err != nil {
		t.Fatal(err)
	}
	observer := &killObserver{snapshots: make(chan killedSnapshot, 16)}
	if err := f.master.Addons.Add(t.Context(), observer); err != nil {
		t.Fatal(err)
	}
	var target flow.Flow
	waiter := make(chan error, 1)
	if err := f.master.Commands.Register("kill.prepare", func(_ context.Context, model flow.Flow) error {
		target = model
		model.Common().Intercept()
		if backup {
			model.Backup()
		}
		ready := make(chan struct{})
		ctx := &resumeObservedContext{Context: t.Context(), entered: ready}
		go func() { waiter <- model.Common().WaitForResume(ctx) }()
		awaitConcurrent(t, ready)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	text := "def tcp_message(f):\n    ctx.master.commands.call('kill.prepare', f)\ndef _message(f):\n    ctx.sleep(1)\n" + indentStarlark(actions) + "\naddons = [module('killer', tcp_message=concurrent(_message))]\n"
	f.load(f.file("kill.star", text))
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	originDone := make(chan error, 1)
	go func() {
		conn, err := origin.Accept()
		if err != nil {
			originDone <- err
			return
		}
		defer func() {
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		}()
		_, err = io.Copy(io.Discard, conn)
		originDone <- err
	}()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	handler, err := proxy.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	handlerDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			handlerDone <- err
			return
		}
		handlerDone <- handler.Handle(ctx, conn, "reverse:tcp://"+origin.Addr().String(), hookdata.LayerSpec{Kind: hookdata.LayerReverse})
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("kill-this-message")); err != nil {
		t.Fatal(err)
	}
	awaitConcurrent(t, entered)
	if liveKill {
		if err := f.master.Do(t.Context(), func(context.Context) error { return target.Common().Kill() }); err != nil {
			t.Fatal(err)
		}
	}
	release()
	var buffer [1]byte
	if n, err := client.Read(buffer[:]); n != 0 || err == nil {
		t.Fatalf("killed transport forwarded bytes: n=%d err=%v", n, err)
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatalf("killed transport did not close: %v", err)
	}
	if err := awaitConcurrent(t, handlerDone); err != nil {
		t.Fatal(err)
	}
	if err := awaitConcurrent(t, originDone); err != nil {
		t.Fatal(err)
	}
	if err := awaitConcurrent(t, waiter); err != nil {
		t.Fatalf("already waiting caller stranded: %v", err)
	}
	snapshot := awaitConcurrent(t, observer.snapshots)
	if snapshot.live || snapshot.intercepted || snapshot.message != flow.KilledMessage {
		t.Fatalf("pre-transport killed state incorrect: %+v", snapshot)
	}
	if target.Common().Live || target.Common().Intercepted() || target.Common().Error == nil || target.Common().Error.Msg != flow.KilledMessage {
		t.Fatalf("terminal killed state: %s", f.logs.String())
	}
	if liveKill && strings.Contains(actions, "f.kill()") {
		f.wantLog("concurrent flow.kill: flow is not killable", 1)
	} else {
		f.wantLog("flow is not killable", 0)
	}
	f.wantLog("Addon error:", 0)
}
