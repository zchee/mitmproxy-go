// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

func (f *scriptFixture) requestScript(body string) {
	f.t.Helper()
	var code strings.Builder
	code.WriteString("def request(f):\n")
	for line := range strings.SplitSeq(body, "\n") {
		code.WriteString("    " + line + "\n")
	}
	f.load(f.file("binding.star", code.String()))
}

func TestScriptBindings(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"flow": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("f.comment = f.id\nf.marked = \"!\"\nf.is_replay = \"request\"\nf.intercept()\nif not f.intercepted:\n    fail(\"intercept failed\")\nf.resume()\nif f.intercepted or not f.live:\n    fail(\"resume/live changed\")")
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			if x.Comment != x.ID || x.Marked != "!" || x.IsReplay == nil || *x.IsReplay != "request" || x.Intercepted() {
				t.Fatalf("flow binding failed: %s", f.logs.String())
			}
		}},
		"http_request": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("f.request.host = \"rewritten.test\"\nf.request.port = 8443\nf.request.scheme = \"https\"\nf.request.method = \"POST\"\nf.request.path = \"/changed\"\nf.request.content = b\"payload\"")
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			r := x.Request
			if r.Host != "rewritten.test" || r.Port != 8443 || r.Path != "/changed" || r.Method != "POST" || r.Scheme != "https" || string(r.RawContent) != "payload" || r.Headers.Get("Content-Length") != "7" {
				t.Fatalf("request setters failed: %#v; %s", r, f.logs.String())
			}
			if host, _ := r.HostHeader(); !strings.Contains(host, "rewritten.test") {
				t.Fatalf("Host not maintained: %q", host)
			}
		}},
		"http_response": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("f.response.status_code = 201\nf.response.reason = \"Created\"\nf.response.content = b\"\\x00\\xff\"\nf.response.stream = True")
			x := f.request()
			r, err := httpmsg.MakeResponse(200, []byte{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			x.Response = r
			f.hook(addon.RequestHook{Flow: x})
			if r.StatusCode != 201 || r.Reason != "Created" || !r.Stream || gocmp.Diff([]byte{0, 255}, r.RawContent) != "" {
				t.Fatalf("response fields failed: %#v; %s", r, f.logs.String())
			}
		}},
		"headers": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("h = f.request.headers\nif h[\"x-a\"] != \"one, two\" or len(h) != 2:\n    fail(\"folding/unique keys\")\nif h.get_all(\"X-A\") != [\"one\", \"two\"]:\n    fail(\"duplicates lost\")\nh[\"x-a\"] = \"replacement\"\nh.set_all(\"X-B\", [\"first\", \"second\"])\nif len(h.items(multi=True)) != 3:\n    fail(\"multi items lost\")\nh.pop(\"x-b\")\nif h.get(\"missing\", \"fallback\") != \"fallback\":\n    fail(\"missing get\")")
			x := f.request()
			x.Request.Headers = httpmsg.Headers{{Name: []byte("X-A"), Value: []byte("one")}, {Name: []byte("x-a"), Value: []byte("two")}, {Name: []byte("X-B"), Value: []byte("before")}}
			f.hook(addon.RequestHook{Flow: x})
			want := httpmsg.Headers{{Name: []byte("X-A"), Value: []byte("replacement")}}
			if diff := gocmp.Diff(want, x.Request.Headers); diff != "" {
				t.Fatalf("headers: %s; %s", diff, f.logs.String())
			}
			f.wantLog("Addon error:", 0)
		}},
		"client_conn": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("f.client_conn.error = \"denied\"\nf.client_conn.sni = \"example.test\"\nif f.client_conn.peername != (\"127.0.0.1\", 1234):\n    fail(\"peer tuple\")")
			x := f.request()
			x.ClientConn = connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 1234}, connection.Address{}, 0)
			f.hook(addon.RequestHook{Flow: x})
			if x.ClientConn.Error == nil || *x.ClientConn.Error != "denied" || x.ClientConn.SNI == nil || *x.ClientConn.SNI != "example.test" {
				t.Fatalf("client metadata write missing: %s", f.logs.String())
			}
		}},
		"server_conn": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("f.server_conn.address = (\"rewritten.test\", 443)\nf.server_conn.error = \"probe\"\nf.server_conn.tls = True")
			x := f.request()
			x.ServerConn = connection.NewServer(nil)
			f.hook(addon.RequestHook{Flow: x})
			if x.ServerConn.Address == nil || x.ServerConn.Address.Host != "rewritten.test" || x.ServerConn.Address.Port != 443 || !x.ServerConn.TLS || x.ServerConn.Error == nil {
				t.Fatalf("server metadata write missing: %s", f.logs.String())
			}
		}},
		"websocket": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("m = f.websocket.messages[-1]\nif not byteops.startswith(m.content, b\"Hello\"):\n    fail(\"bytes prefix\")\nm.content = byteops.replace(m.content, b\"Hello\", b\"HAPPY\")\nm.drop()\nf.websocket.close_reason = \"script\"\nf.websocket.close_code = 1000")
			x := f.request()
			x.WebSocket = &websocket.Data{Messages: []*websocket.Message{{Content: []byte("Hello\x00"), FromClient: true}}}
			f.hook(addon.RequestHook{Flow: x})
			m := x.WebSocket.Messages[0]
			if string(m.Content) != "HAPPY\x00" || !m.Dropped || x.WebSocket.CloseCode == nil || *x.WebSocket.CloseCode != 1000 {
				t.Fatalf("websocket mutation failed: %s", f.logs.String())
			}
		}},
		"tcp": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("tcp.star", "def tcp_message(f):\n    m = f.messages[-1]\n    m.content = byteops.replace(m.content, b\"foo\", b\"bar\")\n    f.messages.append(m.copy())\n"))
			x := flow.NewTCPFlow(nil, nil, true)
			x.Messages = append(x.Messages, &tcp.Message{Content: []byte("foo\xff"), FromClient: true})
			f.hook(addon.TCPMessageHook{Flow: x})
			if len(x.Messages) != 2 || string(x.Messages[0].Content) != "bar\xff" || x.Messages[0] == x.Messages[1] {
				t.Fatalf("TCP message ownership/mutation failed: %s", f.logs.String())
			}
		}},
		"udp": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("udp.star", "def udp_message(f):\n    f.messages[-1].content = b\"\\x00\\xff\"\n    f.messages[-1].from_client = False\n    f.messages.append(f.messages[-1].copy())\n"))
			x := flow.NewUDPFlow(nil, nil, true)
			x.Messages = append(x.Messages, &udp.Message{Content: []byte("before"), FromClient: true})
			f.hook(addon.UDPMessageHook{Flow: x})
			if len(x.Messages) != 2 || x.Messages[0].FromClient || gocmp.Diff([]byte{0, 255}, x.Messages[0].Content) != "" {
				t.Fatalf("UDP datagram mutation failed: %s", f.logs.String())
			}
		}},
		"dns": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("dns.star", "def dns_request(f):\n    if f.request.question.name != \"example.test\":\n        fail(\"question missing\")\n    f.response = f.request.fail(dns.response_codes.NXDOMAIN)\n"))
			x := flow.NewDNSFlow(nil, nil, true)
			x.Request = &dns.Message{ID: 7, Query: true, Questions: []dns.Question{{Name: "example.test", Type: dns.TypeAAAA, Class: 1}}}
			f.hook(addon.DNSRequestHook{Flow: x})
			if x.Response == nil || x.Response.ResponseCode != 3 || x.Response.ID != 7 || x.Response.Query {
				t.Fatalf("DNS response failed: %s", f.logs.String())
			}
		}},
		"error": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("if f.error.msg != \"before\":\n    fail(\"error wrapper\")\nf.error.msg = \"after\"")
			x := f.request()
			x.Error = flow.NewError("before")
			f.hook(addon.RequestHook{Flow: x})
			if x.Error.Msg != "after" {
				t.Fatalf("error.msg unchanged: %s", f.logs.String())
			}
		}},
		"metadata": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("f.metadata = {\"counter\": 1, \"binary\": b\"\\xff\", \"nested\": [True, None]}\nf.metadata[\"counter\"] = 2\nif f.metadata[\"nested\"] != [True, None]:\n    fail(\"metadata conversion\")")
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			n, ok := x.Metadata.Get("counter")
			if !ok || n != int64(2) {
				t.Fatalf("metadata assignment=%#v; %s", n, f.logs.String())
			}
			f.wantLog("Addon error:", 0)
		}},
		"copy_backup_revert": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("copy = f.copy()\nif copy.id == f.id or copy.live:\n    fail(\"copy identity/live\")\nf.backup()\nf.request.path = \"/changed\"\nif not f.modified():\n    fail(\"backup not observed\")\nf.revert()\nif f.modified():\n    fail(\"backup not cleared\")\nf.comment = copy.id")
			x := f.request()
			id := x.ID
			f.hook(addon.RequestHook{Flow: x})
			if x.ID != id || x.Request.Path != "/start" || x.Comment == id || x.Comment == "" {
				t.Fatalf("copy/backup/revert failed: %s", f.logs.String())
			}
			f.wantLog("Addon error:", 0)
		}},
		"invalid_assignment": {func(t *testing.T) {
			for _, body := range []string{"f.request.port = 18446744073709551616", "f.request.content = \"not bytes\"", "f.request.headers.set_all(\"X-A\", [\"good\", 1])", "f.request.port = -1"} {
				f := newFixture(t)
				f.requestScript(body)
				x := f.request()
				before := x.Request.Clone()
				f.hook(addon.RequestHook{Flow: x})
				if diff := gocmp.Diff(before, x.Request); diff != "" {
					t.Fatalf("invalid assignment partially committed: %s", diff)
				}
				f.wantLog("Addon error:", 1)
			}
		}},
		"bytes_ownership": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("bytes.star", "state = {}\ndef request(f):\n    if \"saved\" not in state:\n        state[\"saved\"] = f.request.content\n    else:\n        f.request.content = state[\"saved\"]\n"))
			x := f.request()
			x.Request.SetContent([]byte{0, 255})
			f.hook(addon.RequestHook{Flow: x})
			if err := f.master.Do(t.Context(), func(context.Context) error { x.Request.RawContent[0] = 99; return nil }); err != nil {
				t.Fatal(err)
			}
			y := f.request()
			f.hook(addon.RequestHook{Flow: y})
			if diff := gocmp.Diff([]byte{0, 255}, y.Request.RawContent); diff != "" {
				t.Fatal(diff)
			}
		}},
		"retained_handle_lifetime": {func(t *testing.T) {
			testRetainedHandleLifetime(t)
		}},
		"form": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("f.request.urlencoded_form[\"mitmproxy\"] = \"rocks\"\nf.request.urlencoded_form[\"other\"] = \"space value\"")
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			if x.Request.Headers.Get("Content-Type") != "application/x-www-form-urlencoded" || !strings.Contains(string(x.Request.RawContent), "mitmproxy=rocks") || !strings.Contains(string(x.Request.RawContent), "space+value") {
				t.Fatalf("form setters failed: %q; %s", x.Request.RawContent, f.logs.String())
			}
		}},
		"query": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("f.request.query[\"Key\"] = \"upper\"\nf.request.query[\"key\"] = \"lower\"\nif len(f.request.query) != 2:\n    fail(\"query is case-sensitive\")")
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			if diff := gocmp.Diff([][2]string{{"Key", "upper"}, {"key", "lower"}}, x.Request.Query()); diff != "" {
				t.Fatalf("query: %s; %s", diff, f.logs.String())
			}
		}},
		"response_make": {func(t *testing.T) {
			f := newFixture(t)
			f.requestScript("f.response = http.Response.make(200, b\"Hello World\\xff\", {\"Content-Type\": \"text/plain\"})\nf.response.trailers = http.Headers([(b\"X-Trailer\", b\"present\")])")
			x := f.request()
			f.hook(addon.RequestHook{Flow: x})
			if x.Response == nil || string(x.Response.RawContent) != "Hello World\xff" || x.Response.Trailers.Get("X-Trailer") != "present" {
				t.Fatalf("response constructor/trailers failed: %s", f.logs.String())
			}
		}},
		"dns_records": {func(t *testing.T) {
			f := newFixture(t)
			f.load(f.file("records.star", "def dns_request(f):\n    record = dns.ResourceRecord.AAAA(f.request.question.name, \"::1\", ttl=60)\n    f.response = f.request.succeed([record])\n    if f.response.answers[0].ipv6_address != \"::1\":\n        fail(\"record address\")\n"))
			x := flow.NewDNSFlow(nil, nil, true)
			x.Request = &dns.Message{ID: 1, Query: true, Questions: []dns.Question{{Name: "localhost", Type: dns.TypeAAAA, Class: 1}}}
			f.hook(addon.DNSRequestHook{Flow: x})
			if x.Response == nil || len(x.Response.Answers) != 1 {
				t.Fatalf("record response absent: %s", f.logs.String())
			}
			ip, err := x.Response.Answers[0].IPv6Address()
			if err != nil || ip != netip.IPv6Loopback() {
				t.Fatalf("record=%s, error=%v", ip, err)
			}
			f.wantLog("Addon error:", 0)
		}},
	}
	t.Run("bindings", func(t *testing.T) {
		for name, test := range tests {
			t.Run(name, test.run)
		}
	})
}
