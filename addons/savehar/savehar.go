// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package savehar exports completed HTTP flows to HTTP Archive files.
package savehar

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/human"
	"github.com/zchee/mitmproxy-go/internal/privfile"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/options"
)

// Addon collects completed HTTP flows for hardump and registers save.har.
// All hooks and commands run under the addon dispatch lock. File writes are
// synchronous, as upstream blocks its event loop when exporting a HAR.
type Addon struct {
	options        *options.Manager
	creatorVersion string
	flows          []flow.Flow
	filter         filter.Expr
	stdout         io.Writer
}

// New returns a HAR addon using opts and an injected creator version.
// An empty creatorVersion uses the program's release version.
func New(opts *options.Manager, creatorVersion string) *Addon {
	if creatorVersion == "" {
		creatorVersion = version.Version
	}
	return &Addon{options: opts, creatorVersion: creatorVersion, stdout: os.Stdout}
}

// Name returns the upstream addon name.
func (*Addon) Name() string { return "savehar" }

// Load registers hardump and save.har with their upstream signatures.
func (a *Addon) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "hardump", options.TypeStr, "", "Save a HAR file with all flows on exit. You may select particular flows by setting save_stream_filter. For mitmdump, enabling this option will mean that flows are kept in memory."); err != nil {
		return err
	}
	return loader.AddCommand("save.har", a.exportHAR, command.WithParams("flows", "path"), command.WithHelp("Export flows to an HAR (HTTP Archive) file."))
}

// Configure compiles the stream filter and frees flows when hardump is disabled.
func (a *Addon) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated["save_stream_filter"]; ok {
		var expr filter.Expr
		if spec := a.options.OptStr("save_stream_filter"); spec != nil && *spec != "" {
			var err error
			expr, err = filter.Parse(*spec)
			if err != nil {
				return &options.OptionsError{Err: err}
			}
		}
		a.filter = expr
	}
	if _, ok := updated["hardump"]; ok && a.options.Str("hardump") == "" {
		a.flows = nil
	}
	return nil
}

// Response retains an HTTP flow unless WebSocketEnd will retain it later.
func (a *Addon) Response(_ context.Context, f *flow.HTTPFlow) error {
	if f.WebSocket == nil {
		a.saveFlow(f)
	}
	return nil
}

// Error retains a failed HTTP flow.
func (a *Addon) Error(ctx context.Context, f *flow.HTTPFlow) error { return a.Response(ctx, f) }

// WebSocketEnd retains the handshake together with every WebSocket message.
func (a *Addon) WebSocketEnd(_ context.Context, f *flow.HTTPFlow) error { a.saveFlow(f); return nil }

func (a *Addon) saveFlow(f *flow.HTTPFlow) {
	if a.options.Str("hardump") != "" && filter.Match(a.filter, f) {
		a.flows = append(a.flows, f)
	}
}

// Done writes retained flows to hardump, or to standard output for "-".
func (a *Addon) Done(ctx context.Context) error {
	path := a.options.Str("hardump")
	if path == "" {
		return nil
	}
	if path != "-" {
		return a.exportHAR(ctx, a.flows, command.Path(path))
	}
	data, err := a.marshalHAR(ctx, a.flows)
	if err != nil {
		return err
	}
	_, err = a.stdout.Write(append(data, '\n'))
	return err
}

func (a *Addon) exportHAR(ctx context.Context, flows []flow.Flow, path command.Path) error {
	data, err := a.marshalHAR(ctx, flows)
	if err != nil {
		return err
	}
	if strings.HasSuffix(string(path), ".zhar") {
		var b bytes.Buffer
		writer, err := zlib.NewWriterLevel(&b, zlib.BestCompression)
		if err != nil {
			return err
		}
		if _, err := writer.Write(data); err != nil {
			return errors.Join(err, writer.Close())
		}
		if err := writer.Close(); err != nil {
			return err
		}
		data = b.Bytes()
	}
	file, err := privfile.Create(string(path))
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err = errors.Join(err, file.Close()); err != nil {
		return err
	}
	slog.Log(ctx, addon.LevelAlert, fmt.Sprintf("HAR file saved (%s bytes).", human.PrettySize(int64(len(data)))))
	return nil
}

func (a *Addon) makeHAR(ctx context.Context, flows []flow.Flow) (map[string]any, error) {
	entries := make([]any, 0, len(flows))
	seen := make(map[*connection.Server]struct{})
	skipped := 0
	for _, f := range flows {
		if h, ok := f.(*flow.HTTPFlow); ok {
			entry, err := flowEntry(h, seen)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		} else {
			skipped++
		}
	}
	if skipped > 0 {
		slog.InfoContext(ctx, fmt.Sprintf("Skipped %d flows that weren't HTTP flows.", skipped))
	}
	return map[string]any{"log": map[string]any{"version": "1.2", "creator": map[string]any{"name": "mitmproxy", "version": a.creatorVersion, "comment": ""}, "pages": []any{}, "entries": entries}}, nil
}

func (a *Addon) marshalHAR(ctx context.Context, flows []flow.Flow) ([]byte, error) {
	doc, err := a.makeHAR(ctx, flows)
	if err != nil {
		return nil, err
	}
	return json.Marshal(doc, jsontext.WithIndent("    "), json.Deterministic(true), json.WithMarshalers(json.JoinMarshalers(
		json.MarshalFunc(func(n float64) ([]byte, error) { return []byte(pyrepr.Value(n)), nil }),
		json.MarshalToFunc(marshalString),
	)))
}

// marshalString emits Python's ASCII JSON spelling, including surrogate escapes
// for undecodable wire bytes. Invalid-string options apply only to this value.
func marshalString(enc *jsontext.Encoder, s string) error {
	invalid := !utf8.ValidString(s)
	raw := make([]byte, 0, len(s)+2)
	raw = append(raw, '"')
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && n == 1:
			raw = fmt.Appendf(raw, "\\%sdc%02x", "u", s[0])
		case r == '"' || r == '\\':
			raw = append(raw, '\\', byte(r))
		case r == '\b':
			raw = append(raw, '\\', 'b')
		case r == '\f':
			raw = append(raw, '\\', 'f')
		case r == '\n':
			raw = append(raw, '\\', 'n')
		case r == '\r':
			raw = append(raw, '\\', 'r')
		case r == '\t':
			raw = append(raw, '\\', 't')
		case r < 32 || r > 126:
			if r <= 0xffff {
				raw = fmt.Appendf(raw, "\\%s%04x", "u", r)
			} else {
				r -= 0x10000
				raw = fmt.Appendf(raw, "\\%s%04x\\%s%04x", "u", 0xd800+(r>>10), "u", 0xdc00+(r&0x3ff))
			}
		default:
			raw = append(raw, byte(r))
		}
		s = s[n:]
	}
	raw = append(raw, '"')
	if invalid {
		return json.MarshalEncode(enc, jsontext.Value(raw), jsontext.AllowInvalidUTF8(true), jsontext.PreserveRawStrings(true))
	}
	return json.MarshalEncode(enc, jsontext.Value(raw), jsontext.PreserveRawStrings(true))
}

func flowEntry(f *flow.HTTPFlow, seen map[*connection.Server]struct{}) (map[string]any, error) {
	if f == nil || f.Request == nil {
		return nil, errors.New("savehar: HTTP flow has no request")
	}
	req, resp, server := f.Request, f.Response, f.ServerConn
	// Keep undecodable method bytes as Python surrogateescape does.
	var upper strings.Builder
	start := 0
	for i := 0; i < len(req.Method); {
		r, n := utf8.DecodeRuneInString(req.Method[i:])
		if r == utf8.RuneError && n == 1 {
			upper.WriteString(strings.ToUpper(req.Method[start:i]))
			upper.WriteByte(req.Method[i])
			start = i + 1
		}
		i += n
	}
	upper.WriteString(strings.ToUpper(req.Method[start:]))
	method := upper.String()
	connect, ssl := -1.0, -1.0
	if _, ok := seen[server]; !ok && server != nil && nonzero(server.TimestampTCPSetup) {
		if server.TimestampStart == nil {
			return nil, errors.New("savehar: server TCP setup has no start timestamp")
		}
		connect = 1000 * (*server.TimestampTCPSetup - *server.TimestampStart)
		if nonzero(server.TimestampTLSSetup) {
			ssl = 1000 * (*server.TimestampTLSSetup - *server.TimestampTCPSetup)
		}
		seen[server] = struct{}{}
	}
	send, wait, receive := 0.0, 0.0, 0.0
	if nonzero(req.TimestampEnd) {
		send = 1000 * (*req.TimestampEnd - req.TimestampStart)
	}
	if resp != nil && nonzero(req.TimestampEnd) {
		wait = 1000 * (resp.TimestampStart - *req.TimestampEnd)
	}
	if resp != nil && nonzero(resp.TimestampEnd) {
		receive = 1000 * (*resp.TimestampEnd - resp.TimestampStart)
	}
	timings := map[string]float64{"connect": connect, "ssl": ssl, "send": send, "receive": receive, "wait": wait}
	// Preserve Python's sum order to avoid rounding differences.
	total := 0.0
	for _, v := range []float64{connect, ssl, send, receive, wait} {
		if v >= 0 {
			total += v
		}
	}
	response := map[string]any{"status": 0, "statusText": "", "httpVersion": "", "headers": []any{}, "cookies": []any{}, "content": map[string]any{}, "redirectURL": "", "headersSize": -1, "bodySize": -1, "_transferSize": 0, "_error": nil}
	if resp != nil {
		content, err := resp.Content()
		if err != nil {
			content = resp.RawContent
		}
		body := map[string]any{"size": len(resp.RawContent), "compression": len(content) - len(resp.RawContent), "mimeType": resp.Headers.Get("Content-Type")}
		if len(content) > 0 && strutil.IsMostlyBin(content) {
			body["text"] = base64.StdEncoding.EncodeToString(content)
			body["encoding"] = "base64"
		} else {
			body["text"] = resp.TextOrRaw()
		}
		// Response reasons are wire bytes exposed as Latin-1 by Python.
		reason := make([]rune, 0, len(resp.Reason))
		for _, b := range []byte(resp.Reason) {
			reason = append(reason, rune(b))
		}
		response = map[string]any{"status": resp.StatusCode, "statusText": string(reason), "httpVersion": resp.HTTPVersion, "cookies": responseCookies(resp), "headers": headerPairs(resp.Headers), "content": body, "redirectURL": resp.Headers.Get("Location"), "headersSize": headerSize(resp.Headers), "bodySize": len(resp.RawContent)}
	} else if f.Error != nil {
		response["_error"] = f.Error.Msg
	}
	url := req.PrettyURL()
	if method == "CONNECT" {
		url = "https://" + url + "/"
	}
	cookies := make([]map[string]any, 0)
	for _, c := range req.Cookies() {
		cookies = append(cookies, map[string]any{"name": c.Name, "value": c.Value})
	}
	request := map[string]any{"method": method, "url": url, "httpVersion": req.HTTPVersion, "cookies": cookies, "headers": headerPairs(req.Headers), "queryString": stringPairs(req.Query()), "headersSize": headerSize(req.Headers), "bodySize": len(req.RawContent)}
	switch method {
	case "POST", "PUT", "PATCH":
		var text any
		if req.RawContent != nil {
			text = req.TextOrRaw()
		}
		request["postData"] = map[string]any{"mimeType": req.Headers.Get("Content-Type"), "text": text, "params": stringPairs(req.URLEncodedForm())}
	}
	stamp := isoTimestamp(req.TimestampStart)
	entry := map[string]any{"startedDateTime": stamp, "time": total, "request": request, "response": response, "cache": map[string]any{}, "timings": timings}
	if server != nil && server.Peername != nil {
		entry["serverIPAddress"] = server.Peername.Host
	}
	if f.WebSocket != nil {
		messages := make([]map[string]any, 0, len(f.WebSocket.Messages))
		for _, m := range f.WebSocket.Messages {
			data := base64.StdEncoding.EncodeToString(m.Content)
			if m.IsText() {
				var err error
				data, err = m.Text()
				if err != nil {
					return nil, err
				}
			}
			direction := "receive"
			if m.FromClient {
				direction = "send"
			}
			messages = append(messages, map[string]any{"type": direction, "time": m.Timestamp, "opcode": int(m.Type), "data": data})
		}
		entry["_resourceType"] = "websocket"
		entry["_webSocketMessages"] = messages
	}
	return entry, nil
}

func nonzero(v *float64) bool { return v != nil && *v != 0 }

func isoTimestamp(ts float64) string {
	whole := math.Floor(ts)
	micro := math.RoundToEven((ts - whole) * 1e6)
	date := time.Unix(int64(whole), int64(micro)*1000).UTC()
	layout := "2006-01-02T15:04:05"
	if date.Nanosecond() != 0 {
		layout += ".000000"
	}
	return date.Format(layout) + "+00:00"
}

// Upstream measures str(Headers), which is its repr, not its HTTP wire block.
func headerSize(headers httpmsg.Headers) int {
	raw := []byte("Headers[")
	for i, h := range headers {
		if i != 0 {
			raw = append(raw, ',', ' ')
		}
		raw = append(raw, '(')
		raw = pyrepr.AppendBytes(raw, h.Name)
		raw = append(raw, ',', ' ')
		raw = pyrepr.AppendBytes(raw, h.Value)
		raw = append(raw, ')')
	}
	return len(raw) + 1
}

func headerPairs(headers httpmsg.Headers) []map[string]any {
	pairs := make([]map[string]any, 0, len(headers))
	for _, h := range headers {
		pairs = append(pairs, map[string]any{"name": string(h.Name), "value": string(h.Value)})
	}
	return pairs
}

func stringPairs(fields [][2]string) []map[string]any {
	pairs := make([]map[string]any, 0, len(fields))
	for _, field := range fields {
		pairs = append(pairs, map[string]any{"name": field[0], "value": field[1]})
	}
	return pairs
}

func responseCookies(response *httpmsg.Response) []map[string]any {
	cookies := make([]map[string]any, 0)
	for _, c := range response.Cookies() {
		var path, domain any = "/", ""
		if value, ok := c.Attrs.Lookup("path"); ok {
			path = value
		}
		if value, ok := c.Attrs.Lookup("domain"); ok {
			domain = value
		}
		cookie := map[string]any{"name": c.Name, "value": c.Value, "path": path, "domain": domain, "httpOnly": c.Attrs.Has("httpOnly"), "secure": c.Attrs.Has("secure")}
		if value, ok := c.Attrs.Lookup("sameSite"); ok {
			cookie["sameSite"] = value
		}
		// Upstream omits expires because Set-Cookie accepts many date formats.
		cookies = append(cookies, cookie)
	}
	return cookies
}
