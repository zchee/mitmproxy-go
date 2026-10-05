// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package dumper prints flows in mitmdump's human-readable format.
package dumper

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/human"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/internal/vtcodes"
	"github.com/zchee/mitmproxy-go/options"
)

// Dumper prints completed HTTP flows and individual protocol messages. Call its
// hooks under the addon dispatch lock. Writes intentionally block under that
// lock, as upstream blocks its event loop while writing terminal output.
// Message content is uncoloured; request, response and header styles are emitted
// only when the output supports virtual terminal codes.
type Dumper struct {
	options  *options.Manager
	out      io.Writer
	outHasVT bool
	filter   filter.Expr
}

// New returns a dumper using opts. A nil writer means os.Stdout.
func New(opts *options.Manager, w io.Writer) *Dumper {
	if w == nil {
		w = os.Stdout
	}
	return &Dumper{options: opts, out: w, outHasVT: vtcodes.EnsureSupported(w)}
}

// Load registers the three upstream dumper options.
func (d *Dumper) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "flow_detail", options.TypeInt, 1, fmt.Sprintf(`
            The display detail level for flows in mitmdump: 0 (quiet) to 4 (very verbose).
              0: no output
              1: shortened request URL with response status code
              2: full request URL with response status code and HTTP headers
              3: 2 + truncated response content, content of WebSocket and TCP messages (content_view_lines_cutoff: %d)
              4: 3 + nothing is truncated
            `, options.ContentViewLinesCutoff)); err != nil {
		return err
	}
	if err := loader.AddOption(ctx, "dumper_default_contentview", options.TypeStr, "auto", "The default content view mode.", contentviews.DefaultRegistry.AvailableViews()...); err != nil {
		return err
	}
	return loader.AddOption(ctx, "dumper_filter", options.TypeOptStr, nil, "Limit which flows are dumped.")
}

// Configure compiles a changed flow filter, retaining the old one on failure.
func (d *Dumper) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated["dumper_filter"]; !ok {
		return nil
	}
	var expr filter.Expr
	if spec := d.options.OptStr("dumper_filter"); spec != nil && *spec != "" {
		var err error
		expr, err = filter.Parse(*spec)
		if err != nil {
			return &options.OptionsError{Err: err}
		}
	}
	d.filter = expr
	return nil
}

func (d *Dumper) match(f flow.Flow) bool {
	return d.options.Int("flow_detail") != 0 && (d.filter == nil || filter.Match(d.filter, f))
}

func (d *Dumper) style(text string, s vtcodes.Style) string {
	if d.outHasVT && !s.IsZero() {
		return s.Render(text)
	}
	return text
}

func (d *Dumper) echo(text string, indent int, style vtcodes.Style) error {
	if indent > 0 {
		text = strings.TrimSpace(text)
		if text != "" {
			// Python splitlines recognizes these separators in addition to LF.
			text = strings.NewReplacer("\r\n", "\n", "\r", "\n", "\v", "\n", "\f", "\n", "\x1c", "\n", "\x1d", "\n", "\x1e", "\n", "\u0085", "\n", " ", "\n", " ", "\n").Replace(text)
			pad := strings.Repeat(" ", indent)
			text = pad + strings.ReplaceAll(text, "\n", "\n"+pad)
		}
	}
	_, err := fmt.Fprintln(d.out, d.style(text, style))
	return err
}

func (d *Dumper) echoHeaders(headers httpmsg.Headers) error {
	for _, h := range headers {
		key := d.style(strutil.BytesToEscapedStr(h.Name, false, false), vtcodes.Style{FG: "blue"})
		if err := d.echo(key+": "+strutil.BytesToEscapedStr(h.Value, false, false), 4, vtcodes.Style{}); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dumper) echoTrailers(headers httpmsg.Headers) error {
	if len(headers) == 0 {
		return nil
	}
	if err := d.echo("--- HTTP Trailers", 4, vtcodes.Style{FG: "magenta"}); err != nil {
		return err
	}
	return d.echoHeaders(headers)
}

func (d *Dumper) echoMessage(message any, f flow.Flow) error {
	pretty := contentviews.PrettifyMessage(message, f, d.options.Str("dumper_default_contentview"), nil, 0)
	content := pretty.Text
	if d.options.Int("flow_detail") == 3 {
		content = strutil.CutAfterNLines(content, d.options.Int("content_view_lines_cutoff"))
	}
	if content != "" {
		if err := d.echo("", 0, vtcodes.Style{}); err != nil {
			return err
		}
		// The pinned upstream tests the cut text, but prints the full highlighted
		// text. Preserve this behavior, including its subsequent cutoff notice.
		if err := d.echo(pretty.Text, 4, vtcodes.Style{}); err != nil {
			return err
		}
	}
	if len(content) < len(pretty.Text) {
		if err := d.echo("(cut off)", 4, vtcodes.Style{Dim: new(true)}); err != nil {
			return err
		}
	}
	if d.options.Int("flow_detail") >= 2 {
		return d.echo("", 0, vtcodes.Style{})
	}
	return nil
}

// widthFrom resolves the wrapping width the way Python's
// shutil.get_terminal_size does: a positive integer in the COLUMNS value
// wins, then the width of the terminal attached to stdout, then 80.
func widthFrom(env string, stdout *os.File) int {
	if n, err := strconv.Atoi(env); err == nil && n > 0 {
		return n
	}
	if n, ok := vtcodes.Columns(stdout); ok && n > 0 {
		return n
	}
	return 80
}

func address(a *connection.Address) string {
	if a == nil {
		return human.NoAddress
	}
	return human.FormatAddress(a.Host, a.Port)
}

func (d *Dumper) fmtClient(f flow.Flow) string {
	b := f.Common()
	if b.IsReplay != nil && *b.IsReplay == "request" {
		return d.style("[replay]", vtcodes.Style{FG: "yellow", Bold: new(true)})
	}
	if b.ClientConn.Peername != nil {
		return strutil.EscapeControlCharacters(address(b.ClientConn.Peername), true)
	}
	return ""
}

func (d *Dumper) echoRequestLine(f *flow.HTTPFlow) error {
	request := f.Request
	method := request.Method
	if f.Metadata.Has("h2-pushed-stream") {
		method += " PUSH_PROMISE"
	}
	color := "magenta"
	switch strings.ToUpper(method) {
	case "GET":
		color = "green"
	case "DELETE":
		color = "red"
	}
	method = d.style(strutil.EscapeControlCharacters(method, true), vtcodes.Style{FG: color, Bold: new(true)})
	url := request.URL()
	if d.options.Bool("showhost") {
		url = request.PrettyURL()
	}
	if d.options.Int("flow_detail") == 1 {
		limit := max(widthFrom(os.Getenv("COLUMNS"), os.Stdout)-25, 50)
		if utf8.RuneCountInString(url) > limit {
			url = string([]rune(url)[:limit]) + "…"
		}
	}
	url = d.style(strutil.EscapeControlCharacters(url, true), vtcodes.Style{Bold: new(true)})
	responseVersion := "HTTP/1.1"
	if f.Response != nil {
		responseVersion = f.Response.HTTPVersion
	}
	version := ""
	if !request.IsHTTP10() && !request.IsHTTP11() || request.HTTPVersion != responseVersion {
		version = " " + request.HTTPVersion
	}
	return d.echo(d.fmtClient(f)+": "+method+" "+url+version, 0, vtcodes.Style{})
}

func (d *Dumper) echoResponseLine(f *flow.HTTPFlow) error {
	response := f.Response
	replayText := ""
	if f.IsReplay != nil && *f.IsReplay == "response" {
		replayText = "[replay]"
	}
	replay := ""
	if replayText != "" {
		replay = d.style(replayText, vtcodes.Style{FG: "yellow", Bold: new(true)})
	}
	color := ""
	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		color = "green"
	case response.StatusCode >= 300 && response.StatusCode < 400:
		color = "magenta"
	case response.StatusCode >= 400 && response.StatusCode < 600:
		color = "red"
	}
	code := d.style(strconv.Itoa(response.StatusCode), vtcodes.Style{FG: color, Bold: new(true), Blink: new(response.StatusCode == 418)})
	reason := response.Reason
	if response.IsHTTP2() || response.IsHTTP3() {
		reason = httpmsg.StatusText(response.StatusCode)
	}
	reason = d.style(strutil.EscapeControlCharacters(reason, true), vtcodes.Style{FG: color, Bold: new(true)})
	size := "(content missing)"
	if response.RawContent != nil {
		size = human.PrettySize(int64(len(response.RawContent)))
	}
	size = d.style(size, vtcodes.Style{Bold: new(true)})
	version := ""
	if !response.IsHTTP10() && !response.IsHTTP11() || f.Request != nil && f.Request.HTTPVersion != response.HTTPVersion {
		version = response.HTTPVersion + " "
	}
	arrows := d.style(" <<", vtcodes.Style{Bold: new(true)})
	if d.options.Int("flow_detail") == 1 {
		arrows = strings.Repeat(" ", max(0, utf8.RuneCountInString(address(f.ClientConn.Peername))-(2+len(version)+len(replayText)))) + arrows
	}
	return d.echo(replay+arrows+" "+version+code+" "+reason+" "+size, 0, vtcodes.Style{})
}

func (d *Dumper) echoFlow(f *flow.HTTPFlow) error {
	detail := d.options.Int("flow_detail")
	if f.Request != nil {
		if err := d.echoRequestLine(f); err != nil {
			return err
		}
		if detail >= 2 {
			if err := d.echoHeaders(f.Request.Headers); err != nil {
				return err
			}
		}
		if detail >= 3 {
			if err := d.echoMessage(f.Request, f); err != nil {
				return err
			}
		}
		if detail >= 2 {
			if err := d.echoTrailers(f.Request.Trailers); err != nil {
				return err
			}
		}
	}
	if f.Response != nil {
		if err := d.echoResponseLine(f); err != nil {
			return err
		}
		if detail >= 2 {
			if err := d.echoHeaders(f.Response.Headers); err != nil {
				return err
			}
		}
		if detail >= 3 {
			if err := d.echoMessage(f.Response, f); err != nil {
				return err
			}
		}
		if detail >= 2 {
			if err := d.echoTrailers(f.Response.Trailers); err != nil {
				return err
			}
		}
	}
	if f.Error != nil {
		if err := d.echo(" << "+strutil.EscapeControlCharacters(f.Error.Msg, true), 0, vtcodes.Style{FG: "red", Bold: new(true)}); err != nil {
			return err
		}
	}
	if flusher, ok := d.out.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

// Response prints a matching HTTP flow.
func (d *Dumper) Response(_ context.Context, f *flow.HTTPFlow) error {
	if d.match(f) {
		return d.echoFlow(f)
	}
	return nil
}

// Error prints a matching failed HTTP flow.
func (d *Dumper) Error(ctx context.Context, f *flow.HTTPFlow) error { return d.Response(ctx, f) }

// HTTPConnectError prints a matching failed CONNECT flow.
func (d *Dumper) HTTPConnectError(ctx context.Context, f *flow.HTTPFlow) error {
	return d.Response(ctx, f)
}

func (d *Dumper) protoError(f flow.Flow) error {
	if !d.match(f) {
		return nil
	}
	return d.echo(fmt.Sprintf("Error in %s connection to %s: %s", strings.ToUpper(f.Type()), address(f.Common().ServerConn.Address), f.Common().Error), 0, vtcodes.Style{FG: "red"})
}

// TCPError prints a TCP connection failure.
func (d *Dumper) TCPError(_ context.Context, f *flow.TCPFlow) error { return d.protoError(f) }

// UDPError prints a UDP connection failure.
func (d *Dumper) UDPError(_ context.Context, f *flow.UDPFlow) error { return d.protoError(f) }

func (d *Dumper) protoMessage(f flow.Flow, message any, fromClient bool) error {
	if !d.match(f) {
		return nil
	}
	direction := "<-"
	if fromClient {
		direction = "->"
	}
	typ := f.Type()
	b := f.Common()
	if b.ClientConn.TLSVersion == connection.QUICv1 {
		quicType := "stream"
		if typ == "udp" {
			quicType = "dgrams"
		}
		client, server := "", ""
		if value, ok := b.Metadata.Get("quic_stream_id_client"); ok {
			client = pyrepr.Value(value)
		}
		if value, ok := b.Metadata.Get("quic_stream_id_server"); ok {
			server = pyrepr.Value(value)
		}
		typ = "quic " + quicType + " " + client + " " + direction + " mitmproxy " + direction + " quic " + quicType + " " + server
	}
	if err := d.echo(address(b.ClientConn.Peername)+" "+direction+" "+typ+" "+direction+" "+address(b.ServerConn.Address), 0, vtcodes.Style{}); err != nil {
		return err
	}
	if d.options.Int("flow_detail") >= 3 {
		return d.echoMessage(message, f)
	}
	return nil
}

// TCPMessage prints the last TCP message and, at high detail, its content.
func (d *Dumper) TCPMessage(_ context.Context, f *flow.TCPFlow) error {
	if len(f.Messages) == 0 {
		return nil
	}
	message := f.Messages[len(f.Messages)-1]
	return d.protoMessage(f, message, message.FromClient)
}

// UDPMessage prints the last UDP message and, at high detail, its content.
func (d *Dumper) UDPMessage(_ context.Context, f *flow.UDPFlow) error {
	if len(f.Messages) == 0 {
		return nil
	}
	message := f.Messages[len(f.Messages)-1]
	return d.protoMessage(f, message, message.FromClient)
}
