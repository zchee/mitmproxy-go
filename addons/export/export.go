// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package export renders flows as external commands or raw HTTP messages.
package export

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/options"
)

// Addon provides export commands. Commands run under the addon dispatch lock.
type Addon struct{ options *options.Manager }

// New returns an export addon using opts.
func New(opts *options.Manager) *Addon { return &Addon{options: opts} }

// Name identifies the addon with upstream's spelling.
func (*Addon) Name() string { return "export" }

// Load registers the export option and commands.
func (a *Addon) Load(ctx context.Context, loader *addon.Loader) error {
	if err := loader.AddOption(ctx, "export_preserve_original_ip", options.TypeBool, false, `
            When exporting a request as an external command, make an effort to
            connect to the same IP as in the original request. This helps with
            reproducibility in cases where the behaviour depends on the
            particular host we are connecting to. Currently this only affects
            curl exports.
            `); err != nil {
		return err
	}
	if err := loader.AddCommand("export.formats", a.formats, command.WithHelp("Return a list of the supported export formats.")); err != nil {
		return err
	}
	if err := loader.AddCommand("export.file", a.file, command.WithParams("format", "flow", "path"), command.WithHelp("Export a flow to path.")); err != nil {
		return err
	}
	if err := loader.AddCommand("export.clip", a.clip, command.WithParams("format", "f"), command.WithHelp("Export a flow to the system clipboard.")); err != nil {
		return err
	}
	return loader.AddCommand("export", a.export, command.WithParams("format", "f"), command.WithHelp("Export a flow and return the result."))
}

func (*Addon) formats(context.Context) []string {
	return []string{"curl", "httpie", "raw", "raw_request", "raw_response"}
}

func commandError(text string) error { return &command.Error{Msg: text} }

func cleanupRequest(f flow.Flow) (*httpmsg.Request, error) {
	h, ok := f.(*flow.HTTPFlow)
	if !ok || h == nil || h.Request == nil {
		return nil, commandError("Can't export flow with no request.")
	}
	r := h.Request.Clone()
	if err := r.Decode(false); err != nil {
		return nil, err
	}
	return r, nil
}

func cleanupResponse(f flow.Flow) (*httpmsg.Response, error) {
	h, ok := f.(*flow.HTTPFlow)
	if !ok || h == nil || h.Response == nil {
		return nil, commandError("Can't export flow with no response.")
	}
	r := h.Response.Clone()
	if err := r.Decode(false); err != nil {
		return nil, err
	}
	return r, nil
}

func popHeaders(r *httpmsg.Request) {
	r.Headers.Del("content-length")
	for _, name := range []string{"host", ":authority"} {
		if r.Headers.Get(name) == r.Host {
			r.Headers.Del(name)
		}
	}
}

// Shell quoting follows Python shlex.quote's ASCII-only safe character set.
func shellQuote(s string) string {
	if s != "" {
		safe := true
		for _, c := range []byte(s) {
			charSafe := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_@%+=:,./-", rune(c))
			if !charSafe {
				safe = false
				break
			}
		}
		if safe {
			return s
		}
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func contentForConsole(r *httpmsg.Request) (string, error) {
	text, err := r.Text()
	if err != nil || !utf8.ValidString(text) {
		return "", commandError("Request content must be valid unicode")
	}
	var escaped strings.Builder
	control := false
	for _, c := range text {
		if c < 32 {
			control = true
			fmt.Fprintf(&escaped, `\x%02x`, c)
		} else {
			escaped.WriteRune(c)
		}
	}
	quoted := shellQuote(escaped.String())
	if control {
		return `"$(printf ` + quoted + `)"`, nil
	}
	return quoted, nil
}

func (a *Addon) console(format string, f flow.Flow) ([]byte, error) {
	r, err := cleanupRequest(f)
	if err != nil {
		return nil, err
	}
	popHeaders(r)
	r.Method = strings.ToUpper(r.Method)
	var args []string
	if format == "curl" {
		args = []string{"curl"}
		h := f.(*flow.HTTPFlow)
		if a.options.Bool("export_preserve_original_ip") && h.ServerConn != nil && h.ServerConn.Peername != nil && r.PrettyHost() != h.ServerConn.Peername.Host {
			args = append(args, "--resolve", fmt.Sprintf("%s:%d:[%s]", r.PrettyHost(), r.Port, h.ServerConn.Peername.Host))
		}
		for _, field := range r.Headers {
			if strings.EqualFold(string(field.Name), "accept-encoding") {
				args = append(args, "--compressed")
			} else {
				args = append(args, "-H", string(field.Name)+": "+string(field.Value))
			}
		}
		if r.Method != "GET" {
			if len(r.RawContent) == 0 {
				args = append(args, "-H", "content-length: 0")
			}
			args = append(args, "-X", r.Method)
		}
		args = append(args, r.PrettyURL())
	} else {
		args = []string{"http", r.Method, r.PrettyURL()}
		for _, field := range r.Headers {
			args = append(args, string(field.Name)+": "+string(field.Value))
		}
	}
	for i := range args {
		args[i] = shellQuote(args[i])
	}
	text := strings.Join(args, " ")
	if len(r.RawContent) > 0 {
		body, err := contentForConsole(r)
		if err != nil {
			return nil, err
		}
		if format == "curl" {
			text += " -d " + body
		} else {
			text += " <<< " + body
		}
	}
	return []byte(text), nil
}

func assembleBody(head []byte, m *httpmsg.Message) ([]byte, error) {
	var out bytes.Buffer
	out.Write(head)
	mode := http1.BodyUntilClose
	if strings.Contains(strings.ToLower(m.Headers.Get("transfer-encoding")), "chunked") {
		mode = http1.BodyChunked
	}
	writer, err := http1.NewBodyWriter(&out, http1.BodySize{Mode: mode})
	if err != nil {
		return nil, err
	}
	if _, err = writer.Write(m.RawContent); err != nil {
		return nil, err
	}
	if err = writer.Close(m.Trailers); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func rawRequest(f flow.Flow) ([]byte, error) {
	r, err := cleanupRequest(f)
	if err != nil {
		return nil, err
	}
	if r.RawContent == nil {
		return nil, commandError("Request content missing.")
	}
	return assembleBody(http1.AssembleRequestHead(r, nil, true, nil), &r.Message)
}

func rawResponse(f flow.Flow) ([]byte, error) {
	r, err := cleanupResponse(f)
	if err != nil {
		return nil, err
	}
	if r.RawContent == nil {
		return nil, commandError("Response content missing.")
	}
	return assembleBody(http1.AssembleResponseHead(r, nil, true, nil), &r.Message)
}

func raw(f flow.Flow) ([]byte, error) {
	h, ok := f.(*flow.HTTPFlow)
	if !ok || h == nil {
		return nil, commandError("Can't export flow with no request or response.")
	}
	var parts [][]byte
	if h.Request != nil && h.Request.RawContent != nil {
		r, err := rawRequest(f)
		if err != nil {
			return nil, err
		}
		parts = append(parts, r)
	}
	if h.Response != nil && h.Response.RawContent != nil {
		r, err := rawResponse(f)
		if err != nil {
			return nil, err
		}
		parts = append(parts, r)
	}
	if len(parts) == 0 {
		return nil, commandError("Can't export flow with no request or response.")
	}
	if len(parts) == 2 && h.WebSocket != nil {
		parts = append(parts, h.WebSocket.FormattedMessages())
	}
	return bytes.Join(parts, []byte("\r\n\r\n")), nil
}

func (a *Addon) format(format string, f flow.Flow) ([]byte, error) {
	switch format {
	case "curl", "httpie":
		return a.console(format, f)
	case "raw_request":
		return rawRequest(f)
	case "raw_response":
		return rawResponse(f)
	case "raw":
		return raw(f)
	default:
		return nil, commandError("No such export format: " + format)
	}
}

func (a *Addon) file(ctx context.Context, format string, f flow.Flow, path command.Path) error {
	data, err := a.format(format, f)
	if err != nil {
		return err
	}
	if err = os.WriteFile(string(path), data, 0o600); err != nil {
		slog.ErrorContext(ctx, err.Error())
	}
	return nil
}

func (a *Addon) export(_ context.Context, format string, f flow.Flow) ([]byte, error) {
	data, err := a.format(format, f)
	if err != nil {
		return nil, err
	}
	// Go preserves arbitrary bytes without surrogates. Match backslashreplace
	// at the command boundary, while file exports preserve their original bytes.
	if utf8.Valid(data) {
		return data, nil
	}
	out := make([]byte, 0, len(data))
	for len(data) > 0 {
		r, n := utf8.DecodeRune(data)
		if r == utf8.RuneError && n == 1 {
			out = fmt.Appendf(out, `\x%02x`, data[0])
		} else {
			out = append(out, data[:n]...)
		}
		data = data[n:]
	}
	return out, nil
}

func (a *Addon) clip(ctx context.Context, format string, f flow.Flow) error {
	data, err := a.export(ctx, format, f)
	if err != nil {
		return err
	}
	return copyClipboard(ctx, data)
}
