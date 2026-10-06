// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package cut extracts flow attributes as byte values or text tables.
package cut

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/certs"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

// Addon provides flow attribute extraction commands under the dispatch lock.
type Addon struct{}

// New returns a cut addon.
func New() *Addon { return &Addon{} }

// Name identifies the addon with upstream's spelling.
func (*Addon) Name() string { return "cut" }

// Load registers the cut commands. The addon has no options.
func (a *Addon) Load(_ context.Context, loader *addon.Loader) error {
	if err := loader.AddCommand("cut", a.cut, command.WithParams("flows", "cuts"), command.WithHelp(`Cut data from a set of flows. Cut specifications are attribute paths
        from the base of the flow object, with a few conveniences - "port"
        and "host" retrieve parts of an address tuple, ".header[key]"
        retrieves a header value. Return values converted to strings or
        bytes: SSL certificates are converted to PEM format, bools are "true"
        or "false", "bytes" are preserved, and all other values are
        converted to strings.`)); err != nil {
		return err
	}
	if err := loader.AddCommand("cut.save", a.save, command.WithParams("flows", "cuts", "path"), command.WithHelp(`Save cuts to file. If there are multiple flows or cuts, the format
        is UTF-8 encoded CSV. If there is exactly one row and one column,
        the data is written to file as-is, with raw bytes preserved. If the
        path is prefixed with a "+", values are appended if there is an
        existing file.`)); err != nil {
		return err
	}
	return loader.AddCommand("cut.clip", a.clip, command.WithParams("flows", "cuts"), command.WithHelp(`Send cuts to the clipboard. If there are multiple flows or cuts, the
        format is UTF-8 encoded CSV. If there is exactly one row and one
        column, the data is written to file as-is, with raw bytes preserved.`))
}

func headername(spec string) (string, error) {
	s, ok := strings.CutPrefix(spec, "header[")
	if ok {
		s, ok = strings.CutSuffix(s, "]")
	}
	if !ok {
		return "", &command.Error{Msg: "Invalid header spec: " + spec}
	}
	return strings.TrimSpace(s), nil
}

func message(v any) *httpmsg.Message {
	switch v := v.(type) {
	case *httpmsg.Request:
		if v != nil {
			return &v.Message
		}
	case *httpmsg.Response:
		if v != nil {
			return &v.Message
		}
	case *httpmsg.Message:
		return v
	}
	return nil
}

func attributeName(name string) string {
	var out strings.Builder
	for i := range len(name) {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			if i > 0 && (name[i-1] >= 'a' && name[i-1] <= 'z' || i+1 < len(name) && name[i+1] >= 'a' && name[i+1] <= 'z') {
				out.WriteByte('_')
			}
			c += 'a' - 'A'
		}
		out.WriteByte(c)
	}
	return out.String()
}

func attribute(v any, name string) (any, error) {
	// Properties with computed values must not invoke arbitrary methods: some
	// flow methods mutate state or wait for a connection to resume.
	if m := message(v); m != nil {
		switch name {
		case "content":
			return m.Content()
		case "text":
			return m.Text()
		case "is_http10":
			return m.IsHTTP10(), nil
		case "is_http11":
			return m.IsHTTP11(), nil
		case "is_http2":
			return m.IsHTTP2(), nil
		case "is_http3":
			return m.IsHTTP3(), nil
		}
	}
	switch v := v.(type) {
	case *httpmsg.Request:
		if v != nil {
			switch name {
			case "method":
				return strings.ToUpper(v.Method), nil
			case "url":
				return v.URL(), nil
			case "pretty_url":
				return v.PrettyURL(), nil
			case "pretty_host":
				return v.PrettyHost(), nil
			case "host_header":
				h, _ := v.HostHeader()
				return h, nil
			case "first_line_format":
				return v.FirstLineFormat(), nil
			case "path_components":
				return v.PathComponents(), nil
			}
		}
	case flow.Flow:
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Pointer || !rv.IsNil() {
			switch name {
			case "type":
				return v.Type(), nil
			case "timestamp_start":
				return v.TimestampStart(), nil
			case "intercepted":
				return v.Common().Intercepted(), nil
			case "killable":
				return v.Common().Killable(), nil
			}
		}
	case *connection.Client:
		if v != nil {
			switch name {
			case "tls_established":
				return v.TLSEstablished(), nil
			case "connected":
				return v.Connected(), nil
			case "mitmcert":
				if len(v.MitmCert) == 0 {
					return nil, nil
				}
				return certs.ParseCert(v.MitmCert)
			}
		}
	case *connection.Server:
		if v != nil {
			switch name {
			case "tls_established":
				return v.TLSEstablished(), nil
			case "connected":
				return v.Connected(), nil
			}
		}
	case *certs.Cert:
		if v != nil {
			switch name {
			case "cn":
				return v.CN(), nil
			case "organization":
				return v.Organization(), nil
			case "is_ca":
				return v.IsCA(), nil
			case "has_expired":
				return v.HasExpired(), nil
			case "serial":
				return v.Serial(), nil
			}
		}
	}
	rv := reflect.ValueOf(v)
	for rv.IsValid() && (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface) {
		if rv.IsNil() {
			return nil, nil
		}
		rv = rv.Elem()
	}
	if !rv.IsValid() || rv.Kind() != reflect.Struct {
		return nil, nil
	}
	for _, field := range reflect.VisibleFields(rv.Type()) {
		if !field.IsExported() || attributeName(field.Name) != name {
			continue
		}
		value, err := rv.FieldByIndexErr(field.Index)
		if err != nil {
			return nil, nil
		}
		return value.Interface(), nil
	}
	return nil, nil
}

func extract(cut string, f flow.Flow) (any, error) {
	if h, ok := f.(*flow.HTTPFlow); ok && h != nil && h.WebSocket != nil && (cut == "request.content" || cut == "response.content") {
		return h.WebSocket.FormattedMessages(), nil
	}
	var current any = f
	offset := 0
	for spec := range strings.SplitSeq(cut, ".") {
		offset += len(spec) + 1
		if strings.HasPrefix(spec, "_") {
			return nil, &command.Error{Msg: "Can't access internal attribute " + spec}
		}
		// The header convenience applies only to the last path component.
		if offset > len(cut) && strings.HasPrefix(spec, "header[") {
			if m := message(current); m != nil {
				name, err := headername(spec)
				if err != nil {
					return nil, err
				}
				return m.Headers.Get(name), nil
			}
			return "", nil
		}
		var err error
		current, err = attribute(current, spec)
		if err != nil {
			return nil, err
		}
	}
	rv := reflect.ValueOf(current)
	for rv.IsValid() && (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface) {
		if rv.IsNil() {
			return "", nil
		}
		if c, ok := reflect.TypeAssert[*certs.Cert](rv); ok {
			return string(c.PEM()), nil
		}
		rv = rv.Elem()
	}
	if !rv.IsValid() {
		return "", nil
	}
	switch v := rv.Interface().(type) {
	case []byte:
		if v == nil {
			return "", nil
		}
		return v, nil
	case bool:
		return strconv.FormatBool(v), nil
	case [][]byte:
		if len(v) == 0 {
			return "", nil
		}
		if strings.HasSuffix(cut, ".certificate_list") {
			cert, err := certs.ParseCert(v[0])
			if err != nil {
				return nil, err
			}
			return string(cert.PEM()), nil
		}
		values := make([]any, len(v))
		for i, value := range v {
			values[i] = value
		}
		return pyrepr.Value(values), nil
	case float64:
		if v == 0 {
			return "", nil
		}
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case string:
		return v, nil
	}
	if rv.IsZero() {
		return "", nil
	}
	return fmt.Sprint(rv.Interface()), nil
}

func extractString(spec string, f flow.Flow) (string, error) {
	value, err := extract(spec, f)
	if err != nil {
		return "", err
	}
	if b, ok := value.([]byte); ok {
		return pyrepr.Bytes(b), nil
	}
	return value.(string), nil
}

func (*Addon) cut(_ context.Context, flows []flow.Flow, cuts command.CutSpec) (command.Data, error) {
	rows := make(command.Data, 0, len(flows))
	for _, f := range flows {
		row := make([]any, 0, len(cuts))
		for _, spec := range cuts {
			v, err := extract(spec, f)
			if err != nil {
				return nil, err
			}
			row = append(row, v)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Python's excel CSV dialect quotes only delimiters, quotes and CR/LF, plus
// the single empty field that must be distinguishable from an empty row.
func writeCSVRow(out *strings.Builder, row []string) {
	for i, value := range row {
		if i > 0 {
			out.WriteByte(',')
		}
		if strings.ContainsAny(value, ",\"\r\n") || len(row) == 1 && value == "" {
			out.WriteByte('"')
			out.WriteString(strings.ReplaceAll(value, "\"", "\"\""))
			out.WriteByte('"')
		} else {
			out.WriteString(value)
		}
	}
	out.WriteString("\r\n")
}

func csvData(flows []flow.Flow, cuts command.CutSpec) (string, error) {
	var out strings.Builder
	for _, f := range flows {
		row := make([]string, 0, len(cuts))
		for _, spec := range cuts {
			value, err := extractString(spec, f)
			if err != nil {
				return "", err
			}
			row = append(row, value)
		}
		writeCSVRow(&out, row)
	}
	return out.String(), nil
}

func (*Addon) save(ctx context.Context, flows []flow.Flow, cuts command.CutSpec, path command.Path) error {
	name := string(path)
	appendMode := false
	if rest, ok := strings.CutPrefix(name, "+"); ok {
		appendMode = true
		expanded, err := command.PathType.Parse(ctx, nil, rest)
		if err != nil {
			return err
		}
		name = string(expanded.(command.Path))
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if appendMode {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	fp, err := os.OpenFile(name, flags, 0o600) //nolint:gosec // The command explicitly writes to the user's chosen export path.
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		return nil
	}
	defer func() {
		if err := fp.Close(); err != nil {
			slog.ErrorContext(ctx, err.Error())
		}
	}()
	single := len(cuts) == 1 && len(flows) == 1
	var data []byte
	if single {
		if appendMode {
			info, err := fp.Stat()
			if err != nil {
				slog.ErrorContext(ctx, err.Error())
				return nil
			}
			if info.Size() > 0 {
				data = append(data, '\n')
			}
		}
		value, err := extract(cuts[0], flows[0])
		if err != nil {
			return err
		}
		if b, ok := value.([]byte); ok {
			data = append(data, b...)
		} else {
			data = append(data, value.(string)...)
		}
		if _, err := fp.Write(data); err != nil {
			slog.ErrorContext(ctx, err.Error())
			return nil
		}
	} else {
		for _, f := range flows {
			value, err := csvData([]flow.Flow{f}, cuts)
			if err != nil {
				return err
			}
			if _, err := fp.WriteString(value); err != nil {
				slog.ErrorContext(ctx, err.Error())
				return nil
			}
		}
	}
	if single {
		slog.Log(ctx, addon.LevelAlert, "Saved single cut.")
	} else {
		slog.Log(ctx, addon.LevelAlert, fmt.Sprintf("Saved %d cuts over %d flows as CSV.", len(cuts), len(flows)))
	}
	return nil
}

func (*Addon) clip(ctx context.Context, flows []flow.Flow, cuts command.CutSpec) error {
	var text string
	var err error
	if len(cuts) == 1 && len(flows) == 1 {
		text, err = extractString(cuts[0], flows[0])
		if err != nil {
			return err
		}
		slog.Log(ctx, addon.LevelAlert, "Clipped single cut.")
	} else {
		text, err = csvData(flows, cuts)
		if err != nil {
			return err
		}
		slog.Log(ctx, addon.LevelAlert, fmt.Sprintf("Clipped %d cuts as CSV.", len(cuts)))
	}
	return copyClipboard(ctx, []byte(text))
}
