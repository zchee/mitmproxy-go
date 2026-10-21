// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package style

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/human"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

// FormatFlow projects a borrowed flow into owned, terminal-safe display values.
// Borrowed flows must be held under dispatch; detached snapshots may be formatted
// outside dispatch. Layout is default, list, table or detailview;
// default selects list below 100 columns. Only HTTP list/detail rows have two lines.
func FormatFlow(f flow.Flow, layout string, showHost bool, width int, focused bool) contract.Row {
	if f == nil {
		return contract.Row{}
	}
	if layout == "default" || layout == "" {
		layout = "table"
		if width < 100 {
			layout = "list"
		}
	}
	base := f.Common()
	r := contract.Row{ID: strings.Clone(base.ID), Type: f.Type(), Timestamp: f.TimestampStart(), Intercepted: base.Intercepted(), Marked: flowText(base.Marked), Modified: f.Modified()}
	if base.Error != nil {
		r.Error = flowText(base.Error.Msg)
	}
	if base.IsReplay != nil {
		r.Replay = flowText(*base.IsReplay)
	}
	switch f := f.(type) {
	case *flow.HTTPFlow:
		if f.Request == nil {
			r.Text = Fit("[request missing]", width)
			return r
		}
		q := f.Request
		r.Method, r.Scheme, r.Host, r.Path = flowText(q.Method), flowText(q.Scheme), flowText(q.Host), flowText(q.Path)
		r.URL, r.HTTPVersion = flowText(q.URL()), flowText(q.HTTPVersion)
		if showHost {
			r.Host, r.URL = flowText(q.PrettyHost()), flowText(q.PrettyURL())
		}
		if f.WebSocket != nil {
			switch r.Scheme {
			case "https":
				r.Scheme = "wss"
			case "http":
				r.Scheme = "ws"
			}
		}
		if base.Metadata != nil {
			_, r.PushPromise = base.Metadata.Get("h2-pushed-stream")
		}
		if f.Response != nil {
			r.HasResponse, r.StatusCode = true, f.Response.StatusCode
			r.Reason, r.ContentType = flowText(f.Response.Reason), flowText(f.Response.Headers.Get("content-type"))
			r.Size, r.ContentMissing = int64(len(f.Response.RawContent)), f.Response.RawContent == nil
			if f.Response.TimestampEnd != nil {
				r.Duration = max(0, *f.Response.TimestampEnd-q.TimestampStart)
			}
		}
		r.Text = formatHTTPRow(r, layout, width, focused, nil)
	case *flow.TCPFlow:
		for _, message := range f.Messages {
			if message != nil {
				r.Size += int64(len(message.Content))
				r.Duration = message.Timestamp - r.Timestamp
			}
		}
		r.Text = formatStreamRow(r, base, layout, width, focused)
	case *flow.UDPFlow:
		for _, message := range f.Messages {
			if message != nil {
				r.Size += int64(len(message.Content))
				r.Duration = message.Timestamp - r.Timestamp
			}
		}
		r.Text = formatStreamRow(r, base, layout, width, focused)
	case *flow.DNSFlow:
		answer, status := "...", ""
		if f.Request != nil {
			r.Method = dns.OpCodeToString(f.Request.OpCode)
			if f.Request.Timestamp != nil {
				r.Timestamp = *f.Request.Timestamp
			}
			if len(f.Request.Questions) > 0 {
				r.Host = flowText(f.Request.Questions[0].Name)
				r.Path = dns.TypeToString(f.Request.Questions[0].Type)
			}
		}
		if f.Response != nil {
			r.HasResponse, r.StatusCode = true, dns.HTTPEquivStatusCode(f.Response.ResponseCode)
			status = dns.ResponseCodeToString(f.Response.ResponseCode)
			answers := make([]string, len(f.Response.Answers))
			for i, record := range f.Response.Answers {
				answers[i] = flowText((&dns.Message{Answers: []dns.ResourceRecord{record}}).String())
			}
			answer = strings.Join(answers, ", ")
			if answer == "" {
				answer = "?"
			}
			if f.Response.Timestamp != nil && f.Request != nil && f.Request.Timestamp != nil {
				r.Duration = *f.Response.Timestamp - *f.Request.Timestamp
			}
		}
		if r.Error != "" {
			answer = r.Error
		}
		protocol := "DNS " + r.Method
		if layout == "table" {
			protocol = Fit(protocol, 10)
		}
		r.Text = flowColumns(width, 15, []flowColumn{{text: leftIndicator(r, layout, focused)}, {text: protocol}, {text: r.Host, weight: .5, right: true}, {text: "(" + Truncate(r.Path, 5) + ") ="}, {text: answer, weight: 1}, {text: Fit(status, 9)}, {text: rowDuration(r.Duration)}, {text: rightIndicator(r)}})
	}
	return r
}

func flowText(text string) string {
	return strings.ReplaceAll(Escape(text), "\n", "\\n")
}

// flowColumn mirrors a fixed or weighted source column without retaining widgets.
type flowColumn struct {
	text   string
	tag    string
	weight float64
	right  bool
}

func flowColumns(width, minimum int, columns []flowColumn) string {
	return renderFlowColumns(width, minimum, columns, nil)
}

func renderFlowColumns(width, minimum int, columns []flowColumn, palette *Palette) string {
	width = max(0, width)
	used, weights := 0, 0.0
	visible := len(columns)
	for i, c := range columns {
		n := Width(c.text)
		if c.weight != 0 {
			n = minimum
		}
		if i > 0 {
			n++
		}
		if used+n > width {
			visible = i
			break
		}
		used += n
		weights += c.weight
	}
	columns = columns[:visible]
	remaining := width - used
	var text strings.Builder
	for i, c := range columns {
		if i > 0 {
			text.WriteByte(' ')
		}
		n := Width(c.text)
		if c.weight != 0 {
			extra := int(math.Floor(float64(remaining)*c.weight/weights + .5))
			n = minimum + extra
			remaining -= extra
			weights -= c.weight
		}
		value := c.text
		if c.right {
			if Width(value) > n {
				value = truncateRight(value, n)
			}
			text.WriteString(strings.Repeat(" ", max(0, n-Width(value))))
		} else {
			value = Fit(value, n)
		}
		writeFlowColumn(&text, value, c.tag, palette)
	}
	return Fit(text.String(), width)
}

func truncateRight(text string, width int) string {
	if width <= 0 {
		return ""
	}
	if Width(text) <= width {
		return text
	}
	return ansi.TruncateLeft(text, Width(text)-width+1, "…")
}

func leftIndicator(r contract.Row, layout string, focused bool) string {
	prefix := "  "
	if focused {
		prefix = ">>"
	}
	if layout != "list" {
		prefix += time.Unix(0, int64(r.Timestamp*1e9)).In(time.Local).Format("15:04:05")
	}
	return prefix
}

func rightIndicator(r contract.Row) string {
	replay, mark := " ", "  "
	if r.Replay != "" {
		replay = "↺"
	}
	if r.Marked != "" {
		mark = "● "
	}
	return replay + mark
}

func rowDuration(duration float64) string {
	if duration == 0 {
		return "     "
	}
	return fmt.Sprintf("%5s", truncateRight(human.PrettyDuration(duration), 5))
}

func formatHTTPRow(r contract.Row, layout string, width int, focused bool, palette *Palette) string {
	content, contentTag := flowContentType(r.ContentType)
	methodTag, schemeTag, statusTag, durationTag, sizeTag := "", "", "", "", ""
	if palette != nil {
		methodTag, schemeTag = flowMethodTag(r.Method), flowSchemeTag(r.Scheme)
		statusTag = flowStatusTag(r.StatusCode)
		_, durationTag = FormatDuration(r.Duration)
		sizeTag = flowSizeTag(r.Size)
	}
	if r.Intercepted {
		if r.HasResponse {
			statusTag, sizeTag, durationTag = "intercept", "intercept", "intercept"
			if r.Size != 0 && content != "" {
				contentTag = "intercept"
			}
		} else {
			methodTag, schemeTag = "intercept", "intercept"
		}
	}
	if r.PushPromise && layout == "table" {
		methodTag = "method_http2_push"
	}
	if layout == "table" {
		status, size := "", "     "
		if r.HasResponse {
			status = fmt.Sprint(r.StatusCode)
			if r.ContentMissing {
				content, contentTag = "[content missing]", "content_none"
			} else if r.Size == 0 {
				content, contentTag = "[no content]", "content_none"
			}
		} else if r.Error != "" {
			status, content = "err", r.Error
			statusTag, contentTag = "error", "error"
		} else {
			statusTag = "text"
		}
		if r.Size != 0 {
			size = fmt.Sprintf("%5s", truncateRight(human.PrettySize(r.Size), 5))
		}
		return renderFlowColumns(width, 15, []flowColumn{{text: flowLeftIndicator(r, layout, focused, palette)}, {text: Fit(strings.ToUpper(r.Scheme), 5), tag: schemeTag}, {text: Fit(r.Method, 4), tag: methodTag}, {text: r.Host, tag: "host", weight: .25, right: true}, {text: r.Path, tag: "path", weight: 1}, {text: Fit(status, 3), tag: statusTag}, {text: content, tag: contentTag, weight: .15, right: true}, {text: size, tag: sizeTag}, {text: rowDuration(r.Duration), tag: durationTag}, {text: flowRightIndicator(r, palette)}}, palette)
	}
	prefix := flowLeftIndicator(r, "list", focused, palette)
	if layout == "detailview" {
		prefix = flowPaint(palette, "highlight", human.FormatTimestamp(r.Timestamp, time.Local))
	}
	preamble := prefix + " " + flowPaint(palette, flowMethodTag(r.Method), r.Method)
	if r.PushPromise {
		preamble += " " + flowPaint(palette, "method_http2_push", "PUSH_PROMISE")
	}
	url := r.URL
	if r.HTTPVersion != "HTTP/1.0" && r.HTTPVersion != "HTTP/1.1" {
		url += " " + r.HTTPVersion
	}
	urlTag := "title"
	if r.Intercepted && !r.HasResponse {
		urlTag = "intercept"
	} else if r.HasResponse || r.Error != "" {
		urlTag = "text"
	}
	request := renderFlowColumns(width, 1, []flowColumn{{text: preamble}, {text: url, tag: urlTag, weight: 1}, {text: flowRightIndicator(r, palette)}}, palette)
	response := ""
	if r.HasResponse {
		response = flowPaint(palette, statusTag, fmt.Sprintf("← %d", r.StatusCode))
		if layout == "detailview" && r.Reason != "" {
			response += " " + flowPaint(palette, statusTag, r.Reason)
		}
		if content != "" {
			if r.Intercepted {
				contentTag = "intercept"
			}
			response += " " + flowPaint(palette, contentTag, content)
		}
		size := human.PrettySize(r.Size)
		if r.ContentMissing {
			size = "[content missing]"
		} else if r.Size == 0 {
			size = "[no content]"
		}
		if (r.ContentMissing || r.Size == 0) && !r.Intercepted {
			sizeTag = "text"
		}
		response += " " + flowPaint(palette, sizeTag, size)
		if r.Duration != 0 {
			response += " " + flowPaint(palette, durationTag, human.PrettyDuration(r.Duration))
		}
	} else if r.Error != "" {
		response = flowPaint(palette, "error", "← "+r.Error)
	}
	return request + "\n" + Fit(strings.Repeat(" ", Width(preamble)+1)+response, width)
}

func formatStreamRow(r contract.Row, base *flow.Base, layout string, width int, focused bool) string {
	protocol := strings.ToUpper(r.Type)
	if base.ClientConn != nil && base.ClientConn.TLSVersion == connection.QUICv1 {
		protocol = "QUIC"
	}
	if layout == "table" {
		protocol = Fit(protocol, 5)
	}
	client, server := human.NoAddress, human.NoAddress
	if base.ClientConn != nil && base.ClientConn.Peername != nil {
		client = base.ClientConn.Peername.String()
	}
	if base.ServerConn != nil && base.ServerConn.Address != nil {
		server = base.ServerConn.Address.String()
	}
	columns := []flowColumn{{text: leftIndicator(r, layout, focused)}, {text: protocol}, {text: flowText(client + " <-> " + server), weight: 1}}
	if r.Error != "" {
		columns = append(columns, flowColumn{text: r.Error, weight: 1})
	}
	size := "     "
	if r.Size != 0 {
		size = fmt.Sprintf("%5s", truncateRight(human.PrettySize(r.Size), 5))
	}
	return flowColumns(width, 15, append(columns, flowColumn{text: size}, flowColumn{text: rowDuration(r.Duration)}, flowColumn{text: rightIndicator(contract.Row{Marked: r.Marked})}))
}
