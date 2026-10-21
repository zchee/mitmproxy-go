// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package style

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/publicsuffix"

	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

// RenderFlowRow adds upstream HTTP token styles to an owned, escaped projection.
// Non-HTTP rows retain their existing text, without accessing the live flow store.
func RenderFlowRow(row contract.Row, layout string, width int, focused bool, palette Palette) string {
	if row.Type != "http" || row.Method == "" {
		return row.Text
	}
	if layout == "default" || layout == "" {
		layout = "table"
		if strings.Contains(row.Text, "\n") {
			layout = "list"
		}
	}
	return formatHTTPRow(row, layout, width, focused, &palette)
}

func flowPaint(palette *Palette, tag, text string) string {
	if text == "" || palette == nil || tag == "" {
		return text
	}
	return palette.Style(tag).Render(text)
}

func flowLeftIndicator(row contract.Row, layout string, focused bool, palette *Palette) string {
	text := leftIndicator(row, layout, focused)
	if palette == nil {
		return text
	}
	tag := "text"
	if row.Intercepted {
		tag = "intercept"
	}
	return flowPaint(palette, "focus", text[:2]) + flowPaint(palette, tag, text[2:])
}

func flowRightIndicator(row contract.Row, palette *Palette) string {
	if palette == nil {
		return rightIndicator(row)
	}
	replay, mark := " ", "  "
	if row.Replay != "" {
		replay = flowPaint(palette, "replay", "↺")
	}
	if row.Marked != "" {
		mark = flowPaint(palette, "mark", "●") + " "
	}
	return replay + mark
}

func flowMethodTag(method string) string {
	switch method {
	case "GET":
		return "method_get"
	case "POST":
		return "method_post"
	case "DELETE":
		return "method_delete"
	case "HEAD":
		return "method_head"
	case "PUT":
		return "method_put"
	default:
		return "method_other"
	}
}

func flowSchemeTag(scheme string) string {
	switch scheme {
	case "http", "https", "ws", "wss", "tcp", "udp", "dns", "quic":
		return "scheme_" + scheme
	default:
		return "scheme_other"
	}
}

func flowStatusTag(status int) string {
	switch status / 100 {
	case 2:
		return "code_200"
	case 3:
		return "code_300"
	case 4:
		return "code_400"
	case 5:
		return "code_500"
	default:
		return "code_other"
	}
}

func flowContentType(contentType string) (string, string) {
	content, _, _ := strings.Cut(contentType, ";")
	tag := "content_other"
	switch {
	case strings.HasSuffix(content, "/javascript"):
		tag = "content_script"
	case strings.HasPrefix(content, "text/"):
		tag = "content_text"
	case strings.HasPrefix(content, "image/"), strings.HasPrefix(content, "video/"), strings.HasPrefix(content, "font/"), strings.Contains(content, "/x-font-"):
		tag = "content_media"
	case strings.HasSuffix(content, "/json"), strings.HasSuffix(content, "/xml"):
		tag = "content_data"
	case strings.HasPrefix(content, "application/"):
		tag = "content_raw"
	}
	return content, tag
}

func flowSizeTag(size int64) string {
	return fmt.Sprintf("gradient_%02d", int(99-100*min(math.Log2(1+float64(size))/20, .99)))
}

func writeFlowColumn(output *strings.Builder, text, tag string, palette *Palette) {
	if palette == nil {
		output.WriteString(text)
		return
	}
	if tag != "host" && tag != "path" {
		output.WriteString(flowPaint(palette, tag, text))
		return
	}
	path, _, _ := strings.Cut(text, "?")
	query, slash := len(path), strings.LastIndexByte(path, '/')
	extension := strings.LastIndexByte(path[slash+1:], '.')
	if extension >= 0 {
		extension += slash
	} else {
		extension = len(text)
	}
	tld, sld := 0, 0
	if tag == "host" {
		suffix, _ := publicsuffix.PublicSuffix(text)
		domain, err := publicsuffix.EffectiveTLDPlusOne(text)
		if err != nil {
			domain = text
		}
		tld, sld = len(text)-len(suffix), len(text)-len(domain)-1
	}
	start, previous, inValue := 0, "", false
	for index, character := range text {
		attribute := "text"
		if character == '…' {
			attribute = "focus"
		} else if tag == "host" {
			if index >= tld {
				attribute = "url_domain"
			} else if index != tld-1 && index >= sld {
				attribute = "url_extension"
			}
		} else {
			switch {
			case index < query && character == '/', index < query && index > slash && character == '.', index == query:
				attribute = "url_punctuation"
			case index > query:
				attribute = "url_query_key"
				if inValue {
					attribute = "url_query_value"
				}
				if inValue && character == '&' || !inValue && character == '=' {
					inValue = !inValue
					attribute = "url_punctuation"
				}
			case index > extension:
				attribute = "url_extension"
			case index > slash:
				attribute = "url_filename"
			}
		}
		if character == ' ' {
			attribute = "text"
		}
		if previous != "" && previous != attribute {
			output.WriteString(flowPaint(palette, previous, text[start:index]))
			start = index
		}
		previous = attribute
		if index+utf8.RuneLen(character) == len(text) {
			output.WriteString(flowPaint(palette, previous, text[start:]))
		}
	}
}
