// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

func splitH2PseudoHeaders(fields []hpack.HeaderField) (map[string]string, httpmsg.Headers, error) {
	pseudo := make(map[string]string)
	i := 0
	for ; i < len(fields) && fields[i].IsPseudo(); i++ {
		field := fields[i]
		if _, exists := pseudo[field.Name]; exists {
			return nil, nil, fmt.Errorf("Duplicate HTTP/2 pseudo header: %s", pyrepr.Bytes([]byte(field.Name))) //nolint:staticcheck // Preserve upstream's protocol diagnostic.
		}
		pseudo[field.Name] = field.Value
	}
	return pseudo, h2RegularHeaders(fields[i:]), nil
}

func h2RegularHeaders(fields []hpack.HeaderField) httpmsg.Headers {
	headers := make(httpmsg.Headers, 0, len(fields))
	for _, field := range fields {
		headers = append(headers, httpmsg.Field{Name: []byte(field.Name), Value: []byte(field.Value)})
	}
	return headers
}

func requireH2Pseudo(pseudo map[string]string, name string) (string, error) {
	value, exists := pseudo[name]
	if !exists {
		return "", fmt.Errorf("Required pseudo header is missing: %s", pyrepr.Bytes([]byte(name))) //nolint:staticcheck // Preserve upstream's protocol diagnostic.
	}
	delete(pseudo, name)
	return value, nil
}

func unknownH2Pseudo(fields []hpack.HeaderField, remaining map[string]string) error {
	if len(remaining) == 0 {
		return nil
	}
	var message strings.Builder
	message.WriteString("Unknown pseudo headers: {")
	first := true
	for _, field := range fields {
		if !field.IsPseudo() {
			break
		}
		if _, exists := remaining[field.Name]; !exists {
			continue
		}
		if !first {
			message.WriteString(", ")
		}
		first = false
		message.WriteString(pyrepr.Bytes([]byte(field.Name)))
		message.WriteString(": ")
		message.WriteString(pyrepr.Bytes([]byte(field.Value)))
	}
	message.WriteByte('}')
	return fmt.Errorf("%s", message.String())
}

func parseH2RequestHeaders(fields []hpack.HeaderField) (*httpmsg.Request, error) {
	pseudo, headers, err := splitH2PseudoHeaders(fields)
	if err != nil {
		return nil, err
	}
	method, err := requireH2Pseudo(pseudo, ":method")
	if err != nil {
		return nil, err
	}
	scheme, err := requireH2Pseudo(pseudo, ":scheme")
	if err != nil {
		return nil, err
	}
	path, err := requireH2Pseudo(pseudo, ":path")
	if err != nil {
		return nil, err
	}
	authority := pseudo[":authority"]
	delete(pseudo, ":authority")
	if err := unknownH2Pseudo(fields, pseudo); err != nil {
		return nil, err
	}
	request := &httpmsg.Request{HTTPVersion: "HTTP/2.0", Headers: headers, Method: method, Scheme: scheme, Authority: authority, Path: path}
	if authority != "" {
		request.Host, request.Port, err = httpmsg.ParseAuthorityBytes([]byte(authority), true)
		if err != nil {
			return nil, err
		}
		if request.Port == -1 {
			request.Port = 443
			if scheme == "http" {
				request.Port = 80
			}
		}
	}
	return request, nil
}

func parseH2ResponseHeaders(fields []hpack.HeaderField) (*httpmsg.Response, error) {
	pseudo, headers, err := splitH2PseudoHeaders(fields)
	if err != nil {
		return nil, err
	}
	status, err := requireH2Pseudo(pseudo, ":status")
	if err != nil {
		return nil, err
	}
	code, err := strconv.Atoi(strings.Trim(status, " \t\n\r\v\f"))
	if err != nil {
		return nil, fmt.Errorf("invalid literal for int() with base 10: %s", pyrepr.Bytes([]byte(status)))
	}
	if err := unknownH2Pseudo(fields, pseudo); err != nil {
		return nil, err
	}
	return &httpmsg.Response{HTTPVersion: "HTTP/2.0", Headers: headers, StatusCode: code}, nil
}

func formatH2RequestHeaders(request *httpmsg.Request, normalize bool, logger *slog.Logger) []hpack.HeaderField {
	fields := []hpack.HeaderField{{Name: ":method", Value: request.Method}, {Name: ":scheme", Value: request.Scheme}, {Name: ":path", Value: request.Path}}
	headers := request.Headers
	if request.Authority != "" {
		fields = append(fields, hpack.HeaderField{Name: ":authority", Value: request.Authority})
	} else if !request.IsHTTP2() && !request.IsHTTP3() && headers.Has("host") {
		fields = append(fields, hpack.HeaderField{Name: ":authority", Value: headers.Get("host")})
		headers = headers.Clone()
		headers.Del("host")
	}
	return append(fields, formatH2RegularHeaders(headers, request.IsHTTP2() || request.IsHTTP3(), normalize, logger)...)
}

func formatH2ResponseHeaders(response *httpmsg.Response, normalize bool, logger *slog.Logger) []hpack.HeaderField {
	fields := []hpack.HeaderField{{Name: ":status", Value: strconv.Itoa(response.StatusCode)}}
	return append(fields, formatH2RegularHeaders(response.Headers, response.IsHTTP2() || response.IsHTTP3(), normalize, logger)...)
}

func formatH2RegularHeaders(headers httpmsg.Headers, alreadyH2, normalize bool, logger *slog.Logger) []hpack.HeaderField {
	fields := make([]hpack.HeaderField, 0, len(headers))
	for _, header := range headers {
		name, value := string(header.Name), string(header.Value)
		if alreadyH2 {
			if normalize {
				var isLower bool
				name, isLower = lowercaseH2Name(name)
				if !isLower {
					if logger == nil {
						logger = slog.Default()
					}
					logger.Info(fmt.Sprintf("Lowercased %s header as uppercase is not allowed with HTTP/2.", strings.TrimPrefix(pyrepr.Bytes(header.Name), "b")))
				}
			}
			fields = append(fields, hpack.HeaderField{Name: name, Value: value})
			continue
		}
		name, _ = lowercaseH2Name(name)
		name = strings.Trim(name, " \t\n\r\v\f")
		value = strings.Trim(value, " \t\n\r\v\f")
		switch name {
		case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
			continue
		}
		sensitive := name == "authorization" || name == "proxy-authorization" || strings.Contains("cookie", name) && len(value) < 20
		fields = append(fields, hpack.HeaderField{Name: name, Value: value, Sensitive: sensitive})
	}
	return fields
}

// Header names are byte strings: Python's bytes.lower/islower do not fold Unicode.
func lowercaseH2Name(name string) (string, bool) {
	var lowered []byte
	cased, lower := false, true
	for i := range len(name) {
		b := name[i]
		if b >= 'a' && b <= 'z' {
			cased = true
		} else if b >= 'A' && b <= 'Z' {
			cased, lower = true, false
			if lowered == nil {
				lowered = []byte(name)
			}
			lowered[i] = b + ('a' - 'A')
		}
	}
	if lowered != nil {
		return string(lowered), false
	}
	return name, cased && lower
}
