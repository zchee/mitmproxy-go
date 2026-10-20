// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

func (a *application) editFlow(ctx context.Context, f flow.Flow, body []byte) (err error) {
	f.Backup()
	defer func() {
		if _, ok := errors.AsType[*APIError](err); ok {
			if revertErr := f.Revert(); revertErr != nil {
				err = errors.Join(err, revertErr)
			}
		}
	}()
	fields, err := jsonObject(body)
	if err != nil {
		return err
	}
	for key, value := range fields.All() {
		switch key {
		case "marked", "comment":
			var text string
			if err := json.Unmarshal(value, &text); err != nil {
				return err
			}
			if key == "marked" {
				f.Common().Marked = text
			} else {
				f.Common().Comment = text
			}
		case "request", "response":
			httpFlow, ok := f.(*flow.HTTPFlow)
			if !ok {
				return apiError(400, "Unknown update "+key+": "+jsonDisplay(value))
			}
			changes, err := jsonObject(value)
			if err != nil {
				return err
			}
			for field, raw := range changes.All() {
				if err := updateHTTP(httpFlow, key, field, raw); err != nil {
					return err
				}
			}
		default:
			return apiError(400, "Unknown update "+key+": "+jsonDisplay(value))
		}
	}
	return a.view.Update(ctx, []flow.Flow{f})
}

func updateHTTP(f *flow.HTTPFlow, part, key string, value jsontext.Value) error {
	var message *httpmsg.Message
	if part == "request" && f.Request != nil {
		message = &f.Request.Message
	}
	if part == "response" && f.Response != nil {
		message = &f.Response.Message
	}
	if message == nil {
		return fmt.Errorf("flow has no %s", part)
	}
	switch key {
	case "headers", "trailers":
		var pairs [][]string
		if err := json.Unmarshal(value, &pairs); err != nil {
			return err
		}
		headers := make(httpmsg.Headers, 0, len(pairs))
		for _, pair := range pairs {
			if len(pair) != 2 {
				return fmt.Errorf("header requires two values")
			}
			headers = append(headers, httpmsg.Field{Name: []byte(pair[0]), Value: []byte(pair[1])})
		}
		if key == "headers" {
			message.Headers = headers
		} else {
			message.Trailers = headers
		}
	case "content":
		if string(value) == "null" {
			message.SetContent(nil)
			return nil
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return err
		}
		message.SetText(text)
	case "http_version":
		message.HTTPVersion = jsonDisplay(value)
	default:
		if part == "request" {
			text := jsonDisplay(value)
			switch key {
			case "method":
				f.Request.Method = text
			case "scheme":
				f.Request.Scheme = text
			case "host":
				f.Request.SetHost(text)
			case "path":
				f.Request.Path = text
			case "port":
				number, err := jsonInteger(value)
				if err != nil {
					return err
				}
				f.Request.SetPort(number)
			default:
				return apiError(400, "Unknown update request."+key+": "+text)
			}
		} else {
			switch key {
			case "reason":
				f.Response.Reason = jsonDisplay(value)
			case "code":
				number, err := jsonInteger(value)
				if err != nil {
					return err
				}
				f.Response.StatusCode = number
			default:
				return apiError(400, "Unknown update response."+key+": "+jsonDisplay(value))
			}
		}
	}
	return nil
}

func jsonInteger(raw []byte) (int, error) {
	var integer int
	if err := json.Unmarshal(raw, &integer); err == nil {
		return integer, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(text))
}

func jsonDisplay(raw []byte) string {
	return jsonRepr(raw, false)
}

func jsonRepr(raw []byte, quoteString bool) string {
	if len(raw) == 0 {
		return ""
	}
	switch raw[0] {
	case '"':
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return string(raw)
		}
		if quoteString {
			return pyrepr.Str(text)
		}
		return text
	case 'n':
		return "None"
	case 't':
		return "True"
	case 'f':
		return "False"
	case '[':
		var values []jsontext.Value
		if json.Unmarshal(raw, &values) != nil {
			return string(raw)
		}
		parts := make([]string, len(values))
		for i, value := range values {
			parts[i] = jsonRepr(value, true)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case '{':
		object, err := jsonObject(raw)
		if err != nil {
			return string(raw)
		}
		parts := make([]string, 0, object.Len())
		for key, value := range object.All() {
			parts = append(parts, pyrepr.Str(key)+": "+jsonRepr(value, true))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return string(raw)
	}
}
