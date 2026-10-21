// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"errors"
	"fmt"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

type requestValue struct {
	*object
	i       *invocation
	request *httpmsg.Request
}
type responseValue struct {
	*object
	i        *invocation
	response *httpmsg.Response
}

// HTTP message fields preserve None versus empty content/trailers. Body writes
// use the native setters, so encoding and Content-Length remain consistent.
func messageGet(i *invocation, m *httpmsg.Message, name string) (starlark.Value, error) {
	switch name {
	case "headers":
		return wrapHeaders(i, &m.Headers), nil
	case "trailers":
		if m.Trailers == nil {
			return starlark.None, nil
		}
		return wrapHeaders(i, &m.Trailers), nil
	case "raw_content":
		if m.RawContent == nil {
			return starlark.None, nil
		}
		return starlark.Bytes(m.RawContent), nil
	case "content":
		content, err := m.Content()
		if err != nil {
			return nil, err
		}
		if content == nil {
			return starlark.None, nil
		}
		return starlark.Bytes(content), nil
	case "text":
		if m.RawContent == nil {
			return starlark.None, nil
		}
		text, err := m.Text()
		return starlark.String(text), err
	case "http_version":
		return starlark.String(m.HTTPVersion), nil
	case "stream":
		return starlark.Bool(m.Stream), nil
	case "timestamp_start":
		return starlark.Float(m.TimestampStart), nil
	case "timestamp_end":
		return optionalFloat(m.TimestampEnd), nil
	}
	return nil, nil
}

func messageSet(m *httpmsg.Message, name string, value starlark.Value) error {
	switch name {
	case "headers", "trailers":
		if value == starlark.None && name == "trailers" {
			m.Trailers = nil
			return nil
		}
		h, err := headersNative(value)
		if err != nil {
			return err
		}
		if name == "headers" {
			m.Headers = h
		} else {
			m.Trailers = h
		}
		return nil
	case "content", "raw_content":
		var data []byte
		if value != starlark.None {
			var err error
			data, err = bytesValue(value)
			if err != nil {
				return err
			}
		}
		if name == "content" {
			m.SetContent(data)
		} else {
			m.RawContent = data
		}
		return nil
	case "text":
		if value == starlark.None {
			m.SetContent(nil)
			return nil
		}
		text, err := stringValue(value)
		if err == nil {
			m.SetText(text)
		}
		return err
	case "http_version":
		text, err := stringValue(value)
		if err == nil {
			m.HTTPVersion = text
		}
		return err
	case "stream":
		b, err := boolValue(value)
		if err == nil {
			m.Stream = b
		}
		return err
	}
	return fmt.Errorf("message.%s is read-only or unsupported", name)
}

func wrapRequest(i *invocation, r *httpmsg.Request) starlark.Value {
	if r == nil {
		return starlark.None
	}
	v := &requestValue{i: i, request: r}
	v.object = &object{kind: "request", check: i.modelCheck, names: []string{"host", "port", "scheme", "method", "authority", "path", "url", "pretty_host", "pretty_url", "query", "urlencoded_form", "headers", "trailers", "content", "raw_content", "text", "http_version", "stream", "timestamp_start", "timestamp_end"}, get: func(name string) (starlark.Value, error) {
		switch name {
		case "host":
			return starlark.String(r.Host), nil
		case "port":
			return starlark.MakeInt(r.Port), nil
		case "scheme":
			return starlark.String(r.Scheme), nil
		case "method":
			return starlark.String(r.Method), nil
		case "authority":
			return starlark.String(r.Authority), nil
		case "path":
			return starlark.String(r.Path), nil
		case "url":
			return starlark.String(r.URL()), nil
		case "pretty_host":
			return starlark.String(r.PrettyHost()), nil
		case "pretty_url":
			return starlark.String(r.PrettyURL()), nil
		case "query":
			return wrapPairs(i, r.Query, r.SetQuery), nil
		case "urlencoded_form":
			return wrapPairs(i, r.URLEncodedForm, r.SetURLEncodedForm), nil
		}
		return messageGet(i, &r.Message, name)
	}, set: func(name string, value starlark.Value) error {
		switch name {
		case "port":
			port, err := intValue(value)
			if err != nil {
				return err
			}
			if port < 0 || port > 65535 {
				return errors.New("port is outside 0..65535")
			}
			r.SetPort(port)
			return nil
		case "host", "scheme", "method", "authority", "path", "url":
			x, err := stringValue(value)
			if err != nil {
				return err
			}
			switch name {
			case "host":
				r.SetHost(x)
			case "scheme":
				r.Scheme = x
			case "method":
				r.Method = x
			case "authority":
				r.SetAuthority(x)
			case "path":
				r.Path = x
			case "url":
				return r.SetURL(x)
			}
			return nil
		case "query", "urlencoded_form":
			h, err := headersNative(value)
			if err != nil {
				return err
			}
			pairs := make([][2]string, len(h))
			for n, field := range h {
				pairs[n] = [2]string{string(field.Name), string(field.Value)}
			}
			if name == "query" {
				r.SetQuery(pairs)
			} else {
				r.SetURLEncodedForm(pairs)
			}
			return nil
		}
		return messageSet(&r.Message, name, value)
	}}
	return v
}

func wrapResponse(i *invocation, r *httpmsg.Response) starlark.Value {
	if r == nil {
		return starlark.None
	}
	v := &responseValue{i: i, response: r}
	v.object = &object{kind: "response", check: i.modelCheck, names: []string{"status_code", "reason", "headers", "trailers", "content", "raw_content", "text", "http_version", "stream", "timestamp_start", "timestamp_end"}, get: func(name string) (starlark.Value, error) {
		switch name {
		case "status_code":
			return starlark.MakeInt(r.StatusCode), nil
		case "reason":
			return starlark.String(r.Reason), nil
		}
		return messageGet(i, &r.Message, name)
	}, set: func(name string, value starlark.Value) error {
		switch name {
		case "status_code":
			n, err := intValue(value)
			if err != nil {
				return err
			}
			if n < 100 || n > 999 {
				return errors.New("status_code is outside 100..999")
			}
			r.StatusCode = n
			return nil
		case "reason":
			text, err := stringValue(value)
			if err == nil {
				r.Reason = text
			}
			return err
		}
		return messageSet(&r.Message, name, value)
	}}
	return v
}

func httpLibrary(g *capabilities) starlark.Value {
	makeResponse := builtin("http.Response.make", g.check, func(thread *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		i, err := threadInvocation(thread)
		if err != nil {
			return nil, err
		}
		status := 200
		content := starlark.Value(starlark.Bytes(""))
		headers := starlark.Value(starlark.NewDict(0))
		if err := starlark.UnpackArgs("http.Response.make", args, kwargs, "status_code?", &status, "content?", &content, "headers?", &headers); err != nil {
			return nil, err
		}
		var data []byte
		if s, ok := starlark.AsString(content); ok {
			data = []byte(s)
		} else {
			data, err = bytesValue(content)
			if err != nil {
				return nil, err
			}
		}
		h, err := headersNative(headers)
		if err != nil {
			return nil, err
		}
		r, err := httpmsg.MakeResponse(status, data, h)
		if err != nil {
			return nil, err
		}
		return wrapResponse(i, r), nil
	})
	makeHeaders := builtin("http.Headers", g.check, func(thread *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		i, err := threadInvocation(thread)
		if err != nil {
			return nil, err
		}
		fields := starlark.Value(starlark.NewList(nil))
		if err := starlark.UnpackArgs("http.Headers", args, kwargs, "fields?", &fields); err != nil {
			return nil, err
		}
		h, err := headersNative(fields)
		if err != nil {
			return nil, err
		}
		if h == nil {
			h = httpmsg.Headers{}
		}
		return wrapHeaders(i, &h), nil
	})
	return &starlarkstruct.Module{Name: "http", Members: starlark.StringDict{
		"Response": &starlarkstruct.Module{Name: "Response", Members: starlark.StringDict{"make": makeResponse}},
		"Headers":  makeHeaders,
	}}
}
