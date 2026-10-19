// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

var downloadFilename = regexp.MustCompile(`filename=([-\pL\pN_" .()]+)`)

func (a *application) flowContent(w http.ResponseWriter, r *http.Request, name string, args []string) error {
	var uploaded []byte
	if r.Method == http.MethodPost {
		input, err := a.upload(r)
		if err != nil {
			return err
		}
		defer func() { _ = input.Close() }()
		uploaded, err = io.ReadAll(input)
		if err != nil {
			return err
		}
	}
	var snapshot flow.Flow
	var definitions string
	err := a.master.Do(r.Context(), func(ctx context.Context) error {
		f := a.view.GetByID(args[0])
		if f == nil {
			return apiError(404, "Flow not found.")
		}
		if r.Method == http.MethodPost {
			f.Backup()
			message, err := httpMessage(f, args[1])
			if err != nil {
				return err
			}
			message.SetContent(uploaded)
			return a.view.Update(ctx, []flow.Flow{f})
		}
		var err error
		snapshot, err = flow.FromState(state.CopyMap(f.GetState()))
		if a.master.Options.Has("protobuf_definitions") {
			if value := a.master.Options.OptStr("protobuf_definitions"); value != nil {
				definitions = *value
			}
		}
		return err
	})
	if err != nil || r.Method == http.MethodPost {
		return err
	}
	if name == "flow_content" {
		message, err := httpMessage(snapshot, args[1])
		if err != nil {
			return err
		}
		httpFlow := snapshot.(*flow.HTTPFlow)
		filename := ""
		if match := downloadFilename.FindStringSubmatch(message.Headers.Get("Content-Disposition")); match != nil {
			filename = match[1]
		}
		if filename == "" {
			filename, _, _ = strings.Cut(httpFlow.Request.Path, "?")
			_, last, found := strings.CutLast(filename, "/")
			if found {
				filename = last
			}
		}
		filename = strings.Map(func(char rune) rune {
			if unicode.IsLetter(char) || unicode.IsNumber(char) || strings.ContainsRune(`-_" .()`, char) {
				return char
			}
			return -1
		}, filename)
		body := bytes.Clone(message.ContentOrRaw())
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Header().Set("Content-Type", "application/text")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, err = w.Write(body)
		return err
	}
	limit := 0
	if values := r.URL.Query()["lines"]; len(values) > 0 {
		limit, err = strconv.Atoi(strings.TrimSpace(values[0]))
		if err != nil {
			return err
		}
	}
	viewName := args[2]
	if strings.EqualFold(viewName, "auto") {
		viewName = "auto"
	}
	metadata := contentviews.Metadata{Flow: snapshot, ProtobufDefinitions: definitions}
	render := func(message any, fromClient *bool, timestamp *float64) map[string]any {
		pretty := contentviews.PrettifyMessageWithMetadata(message, metadata, viewName, nil, limit)
		value := map[string]any{"text": pretty.Text, "view_name": pretty.ViewName, "syntax_highlight": pretty.SyntaxHighlight, "description": pretty.Description}
		if fromClient != nil {
			value["from_client"] = *fromClient
		}
		if timestamp != nil {
			value["timestamp"] = *timestamp
		}
		if limit > 0 {
			limit -= strings.Count(pretty.Text, "\n") + 1
		}
		return value
	}
	if args[1] != "messages" {
		message, err := httpMessage(snapshot, args[1])
		if err != nil {
			return err
		}
		return writeJSON(w, render(message, nil, nil))
	}
	values := make([]map[string]any, 0)
	bounded := limit > 0
	switch f := snapshot.(type) {
	case *flow.HTTPFlow:
		if f.WebSocket == nil {
			return apiError(400, "This flow has no messages.")
		}
		for _, message := range f.WebSocket.Messages {
			values = append(values, render(message, &message.FromClient, &message.Timestamp))
			if bounded && limit <= 0 {
				break
			}
		}
	case *flow.TCPFlow:
		for _, message := range f.Messages {
			values = append(values, render(message, &message.FromClient, &message.Timestamp))
			if bounded && limit <= 0 {
				break
			}
		}
	case *flow.UDPFlow:
		for _, message := range f.Messages {
			values = append(values, render(message, &message.FromClient, &message.Timestamp))
			if bounded && limit <= 0 {
				break
			}
		}
	default:
		return fmt.Errorf("contentview requires HTTP, TCP or UDP flow")
	}
	return writeJSON(w, values)
}

func httpMessage(f flow.Flow, part string) (*httpmsg.Message, error) {
	value, ok := f.(*flow.HTTPFlow)
	if !ok {
		return nil, fmt.Errorf("HTTP content requires an HTTP flow")
	}
	switch part {
	case "request":
		if value.Request != nil {
			return &value.Request.Message, nil
		}
	case "response":
		if value.Response != nil {
			return &value.Response.Message, nil
		}
	}
	return nil, fmt.Errorf("flow has no HTTP %s message", part)
}
