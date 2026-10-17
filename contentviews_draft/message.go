// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// PrettifyMessage retains the original renderer's flow-only entry point.
func PrettifyMessage(message any, f flow.Flow, viewName string, registry *contentviews.Registry, lineCutoff int) contentviews.Result {
	return PrettifyMessageWithMetadata(message, contentviews.Metadata{Flow: f}, viewName, registry, lineCutoff)
}

// PrettifyMessageWithMetadata renders a message while retaining caller-supplied
// flow and protobuf definitions. Actual input determines all message pointers.
// Rendering does not mutate either the supplied metadata or the message.
func PrettifyMessageWithMetadata(message any, metadata contentviews.Metadata, viewName string, registry *contentviews.Registry, lineCutoff int) contentviews.Result {
	if registry == nil {
		registry = contentviews.DefaultRegistry
	}
	if viewName == "" {
		viewName = "auto"
	}
	data, metadata, description, err := messageData(message, metadata)
	if err != nil {
		return contentviews.Result{Text: err.Error(), SyntaxHighlight: "error", Err: err}
	}
	if data == nil {
		return contentviews.Result{Text: "Content is missing.", SyntaxHighlight: "error"}
	}
	view, err := registry.GetView(data, metadata, viewName)
	if err != nil {
		return contentviews.Result{Text: err.Error(), SyntaxHighlight: "error", Description: description, Err: err}
	}
	text, err := prettify(view, data, metadata)
	result := contentviews.Result{Text: text, SyntaxHighlight: view.SyntaxHighlight(), ViewName: view.Name(), Description: description, Err: err}
	if err != nil {
		slog.Debug("Contentview failed", "view", view.Name(), "error", err)
		if viewName == "auto" {
			result.Text, _ = (contentviews.Raw{}).Prettify(data, metadata)
			result.SyntaxHighlight = "none"
			result.ViewName = "Raw"
			result.Description += "[failed to parse as " + view.Name() + "]"
		} else {
			result.Text = fmt.Sprintf("Couldn't parse as %s:\n%s\n", view.Name(), err)
			result.SyntaxHighlight = "error"
		}
	}
	result.Text = strutil.EscapeControlCharacters(result.Text, true)
	if lineCutoff > 0 {
		cut := strutil.CutAfterNLines(result.Text, lineCutoff)
		result.Truncated = len(cut) < len(result.Text)
		result.Text = cut
	}
	return result
}

func prettify(view contentviews.View, data []byte, metadata contentviews.Metadata) (text string, err error) {
	defer func() {
		if value := recover(); value != nil {
			var ok bool
			if err, ok = value.(error); !ok {
				err = fmt.Errorf("%v", value)
			}
		}
	}()
	return view.Prettify(data, metadata)
}

func expandProtobufDefinitions(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	separators := "/"
	if runtime.GOOS == "windows" {
		separators = `/\`
	}
	end := strings.IndexAny(path, separators)
	if end < 0 {
		end = len(path)
	}
	name := path[1:end]
	home, err := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		if err != nil {
			if suffix, found := os.LookupEnv("HOMEPATH"); found {
				home = os.Getenv("HOMEDRIVE") + suffix
			}
		}
		if name != "" && name != os.Getenv("USERNAME") {
			if filepath.Base(home) != os.Getenv("USERNAME") {
				return "", fmt.Errorf("cannot resolve protobuf definitions home")
			}
			home = filepath.Join(filepath.Dir(home), name)
		}
	} else if name != "" {
		account, lookupErr := user.Lookup(name)
		if lookupErr != nil {
			return "", fmt.Errorf("cannot resolve protobuf definitions home")
		}
		home = account.HomeDir
	} else if err != nil {
		account, lookupErr := user.Current()
		if lookupErr != nil {
			return "", fmt.Errorf("cannot resolve protobuf definitions home")
		}
		home = account.HomeDir
	}
	if home == "" {
		return "", fmt.Errorf("cannot resolve protobuf definitions home")
	}
	var expanded strings.Builder
	expanded.WriteString(strings.TrimRight(home, separators))
	for part := range strings.FieldsFuncSeq(path[end:], func(r rune) bool { return strings.ContainsRune(separators, r) }) {
		if part != "." {
			expanded.WriteByte(filepath.Separator)
			expanded.WriteString(part)
		}
	}
	if expanded.Len() == 0 {
		expanded.WriteByte(filepath.Separator)
	}
	return expanded.String(), nil
}

func messageData(message any, supplied contentviews.Metadata) ([]byte, contentviews.Metadata, string, error) {
	metadata := contentviews.Metadata{Flow: supplied.Flow, ProtobufDefinitions: supplied.ProtobufDefinitions}
	definitions, err := expandProtobufDefinitions(metadata.ProtobufDefinitions)
	if err != nil {
		return nil, metadata, "", err
	}
	metadata.ProtobufDefinitions = definitions
	switch m := message.(type) {
	case *httpmsg.Request:
		if m != nil {
			metadata.HTTPMessage = &m.Message
			metadata.HTTPRequest = m
		}
	case *httpmsg.Response:
		if m != nil {
			metadata.HTTPMessage = &m.Message
		}
	case *httpmsg.Message:
		metadata.HTTPMessage = m
		if f, ok := metadata.Flow.(*flow.HTTPFlow); ok && f != nil && f.Request != nil && m == &f.Request.Message {
			metadata.HTTPRequest = f.Request
		}
	case *tcp.Message:
		metadata.TCPMessage = m
		metadata.Protocol = "tcp"
		if m != nil {
			return m.Content, metadata, "", nil
		}
	case *udp.Message:
		metadata.UDPMessage = m
		metadata.Protocol = "udp"
		if m != nil {
			return m.Content, metadata, "", nil
		}
	case *websocket.Message:
		metadata.WebSocketMessage = m
		metadata.Protocol = "websocket"
		if m != nil {
			return m.Content, metadata, "", nil
		}
	case nil:
		return nil, metadata, "", nil
	default:
		return nil, metadata, "", fmt.Errorf("%w %T", contentviews.ErrUnsupportedMessage, message)
	}
	if m := metadata.HTTPMessage; m != nil {
		metadata.Protocol = "http"
		media, _, _ := strings.Cut(m.Headers.Get("content-type"), ";")
		major, minor, ok := strings.Cut(media, "/")
		if ok {
			metadata.ContentType = strings.TrimSpace(major) + "/" + strings.TrimSpace(minor)
		}
		data, err := m.Content()
		if err != nil {
			return m.RawContent, metadata, "[cannot decode]", nil
		}
		if !bytes.Equal(data, m.RawContent) {
			return data, metadata, "[decoded " + m.Headers.Get("content-encoding") + "]", nil
		}
		return data, metadata, "", nil
	}
	return nil, metadata, "", nil
}
