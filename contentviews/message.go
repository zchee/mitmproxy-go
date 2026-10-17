// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/tcp"
	"github.com/zchee/mitmproxy-go/udp"
	"github.com/zchee/mitmproxy-go/websocket"
)

// ErrUnsupportedMessage indicates a message type not supported by PrettifyMessage.
var ErrUnsupportedMessage = errors.New("unsupported contentview message")

// PrettifyMessage renders an HTTP, TCP, UDP, or WebSocket message. HTTP inputs
// may be *httpmsg.Message, *httpmsg.Request, or *httpmsg.Response. A nil registry
// uses DefaultRegistry. An empty viewName means auto. Positive lineCutoff limits
// text through that many newlines; nonpositive values leave the text uncut.
// Callers pass options.Manager.Int("content_view_lines_cutoff") when appropriate.
// A failed automatic view falls back to Raw; an explicitly requested view's
// failure is displayed as an error. Result.Err preserves either failure and wraps
// ErrUnsupportedMessage for unsupported message types. The input and its flow
// must not be mutated concurrently while this function runs.
func PrettifyMessage(message any, f flow.Flow, viewName string, registry *Registry, lineCutoff int) Result {
	return PrettifyMessageWithMetadata(message, Metadata{Flow: f}, viewName, registry, lineCutoff)
}

// PrettifyMessageWithMetadata renders a message using the same options and
// fallback behavior as PrettifyMessage. It retains the supplied flow and expands
// the protobuf definitions home path, deriving other metadata from the message.
// It does not mutate the supplied metadata. The message and its flow must not be
// mutated concurrently while this function runs.
func PrettifyMessageWithMetadata(message any, metadata Metadata, viewName string, registry *Registry, lineCutoff int) Result {
	if registry == nil {
		registry = DefaultRegistry
	}
	if viewName == "" {
		viewName = "auto"
	}
	data, metadata, description, err := messageData(message, metadata)
	if err != nil {
		return Result{Text: err.Error(), SyntaxHighlight: "error", Err: err}
	}
	if data == nil {
		return Result{Text: "Content is missing.", SyntaxHighlight: "error"}
	}
	view, err := registry.GetView(data, metadata, viewName)
	if err != nil {
		return Result{Text: err.Error(), SyntaxHighlight: "error", Description: description, Err: err}
	}
	text, err := prettify(view, data, metadata)
	result := Result{Text: text, SyntaxHighlight: view.SyntaxHighlight(), ViewName: view.Name(), Description: description, Err: err}
	if err != nil {
		logSink().Debug("Contentview failed", "view", view.Name(), "error", err)
		if viewName == "auto" {
			result.Text, _ = (Raw{}).Prettify(data, metadata)
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

func prettify(view View, data []byte, metadata Metadata) (text string, err error) {
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

func messageData(message any, supplied Metadata) ([]byte, Metadata, string, error) {
	metadata := Metadata{Flow: supplied.Flow, ProtobufDefinitions: supplied.ProtobufDefinitions}
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
		return nil, metadata, "", fmt.Errorf("%w %T", ErrUnsupportedMessage, message)
	}
	if m := metadata.HTTPMessage; m != nil {
		metadata.Protocol = "http"
		// Content type parsing is deliberately as permissive as upstream: only
		// the media type, before its first parameter, is passed to the views.
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
