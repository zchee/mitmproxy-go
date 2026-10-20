// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/omap"
)

const receiveLimit int64 = 4 << 30

// APIError is an upstream-compatible HTTP error with a literal response body.
type APIError struct {
	Status  int
	Message string
}

// Error returns the API diagnostic.
func (e *APIError) Error() string { return e.Message }

func apiError(status int, message string) error { return &APIError{Status: status, Message: message} }

func writeWebError(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError
	var body string
	if e, ok := errors.AsType[*APIError](err); ok {
		status, body = e.Status, e.Message
	} else {
		slog.ErrorContext(r.Context(), "Web request failed", "error", err)
	}
	if body == "" {
		body = fmt.Sprintf("<html><title>%d: %s</title><body>%d: %s</body></html>", status, http.StatusText(status), status, http.StatusText(status))
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Del("Content-Disposition")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, body)
	}
}

func requestJSON(r *http.Request) ([]byte, error) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return nil, apiError(400, "Invalid Content-Type, expected application/json.")
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var value jsontext.Value
	if err := json.Unmarshal(body, &value, jsontext.AllowDuplicateNames(true)); err != nil {
		if syntax, ok := errors.AsType[*jsontext.SyntacticError](err); ok {
			return nil, apiError(400, fmt.Sprintf("Malformed JSON: %v (byte %d)", syntax.Err, syntax.ByteOffset))
		}
		return nil, apiError(400, "Malformed JSON: "+err.Error())
	}
	return body, nil
}

// Decode objects in insertion order: edits and duplicate keys follow Python dicts.
func jsonObject(body []byte) (*omap.Map[jsontext.Value], error) {
	decoder := jsontext.NewDecoder(bytes.NewReader(body), jsontext.AllowDuplicateNames(true))
	token, err := decoder.ReadToken()
	if err != nil {
		return nil, err
	}
	if token.Kind() != '{' {
		return nil, fmt.Errorf("JSON value has kind %q, expected an object", token.Kind())
	}
	result := omap.New[jsontext.Value]()
	for decoder.PeekKind() != '}' {
		key, err := decoder.ReadToken()
		if err != nil {
			return nil, err
		}
		name := key.String()
		value, err := decoder.ReadValue()
		if err != nil {
			return nil, err
		}
		result.Set(name, bytes.Clone(value))
	}
	if _, err := decoder.ReadToken(); err != nil {
		return nil, err
	}
	return result, nil
}
