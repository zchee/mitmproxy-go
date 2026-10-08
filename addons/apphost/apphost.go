// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package apphost serves in-process HTTP handlers from proxy request hooks.
package apphost

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

// App hosts an HTTP handler at a hostname and optional port. Responses are
// buffered completely before they are assigned to the flow. Handlers run
// outside the dispatch lock and must support concurrent requests. WebSocket
// upgrades and connection hijacking are not supported.
//
// App methods are called under the addon's dispatch lock.
type App struct {
	handler http.Handler
	host    string
	port    int
	name    string
}

// New returns an app hosting handler for host. A zero port matches any port.
func New(handler http.Handler, host string, port int) *App {
	portName := "None"
	if port != 0 {
		portName = strconv.Itoa(port)
	}
	return &App{handler: handler, host: host, port: port, name: "asgiapp:" + host + ":" + portName}
}

// Name returns the app's registration name, fixed when it is constructed.
func (a *App) Name() string { return a.name }

// SetHost changes the host matched by the app. Call it under the dispatch lock.
func (a *App) SetHost(host string) { a.host = host }

// Request serves matching live requests that do not already have a response
// or an error. The handler runs inside addon.Concurrent with a private request
// snapshot; the completed response is published after reacquiring the lock.
func (a *App) Request(ctx context.Context, f *flow.HTTPFlow) error {
	if f.Request == nil || f.Request.PrettyHost() != a.host || (a.port != 0 && f.Request.Port != a.port) || !f.Live || f.Error != nil || f.Response != nil {
		return nil
	}
	source := f.Request.Clone()
	u, err := url.ParseRequestURI(source.Path)
	if err != nil {
		return appError(f, err)
	}
	u.Scheme = source.Scheme
	host, present := source.HostHeader()
	if !present {
		host = net.JoinHostPort(source.Host, strconv.Itoa(source.Port))
	}
	u.Host = host
	req, err := http.NewRequestWithContext(ctx, source.Method, u.String(), bytes.NewReader(source.RawContent))
	if err != nil {
		return appError(f, err)
	}
	req.RequestURI = source.Path
	req.Proto = source.HTTPVersion
	if major, minor, ok := http.ParseHTTPVersion(source.HTTPVersion); ok {
		req.ProtoMajor, req.ProtoMinor = major, minor
	}
	for _, field := range source.Headers {
		req.Header.Add(string(field.Name), string(field.Value))
	}
	if f.ClientConn != nil && f.ClientConn.Peername != nil {
		req.RemoteAddr = net.JoinHostPort(f.ClientConn.Peername.Host, strconv.Itoa(f.ClientConn.Peername.Port))
	}
	handler := a.handler
	var response *httpmsg.Response
	_, err = addon.Concurrent(ctx, func(ctx context.Context) error {
		var err error
		response, err = serve(handler, req.WithContext(ctx))
		return err
	})
	if err := ctx.Err(); err != nil {
		return err
	}
	if err != nil {
		return appError(f, err)
	}
	f.Response = response
	return nil
}

func appError(f *flow.HTTPFlow, err error) error {
	f.Response, _ = httpmsg.MakeResponse(http.StatusInternalServerError, []byte("ASGI Error."), nil)
	return fmt.Errorf("Error in asgi app: %w", err) //nolint:staticcheck // Preserve upstream's logged error prefix.
}

func serve(handler http.Handler, request *http.Request) (response *httpmsg.Response, err error) {
	defer func() {
		if value := recover(); value != nil {
			response, err = nil, fmt.Errorf("handler panic: %v", value)
		}
	}()
	recorder := httptest.NewRecorder()
	// Unlike a network http.Server, upstream rejects an app that returns
	// without starting a response. An explicit WriteHeader(200) is valid.
	recorder.Code = 0
	handler.ServeHTTP(recorder, request)
	if recorder.Code == 0 {
		return nil, fmt.Errorf("no response sent")
	}
	result := recorder.Result()
	defer func() { _ = result.Body.Close() }()
	response, err = httpmsg.MakeResponse(result.StatusCode, nil, nil)
	if err != nil {
		return nil, err
	}
	response.Headers = make(httpmsg.Headers, 0, len(result.Header))
	for _, name := range slices.Sorted(maps.Keys(result.Header)) {
		for _, value := range result.Header[name] {
			response.Headers.Add(name, value)
		}
	}
	// Handler bytes are already in their wire encoding; SetContent would
	// encode a compressed response a second time.
	response.RawContent = recorder.Body.Bytes()
	if request.Method == http.MethodHead {
		response.RawContent = []byte{}
	}
	if !response.Headers.Has("transfer-encoding") && (request.Method != http.MethodHead || !response.Headers.Has("content-length")) {
		response.Headers.Set("content-length", strconv.Itoa(recorder.Body.Len()))
	}
	return response, nil
}
