// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest && unix

package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/zchee/gows"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

type webOriginRequest struct {
	Method string
	Path   string
	Header string
}

type webLiveResult struct {
	Added  []any
	Origin webOriginRequest
}

func testLiveWebFlows(t *testing.T, binary string) {
	t.Helper()
	requests := make(chan webOriginRequest, 8)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requests <- webOriginRequest{r.Method, r.URL.RequestURI(), r.Header.Get("X-Acceptance")}:
		default:
			t.Error("controlled origin request inventory overflow")
		}
		if _, err := io.WriteString(w, "live replay response"); err != nil {
			t.Errorf("controlled origin response: %v", err)
		}
	}))
	defer origin.Close()
	var headers httpmsg.Headers
	headers.Set("X-Acceptance", "live-replay-nonsecret")
	request, err := httpmsg.MakeRequest(http.MethodGet, origin.URL+"/live-replay", []byte{}, headers)
	if err != nil {
		t.Fatal(err)
	}
	request.Headers.Set("Host", httpmsg.HostPort(request.Scheme, request.Host, request.Port))
	address := connection.Address{Host: request.Host, Port: request.Port}
	input := flow.NewHTTPFlow(connection.NewClient(connection.Address{Host: "127.0.0.1", Port: 12345}, connection.Address{Host: "127.0.0.1", Port: 18080}, 1), connection.NewServer(new(address)), false)
	input.Request = request
	var dump bytes.Buffer
	if err := flowio.NewWriter(&dump).Add(input); err != nil {
		t.Fatal(err)
	}
	tuple := newWebInputTuple(t, "")
	uv, args := pythonWebCommand(t, tuple)
	python := captureLiveWebFlows(t, startWebProcess(t, uv, args, "python-live"), tuple, dump.Bytes(), requests)
	select {
	case <-requests:
		t.Fatal("Python replay produced an extra origin request")
	default:
	}
	resetWebConfdir(t, tuple)
	goResult := captureLiveWebFlows(t, startWebProcess(t, binary, tuple.goArgs(), "go-live"), tuple, dump.Bytes(), requests)
	select {
	case <-requests:
		t.Fatal("Go replay produced an extra origin request")
	default:
	}
	if diff := gocmp.Diff(python, goResult); diff != "" {
		t.Errorf("live flows/add sequence or real-origin replay differs (-python +go):\n%s", diff)
	}
}

func captureLiveWebFlows(t *testing.T, process *webProcess, tuple webInputTuple, dump []byte, origin <-chan webOriginRequest) webLiveResult {
	t.Helper()
	trace := newWebLiveTrace(t, process.logPath)
	defer func() {
		process.stop(t)
		verifyWebPortsReleased(t, tuple)
	}()
	probe := webClient(t)
	waitWebReady(t, process, probe, tuple, func(state []byte) bool {
		if !expectedWebListener(state) {
			return false
		}
		status, _, raw, err := requestWeb(t.Context(), probe, tuple, http.MethodGet, "/flows", nil)
		var values []jsontext.Value
		return err == nil && status == http.StatusOK && json.Unmarshal(raw, &values) == nil && len(values) == 0
	})
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	// The login form creates the same XSRF cookie a fresh browser receives.
	client := webClient(t)
	login, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", tuple.webPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(login)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("fresh-browser login status=%d, want 403", response.StatusCode)
	}
	foundXSRF := false
	for _, cookie := range client.Jar.Cookies(login.URL) {
		login.AddCookie(cookie)
		foundXSRF = foundXSRF || cookie.Name == "_mitmproxy_xsrf" && cookie.Value != ""
	}
	if !foundXSRF {
		t.Fatal("real login response did not initialize the browser XSRF cookie")
	}
	dialer := gows.Dialer{HTTPHeader: login.Header}
	transport, handshake, err := dialer.Dial(ctx, fmt.Sprintf("ws://127.0.0.1:%d/updates?token=%s", tuple.webPort, url.QueryEscape(webTestPassword)))
	if err != nil {
		t.Fatal(err)
	}
	trace.record(webLiveTraceEvent{Event: "handshake_complete"})
	if handshake.Compressed {
		_ = transport.Close()
		t.Fatal("updates must not negotiate compression")
	}
	socket := gows.NewClientConn(transport, gows.WithBuffered(handshake.Buffered), gows.WithReadLimit(10<<20))
	handshake.Release()
	defer func() {
		closeContext, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		if err := socket.CloseContext(closeContext, gows.CloseNormalClosure, ""); err != nil {
			t.Errorf("close owned updates client: %v", err)
		}
	}()
	delivery, cancelDelivery := context.WithTimeout(ctx, 5*time.Second)
	defer cancelDelivery()
	trace.record(webLiveTraceEvent{Event: "http_sent", Method: http.MethodPost, Path: "/flows/dump"})
	status, _, _, err := requestWeb(delivery, client, tuple, http.MethodPost, "/flows/dump", dump)
	trace.record(webLiveTraceEvent{Event: "http_response", Method: http.MethodPost, Path: "/flows/dump", Status: new(status)})
	if err != nil || status != http.StatusOK {
		t.Fatalf("controlled upload: status=%d error=%v", status, err)
	}
	normalizer := new(webBijections)
	deadline, _ := delivery.Deadline()
	result := webLiveResult{Added: collectWebFlowEvents(t, socket, normalizer, deadline, "", trace)}
	flowsReply := captureWebReply(t, client, tuple, "/flows")
	var inventory []struct {
		ID string `json:"id"`
	}
	if flowsReply.Status != http.StatusOK || json.Unmarshal(flowsReply.Body, &inventory) != nil || len(inventory) != 1 {
		t.Fatal("controlled upload did not produce exactly one flow")
	}
	trace.record(webLiveTraceEvent{Event: "http_sent", Method: http.MethodPost, Path: "/flows/" + url.PathEscape(inventory[0].ID) + "/replay"})
	status, _, _, err = requestWeb(ctx, client, tuple, http.MethodPost, "/flows/"+url.PathEscape(inventory[0].ID)+"/replay", []byte{})
	trace.record(webLiveTraceEvent{Event: "http_response", Method: http.MethodPost, Path: "/flows/" + url.PathEscape(inventory[0].ID) + "/replay", Status: new(status)})
	if err != nil || status != http.StatusOK {
		t.Fatalf("controlled replay: status=%d error=%v", status, err)
	}
	select {
	case result.Origin = <-origin:
		want := webOriginRequest{http.MethodGet, "/live-replay", "live-replay-nonsecret"}
		if diff := gocmp.Diff(want, result.Origin); diff != "" {
			t.Fatalf("actual replay request differs (-want +got):\n%s", diff)
		}
	case <-ctx.Done():
		t.Fatal("replay never reached the real controlled origin")
	}
	replayed := waitWebReplayComplete(t, ctx, client, tuple)
	const marker = "live-sequence-complete"
	body, err := json.Marshal(map[string]string{"comment": marker})
	if err != nil {
		t.Fatal(err)
	}
	trace.record(webLiveTraceEvent{Event: "http_sent", Method: http.MethodPut, Path: "/flows/" + url.PathEscape(replayed)})
	status, _, _, err = requestWeb(ctx, client, tuple, http.MethodPut, "/flows/"+url.PathEscape(replayed), body, "application/json")
	trace.record(webLiveTraceEvent{Event: "http_response", Method: http.MethodPut, Path: "/flows/" + url.PathEscape(replayed), Status: new(status)})
	if err != nil || status != http.StatusOK {
		t.Fatalf("ordered update marker: status=%d error=%v", status, err)
	}
	result.Added = append(result.Added, collectWebFlowEvents(t, socket, normalizer, time.Now().Add(5*time.Second), marker, trace)...)
	return result
}

func waitWebReplayComplete(t *testing.T, ctx context.Context, client *http.Client, tuple webInputTuple) string {
	t.Helper()
	timer := time.NewTicker(25 * time.Millisecond)
	defer timer.Stop()
	for {
		status, _, raw, err := requestWeb(ctx, client, tuple, http.MethodGet, "/flows", nil)
		if err != nil || status != http.StatusOK {
			t.Fatalf("replay completion inventory: status=%d error=%v", status, err)
		}
		var values []struct {
			ID       string         `json:"id"`
			IsReplay *string        `json:"is_replay"`
			Response jsontext.Value `json:"response"`
			Error    jsontext.Value `json:"error"`
		}
		if err := json.Unmarshal(raw, &values); err != nil {
			t.Fatal(err)
		}
		for _, value := range values {
			if value.IsReplay != nil && *value.IsReplay == "request" && value.Response.Kind() == '{' && (len(value.Error) == 0 || value.Error.Kind() == 'n') {
				return value.ID
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("replay response did not become visible")
		case <-timer.C:
		}
	}
}

func collectWebFlowEvents(t *testing.T, socket *gows.Conn, normalizer *webBijections, deadline time.Time, marker string, trace *webLiveTrace) []any {
	t.Helper()
	phase := "initial_flows_add"
	if marker != "" {
		phase = "comment_marker"
	}
	trace.record(webLiveTraceEvent{Event: "wait_start", Phase: phase, DeadlineNS: new(deadline.Sub(trace.started).Nanoseconds())})
	if err := socket.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	var added []any
	for range 4096 {
		opcode, raw, err := socket.ReadMessage()
		if err != nil {
			trace.record(webLiveTraceEvent{Event: "read_error", Phase: phase, ErrorType: fmt.Sprintf("%T", err)})
			t.Fatalf("updates delivery: %v", err)
		}
		trace.frame(phase, opcode, raw)
		if opcode != gows.OpcodeText {
			t.Fatal("updates must use text messages")
		}
		var message struct {
			Type    string         `json:"type"`
			Payload jsontext.Value `json:"payload"`
		}
		if err := json.Unmarshal(raw, &message); err != nil {
			t.Fatal("invalid updates envelope")
		}
		if message.Type != "flows/add" && message.Type != "flows/update" {
			continue
		}
		var fields map[string]jsontext.Value
		if err := json.Unmarshal(message.Payload, &fields); err != nil {
			t.Fatal("flow updates payload must be an object")
		}
		if message.Type == "flows/add" {
			flow := fields["flow"]
			if err := decodeFlowSchema(flow); err != nil {
				t.Fatal(err)
			}
			normalized, err := normalizer.flow(flow)
			if err != nil {
				t.Fatal(err)
			}
			value, err := decodeWebComparable(bytes.Clone(raw))
			if err != nil {
				t.Fatal(err)
			}
			envelope := value.(map[string]any)
			payload := envelope["payload"].(map[string]any)
			payload["flow"] = normalized
			added = append(added, envelope)
			if marker == "" {
				trace.record(webLiveTraceEvent{Event: "wait_complete", Phase: phase})
				return added
			}
		} else if message.Type == "flows/update" && marker != "" {
			var value struct {
				Comment string `json:"comment"`
			}
			if err := json.Unmarshal(fields["flow"], &value); err == nil && value.Comment == marker {
				trace.record(webLiveTraceEvent{Event: "wait_complete", Phase: phase})
				return added
			}
		}
	}
	t.Fatal("updates exceeded the bounded controlled-event inventory")
	return nil
}
