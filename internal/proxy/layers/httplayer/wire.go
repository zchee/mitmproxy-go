// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"sync"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/http1"
)

// requestWire pairs a parsed request head with a pristine copy of the parsed
// message, taken before any handler could change it. The head preserves the
// exact wire bytes for re-assembly; the pristine copy tells the sending
// endpoint whether the message it emits still means what was read.
type requestWire struct {
	head     *http1.RequestHead
	pristine *httpmsg.Request
}

// responseWire is requestWire for a response head.
type responseWire struct {
	head     *http1.ResponseHead
	pristine *httpmsg.Response
}

// wireStore carries parsed heads from the endpoint that read them to the
// endpoint that re-emits them, so unchanged messages keep their exact wire
// bytes and the fidelity counter sees only proxy-made normalizations.
// It is scoped to one client connection and keyed by stream. Responses queue
// in order because informational heads precede the final head; requests have
// one head per stream. A send that finds no entry, such as a synthetic error
// response or a replayed request, assembles canonically and counts nothing.
type wireStore struct {
	mu        sync.Mutex
	requests  map[StreamID]*requestWire
	responses map[StreamID][]*responseWire
}

func newWireStore() *wireStore {
	return &wireStore{requests: make(map[StreamID]*requestWire), responses: make(map[StreamID][]*responseWire)}
}

func (w *wireStore) putRequest(id StreamID, entry *requestWire) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.requests[id] = entry
}

func (w *wireStore) takeRequest(id StreamID) *requestWire {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry := w.requests[id]
	delete(w.requests, id)
	return entry
}

func (w *wireStore) putResponse(id StreamID, entry *responseWire) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.responses[id] = append(w.responses[id], entry)
}

func (w *wireStore) takeResponse(id StreamID) *responseWire {
	w.mu.Lock()
	defer w.mu.Unlock()
	queue := w.responses[id]
	if len(queue) == 0 {
		return nil
	}
	entry := queue[0]
	if len(queue) == 1 {
		delete(w.responses, id)
	} else {
		w.responses[id] = queue[1:]
	}
	return entry
}

// drop discards the entries of a finished or failed stream.
func (w *wireStore) drop(id StreamID) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.requests, id)
	delete(w.responses, id)
}

// headersEqual reports whether two header blocks are byte-identical in
// spelling, value and order.
func headersEqual(a, b httpmsg.Headers) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].Name, b[i].Name) || !bytes.Equal(a[i].Value, b[i].Value) {
			return false
		}
	}
	return true
}

// requestChanged reports whether a request's head no longer matches the
// pristine parse. Host and Port are metadata, not wire bytes, and are not
// compared. A changed head is excluded from fidelity accounting because the
// difference was made deliberately, by a handler or by the proxy's own
// target or Host rewriting, and is not a normalization.
func requestChanged(pristine, current *httpmsg.Request) bool {
	return pristine.Method != current.Method ||
		pristine.Scheme != current.Scheme ||
		pristine.Authority != current.Authority ||
		pristine.Path != current.Path ||
		pristine.HTTPVersion != current.HTTPVersion ||
		!headersEqual(pristine.Headers, current.Headers)
}

// responseChanged is requestChanged for a response head.
func responseChanged(pristine, current *httpmsg.Response) bool {
	return pristine.StatusCode != current.StatusCode ||
		pristine.Reason != current.Reason ||
		pristine.HTTPVersion != current.HTTPVersion ||
		!headersEqual(pristine.Headers, current.Headers)
}
