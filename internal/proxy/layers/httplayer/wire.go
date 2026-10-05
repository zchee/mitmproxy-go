// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bytes"
	"context"
	"sync"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// requestWire retains the parsed wire bytes and records addon head edits
// separately from the proxy's own target and header rewrites.
type requestWire struct {
	head         *http1.RequestHead
	addonChanged bool
}

// responseWire is requestWire for a response head.
type responseWire struct {
	head         *http1.ResponseHead
	addonChanged bool
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

// fireHook captures heads after proxy preparation but before addons run.
// Only head fields are copied: buffered bodies may be large and do not affect
// head assembly. Once a streaming head was emitted, later hooks cannot change
// its already-recorded fidelity count.
func (s *httpStream) fireHook(ctx context.Context, prepare func(context.Context) error, hook addon.Hook) (*layer.Snapshot, error) {
	var request *httpmsg.Request
	var response *httpmsg.Response
	snapshot, err := s.c.Hooks.FireFunc(ctx, func(ctx context.Context) error {
		if prepare != nil {
			if err := prepare(ctx); err != nil {
				return err
			}
		}
		if s.wire != nil {
			if s.flow.Request != nil {
				request = new(*s.flow.Request)
				request.Headers = request.Headers.Clone()
			}
			if s.flow.Response != nil {
				response = new(*s.flow.Response)
				response.Headers = response.Headers.Clone()
			}
		}
		return nil
	}, hook)
	if err != nil || s.wire == nil {
		return snapshot, err
	}
	s.wire.mu.Lock()
	defer s.wire.mu.Unlock()
	if entry := s.wire.requests[s.id]; entry != nil && request != nil && snapshot.Request != nil {
		entry.addonChanged = entry.addonChanged || requestChanged(request, snapshot.Request)
	}
	if queue := s.wire.responses[s.id]; len(queue) != 0 && response != nil && snapshot.Response != nil {
		entry := queue[len(queue)-1]
		entry.addonChanged = entry.addonChanged || responseChanged(response, snapshot.Response)
	}
	return snapshot, nil
}

// requestChanged reports whether a hook changed the request's emitted head.
// Host and Port are routing metadata rather than wire fields.
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
