// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"bytes"
	"errors"
	"slices"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

// Commands may retain arguments (replay.client queues its input). Each call owns
// a separate graph; only detached synchronous results return to the worker.
type commandOwnership struct{ flows map[flow.Flow]flow.Flow }

func (o *commandOwnership) argument(value any) any {
	switch value := value.(type) {
	case flow.Flow:
		if o.flows == nil {
			o.flows = make(map[flow.Flow]flow.Flow)
		}
		if prior := o.flows[value]; prior != nil {
			return prior
		}
		copy := invocationClone(value)
		o.flows[value] = copy
		return copy
	case []flow.Flow:
		out := make([]flow.Flow, len(value))
		for n, f := range value {
			out[n] = o.argument(f).(flow.Flow)
		}
		return out
	case []byte:
		return bytes.Clone(value)
	case []string:
		return slices.Clone(value)
	case command.CutSpec:
		return slices.Clone(value)
	case command.Data:
		out := make(command.Data, len(value))
		for n, row := range value {
			out[n] = o.argument(row).([]any)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for n, x := range value {
			out[n] = o.argument(x)
		}
		return out
	case *state.Map:
		return state.CopyMap(value)
	default:
		return value
	}
}

func (o *commandOwnership) copyBack() error {
	var errs []error
	for worker, retained := range o.flows {
		// SetState here targets detached worker storage, never a live flow.
		// Its post-call state is copied before the retained graph can run again.
		var request *httpmsg.Request
		var response *httpmsg.Response
		if h, ok := worker.(*flow.HTTPFlow); ok {
			request, response = h.Request, h.Response
		}
		snapshot := invocationClone(retained)
		if err := worker.SetState(state.CopyMap(snapshot.GetState())); err != nil {
			errs = append(errs, err)
			continue
		}
		worker.Common().Live = snapshot.Common().Live
		if h, ok := worker.(*flow.HTTPFlow); ok {
			source := snapshot.(*flow.HTTPFlow)
			h.Request, h.Response = source.Request, source.Response
			if request != nil && source.Request != nil {
				*request = *source.Request
				h.Request = request
			}
			if response != nil && source.Response != nil {
				*response = *source.Response
				h.Response = response
			}
		}
	}
	return errors.Join(errs...)
}
